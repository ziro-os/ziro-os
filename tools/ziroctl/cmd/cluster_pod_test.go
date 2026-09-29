package cmd

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPodCIDRs(t *testing.T) {
	for _, bad := range []string{"10.200.0.0/16" /* mesh */, "172.20.5.0/24" /* ziro-net */, "10.4.0.0/16", "10.201.0.0/24", "10.201.0.1/16", "fd00::/48", "x"} {
		if validatePodCIDR(bad, defaultMeshCIDR) == nil {
			t.Fatalf("accepted pod CIDR %s", bad)
		}
	}
	if err := validatePodCIDR(defaultPodCIDR, defaultMeshCIDR); err != nil {
		t.Fatal(err)
	}
	st := &ClusterState{PodCIDR: "10.201.0.0/23"}
	var got []string
	for i := 0; i < 2; i++ {
		c, err := allocPodCIDR(st)
		if err != nil {
			t.Fatal(err)
		}
		st.Nodes = append(st.Nodes, ClusterNode{ID: c, PodCIDR: c})
		got = append(got, c)
	}
	if strings.Join(got, ",") != "10.201.0.0/24,10.201.1.0/24" {
		t.Fatalf("allocated %v", got)
	}
	if _, err := allocPodCIDR(st); err == nil {
		t.Fatal("a full pod network must be reported")
	}
	if podGateway("10.201.3.0/24") != "10.201.3.1" {
		t.Fatal("gateway is .1")
	}
}

func podState() *ClusterState {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b"), PodCIDR: "10.201.0.0/16", PolicyDefault: "deny"}
	for i, c := range []string{"10.201.0.0/24", "10.201.1.0/24"} {
		st.Nodes[i].PodCIDR, st.Nodes[i].MeshIP = c, "10.200.0."+string(rune('1'+i))
	}
	upsertApp(st, ClusteredApp{Name: "web", Image: "nginx", Replicas: 2, Port: "8080:80", Network: "pod"})
	upsertApp(st, ClusteredApp{Name: "api", Image: "api", Replicas: 1, Network: "pod", AllowFrom: []string{"web"}})
	upsertApp(st, ClusteredApp{Name: "other", Image: "o", Replicas: 1, Network: "pod"})
	scheduleReplicas(st, now)
	return st
}

func TestAssignPodIPs(t *testing.T) {
	st := podState()
	seen := map[string]bool{}
	for _, r := range st.Replicas {
		n := st.node(r.Node)
		p, _ := netip.ParsePrefix(n.PodCIDR)
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !p.Contains(ip) || strings.HasSuffix(r.IP, ".0") || strings.HasSuffix(r.IP, ".1") || seen[r.IP] {
			t.Fatalf("bad IP %q for %s-%d on %s", r.IP, r.App, r.Index, r.Node)
		}
		seen[r.IP] = true
	}
	before := append([]Replica(nil), st.Replicas...)
	scheduleReplicas(st, time.Now())
	for i := range before {
		if before[i].IP != st.Replicas[i].IP {
			t.Fatal("IPs must be stable while replicas stay put")
		}
	}
	// A rollout replaces containers in place: same IP. A moved replica gets one in its new /24.
	upsertApp(st, ClusteredApp{Name: "other", Image: "o:2", Replicas: 1, Network: "pod"})
	scheduleReplicas(st, time.Now())
	r := &st.Replicas[1] // other-1
	old := r.IP
	if r.App != "other" || r.IP != before[1].IP {
		t.Fatalf("rollout changed the IP: %+v", r)
	}
	moveTo := map[string]string{"a": "b", "b": "a"}[r.Node]
	r.Node = moveTo
	assignPodIPs(st)
	if p, _ := netip.ParsePrefix(st.node(moveTo).PodCIDR); r.IP == old || !p.Contains(netip.MustParseAddr(r.IP)) {
		t.Fatalf("moved replica kept %s", r.IP)
	}
	// Apps outside the pod network get no IP.
	st.app("other").Network = ""
	assignPodIPs(st)
	if st.Replicas[1].IP != "" {
		t.Fatal("non-pod app got a pod IP")
	}
}

func TestPodPolicy(t *testing.T) {
	st := podState()
	markRunning(st)
	var api, web []string
	for _, r := range st.Replicas {
		switch r.App {
		case "api":
			api = append(api, r.Node, r.IP)
		case "web":
			web = append(web, r.IP)
		}
	}
	p := policyFor(st, api[0])
	var rule *PodRule
	for i := range p.PodRules {
		if p.PodRules[i].App == "api" {
			rule = &p.PodRules[i]
		}
	}
	if rule == nil || strings.Join(rule.Dst, ",") != api[1] || strings.Join(rule.Src, ",") != strings.Join(sorted(web), ",") {
		t.Fatalf("api pod rule: %+v (web %v)", p.PodRules, web)
	}
	s, err := buildPolicyScript(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr " + st.node(api[0]).PodCIDR + " ct status dnat iifname != \"ziro0\" ip saddr != 10.201.0.0/16 accept",
		"ip saddr { " + strings.Join(sorted(web), ", ") + " } ip daddr { " + api[1] + " } accept",
		"ip daddr " + st.node(api[0]).PodCIDR + " drop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q:\n%s", want, s)
		}
	}
	p.PodRules[0].Src = []string{"1.2.3.4 } accept; drop {"}
	if _, err := buildPolicyScript(p); err == nil {
		t.Fatal("injected address accepted")
	}
}

func sorted(v []string) []string {
	out := append([]string(nil), v...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func TestPodDNS(t *testing.T) {
	d := &podDNS{clients: netip.MustParsePrefix("127.0.0.0/8")}
	d.setEndpoints(map[string][]string{"web": {"10.201.0.2", "10.201.1.2"}})

	r := d.answer(dnsQuery("Web.Cluster.Ziro.", 1))
	if r == nil || r[0] != 0x12 || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) != 2 {
		t.Fatalf("A answer: %x", r)
	}
	if !strings.Contains(string(r), string([]byte{10, 201, 1, 2})) {
		t.Fatal("answer lacks the replica IP")
	}
	if r := d.answer(dnsQuery("nope.cluster.ziro", 1)); r == nil || r[3]&0x0f != 3 {
		t.Fatalf("unknown app must be NXDOMAIN: %x", r)
	}
	if r := d.answer(dnsQuery("a.web.cluster.ziro", 1)); r == nil || r[3]&0x0f != 3 {
		t.Fatal("deeper names must be NXDOMAIN")
	}
	if r := d.answer(dnsQuery("web.cluster.ziro", 28)); r == nil || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) != 0 {
		t.Fatal("AAAA: NOERROR, no data")
	}
	if d.answer(dnsQuery("example.com", 1)) != nil || d.answer([]byte{1, 2, 3}) != nil {
		t.Fatal("non-cluster names go upstream; garbage is ignored")
	}

	// Real UDP round trip; clients outside the allowed range get nothing.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	go d.serve(addr)
	time.Sleep(100 * time.Millisecond)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(dnsQuery("web.cluster.ziro", 1))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	if n, err := c.Read(buf); err != nil || binary.BigEndian.Uint16(buf[6:]) != 2 || n < 40 {
		t.Fatalf("udp round trip: %v", err)
	}
	d.mu.Lock()
	d.clients = netip.MustParsePrefix("10.0.0.0/8")
	d.mu.Unlock()
}

func TestPodPlumbing(t *testing.T) {
	b, err := podConflist("10.201.3.0/24")
	var conf struct {
		Name    string           `json:"name"`
		Plugins []map[string]any `json:"plugins"`
	}
	if err != nil || json.Unmarshal(b, &conf) != nil || conf.Name != podNetName || conf.Plugins[0]["type"] != "ptp" ||
		conf.Plugins[0]["ipMasq"] != false || conf.Plugins[0]["ipam"].(map[string]any)["gateway"] != "10.201.3.1" {
		t.Fatalf("conflist: %s", b)
	}
	nat, err := podNATScript("10.201.3.0/24", "10.201.0.0/16", "10.200.0.0/16")
	if err != nil || !strings.Contains(nat, "ip saddr 10.201.3.0/24 ip daddr != { 10.201.0.0/16, 10.200.0.0/16 } masquerade") {
		t.Fatalf("nat: %v\n%s", err, nat)
	}
	if _, err := podNATScript("10.201.3.0/24; flush ruleset", "10.201.0.0/16", "10.200.0.0/16"); err == nil {
		t.Fatal("injection accepted")
	}
	args := strings.Join(runArgs(Assignment{Name: "zc-web-1-x", App: "web", Image: "nginx", IP: "10.201.3.2", DNS: "10.201.3.1"}), " ")
	if !strings.Contains(args, "--network ziro-cluster --ip 10.201.3.2 --dns 10.201.3.1 --dns-search cluster.ziro -- nginx") {
		t.Fatalf("run args: %s", args)
	}
	fw, err := buildNftScript(FirewallConfig{AllowedPorts: []FirewallRule{{Port: 53, Protocol: "udp", Source: "10.201.3.0/24"}}})
	if err != nil || !strings.Contains(fw, "ip saddr 10.201.3.0/24 udp dport 53 accept") {
		t.Fatalf("scoped firewall rule: %v\n%s", err, fw)
	}
	if _, err := buildNftScript(FirewallConfig{AllowedPorts: []FirewallRule{{Port: 53, Protocol: "udp", Source: "evil"}}}); err == nil {
		t.Fatal("bad source accepted")
	}
	rc := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(rc, []byte("search x\nnameserver 10.201.3.1\nnameserver 1.1.1.1\nnameserver bad\n"), 0644)
	if got := strings.Join(hostResolvers(rc, "10.201.3.1"), ","); got != "1.1.1.1" {
		t.Fatalf("resolvers: %s", got)
	}
}

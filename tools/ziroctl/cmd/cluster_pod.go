package cmd

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

// Pod network: every node owns a /24 of the cluster pod CIDR and every replica gets a routed IP
// from it, assigned by the master when the replica is placed (so policy and DNS know it before
// the container starts). Containers attach with the CNI ptp plugin (a veth and /32 route per
// container, no bridge), so even same-node traffic is routed and policed by nftables. Nodes
// route each other's /24 over WireGuard (AllowedIPs); only traffic leaving the cluster is
// masqueraded, so the destination node sees the real pod source IP. Each agent answers
// <app>.cluster.ziro on its node's gateway IP (.1) with the IPs of running replicas.

const (
	podNetName  = "ziro-cluster"
	podConfPath = "/etc/cni/net.d/20-ziro-cluster.conflist"
	podDNSIface = "ziro-dns0"
	podMTU      = 1420 // 1500 underlay minus WireGuard overhead
	podNATTable = "ip ziro_pods"
)

// Ranges other Ziro networks already use: a pod CIDR must not overlap them.
var reservedNets = []string{"172.20.0.0/16" /* ziro-net (CRI) */, "10.4.0.0/24" /* nerdctl bridge */}

func validatePodCIDR(pod, mesh string) error {
	p, err := netip.ParsePrefix(pod)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 23 || p.Masked() != p {
		return fmt.Errorf("invalid pod CIDR %q (want an IPv4 network from /8 to /23, e.g. %s)", pod, defaultPodCIDR)
	}
	for _, other := range append([]string{mesh}, reservedNets...) {
		if o, err := netip.ParsePrefix(other); err == nil && o.Overlaps(p) {
			return fmt.Errorf("pod CIDR %s overlaps %s", pod, other)
		}
	}
	return nil
}

// allocPodCIDR hands out the next free /24 of the cluster pod network.
func allocPodCIDR(st *ClusterState) (string, error) {
	p, err := netip.ParsePrefix(st.PodCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid pod CIDR %q", st.PodCIDR)
	}
	used := map[string]bool{}
	for _, n := range st.Nodes {
		used[n.PodCIDR] = true
	}
	for a := p.Addr(); p.Contains(a); {
		sub := netip.PrefixFrom(a, 24)
		if !used[sub.String()] {
			return sub.String(), nil
		}
		b := a.As4()
		if b[2] == 255 {
			if b[1] == 255 {
				break
			}
			b[1]++
		}
		b[2]++
		a = netip.AddrFrom4(b)
	}
	return "", fmt.Errorf("pod network %s is full", st.PodCIDR)
}

// podGateway is the node's .1: the DNS responder and the ptp gateway for its containers.
func podGateway(nodeCIDR string) string {
	p, err := netip.ParsePrefix(nodeCIDR)
	if err != nil {
		return ""
	}
	return p.Addr().Next().String()
}

// assignPodIPs gives every placed pod-network replica an IP in its node's /24 and clears it
// when the replica is unplaced or moved: a replica keeps its IP while it stays on a node
// (rollouts replace the container in place), and gets a new one when it moves.
func assignPodIPs(st *ClusterState) {
	used := map[string]bool{}
	for i := range st.Replicas {
		r := &st.Replicas[i]
		n := st.node(r.Node)
		a := st.app(r.App)
		ok := n != nil && n.PodCIDR != "" && a != nil && a.Network == "pod"
		if ok && r.IP != "" {
			p, _ := netip.ParsePrefix(n.PodCIDR)
			ip, err := netip.ParseAddr(r.IP)
			ok = err == nil && p.Contains(ip) && !used[r.IP]
		} else {
			ok = false
		}
		if !ok {
			r.IP = ""
			continue
		}
		used[r.IP] = true
	}
	for i := range st.Replicas {
		r := &st.Replicas[i]
		n := st.node(r.Node)
		a := st.app(r.App)
		if r.IP != "" || n == nil || n.PodCIDR == "" || a == nil || a.Network != "pod" {
			continue
		}
		p, _ := netip.ParsePrefix(n.PodCIDR)
		for ip := p.Addr().Next().Next(); p.Contains(ip); ip = ip.Next() { // .2 up; .1 is the gateway
			if !p.Contains(ip.Next()) {
				break // broadcast
			}
			if !used[ip.String()] {
				r.IP = ip.String()
				used[r.IP] = true
				break
			}
		}
	}
}

// podEndpoints maps each app to the pod IPs of its running replicas (discovery, gateway).
func podEndpoints(st *ClusterState) map[string][]string {
	out := map[string][]string{}
	for _, r := range st.Replicas {
		if r.IP != "" && st.replicaRunning(r) {
			out[r.App] = append(out[r.App], r.IP)
		}
	}
	for _, ips := range out {
		sort.Strings(ips)
	}
	return out
}

// placedPodIPs maps each app to the pod IPs of all its placed replicas (policy sources: a
// replica that is still starting must already be admitted).
func placedPodIPs(st *ClusterState) map[string][]string {
	out := map[string][]string{}
	for _, r := range st.Replicas {
		if r.IP != "" {
			out[r.App] = append(out[r.App], r.IP)
		}
	}
	return out
}

var clusterNetworkCmd = &cobra.Command{Use: "network", Short: "Cluster pod network (routed container IPs + DNS)"}

var clusterNetworkEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Move an existing cluster to the pod network (apps roll over one replica at a time)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		if err := validatePodCIDR(clusterPodCIDR, meshCIDR(cfg)); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			if st.PodCIDR != "" {
				return fmt.Errorf("the pod network is already enabled (%s)", st.PodCIDR)
			}
			st.PodCIDR = clusterPodCIDR
			for i := range st.Nodes {
				c, err := allocPodCIDR(st)
				if err != nil {
					return err
				}
				st.Nodes[i].PodCIDR = c
			}
			for i := range st.Apps {
				upsertApp(st, withPodNetwork(st, st.Apps[i]))
			}
			scheduleReplicas(st, time.Now())
			fmt.Printf("✓ pod network %s enabled; apps roll over to it one replica at a time (ziroctl cluster services)\n", st.PodCIDR)
			return nil
		})
	},
}

func withPodNetwork(st *ClusterState, a ClusteredApp) ClusteredApp {
	if st.PodCIDR != "" {
		a.Network = "pod"
	}
	return a
}

var clusterNetworkStatusCmd = &cobra.Command{
	Use: "status", Short: "Show the pod network, node subnets and replica IPs",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		type nodeNet struct {
			Node    string `json:"node"`
			PodCIDR string `json:"pod_cidr"`
		}
		type replicaNet struct {
			Replica string `json:"replica"`
			Node    string `json:"node"`
			IP      string `json:"ip"`
		}
		v := struct {
			PodCIDR  string       `json:"pod_cidr"`
			Nodes    []nodeNet    `json:"nodes"`
			Replicas []replicaNet `json:"replicas"`
		}{PodCIDR: st.PodCIDR, Nodes: []nodeNet{}, Replicas: []replicaNet{}}
		for _, n := range st.Nodes {
			v.Nodes = append(v.Nodes, nodeNet{n.ID, n.PodCIDR})
		}
		for _, r := range st.Replicas {
			v.Replicas = append(v.Replicas, replicaNet{fmt.Sprintf("%s-%d", r.App, r.Index), r.Node, r.IP})
		}
		return printResult(v, func() {
			if v.PodCIDR == "" {
				fmt.Println("Pod network: off (host ports only). Enable: ziroctl cluster network enable")
				return
			}
			fmt.Printf("Pod network: %s\n\n", v.PodCIDR)
			for _, n := range v.Nodes {
				fmt.Printf("  %-14s %s\n", n.Node, n.PodCIDR)
			}
			fmt.Println()
			for _, r := range v.Replicas {
				fmt.Printf("  %-24s %-14s %s\n", r.Replica, r.Node, r.IP)
			}
		})
	},
}

func init() {
	clusterNetworkCmd.AddCommand(clusterNetworkEnableCmd, clusterNetworkStatusCmd)
	clusterCmd.AddCommand(clusterNetworkCmd)
}

// ---- agent side ----

// podConflist is the CNI config for the node's /24. ipMasq is off: masquerading is done once,
// for traffic leaving the cluster only (applyPodNetwork).
func podConflist(nodeCIDR string) ([]byte, error) {
	gw := podGateway(nodeCIDR)
	if gw == "" {
		return nil, fmt.Errorf("invalid node pod CIDR %q", nodeCIDR)
	}
	return json.MarshalIndent(map[string]any{
		"cniVersion": "1.0.0",
		"name":       podNetName,
		"plugins": []map[string]any{
			{"type": "ptp", "ipMasq": false, "mtu": podMTU, "ipam": map[string]any{
				"type": "host-local", "subnet": nodeCIDR, "gateway": gw,
				"routes": []map[string]string{{"dst": "0.0.0.0/0"}},
			}},
			{"type": "portmap", "capabilities": map[string]bool{"portMappings": true}},
		},
	}, "", "  ")
}

// podNATScript masquerades pod traffic leaving the cluster (not to other pods or the mesh).
func podNATScript(nodeCIDR, podNet, meshNet string) (string, error) {
	for _, c := range []string{nodeCIDR, podNet, meshNet} {
		if p, err := netip.ParsePrefix(c); err != nil || !p.Addr().Is4() {
			return "", fmt.Errorf("invalid network %q", c)
		}
	}
	return fmt.Sprintf(`table %[1]s
delete table %[1]s
table %[1]s {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    ip saddr %[2]s ip daddr != { %[3]s, %[4]s } masquerade
  }
}
`, podNATTable, nodeCIDR, podNet, meshNet), nil
}

var podNetApplied atomic.Value // string: last applied "<nodeCIDR> <podNet> <meshNet>"

// applyPodNetwork converges the node's pod plumbing. Idempotent and cheap when nothing changed.
func applyPodNetwork(nodeCIDR, podNet, meshNet string) error {
	key := nodeCIDR + " " + podNet + " " + meshNet
	if v, _ := podNetApplied.Load().(string); v == key {
		return nil
	}
	conf, err := podConflist(nodeCIDR)
	if err != nil {
		return err
	}
	nat, err := podNATScript(nodeCIDR, podNet, meshNet)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(podConfPath); err != nil || string(cur) != string(conf) {
		if err := os.MkdirAll(dirOf(podConfPath), 0755); err != nil {
			return err
		}
		if err := writeFileAtomic(podConfPath, conf, 0644); err != nil {
			return err
		}
	}
	gw := podGateway(nodeCIDR)
	if !linkExists(podDNSIface) {
		if err := run("ip", "link", "add", podDNSIface, "type", "dummy"); err != nil {
			return err
		}
	}
	for _, c := range [][]string{
		{"ip", "address", "replace", gw + "/32", "dev", podDNSIface},
		{"ip", "link", "set", "up", "dev", podDNSIface},
		{"ip", "route", "replace", podNet, "dev", meshIface}, // other nodes' /24s (more specific /32s win locally)
	} {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(nat)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("nft pod nat: %v: %s", err, strings.TrimSpace(string(out)))
	}
	allowFirewall([]FirewallRule{
		{Port: 53, Protocol: "udp", Source: nodeCIDR, Comment: "Ziro pod DNS"},
		{Port: 53, Protocol: "tcp", Source: nodeCIDR, Comment: "Ziro pod DNS"},
	}, "")
	podNetApplied.Store(key)
	return nil
}

func teardownPodNetwork() {
	_ = os.Remove(podConfPath)
	if linkExists(podDNSIface) {
		_ = run("ip", "link", "del", podDNSIface)
	}
	_ = exec.Command("nft", "delete", "table", "ip", "ziro_pods").Run()
}

// ---- DNS responder ----

// podDNS answers A queries for <app>.cluster.ziro from the master's view of running replicas
// and relays every other query, byte for byte, to the node's own resolvers. It only serves
// clients inside the node's pod /24 (the firewall rule is scoped the same way).
type podDNS struct {
	mu        sync.RWMutex
	eps       map[string][]string // app -> pod IPs
	clients   netip.Prefix
	upstreams []string
	egress    *egressLearner // fills egress-controlled apps' allow sets from their DNS answers
}

func (d *podDNS) setEndpoints(eps map[string][]string) {
	d.mu.Lock()
	d.eps = eps
	d.mu.Unlock()
}

// dnsName decodes the question name at off (no compression in questions), lowercased.
func dnsName(msg []byte, off int) (string, int, error) {
	var labels []string
	for n := 0; off < len(msg) && n < 128; n++ {
		l := int(msg[off])
		off++
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")) + ".", off, nil
		}
		if l > 63 || off+l > len(msg) {
			break
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return "", 0, errors.New("bad name")
}

// answer builds the reply for a cluster-zone query, or returns nil when the query belongs to
// the upstream resolvers.
func (d *podDNS) answer(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	name, end, err := dnsName(q, 12)
	if err != nil || end+4 > len(q) || !strings.HasSuffix(name, "."+meshDomain+".") {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end : end+2])
	app := strings.TrimSuffix(name, "."+meshDomain+".")
	d.mu.RLock()
	ips, known := d.eps[app]
	d.mu.RUnlock()

	resp := append([]byte{}, q[:end+4]...)   // header + question
	resp[2] = 0x84 | q[2]&0x01               // QR, AA, keep RD
	resp[3] = 0x80                           // RA, RCODE 0
	binary.BigEndian.PutUint16(resp[6:], 0)  // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:], 0) // ARCOUNT
	if !known || strings.Contains(app, ".") {
		resp[3] |= 3 // NXDOMAIN
		return resp
	}
	if qtype != 1 && qtype != 255 { // not A/ANY: the name exists, no data of that type
		return resp
	}
	n := 0
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			continue
		}
		a := ip.As4()
		// name pointer to the question, TYPE A, CLASS IN, TTL 5s, RDLENGTH 4
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, a[0], a[1], a[2], a[3])
		n++
	}
	binary.BigEndian.PutUint16(resp[6:], uint16(n))
	return resp
}

func addrIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	return ""
}

func (d *podDNS) allowed(addr net.Addr) bool {
	var ip netip.Addr
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	}
	return d.clients.Contains(ip.Unmap())
}

func (d *podDNS) forward(q []byte, useTCP bool) []byte {
	for _, up := range d.upstreams {
		network := "udp"
		if useTCP {
			network = "tcp"
		}
		c, err := net.DialTimeout(network, net.JoinHostPort(up, "53"), 2*time.Second)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		var resp []byte
		if useTCP {
			resp, err = tcpExchange(c, q)
		} else {
			buf := make([]byte, 65535)
			if _, err = c.Write(q); err == nil {
				var n int
				n, err = c.Read(buf)
				resp = buf[:n]
			}
		}
		c.Close()
		if err == nil && len(resp) >= 12 && resp[0] == q[0] && resp[1] == q[1] {
			return resp
		}
	}
	return nil
}

func tcpExchange(c net.Conn, q []byte) ([]byte, error) {
	if _, err := c.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)); err != nil {
		return nil, err
	}
	return readTCPMsg(c)
}

func readTCPMsg(c io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(c, msg)
	return msg, err
}

func (d *podDNS) serve(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return err
	}
	sem := make(chan struct{}, 256) // bound concurrent upstream relays
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !d.allowed(c.RemoteAddr()) {
				c.Close()
				continue
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp := d.answer(q)
				if resp == nil {
					if resp = d.forward(q, true); resp != nil {
						d.egress.learn(addrIP(c.RemoteAddr()), resp) // before the pod gets the answer
					}
				}
				if resp != nil {
					_, _ = c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...))
				}
			}()
		}
	}()
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if !d.allowed(from) {
			continue
		}
		q := append([]byte{}, buf[:n]...)
		if resp := d.answer(q); resp != nil {
			_, _ = pc.WriteTo(resp, from)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				if resp := d.forward(q, false); resp != nil {
					d.egress.learn(addrIP(from), resp) // before the pod gets the answer (and connects)
					_, _ = pc.WriteTo(resp, from)
				}
			}()
		default: // overloaded: drop, the client retries
		}
	}
}

// hostResolvers reads the node's nameservers (the pod DNS itself is skipped).
func hostResolvers(path, self string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" && f[1] != self {
			if _, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, f[1])
			}
		}
	}
	return out
}

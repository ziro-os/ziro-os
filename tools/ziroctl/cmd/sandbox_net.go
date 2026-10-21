package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Sandbox network: egress policy enforced outside the workload, failing closed.
//
// A sandbox with network mode none has no interface at all. One with mode allowlist or open
// gets a routed IP on the sandbox subnet (the CNI ptp plugin: a veth and /32 route per
// sandbox, no bridge), so all of its traffic, even to another sandbox, crosses the host's
// forward hook. The IP is assigned before the container starts and the nftables rules for it
// are in place first; an address nothing allows is dropped by the table's last rule.
//
// Table inet ziro_sandbox:
//   - traffic into the subnet is dropped unless it answers a sandbox's own connection
//     (sandbox to sandbox, and anything from outside);
//   - from a sandbox to the host, only DNS on the gateway address is accepted;
//   - open: anything but the blocked ranges (private, loopback, link-local and cloud metadata,
//     CGNAT, multicast, reserved);
//   - allowlist: listed CIDRs (a private range needs an operator), then the addresses the
//     allowed domains resolve to, learned by the sandbox DNS responder from its own answers
//     (private addresses in answers are ignored, so a domain can't be rebound to the LAN);
//   - names that aren't allowed get NXDOMAIN from the responder.
//
// Network policy is the dynamic part of a sandbox (PUT .../network applies it live); the rest
// of the spec is fixed at create. A sandbox created without a network can't get one later.
//
// Known limitation: IPv4 only (IPv6 is off on the sandbox network); domains allow every port;
// addresses learned from DNS are lost when ziro-sandboxd restarts (sandboxes resolve again).

const (
	sandboxNetName   = "ziro-sandbox"
	sandboxConfPath  = "/etc/cni/net.d/30-ziro-sandbox.conflist"
	sandboxDNSIface  = "zsbx-dns0"
	sandboxTable     = "ziro_sandbox"     // inet
	sandboxNATTable  = "ziro_sandbox_nat" // ip
	sandboxDefSubnet = "10.250.0.0/16"
)

// sandboxBlocked are the ranges no sandbox reaches unless an operator allows them.
var sandboxBlocked = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"}

var (
	sandboxNft      = nftRun
	sandboxNftAdd   = nftAddElements
	sandboxNetSetup = setupSandboxNetwork
)

func validateSandboxSubnet(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 24 || p.Masked() != p {
		return fmt.Errorf("sandbox subnet %q must be an IPv4 network from /16 to /24", s)
	}
	for _, other := range append(append([]string{}, reservedNets...), defaultPodCIDR, defaultMeshCIDR) {
		if o, _ := netip.ParsePrefix(other); o.Overlaps(p) {
			return fmt.Errorf("sandbox subnet %s overlaps %s", s, other)
		}
	}
	return nil
}

func networked(s schema.SandboxSpec) bool {
	return s.Network != nil && s.Network.Mode != "" && s.Network.Mode != schema.SandboxNetNone
}

// privilegedAllow returns the first allow entry inside a blocked range (needs an operator).
func privilegedAllow(n *schema.SandboxNetwork) string {
	if n == nil {
		return ""
	}
	for _, e := range n.Allow {
		p, err := schema.SandboxAllowPrefix(e)
		if err != nil {
			continue
		}
		for _, b := range sandboxBlocked {
			if netip.MustParsePrefix(b).Overlaps(p) {
				return e
			}
		}
	}
	return ""
}

// allocSandboxIP returns the first free address of the subnet after the gateway; the caller
// holds the store lock.
func allocSandboxIP(subnet string, all map[string]*sdkapi.Sandbox) (string, error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, sb := range all {
		used[sb.IP] = true
	}
	for a := p.Addr().Next().Next(); p.Contains(a) && p.Contains(a.Next()); a = a.Next() {
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("the sandbox network %s is full", subnet)
}

func sandboxGateway(subnet string) string {
	return netip.MustParsePrefix(subnet).Addr().Next().String()
}

func sandboxSet(id string) string { return "s" + id }

// sandboxNftScript renders the whole table for the sandboxes that have an IP. It keeps the
// learned-address sets of sandboxes that still exist (flushing chains, not the table) and
// deletes the sets of those in gone.
func sandboxNftScript(subnet string, sbs []sdkapi.Sandbox, gone []string, proxyPort int) (string, error) {
	if err := validateSandboxSubnet(subnet); err != nil {
		return "", err
	}
	gw := sandboxGateway(subnet)
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	t := "inet " + sandboxTable
	w("table %s {", t)
	w("  set blocked { type ipv4_addr; flags interval; }")
	for _, sb := range sbs {
		w("  set %ss { type ipv4_addr; flags interval; }", sandboxSet(sb.ID))
		w("  set %sd { type ipv4_addr; flags timeout; }", sandboxSet(sb.ID))
	}
	w("  chain forward { type filter hook forward priority -10; policy accept; }")
	w("  chain input { type filter hook input priority -10; policy accept; }")
	w("  chain prerouting { type nat hook prerouting priority dstnat; policy accept; }")
	w("}")
	w("flush chain %s forward", t)
	w("flush chain %s input", t)
	w("flush chain %s prerouting", t)
	for _, id := range gone {
		if !sandboxIDRe.MatchString(id) {
			return "", fmt.Errorf("bad sandbox id %q", id)
		}
		w("delete set %s %ss", t, sandboxSet(id))
		w("delete set %s %sd", t, sandboxSet(id))
	}
	w("flush set %s blocked", t)
	w("add element %s blocked { %s }", t, strings.Join(sandboxBlocked, ", "))
	w("add rule %s forward ip daddr %s ct state established,related accept", t, subnet)
	w("add rule %s forward ip daddr %s counter drop comment \"into a sandbox\"", t, subnet)
	w("add rule %s forward ip saddr != %s accept", t, subnet)
	w("add rule %s forward ct state established,related accept", t)
	for _, sb := range sbs {
		ip, err := netip.ParseAddr(sb.IP)
		if err != nil || !netip.MustParsePrefix(subnet).Contains(ip) {
			return "", fmt.Errorf("sandbox %s: bad IP %q", sb.ID, sb.IP)
		}
		set := sandboxSet(sb.ID)
		from := fmt.Sprintf("add rule %s forward ip saddr %s ", t, ip)
		switch sb.Spec.Network.Mode {
		case schema.SandboxNetOpen:
			w(from + "ip daddr @blocked drop")
			w(from + "accept")
		case schema.SandboxNetAllowlist:
			var cidrs []string
			for _, e := range sb.Spec.Network.Allow {
				if p, err := schema.SandboxAllowPrefix(e); err == nil {
					cidrs = append(cidrs, p.String())
				}
			}
			w("flush set %s %ss", t, set)
			if len(cidrs) > 0 {
				w("add element %s %ss { %s }", t, set, strings.Join(cidrs, ", "))
			}
			w(from + "ip daddr @" + set + "s accept")
			w(from + "ip daddr @blocked drop")
			w(from + "ip daddr @" + set + "d accept")
		}
		// mode none (a live sandbox switched off): no rule, the drop below applies
	}
	w("add rule %s forward counter drop comment \"sandbox egress\"", t)
	w("add rule %s input ip saddr %s ip daddr %s udp dport 53 accept", t, subnet, gw)
	w("add rule %s input ip saddr %s ip daddr %s tcp dport 53 accept", t, subnet, gw)
	// Sandboxes with secrets: their HTTPS goes through the egress proxy (credential injection).
	if proxyPort > 0 {
		for _, sb := range sbs {
			if len(sb.Spec.Secrets) > 0 && sb.Spec.Network.Mode != schema.SandboxNetNone {
				w("add rule %s prerouting ip saddr %s tcp dport 443 redirect to :%d", t, sb.IP, proxyPort)
				w("add rule %s input ip saddr %s tcp dport %d accept", t, sb.IP, proxyPort)
			}
		}
	}
	w("add rule %s input ip saddr %s ct state established,related accept", t, subnet)
	w("add rule %s input ip saddr %s counter drop comment \"sandbox to host\"", t, subnet)
	return b.String(), nil
}

// sandboxNet is the daemon's network side: the policy the DNS responder applies and the last
// applied table.
type sandboxNet struct {
	subnet string
	mu     sync.Mutex
	ready  bool
	sets   map[string]bool     // sandbox ids with sets in the table
	byIP   map[string]ipPolicy // the DNS responder's view
	dnsMu  sync.RWMutex

	proxyPort int                             // the egress proxy (0: off)
	learned   map[string]map[string]time.Time // sandbox id -> address -> until (what the sets hold, for the proxy)
}

type ipPolicy struct {
	id  string
	net *schema.SandboxNetwork
}

func newSandboxNet(subnet string) *sandboxNet {
	return &sandboxNet{subnet: subnet, sets: map[string]bool{}, byIP: map[string]ipPolicy{}, learned: map[string]map[string]time.Time{}}
}

// setupSandboxNetwork writes the CNI network, the gateway/DNS address, masquerading for
// traffic leaving the host, the firewall rules for DNS, and starts the DNS responder.
func setupSandboxNetwork(n *sandboxNet) error {
	gw := sandboxGateway(n.subnet)
	conf, _ := json.MarshalIndent(map[string]any{
		"cniVersion": "1.0.0",
		"name":       sandboxNetName,
		"plugins": []map[string]any{{"type": "ptp", "ipMasq": false, "mtu": 1500, "ipam": map[string]any{
			"type": "host-local", "subnet": n.subnet, "gateway": gw,
			"routes": []map[string]string{{"dst": "0.0.0.0/0"}},
		}}},
	}, "", "  ")
	if cur, err := os.ReadFile(sandboxConfPath); err != nil || string(cur) != string(conf) {
		if err := os.MkdirAll(dirOf(sandboxConfPath), 0755); err != nil {
			return err
		}
		if err := writeFileAtomic(sandboxConfPath, conf, 0644); err != nil {
			return err
		}
	}
	if !linkExists(sandboxDNSIface) {
		if err := run("ip", "link", "add", sandboxDNSIface, "type", "dummy"); err != nil {
			return err
		}
	}
	for _, c := range [][]string{
		{"ip", "address", "replace", gw + "/32", "dev", sandboxDNSIface},
		{"ip", "link", "set", "up", "dev", sandboxDNSIface},
	} {
		if err := run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	nat := fmt.Sprintf("table ip %[1]s\ndelete table ip %[1]s\ntable ip %[1]s {\n  chain postrouting {\n"+
		"    type nat hook postrouting priority 100; policy accept;\n    ip saddr %[2]s ip daddr != %[2]s masquerade\n  }\n}\n",
		sandboxNATTable, n.subnet)
	if err := sandboxNft(nat); err != nil {
		return fmt.Errorf("sandbox nat: %w", err)
	}
	// A fresh table: sets from an earlier daemon are gone with their learned addresses.
	_ = sandboxNft(fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", sandboxTable))
	allowFirewall([]FirewallRule{
		{Port: 53, Protocol: "udp", Source: n.subnet, Comment: "Ziro sandbox DNS"},
		{Port: 53, Protocol: "tcp", Source: n.subnet, Comment: "Ziro sandbox DNS"},
	}, "")
	clients := netip.MustParsePrefix(n.subnet)
	dns := &podDNS{clients: clients, upstreams: hostResolvers("/etc/resolv.conf", gw), policy: n}
	go func() {
		for { // the address can briefly be missing while the link is (re)created: retry
			fmt.Printf("[sandboxd] dns: %v\n", dns.serve(net.JoinHostPort(gw, "53")))
			time.Sleep(5 * time.Second)
		}
	}()
	return nil
}

// apply converges the table and the DNS policy to the sandboxes. Called after every change.
func (n *sandboxNet) apply(all []sdkapi.Sandbox) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var sbs []sdkapi.Sandbox
	byIP := map[string]ipPolicy{}
	keep := map[string]bool{}
	for _, sb := range all {
		if sb.IP == "" || sb.Spec.Network == nil {
			continue
		}
		sbs = append(sbs, sb)
		byIP[sb.IP] = ipPolicy{sb.ID, sb.Spec.Network}
		keep[sb.ID] = true
	}
	if !n.ready {
		if len(sbs) == 0 {
			return nil
		}
		return errors.New("the sandbox network isn't set up (see /var/log/ziro-sandboxd.log)")
	}
	var gone []string
	for id := range n.sets {
		if !keep[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	sort.Slice(sbs, func(i, j int) bool { return sbs[i].IP < sbs[j].IP })
	script, err := sandboxNftScript(n.subnet, sbs, gone, n.proxyPort)
	if err != nil {
		return err
	}
	if err := sandboxNft(script); err != nil {
		return err
	}
	n.sets = keep
	n.dnsMu.Lock()
	n.byIP = byIP
	for id := range n.learned {
		if !keep[id] {
			delete(n.learned, id)
		}
	}
	n.dnsMu.Unlock()
	return nil
}

// allow: which names a sandbox may resolve (the DNS responder asks).
func (n *sandboxNet) allow(client, name string) bool {
	n.dnsMu.RLock()
	p := n.byIP[client].net
	n.dnsMu.RUnlock()
	if p == nil {
		return false
	}
	switch p.Mode {
	case schema.SandboxNetOpen:
		return true
	case schema.SandboxNetAllowlist:
		return matchesAny(name, sandboxDomains(p))
	}
	return false
}

// learn adds the public addresses an allowed name resolved to into the sandbox's set.
func (n *sandboxNet) learn(client string, resp []byte) {
	n.dnsMu.RLock()
	pol := n.byIP[client]
	n.dnsMu.RUnlock()
	p := pol.net
	if p == nil || p.Mode != schema.SandboxNetAllowlist {
		return
	}
	q, ips, keep := dnsAnswerA(resp)
	if !matchesAny(q, sandboxDomains(p)) {
		return
	}
	var public []string
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil && !sandboxBlockedAddr(a) {
			public = append(public, s)
		}
	}
	if len(public) == 0 {
		return
	}
	if err := sandboxNftAdd("inet", sandboxTable, sandboxSet(pol.id)+"d", public, keep); err != nil {
		fmt.Printf("[sandboxd] %s: learn %s: %v\n", pol.id, q, err)
		return
	}
	until := time.Now().Add(keep)
	n.dnsMu.Lock()
	if n.learned[pol.id] == nil {
		n.learned[pol.id] = map[string]time.Time{}
	}
	for _, ip := range public {
		n.learned[pol.id][ip] = until
	}
	n.dnsMu.Unlock()
}

func (n *sandboxNet) policyOf(ip string) ipPolicy {
	n.dnsMu.RLock()
	defer n.dnsMu.RUnlock()
	return n.byIP[ip]
}

// egressAllowed is the forward rules' verdict for a destination, for traffic the egress proxy
// carries on a sandbox's behalf.
func (n *sandboxNet) egressAllowed(pol ipPolicy, dst netip.Addr) bool {
	if pol.net == nil {
		return false
	}
	switch pol.net.Mode {
	case schema.SandboxNetOpen:
		return !sandboxBlockedAddr(dst)
	case schema.SandboxNetAllowlist:
		for _, e := range pol.net.Allow {
			if p, err := schema.SandboxAllowPrefix(e); err == nil && p.Contains(dst) {
				return true
			}
		}
		if sandboxBlockedAddr(dst) {
			return false
		}
		n.dnsMu.RLock()
		until, ok := n.learned[pol.id][dst.String()]
		n.dnsMu.RUnlock()
		return ok && time.Now().Before(until)
	}
	return false
}

func sandboxBlockedAddr(a netip.Addr) bool {
	for _, b := range sandboxBlocked {
		if netip.MustParsePrefix(b).Contains(a) {
			return true
		}
	}
	return false
}

// sandboxDomains are the domain entries of an allowlist, as fqdns ("*.x" means x and below,
// like "x").
func sandboxDomains(p *schema.SandboxNetwork) []string {
	var out []string
	for _, e := range p.Allow {
		if _, err := schema.SandboxAllowPrefix(e); err != nil {
			out = append(out, fqdn(strings.TrimPrefix(e, "*.")))
		}
	}
	return out
}

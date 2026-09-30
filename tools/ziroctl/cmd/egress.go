package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Egress control for pod-network apps. An app deployed with --egress may only open connections
// to the listed CIDRs and to the addresses its allowed domains resolve to; everything else leaving
// its pods is dropped. In-cluster traffic (pods, mesh) stays governed by the app policy.
//
// Enforcement is an nftables table on each node, per app: <set>p (local pod IPs), <set>s (static
// CIDRs) and <set>d (addresses learned from DNS, with a timeout). The node's pod DNS responder fills
// <set>d when a pod of the app resolves an allowed domain (the dnsmasq nftset approach). The table
// is never deleted while apps use it: re-applies flush the chain and static sets but keep the
// learned addresses, so a pod's cached DNS answers stay valid.
//
// ponytail: IPv4 only (the pod network is IPv4); host-network apps are not covered.

const egressTable = "inet ziro_egress"

// validateEgress accepts IPv4 addresses/CIDRs and domain names (subdomains included).
func validateEgress(list []string) error {
	if len(list) > 64 {
		return fmt.Errorf("too many egress entries (max 64)")
	}
	for _, e := range list {
		if p, err := netip.ParsePrefix(e); err == nil {
			if !p.Addr().Is4() {
				return fmt.Errorf("egress %q: only IPv4 (the pod network is IPv4)", e)
			}
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			if !a.Is4() {
				return fmt.Errorf("egress %q: only IPv4", e)
			}
			continue
		}
		if !validDomain(e) {
			return fmt.Errorf("egress %q is neither an IPv4 CIDR nor a domain", e)
		}
	}
	return nil
}

func egressSet(app string) string {
	h := sha256.Sum256([]byte(app))
	return "e" + hex.EncodeToString(h[:6])
}

type egressApp struct {
	App     string
	Set     string
	PodIPs  []string
	CIDRs   []string
	Domains []string // fqdn
}

// egressApps joins the cluster's egress lists with this node's pod replicas.
func egressApps(egress map[string][]string, assignments []Assignment) []egressApp {
	pods := map[string][]string{}
	for _, a := range assignments {
		if a.IP != "" {
			pods[a.App] = append(pods[a.App], a.IP)
		}
	}
	var out []egressApp
	for app, list := range egress {
		if len(pods[app]) == 0 {
			continue
		}
		e := egressApp{App: app, Set: egressSet(app), PodIPs: pods[app]}
		for _, x := range list {
			if p, err := netip.ParsePrefix(x); err == nil {
				e.CIDRs = append(e.CIDRs, p.Masked().String())
			} else if a, err := netip.ParseAddr(x); err == nil {
				e.CIDRs = append(e.CIDRs, a.String()+"/32")
			} else {
				e.Domains = append(e.Domains, fqdn(x))
			}
		}
		sort.Strings(e.PodIPs)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out
}

func buildEgressScript(apps []egressApp, podNet, meshNet string) (string, error) {
	if len(apps) == 0 {
		return "table " + egressTable + "\ndelete table " + egressTable + "\n", nil
	}
	for _, c := range []string{podNet, meshNet} {
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err != nil || !p.Addr().Is4() {
			return "", fmt.Errorf("invalid network %q", c)
		}
	}
	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f+"\n", a...) }
	w("table %s {", egressTable)
	for _, a := range apps {
		w("  set %sp { type ipv4_addr; }", a.Set)
		w("  set %ss { type ipv4_addr; flags interval; }", a.Set)
		w("  set %sd { type ipv4_addr; flags timeout; }", a.Set)
	}
	w("  chain forward { type filter hook forward priority -5; policy accept; }")
	w("}")
	w("flush chain %s forward", egressTable)
	w("add rule %s forward ct state established,related accept", egressTable)
	var internal []string
	for _, c := range []string{podNet, meshNet} {
		if c != "" {
			internal = append(internal, c)
		}
	}
	for _, a := range apps {
		for _, ip := range a.PodIPs {
			if x, err := netip.ParseAddr(ip); err != nil || !x.Is4() {
				return "", fmt.Errorf("invalid pod IP %q", ip)
			}
		}
		w("flush set %s %sp", egressTable, a.Set)
		w("add element %s %sp { %s }", egressTable, a.Set, strings.Join(a.PodIPs, ", "))
		w("flush set %s %ss", egressTable, a.Set)
		if len(a.CIDRs) > 0 {
			w("add element %s %ss { %s }", egressTable, a.Set, strings.Join(a.CIDRs, ", "))
		}
		in := fmt.Sprintf("add rule %s forward ip saddr @%sp ", egressTable, a.Set)
		if len(internal) > 0 {
			w(in+"ip daddr { %s } accept", strings.Join(internal, ", "))
		}
		w(in + "ip daddr @" + a.Set + "s accept")
		w(in + "ip daddr @" + a.Set + "d accept")
		w(in+"counter drop comment %q", "egress "+a.App)
	}
	return sb.String(), nil
}

var (
	egressMu      sync.Mutex
	egressApplied string
)

// applyEgress renders the table when the inputs change (heartbeats would otherwise churn nft).
func applyEgress(egress map[string][]string, assignments []Assignment, podNet, meshNet string) error {
	apps := egressApps(egress, assignments)
	script, err := buildEgressScript(apps, podNet, meshNet)
	if err != nil {
		return err
	}
	egressMu.Lock()
	defer egressMu.Unlock()
	if script == egressApplied {
		return nil
	}
	if len(apps) == 0 && egressApplied == "" {
		egressApplied = script
		return nil // nothing was ever installed
	}
	if err := nftRun(script); err != nil {
		return fmt.Errorf("egress: %w", err)
	}
	egressApplied = script
	return nil
}

// ---- learning from DNS (pod DNS responder) ----

type egressLearner struct {
	mu      sync.RWMutex
	domains map[string][]string // app -> allowed fqdns
	ipApp   map[string]string   // local pod IP -> app
	add     func(set string, ips []string, ttl time.Duration) error
}

func (l *egressLearner) set(egress map[string][]string, assignments []Assignment) {
	d := map[string][]string{}
	ipApp := map[string]string{}
	for _, a := range egressApps(egress, assignments) {
		if len(a.Domains) > 0 {
			d[a.App] = a.Domains
			for _, ip := range a.PodIPs {
				ipApp[ip] = a.App
			}
		}
	}
	l.mu.Lock()
	l.domains, l.ipApp = d, ipApp
	l.mu.Unlock()
}

// learn adds the A records of an allowed domain's answer to the querying app's set.
func (l *egressLearner) learn(client string, resp []byte) {
	if l == nil {
		return
	}
	l.mu.RLock()
	app := l.ipApp[client]
	allowed := l.domains[app]
	l.mu.RUnlock()
	if app == "" {
		return
	}
	var m dnsmessage.Message
	if m.Unpack(resp) != nil || len(m.Questions) != 1 {
		return
	}
	q := strings.ToLower(m.Questions[0].Name.String())
	ok := false
	for _, d := range allowed {
		ok = ok || matchSuffix(q, d)
	}
	if !ok {
		return
	}
	var ips []string
	ttl := uint32(86400)
	for _, rr := range m.Answers {
		if a, isA := rr.Body.(*dnsmessage.AResource); isA {
			ips = append(ips, netip.AddrFrom4(a.A).String())
			ttl = min(ttl, rr.Header.TTL)
		}
	}
	if len(ips) == 0 {
		return
	}
	// Grace beyond the TTL: clients reuse answers a little past it.
	d := max(time.Duration(ttl)*time.Second, 5*time.Minute)
	if err := l.add(egressSet(app), ips, d); err != nil {
		fmt.Printf("[egress] %s: %v\n", app, err)
	}
}

func nftAddLearned(set string, ips []string, ttl time.Duration) error {
	elems := make([]string, len(ips))
	for i, ip := range ips {
		elems[i] = fmt.Sprintf("%s timeout %ds", ip, int(ttl/time.Second))
	}
	out, err := exec.Command("nft", "add", "element", "inet", "ziro_egress", set+"d", "{ "+strings.Join(elems, ", ")+" }").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

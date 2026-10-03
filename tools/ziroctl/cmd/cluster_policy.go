package cmd

import (
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// App network policy. A rule lives on the destination app (allow_from: [apps] or "*"); with the
// cluster default "deny", an app is reachable only from the replicas of allowed apps. Each agent
// enforces its node's rules in its own nft table, ahead of the host firewall (which trusts
// ziro0): a drop in either base chain is final.
// On the pod network sources and destinations are replica IPs, and same-node traffic is policed
// too (ptp: every container is routed through the host). Replicas without a pod IP (clusters
// without the pod network, or mid-migration) are identified by their node's mesh IP, since
// their containers are masqueraded to it.
const policyTable = "inet ziro_cluster"

// MeshRule admits mesh traffic from Sources (mesh IPs) to a host port on the receiving node.
type MeshRule struct {
	App     string   `json:"app"`
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Sources []string `json:"sources"`
}

// PodRule admits traffic from Src to the local replicas Dst of one app (all ports).
type PodRule struct {
	App string   `json:"app"`
	Dst []string `json:"dst"`
	Src []string `json:"src"`
}

// MeshPolicy is one node's view of the policy, sent in heartbeat replies.
type MeshPolicy struct {
	Deny     bool       `json:"deny"`
	Rules    []MeshRule `json:"rules,omitempty"`
	Transit  []string   `json:"transit,omitempty"`   // hub only: remote peers it relays into the mesh
	LocalPod string     `json:"local_pod,omitempty"` // this node's pod /24 (pod network on)
	PodNet   string     `json:"pod_net,omitempty"`
	PodRules []PodRule  `json:"pod_rules,omitempty"`
}

// placedSources maps each app to the addresses its placed replicas send from: the pod IP, or
// the node's mesh IP without one. Placement (not "running") is used so a client replica can
// connect while it starts up.
func placedSources(st *ClusterState) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, r := range st.Replicas {
		ip := r.IP
		if n := st.node(r.Node); ip == "" && n != nil {
			ip = n.MeshIP
		}
		if ip == "" || seen[r.App+"\x00"+ip] {
			continue
		}
		seen[r.App+"\x00"+ip] = true
		out[r.App] = append(out[r.App], ip)
	}
	return out
}

func allowedSources(st *ClusterState, app *ClusteredApp, placed map[string][]string) []string {
	set := map[string]bool{}
	for _, ip := range gatewaySources(st, app.Name) {
		set[ip] = true
	}
	for _, from := range app.AllowFrom {
		if from == "peers" || strings.HasPrefix(from, "peer:") {
			for _, rp := range st.Peers {
				if from == "peers" || from == "peer:"+rp.Name {
					set[rp.MeshIP] = true
				}
			}
			continue
		}
		if from == "*" {
			for _, ips := range placed {
				for _, ip := range ips {
					set[ip] = true
				}
			}
			continue
		}
		for _, ip := range placed[from] {
			set[ip] = true
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// policyFor computes the rules nodeID enforces for the replicas it hosts.
func policyFor(st *ClusterState, nodeID string) *MeshPolicy {
	p := &MeshPolicy{Deny: st.PolicyDefault == "deny"}
	if !p.Deny {
		return p
	}
	// The hub only relays remote peers; each destination node still enforces allow_from.
	if hub := peerHub(st); hub != nil && hub.ID == nodeID {
		for _, rp := range st.Peers {
			p.Transit = append(p.Transit, rp.MeshIP)
		}
		sort.Strings(p.Transit)
	}
	placed := placedSources(st)
	if n := st.node(nodeID); n != nil && n.PodCIDR != "" && st.PodCIDR != "" {
		p.LocalPod, p.PodNet = n.PodCIDR, st.PodCIDR
		dst := map[string][]string{}
		for _, r := range st.Replicas {
			if r.Node == nodeID && r.IP != "" {
				dst[r.App] = append(dst[r.App], r.IP)
			}
		}
		for app, ips := range dst {
			if a := st.app(app); a != nil {
				if src := allowedSources(st, a, placed); len(src) > 0 {
					sort.Strings(ips)
					p.PodRules = append(p.PodRules, PodRule{App: app, Dst: ips, Src: src})
				}
			}
		}
		sort.Slice(p.PodRules, func(i, j int) bool { return p.PodRules[i].App < p.PodRules[j].App })
	}
	seen := map[string]bool{}
	for _, r := range st.Replicas {
		if r.Node != nodeID {
			continue
		}
		spec, _ := st.specFor(r) // the port this replica really publishes (old one mid-rollout)
		key := hostPortKey(spec.Port)
		cur := st.app(r.App) // but always the current policy
		if key == "" || cur == nil || seen[key] {
			continue
		}
		seen[key] = true
		src := allowedSources(st, cur, placed)
		if len(src) == 0 {
			continue
		}
		port, proto, _ := strings.Cut(key, "/")
		n, _ := strconv.Atoi(port)
		p.Rules = append(p.Rules, MeshRule{App: r.App, Port: n, Proto: proto, Sources: src})
	}
	if r := storagePolicyRule(st, nodeID); r != nil {
		p.Rules = append(p.Rules, *r)
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		if p.Rules[i].Port != p.Rules[j].Port {
			return p.Rules[i].Port < p.Rules[j].Port
		}
		return p.Rules[i].Proto < p.Rules[j].Proto
	})
	return p
}

// buildPolicyScript renders an atomic nft transaction. The policy comes from the master over
// pinned TLS but is still validated here: nothing unchecked reaches the nft parser.
// Allow mode (or no policy) just removes the table.
func buildPolicyScript(p *MeshPolicy) (string, error) {
	var sb strings.Builder
	sb.WriteString("table " + policyTable + "\ndelete table " + policyTable + "\n")
	if p == nil || !p.Deny {
		return sb.String(), nil
	}
	var rules []string
	for _, s := range p.Transit {
		if a, err := netip.ParseAddr(s); err != nil || !a.Is4() {
			return "", fmt.Errorf("invalid transit source %q", s)
		}
	}
	var podRules []string
	if p.LocalPod != "" {
		for _, c := range []string{p.LocalPod, p.PodNet} {
			if pr, err := netip.ParsePrefix(c); err != nil || !pr.Addr().Is4() {
				return "", fmt.Errorf("invalid pod network %q", c)
			}
		}
		for _, r := range p.PodRules {
			for _, ip := range append(append([]string{}, r.Dst...), r.Src...) {
				if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
					return "", fmt.Errorf("invalid pod rule address %q", ip)
				}
			}
			if len(r.Dst) == 0 || len(r.Src) == 0 {
				return "", fmt.Errorf("invalid pod rule for %q", r.App)
			}
			podRules = append(podRules, fmt.Sprintf("    ip saddr { %s } ip daddr { %s } accept\n",
				strings.Join(r.Src, ", "), strings.Join(r.Dst, ", ")))
		}
	}
	for _, r := range p.Rules {
		if r.Port < 1 || r.Port > 65535 || (r.Proto != "tcp" && r.Proto != "udp") || len(r.Sources) == 0 {
			return "", fmt.Errorf("invalid policy rule %d/%s", r.Port, r.Proto)
		}
		for _, s := range r.Sources {
			if a, err := netip.ParseAddr(s); err != nil || !a.Is4() {
				return "", fmt.Errorf("invalid policy source %q", s)
			}
		}
		// ct original proto-dst matches the published host port before and after CNI DNAT,
		// so one rule covers both the input and forward paths.
		rules = append(rules, fmt.Sprintf("    iifname %q ip saddr { %s } meta l4proto %s ct original proto-dst %d accept\n",
			meshIface, strings.Join(r.Sources, ", "), r.Proto, r.Port))
	}
	sb.WriteString("table " + policyTable + " {\n")
	for _, hook := range []string{"input", "forward"} {
		fmt.Fprintf(&sb, "  chain %s {\n    type filter hook %s priority -10; policy accept;\n", hook, hook)
		fmt.Fprintf(&sb, "    iifname %q ct state established,related accept\n", meshIface)
		fmt.Fprintf(&sb, "    iifname %q meta l4proto icmp accept\n", meshIface)
		if hook == "forward" && len(p.Transit) > 0 {
			fmt.Fprintf(&sb, "    iifname %q oifname %q ip saddr { %s } accept\n", meshIface, meshIface, strings.Join(p.Transit, ", "))
		}
		if hook == "forward" && p.LocalPod != "" {
			fmt.Fprintf(&sb, "    ip daddr %s ct state established,related accept\n", p.LocalPod)
			fmt.Fprintf(&sb, "    ip daddr %s meta l4proto icmp accept\n", p.LocalPod)
			// Published ports stay public for clients outside the cluster (host firewall rules);
			// pods and mesh traffic hitting a published port are policed like any other.
			fmt.Fprintf(&sb, "    ip daddr %s ct status dnat iifname != %q ip saddr != %s accept\n", p.LocalPod, meshIface, p.PodNet)
		}
		for _, r := range rules {
			sb.WriteString(r)
		}
		if hook == "forward" && p.LocalPod != "" {
			for _, r := range podRules {
				sb.WriteString(r)
			}
			fmt.Fprintf(&sb, "    ip daddr %s drop\n", p.LocalPod)
		}
		fmt.Fprintf(&sb, "    iifname %q drop\n  }\n", meshIface)
	}
	sb.WriteString("}\n")
	return sb.String(), nil
}

func applyClusterPolicy(p *MeshPolicy) error {
	script, err := buildPolicyScript(p)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("nft"); err != nil && (p == nil || !p.Deny) {
		return nil // nothing to enforce; only deny mode requires nft (and fails closed without it)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft policy: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeClusterPolicy() {
	_ = exec.Command("nft", "delete", "table", "inet", "ziro_cluster").Run()
}

// ---- CLI ----

var clusterPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Control which apps may reach each other",
	Example: `  ziroctl cluster policy ls
  ziroctl cluster policy default deny`,
	Long: `With the default "deny" (new clusters), an app's port is reachable over the mesh only from
nodes running an app listed in its allow_from:

  ziroctl cluster deploy --name api --allow-from web,worker   # or "*" for any cluster app
  ziroctl cluster policy ls

"allow" keeps the mesh open between all nodes (clusters created before policies existed).
Public (non --mesh-only) ports stay governed by the host firewall.`,
}

var clusterPolicyDefaultCmd = &cobra.Command{
	Use:   "default deny|allow",
	Short: "Set the default for mesh traffic to app ports",
	Example: `  ziroctl cluster policy default deny
  ziroctl cluster policy default allow`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"deny", "allow"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if args[0] != "deny" && args[0] != "allow" {
			return fmt.Errorf("want deny or allow")
		}
		return withState(func(st *ClusterState) error {
			st.PolicyDefault = args[0]
			fmt.Printf("✓ mesh policy default: %s (agents apply it within ~%ds)\n", args[0], int(agentInterval.Seconds()))
			return nil
		})
	},
}

type policyView struct {
	Default string          `json:"default"`
	Apps    []appPolicyView `json:"apps"`
}

type appPolicyView struct {
	App       string   `json:"app"`
	Port      string   `json:"port,omitempty"`
	AllowFrom []string `json:"allow_from"`
	Sources   []string `json:"sources"` // mesh IPs currently admitted
}

var clusterPolicyLsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "Show who may reach each app",
	Example: `  ziroctl cluster policy ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		v := policyView{Default: st.PolicyDefault, Apps: []appPolicyView{}}
		if v.Default == "" {
			v.Default = "allow"
		}
		placed := placedSources(st)
		for i := range st.Apps {
			a := &st.Apps[i]
			av := appPolicyView{App: a.Name, Port: hostPortKey(a.Port), AllowFrom: a.AllowFrom, Sources: allowedSources(st, a, placed)}
			if av.AllowFrom == nil {
				av.AllowFrom = []string{}
			}
			v.Apps = append(v.Apps, av)
		}
		return printResult(v, func() {
			fmt.Printf("Default: %s\n\n", v.Default)
			fmt.Printf("%-16s %-10s %-24s %s\n", "APP", "PORT", "ALLOW FROM", "ADMITTED NODES")
			fmt.Println(strings.Repeat("-", 80))
			for _, a := range v.Apps {
				from, src, port := strings.Join(a.AllowFrom, ","), strings.Join(a.Sources, ","), a.Port
				if v.Default == "allow" {
					from, src = "(any)", "(all)"
				}
				for _, s := range []*string{&from, &src, &port} {
					if *s == "" {
						*s = "-"
					}
				}
				fmt.Printf("%-16s %-10s %-24s %s\n", a.App, port, from, src)
			}
		})
	},
}

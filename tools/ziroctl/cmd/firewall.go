package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	firewallConfigFile = "/etc/ziro/firewall.json"
)

type FirewallRule struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp", "udp"
	Comment  string `json:"comment"`
	Source   string `json:"source,omitempty"` // IPv4 CIDR the rule is limited to (managed rules, e.g. pod DNS)
	Iface    string `json:"iface,omitempty"`  // interface the rule applies to (tailscale0): only traffic arriving there matches
}

// sameRule reports whether two rules open the same thing (comments don't matter).
func (r FirewallRule) sameRule(o FirewallRule) bool {
	return r.Port == o.Port && r.Protocol == o.Protocol && r.Source == o.Source && r.Iface == o.Iface
}

type BlockedIP struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

type FirewallConfig struct {
	Enabled      bool           `json:"enabled"`
	DefaultInput string         `json:"default_input"` // "DROP" or "ACCEPT"
	AllowedPorts []FirewallRule `json:"allowed_ports"`
	BlockedIPs   []BlockedIP    `json:"blocked_ips"`
	// Interfaces whose traffic is authenticated elsewhere (the WireGuard cluster mesh).
	TrustedInterfaces []string `json:"trusted_interfaces,omitempty"`
	// Flood/scan limits and bans (Ziro Guard, protect.go); on by default with the firewall.
	Guard GuardConfig `json:"guard,omitempty"`
	// Flowtable lists the network interfaces whose forwarded TCP and UDP flows take the kernel's
	// flow offload fast path once established (routed and NATed traffic: containers, the mesh). Off
	// (empty) by default.
	Flowtable []string `json:"flowtable,omitempty"`
}

var (
	fwComment string
	fwIface   string
)

var firewallCmd = &cobra.Command{
	Use:     "firewall",
	Aliases: []string{"fw", "nftables"},
	Short:   "Manage inbound firewall rules",
	Example: `  ziroctl firewall enable
  ziroctl firewall allow 443/tcp
  ziroctl firewall status`,
}

var fwStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show whether the firewall is on and what it allows",
	Example: `  ziroctl firewall status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadFirewallConfig()
		statusStr := "\033[1;31mINACTIVE (Disabled)\033[0m"
		if cfg.Enabled {
			statusStr = "\033[1;32mACTIVE (Enabled)\033[0m"
		}

		backend := "nftables"
		if _, err := exec.LookPath("nft"); err != nil {
			backend = "iptables"
		}
		return printResult(map[string]any{"enabled": cfg.Enabled, "engine": backend, "default_input": cfg.DefaultInput,
			"allowed_ports": len(cfg.AllowedPorts), "blocked": len(cfg.BlockedIPs)}, func() {
			fmt.Printf("Status:         %s\n", statusStr)
			fmt.Printf("Engine:         %s\n", backend)
			fmt.Printf("Default policy: input %s, forward accept, output accept\n", cfg.DefaultInput)
			fmt.Printf("Allowed ports:  %d rule(s)\n", len(cfg.AllowedPorts))
			fmt.Printf("Blocked:        %d address(es)\n", len(cfg.BlockedIPs))
		})
	},
}

// ---- operations (CLI and API) ----

// commitFirewall saves the config and, when the firewall is on, applies it.
func commitFirewall(cfg FirewallConfig) error {
	if err := saveFirewallConfig(cfg); err != nil {
		return err
	}
	if cfg.Enabled {
		return applyFirewallRules(cfg)
	}
	return nil
}

func setFirewallEnabled(on bool) error {
	cfg := loadFirewallConfig()
	cfg.Enabled = on
	if err := saveFirewallConfig(cfg); err != nil {
		return err
	}
	if on {
		return applyFirewallRules(cfg)
	}
	flushFirewallRules()
	return nil
}

// firewallAllow opens a port (e.g. 8443, 80/tcp, 51820/udp); added is false when already open.
func firewallAllow(spec, comment string) (added bool, err error) {
	return firewallAllowOn(spec, comment, "")
}

// firewallAllowOn opens a port for traffic arriving on one interface only (iface "" = any
// interface). The match is on the interface, not on a source address: an address can be spoofed
// from another interface (rp_filter is loose), the interface a packet arrived on cannot.
func firewallAllowOn(spec, comment, iface string) (added bool, err error) {
	port, proto := parsePortProto(spec)
	if port <= 0 {
		return false, fmt.Errorf("invalid port specification: %s", spec)
	}
	if err := checkRuleIface(iface); err != nil {
		return false, err
	}
	want := FirewallRule{Port: port, Protocol: proto, Iface: iface}
	cfg := loadFirewallConfig()
	for _, r := range cfg.AllowedPorts {
		if r.sameRule(want) {
			return false, nil
		}
	}
	want.Comment = comment
	cfg.AllowedPorts = append(cfg.AllowedPorts, want)
	return true, commitFirewall(cfg)
}

// firewallDenyOn closes a rule opened with firewallAllowOn (same port, protocol and interface).
func firewallDenyOn(spec, iface string) error {
	port, proto := parsePortProto(spec)
	if port <= 0 {
		return fmt.Errorf("invalid port specification: %s", spec)
	}
	if err := checkRuleIface(iface); err != nil {
		return err
	}
	want := FirewallRule{Port: port, Protocol: proto, Iface: iface}
	cfg := loadFirewallConfig()
	kept := cfg.AllowedPorts[:0]
	for _, r := range cfg.AllowedPorts {
		if !r.sameRule(want) {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(cfg.AllowedPorts) {
		on := ""
		if iface != "" {
			on = " on " + iface
		}
		return errNotFound(fmt.Sprintf("port %d/%s%s is not in the allow list", port, proto, on))
	}
	cfg.AllowedPorts = kept
	return commitFirewall(cfg)
}

// checkRuleIface validates a rule's interface name ("" = any interface).
func checkRuleIface(iface string) error {
	if iface != "" && (!ifaceNameRe.MatchString(iface) || iface == "lo") {
		return fmt.Errorf("invalid interface %q", iface)
	}
	return nil
}

// firewallBlock quarantines an IP or CIDR (idempotent); it returns the canonical target.
func firewallBlock(target, comment string) (string, error) {
	_, ip, err := canonicalBlockTarget(strings.TrimSpace(target))
	if err != nil {
		return "", err
	}
	cfg := loadFirewallConfig()
	for _, b := range cfg.BlockedIPs {
		if _, saved, err := canonicalBlockTarget(b.IP); err == nil && saved == ip {
			return ip, commitFirewall(cfg)
		}
	}
	cfg.BlockedIPs = append(cfg.BlockedIPs, BlockedIP{IP: ip, Comment: comment})
	return ip, commitFirewall(cfg)
}

func firewallUnblock(target string) (string, error) {
	_, ip, err := canonicalBlockTarget(strings.TrimSpace(target))
	if err != nil {
		return "", err
	}
	cfg := loadFirewallConfig()
	kept := cfg.BlockedIPs[:0]
	for _, b := range cfg.BlockedIPs {
		if _, saved, err := canonicalBlockTarget(b.IP); !(err == nil && saved == ip) {
			kept = append(kept, b)
		}
	}
	if len(kept) == len(cfg.BlockedIPs) {
		return ip, errNotFound("IP " + ip + " is not in the blocked list")
	}
	cfg.BlockedIPs = kept
	return ip, commitFirewall(cfg)
}

// ---- commands ----

var fwEnableCmd = &cobra.Command{
	Use:     "enable",
	Short:   "Turn the firewall on with the default rules",
	Example: `  ziroctl firewall enable`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setFirewallEnabled(true); err != nil {
			return err
		}
		fmt.Println("✓ Firewall enabled and applied")
		return nil
	},
}

var fwDisableCmd = &cobra.Command{
	Use:     "disable",
	Short:   "Turn the firewall off and accept all traffic",
	Example: `  ziroctl firewall disable`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setFirewallEnabled(false); err != nil {
			return err
		}
		fmt.Println("✓ Firewall disabled: all inbound traffic is allowed")
		return nil
	},
}

var fwAllowCmd = &cobra.Command{
	Use:   "allow <port[/proto]>",
	Short: "Allow inbound traffic to a port",
	Example: `  ziroctl firewall allow 443
  ziroctl firewall allow 51820/udp --comment wireguard
  ziroctl firewall allow 22 --iface tailscale0`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		added, err := firewallAllowOn(args[0], fwComment, fwIface)
		if err != nil {
			return err
		}
		if !added {
			fmt.Printf("%s is already allowed\n", args[0])
			return nil
		}
		fmt.Printf("✓ Allowed inbound %s\n", args[0])
		return nil
	},
}

var fwDenyCmd = &cobra.Command{
	Use:   "deny <port[/proto]>",
	Short: "Close a port opened with allow",
	Example: `  ziroctl firewall deny 8080/tcp
  ziroctl firewall deny 22 --iface tailscale0`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewallDenyOn(args[0], fwIface); err != nil {
			return err
		}
		fmt.Printf("✓ Removed %s from the allow list\n", args[0])
		return nil
	},
}

var fwBlockIPCmd = &cobra.Command{
	Use:   "block-ip <ip-or-cidr>",
	Short: "Block all inbound traffic from an IP or network",
	Example: `  ziroctl firewall block-ip 203.0.113.9
  ziroctl firewall block-ip 198.51.100.0/24 --comment scanner`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip, err := firewallBlock(args[0], fwComment)
		if err != nil {
			return err
		}
		fmt.Printf("✓ Blocked inbound traffic from %s\n", ip)
		return nil
	},
}

var fwUnblockIPCmd = &cobra.Command{
	Use:     "unblock-ip <ip-or-cidr>",
	Short:   "Unblock an IP or network",
	Example: `  ziroctl firewall unblock-ip 203.0.113.9`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip, err := firewallUnblock(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("✓ Unblocked %s\n", ip)
		return nil
	},
}

var fwListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List allowed ports and blocked addresses",
	Example: `  ziroctl firewall list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadFirewallConfig()
		if jsonOutput {
			return printResult(cfg, nil)
		}
		fmt.Println("--- Allowed Inbound Ports ---")
		if len(cfg.AllowedPorts) == 0 {
			fmt.Println("  (none)")
		} else {
			fmt.Printf("  %-12s %-8s %s\n", "PORT", "PROTO", "COMMENT")
			for _, r := range cfg.AllowedPorts {
				c := r.Comment
				if r.Source != "" {
					c += " (from " + r.Source + ")"
				}
				if r.Iface != "" {
					c += " (on " + r.Iface + ")"
				}
				fmt.Printf("  %-12d %-8s %s\n", r.Port, strings.ToUpper(r.Protocol), c)
			}
		}

		fmt.Println("\n--- Quarantined / Blocked IPs ---")
		if len(cfg.BlockedIPs) == 0 {
			fmt.Println("  (none)")
		} else {
			fmt.Printf("  %-20s %s\n", "IP / CIDR", "REASON")
			for _, b := range cfg.BlockedIPs {
				fmt.Printf("  %-20s %s\n", b.IP, b.Comment)
			}
		}
		return nil
	},
}

var fwApplyCmd = &cobra.Command{
	Use:    "apply",
	Hidden: true,
	Short:  "Apply saved firewall rules (internal service helper)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := loadFirewallConfig()
		if cfg.Enabled {
			if err := applyFirewallRules(cfg); err != nil {
				os.Exit(1)
			}
		}
		return nil
	},
}

func parsePortProto(s string) (int, string) {
	proto := "tcp"
	portStr := s
	if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		portStr = parts[0]
		proto = strings.ToLower(parts[1])
	}
	p, _ := strconv.Atoi(portStr)
	if p > 65535 || (proto != "tcp" && proto != "udp") {
		return 0, proto
	}
	return p, proto
}

func canonicalBlockTarget(s string) (string, string, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return "", "", fmt.Errorf("mapped IPv4 prefix must be at least /96")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		family := "ip6"
		if prefix.Addr().Is4() {
			family = "ip"
		}
		return family, prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return "", "", fmt.Errorf("invalid IP or CIDR %q", s)
	}
	addr = addr.Unmap()
	family := "ip6"
	if addr.Is4() {
		family = "ip"
	}
	return family, addr.String(), nil
}

func loadFirewallConfig() FirewallConfig {
	defCfg := FirewallConfig{
		Enabled:      true,
		DefaultInput: "DROP",
		AllowedPorts: []FirewallRule{
			{Port: 22, Protocol: "tcp", Comment: "SSH Secure Shell"},
			{Port: 51820, Protocol: "udp", Comment: "WireGuard Mesh VPN"},
		},
		BlockedIPs: []BlockedIP{},
	}

	data, err := os.ReadFile(firewallConfigFile)
	if err != nil {
		return defCfg
	}

	var cfg FirewallConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defCfg
	}
	return cfg
}

func saveFirewallConfig(cfg FirewallConfig) error {
	if err := os.MkdirAll(filepath.Dir(firewallConfigFile), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(firewallConfigFile, data, 0644)
}

func applyFirewallRules(cfg FirewallConfig) error {
	var err error
	if _, lookErr := exec.LookPath("nft"); lookErr == nil {
		err = applyNftables(cfg)
	} else {
		err = applyIptables(cfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "firewall: %v\n", err)
	}
	return err
}

// nftTable is the only table Ziro owns. We never 'flush ruleset': that would wipe
// the NAT/forward rules installed by CNI, nerdctl, WireGuard and kube-proxy.
const nftTable = "inet ziro"

func buildNftScript(cfg FirewallConfig) (string, error) {
	policy := "drop"
	if strings.EqualFold(cfg.DefaultInput, "ACCEPT") {
		policy = "accept"
	}

	var sb strings.Builder
	// Declare-then-delete makes the replace atomic and idempotent within one nft transaction.
	sb.WriteString("table " + nftTable + "\n")
	sb.WriteString("delete table " + nftTable + "\n")
	sb.WriteString("table " + nftTable + " {\n")
	// Blocked sources live in interval sets: one hash/tree lookup however long the list is, instead of
	// one rule per address walked in order for every packet.
	var block4, block6 []string
	for _, b := range cfg.BlockedIPs {
		fam, target, err := canonicalBlockTarget(b.IP)
		if err != nil {
			return "", err
		}
		if fam == "ip" {
			block4 = append(block4, target)
		} else {
			block6 = append(block6, target)
		}
	}
	for _, set := range []struct {
		name, typ string
		els       []string
	}{{"blocked4", "ipv4_addr", block4}, {"blocked6", "ipv6_addr", block6}} {
		if len(set.els) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  set %s {\n    type %s\n    flags interval\n    auto-merge\n    elements = { %s }\n  }\n",
			set.name, set.typ, strings.Join(slices.Compact(slices.Sorted(slices.Values(set.els))), ", ")))
	}
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority 0; policy " + policy + ";\n")
	sb.WriteString("    iif \"lo\" accept\n")
	sb.WriteString("    ct state invalid drop\n")

	if len(block4) > 0 {
		sb.WriteString("    ip saddr @blocked4 drop\n")
	}
	if len(block6) > 0 {
		sb.WriteString("    ip6 saddr @blocked6 drop\n")
	}
	// Loopback remains trusted; quarantine every other source before broad accepts.
	for _, ifc := range cfg.TrustedInterfaces {
		if !ifaceNameRe.MatchString(ifc) {
			return "", fmt.Errorf("invalid trusted interface %q", ifc)
		}
		sb.WriteString(fmt.Sprintf("    iifname %q accept\n", ifc))
	}
	sb.WriteString("    ct state established,related accept\n")
	sb.WriteString("    ip protocol icmp accept\n")
	sb.WriteString("    ip6 nexthdr icmpv6 accept\n")
	plain := map[string][]int{}
	for _, r := range cfg.AllowedPorts {
		if r.Port < 1 || r.Port > 65535 || (r.Protocol != "tcp" && r.Protocol != "udp") {
			return "", fmt.Errorf("invalid port rule %d/%s", r.Port, r.Protocol)
		}
		if err := checkRuleIface(r.Iface); err != nil {
			return "", err
		}
		match := ""
		if r.Iface != "" {
			match = fmt.Sprintf("iifname %q ", r.Iface)
		}
		if r.Source != "" {
			p, err := netip.ParsePrefix(r.Source)
			if err != nil || !p.Addr().Is4() {
				return "", fmt.Errorf("invalid rule source %q", r.Source)
			}
			sb.WriteString(fmt.Sprintf("    %sip saddr %s %s dport %d accept\n", match, p.Masked(), r.Protocol, r.Port))
			continue
		}
		if match == "" {
			plain[r.Protocol] = append(plain[r.Protocol], r.Port)
			continue
		}
		sb.WriteString(fmt.Sprintf("    %s%s dport %d accept\n", match, r.Protocol, r.Port))
	}
	// Unscoped ports: one rule per protocol, the ports in an anonymous set.
	for _, proto := range []string{"tcp", "udp"} {
		ports := slices.Compact(slices.Sorted(slices.Values(plain[proto])))
		switch len(ports) {
		case 0:
		case 1:
			sb.WriteString(fmt.Sprintf("    %s dport %d accept\n", proto, ports[0]))
		default:
			list := make([]string, len(ports))
			for i, p := range ports {
				list[i] = strconv.Itoa(p)
			}
			sb.WriteString(fmt.Sprintf("    %s dport { %s } accept\n", proto, strings.Join(list, ", ")))
		}
	}
	sb.WriteString("  }\n}\n")
	return sb.String(), nil
}

func applyNftables(cfg FirewallConfig) error {
	script, err := buildNftScript(cfg)
	if err != nil {
		return err
	}
	if err := nftRun(script); err != nil {
		return err
	}
	// The guard is extra protection: if the kernel lacks a feature it needs, the firewall itself
	// must still be up. `security protect status` and `security audit` report it inactive.
	if err := applyGuard(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "firewall: Ziro Guard not active: %v\n", err)
	}
	// The same for the flow offload table: a missing device or kernel feature never takes the firewall down.
	if err := applyFlowtable(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "firewall: flow offload not active: %v\n", err)
	}
	return nil
}

// flowTable is the table of the flow offload fast path, separate from the firewall's own so that
// loading it can fail (an interface that is not there yet, a kernel without the feature) harmlessly.
const flowTable = "inet ziro_flow"

const maxFlowDevices = 8

func validFlowDevices(devs []string) error {
	if len(devs) > maxFlowDevices {
		return fmt.Errorf("at most %d flowtable interfaces", maxFlowDevices)
	}
	seen := map[string]bool{}
	for _, d := range devs {
		if !ifaceNameRe.MatchString(d) || strings.HasSuffix(d, "*") || seen[d] {
			return fmt.Errorf("invalid or repeated flowtable interface %q", d)
		}
		seen[d] = true
	}
	return nil
}

// buildFlowScript declares the flowtable on devs and adds established TCP and UDP flows to it. The
// counter shows how many packets still take the slow path: an offloaded flow is seen only while it
// starts.
func buildFlowScript(devs []string) (string, error) {
	if err := validFlowDevices(devs); err != nil {
		return "", err
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("no flowtable interfaces")
	}
	var sb strings.Builder
	sb.WriteString("table " + flowTable + "\ndelete table " + flowTable + "\n")
	sb.WriteString("table " + flowTable + " {\n")
	sb.WriteString("  flowtable ft { hook ingress priority 0; devices = { " + strings.Join(devs, ", ") + " }; }\n")
	sb.WriteString("  chain forward { type filter hook forward priority 0; policy accept;\n")
	sb.WriteString("    meta l4proto { tcp, udp } counter flow add @ft\n  }\n}\n")
	return sb.String(), nil
}

// applyFlowtable installs the flow offload table for the configured interfaces that exist, or removes it.
func applyFlowtable(cfg FirewallConfig) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	if !cfg.Enabled || len(cfg.Flowtable) == 0 {
		return removeFlowtable()
	}
	if err := validFlowDevices(cfg.Flowtable); err != nil {
		return err
	}
	var present, missing []string
	for _, d := range cfg.Flowtable {
		if _, err := net.InterfaceByName(d); err == nil {
			present = append(present, d)
		} else {
			missing = append(missing, d)
		}
	}
	if len(present) == 0 {
		_ = removeFlowtable()
		return fmt.Errorf("none of the interfaces %s exists", strings.Join(cfg.Flowtable, ", "))
	}
	script, err := buildFlowScript(present)
	if err != nil {
		return err
	}
	if err := nftRun(script); err != nil {
		return err
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "firewall: flow offload skips %s (no such interface yet; run `ziroctl firewall apply` once it exists)\n", strings.Join(missing, ", "))
	}
	return nil
}

func removeFlowtable() error {
	if exec.Command("nft", "list", "table", "inet", "ziro_flow").Run() != nil {
		return nil // nothing to remove
	}
	return nftRun("table " + flowTable + "\ndelete table " + flowTable + "\n")
}

// setFlowtable saves the interface list and re-applies the firewall.
func setFlowtable(devs []string) error {
	if err := validFlowDevices(devs); err != nil {
		return err
	}
	cfg := loadFirewallConfig()
	cfg.Flowtable = devs
	if err := saveFirewallConfig(cfg); err != nil {
		return err
	}
	if cfg.Enabled {
		return applyFirewallRules(cfg)
	}
	return nil
}

var fwFlowtableCmd = &cobra.Command{
	Use:   "flowtable [interface... | off]",
	Short: "Fast path for forwarded flows",
	Long: `Once a forwarded TCP or UDP connection is established, its packets skip most of the netfilter hooks and
go straight from one interface to the other. It helps routed and NATed traffic (containers, the mesh), not traffic
to this host. Name the interfaces the traffic crosses (the uplink and the container bridge); off removes it.
Without arguments it shows the current setting.`,
	Example: `  ziroctl firewall flowtable eth0 nerdctl0
  ziroctl firewall flowtable off`,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case len(args) == 0:
			cfg := loadFirewallConfig()
			return printResult(map[string]any{"interfaces": cfg.Flowtable}, func() {
				if len(cfg.Flowtable) == 0 {
					fmt.Println("flow offload is off")
				} else {
					fmt.Printf("flow offload on %s\n", strings.Join(cfg.Flowtable, ", "))
				}
			})
		case len(args) == 1 && args[0] == "off":
			if err := setFlowtable(nil); err != nil {
				return err
			}
			fmt.Println("✓ flow offload is off")
		default:
			if err := setFlowtable(args); err != nil {
				return err
			}
			fmt.Printf("✓ flow offload on %s\n", strings.Join(args, ", "))
		}
		return nil
	},
}

func applyIptables(cfg FirewallConfig) error {
	if _, err := buildNftScript(cfg); err != nil { // same validation as nft path
		return err
	}
	policy := "DROP"
	if strings.EqualFold(cfg.DefaultInput, "ACCEPT") {
		policy = "ACCEPT"
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("firewall requires %s: %w", bin, err)
		}
		var ruleErr error
		run := func(a ...string) {
			if ruleErr != nil {
				return
			}
			if out, err := exec.Command(bin, a...).CombinedOutput(); err != nil {
				ruleErr = fmt.Errorf("%s: %w: %s", bin, err, strings.TrimSpace(string(out)))
			}
		}
		// Fail closed while rebuilding, including when the final policy is ACCEPT.
		run("-P", "INPUT", "DROP")
		run("-F", "INPUT")
		run("-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
		for _, b := range cfg.BlockedIPs {
			if fam, target, _ := canonicalBlockTarget(b.IP); (fam == "ip") == (bin == "iptables") {
				run("-A", "INPUT", "-s", target, "-j", "DROP")
			}
		}
		for _, ifc := range cfg.TrustedInterfaces {
			run("-A", "INPUT", "-i", ifc, "-j", "ACCEPT")
		}
		run("-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
		for _, r := range cfg.AllowedPorts {
			if r.Source != "" && bin != "iptables" { // sources are IPv4 (validated by buildNftScript above)
				continue
			}
			a := []string{"-A", "INPUT"}
			if r.Iface != "" {
				a = append(a, "-i", r.Iface)
			}
			if r.Source != "" {
				a = append(a, "-s", r.Source)
			}
			run(append(a, "-p", r.Protocol, "--dport", strconv.Itoa(r.Port), "-j", "ACCEPT")...)
		}
		run("-P", "INPUT", policy)
		if ruleErr != nil {
			return ruleErr
		}
	}
	return nil
}

func flushFirewallRules() {
	if _, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command("nft", "delete", "table", "inet", "ziro").Run()
		_ = removeGuard()
		return
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		_ = exec.Command(bin, "-P", "INPUT", "ACCEPT").Run()
		_ = exec.Command(bin, "-F", "INPUT").Run()
	}
}

func init() {
	fwAllowCmd.Flags().StringVarP(&fwComment, "comment", "m", "", "Rule description or purpose")
	fwBlockIPCmd.Flags().StringVarP(&fwComment, "comment", "m", "", "Reason for blocking IP")
	fwAllowCmd.Flags().StringVar(&fwIface, "iface", "", "Only traffic arriving on this interface (e.g. tailscale0)")
	fwDenyCmd.Flags().StringVar(&fwIface, "iface", "", "The rule for this interface")

	firewallCmd.AddCommand(fwStatusCmd)
	firewallCmd.AddCommand(fwEnableCmd)
	firewallCmd.AddCommand(fwDisableCmd)
	firewallCmd.AddCommand(fwAllowCmd)
	firewallCmd.AddCommand(fwDenyCmd)
	firewallCmd.AddCommand(fwBlockIPCmd)
	firewallCmd.AddCommand(fwUnblockIPCmd)
	firewallCmd.AddCommand(fwListCmd)
	firewallCmd.AddCommand(fwApplyCmd)
	firewallCmd.AddCommand(fwFlowtableCmd)
	rootCmd.AddCommand(firewallCmd)
}

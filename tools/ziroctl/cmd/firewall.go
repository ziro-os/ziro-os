package cmd

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
}

var (
	fwComment string
)

var firewallCmd = &cobra.Command{
	Use:     "firewall",
	Aliases: []string{"fw", "nftables"},
	Short:   "Manage Ziro-OS host and container network firewall rules (nftables/iptables)",
}

var fwStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display firewall status and summary of active protections",
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
	port, proto := parsePortProto(spec)
	if port <= 0 {
		return false, fmt.Errorf("invalid port specification: %s", spec)
	}
	cfg := loadFirewallConfig()
	for _, r := range cfg.AllowedPorts {
		if r.Port == port && r.Protocol == proto && r.Source == "" {
			return false, nil
		}
	}
	cfg.AllowedPorts = append(cfg.AllowedPorts, FirewallRule{Port: port, Protocol: proto, Comment: comment})
	return true, commitFirewall(cfg)
}

func firewallDeny(spec string) error {
	port, proto := parsePortProto(spec)
	if port <= 0 {
		return fmt.Errorf("invalid port specification: %s", spec)
	}
	cfg := loadFirewallConfig()
	kept := cfg.AllowedPorts[:0]
	for _, r := range cfg.AllowedPorts {
		if !(r.Port == port && r.Protocol == proto && r.Source == "") {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(cfg.AllowedPorts) {
		return errNotFound(fmt.Sprintf("port %d/%s is not in the allow list", port, proto))
	}
	cfg.AllowedPorts = kept
	return commitFirewall(cfg)
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
	Use:   "enable",
	Short: "Enable cloud firewall and apply hardened security rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := setFirewallEnabled(true); err != nil {
			return err
		}
		fmt.Println("✓ Firewall enabled and applied")
		return nil
	},
}

var fwDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable firewall and permit all incoming traffic",
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
	Short: "Allow inbound network traffic on a port (e.g. 8443, 80/tcp, 51820/udp)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		added, err := firewallAllow(args[0], fwComment)
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
	Short: "Deny and remove inbound allowance for a port",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewallDeny(args[0]); err != nil {
			return err
		}
		fmt.Printf("✓ Removed %s from the allow list\n", args[0])
		return nil
	},
}

var fwBlockIPCmd = &cobra.Command{
	Use:   "block-ip <ip-or-cidr>",
	Short: "Quarantine incoming traffic from an IP address or CIDR (loopback is trusted)",
	Args:  cobra.ExactArgs(1),
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
	Use:   "unblock-ip <ip-or-cidr>",
	Short: "Remove IP quarantine and allow communication",
	Args:  cobra.ExactArgs(1),
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
	Use:   "list",
	Short: "List all active firewall rules, allowed ports, and blocked IPs",
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
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority 0; policy " + policy + ";\n")
	sb.WriteString("    iif \"lo\" accept\n")
	sb.WriteString("    ct state invalid drop\n")

	for _, b := range cfg.BlockedIPs {
		fam, target, err := canonicalBlockTarget(b.IP)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("    %s saddr %s drop\n", fam, target))
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
	for _, r := range cfg.AllowedPorts {
		if r.Port < 1 || r.Port > 65535 || (r.Protocol != "tcp" && r.Protocol != "udp") {
			return "", fmt.Errorf("invalid port rule %d/%s", r.Port, r.Protocol)
		}
		if r.Source != "" {
			p, err := netip.ParsePrefix(r.Source)
			if err != nil || !p.Addr().Is4() {
				return "", fmt.Errorf("invalid rule source %q", r.Source)
			}
			sb.WriteString(fmt.Sprintf("    ip saddr %s %s dport %d accept\n", p.Masked(), r.Protocol, r.Port))
			continue
		}
		sb.WriteString(fmt.Sprintf("    %s dport %d accept\n", r.Protocol, r.Port))
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
	return nil
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
			switch {
			case r.Source == "":
				run("-A", "INPUT", "-p", r.Protocol, "--dport", strconv.Itoa(r.Port), "-j", "ACCEPT")
			case bin == "iptables": // sources are IPv4 (validated by buildNftScript above)
				run("-A", "INPUT", "-s", r.Source, "-p", r.Protocol, "--dport", strconv.Itoa(r.Port), "-j", "ACCEPT")
			}
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

	firewallCmd.AddCommand(fwStatusCmd)
	firewallCmd.AddCommand(fwEnableCmd)
	firewallCmd.AddCommand(fwDisableCmd)
	firewallCmd.AddCommand(fwAllowCmd)
	firewallCmd.AddCommand(fwDenyCmd)
	firewallCmd.AddCommand(fwBlockIPCmd)
	firewallCmd.AddCommand(fwUnblockIPCmd)
	firewallCmd.AddCommand(fwListCmd)
	firewallCmd.AddCommand(fwApplyCmd)
	rootCmd.AddCommand(firewallCmd)
}

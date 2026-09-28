package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const (
	firewallConfigFile = "/etc/ziro/firewall.json"
)

type FirewallRule struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp", "udp"
	Comment  string `json:"comment"`
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
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadFirewallConfig()
		statusStr := "\033[1;31mINACTIVE (Disabled)\033[0m"
		if cfg.Enabled {
			statusStr = "\033[1;32mACTIVE (Enabled)\033[0m"
		}

		backend := "nftables"
		if _, err := exec.LookPath("nft"); err != nil {
			backend = "iptables (legacy fallback)"
		}

		fmt.Println("=== Ziro-OS Cloud Firewall ===")
		fmt.Printf("Status:        %s\n", statusStr)
		fmt.Printf("Engine:        %s\n", backend)
		fmt.Printf("Default Policy: INPUT %s, FORWARD ACCEPT, OUTPUT ACCEPT\n", cfg.DefaultInput)
		fmt.Printf("Allowed Ports: %d port rule(s)\n", len(cfg.AllowedPorts))
		fmt.Printf("Blocked IPs:   %d IP(s) quarantined\n", len(cfg.BlockedIPs))
	},
}

var fwEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable cloud firewall and apply hardened security rules",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadFirewallConfig()
		cfg.Enabled = true
		_ = saveFirewallConfig(cfg)
		applyFirewallRules(cfg)
		fmt.Println("✓ Ziro-OS Cloud Firewall ENABLED and active.")
	},
}

var fwDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable firewall and permit all incoming traffic",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadFirewallConfig()
		cfg.Enabled = false
		_ = saveFirewallConfig(cfg)
		flushFirewallRules()
		fmt.Println("✓ Ziro-OS Cloud Firewall DISABLED (All traffic allowed).")
	},
}

var fwAllowCmd = &cobra.Command{
	Use:   "allow <port[/proto]>",
	Short: "Allow inbound network traffic on a port (e.g. 8443, 80/tcp, 51820/udp)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		spec := args[0]
		port, proto := parsePortProto(spec)
		if port <= 0 {
			fmt.Printf("Invalid port specification: %s\n", spec)
			return
		}

		cfg := loadFirewallConfig()
		// Avoid duplicate
		for _, r := range cfg.AllowedPorts {
			if r.Port == port && r.Protocol == proto {
				fmt.Printf("Port %d/%s is already allowed.\n", port, proto)
				return
			}
		}

		cfg.AllowedPorts = append(cfg.AllowedPorts, FirewallRule{
			Port:     port,
			Protocol: proto,
			Comment:  fwComment,
		})
		_ = saveFirewallConfig(cfg)
		if cfg.Enabled {
			applyFirewallRules(cfg)
		}
		fmt.Printf("✓ Allowed incoming traffic on port %d/%s\n", port, proto)
	},
}

var fwDenyCmd = &cobra.Command{
	Use:   "deny <port[/proto]>",
	Short: "Deny and remove inbound allowance for a port",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		spec := args[0]
		port, proto := parsePortProto(spec)
		if port <= 0 {
			fmt.Printf("Invalid port specification: %s\n", spec)
			return
		}

		cfg := loadFirewallConfig()
		var newRules []FirewallRule
		found := false
		for _, r := range cfg.AllowedPorts {
			if r.Port == port && r.Protocol == proto {
				found = true
				continue
			}
			newRules = append(newRules, r)
		}

		if !found {
			fmt.Printf("Port %d/%s was not found in allow list.\n", port, proto)
			return
		}

		cfg.AllowedPorts = newRules
		_ = saveFirewallConfig(cfg)
		if cfg.Enabled {
			applyFirewallRules(cfg)
		}
		fmt.Printf("✓ Denied/removed port %d/%s from firewall allow list.\n", port, proto)
	},
}

var fwBlockIPCmd = &cobra.Command{
	Use:   "block-ip <ip-or-cidr>",
	Short: "Immediately quarantine and drop all packets from an IP address or CIDR",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := strings.TrimSpace(args[0])
		if ip == "" {
			fmt.Println("Error: IP or CIDR cannot be empty.")
			return
		}

		cfg := loadFirewallConfig()
		for _, b := range cfg.BlockedIPs {
			if b.IP == ip {
				fmt.Printf("IP %s is already blocked.\n", ip)
				return
			}
		}

		cfg.BlockedIPs = append(cfg.BlockedIPs, BlockedIP{
			IP:      ip,
			Comment: fwComment,
		})
		_ = saveFirewallConfig(cfg)
		if cfg.Enabled {
			applyFirewallRules(cfg)
		}
		fmt.Printf("🛡️ Quarantined & BLOCKED traffic from IP: %s\n", ip)
	},
}

var fwUnblockIPCmd = &cobra.Command{
	Use:   "unblock-ip <ip-or-cidr>",
	Short: "Remove IP quarantine and allow communication",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := strings.TrimSpace(args[0])
		cfg := loadFirewallConfig()
		var newBlocked []BlockedIP
		found := false
		for _, b := range cfg.BlockedIPs {
			if b.IP == ip {
				found = true
				continue
			}
			newBlocked = append(newBlocked, b)
		}

		if !found {
			fmt.Printf("IP %s was not found in blocked list.\n", ip)
			return
		}

		cfg.BlockedIPs = newBlocked
		_ = saveFirewallConfig(cfg)
		if cfg.Enabled {
			applyFirewallRules(cfg)
		}
		fmt.Printf("✓ Unblocked IP: %s\n", ip)
	},
}

var fwListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active firewall rules, allowed ports, and blocked IPs",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadFirewallConfig()
		fmt.Println("--- Allowed Inbound Ports ---")
		if len(cfg.AllowedPorts) == 0 {
			fmt.Println("  (none)")
		} else {
			fmt.Printf("  %-12s %-8s %s\n", "PORT", "PROTO", "COMMENT")
			for _, r := range cfg.AllowedPorts {
				fmt.Printf("  %-12d %-8s %s\n", r.Port, strings.ToUpper(r.Protocol), r.Comment)
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
	},
}

var fwApplyCmd = &cobra.Command{
	Use:    "apply",
	Hidden: true,
	Short:  "Apply saved firewall rules (internal service helper)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadFirewallConfig()
		if cfg.Enabled {
			applyFirewallRules(cfg)
		}
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
	return p, proto
}

func loadFirewallConfig() FirewallConfig {
	defCfg := FirewallConfig{
		Enabled:      true,
		DefaultInput: "DROP",
		AllowedPorts: []FirewallRule{
			{Port: 22, Protocol: "tcp", Comment: "SSH Secure Shell"},
			{Port: 8443, Protocol: "tcp", Comment: "Ziro REST API Control Plane"},
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
	_ = os.MkdirAll("/etc/ziro", 0755)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(firewallConfigFile, data, 0644)
}

func applyFirewallRules(cfg FirewallConfig) {
	// Try nftables first
	if _, err := exec.LookPath("nft"); err == nil {
		applyNftables(cfg)
		return
	}
	// Fallback to iptables
	applyIptables(cfg)
}

func applyNftables(cfg FirewallConfig) {
	var sb strings.Builder
	sb.WriteString("flush ruleset\n")
	sb.WriteString("table inet filter {\n")
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority 0; policy drop;\n")
	sb.WriteString("    iif \"lo\" accept\n")
	sb.WriteString("    ct state established,related accept\n")

	// Drop blocked IPs first
	for _, b := range cfg.BlockedIPs {
		sb.WriteString(fmt.Sprintf("    ip saddr %s drop\n", b.IP))
	}

	// Allow specified ports
	for _, r := range cfg.AllowedPorts {
		sb.WriteString(fmt.Sprintf("    %s dport %d accept\n", r.Protocol, r.Port))
	}

	sb.WriteString("  }\n")
	sb.WriteString("  chain forward {\n")
	sb.WriteString("    type filter hook forward priority 0; policy accept;\n")
	sb.WriteString("  }\n")
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority 0; policy accept;\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(sb.String())
	_ = cmd.Run()
}

func applyIptables(cfg FirewallConfig) {
	// Clear existing
	_ = exec.Command("iptables", "-F", "INPUT").Run()
	_ = exec.Command("iptables", "-P", "INPUT", "DROP").Run()
	_ = exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
	_ = exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run()

	// Loopback and established
	_ = exec.Command("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()

	// Blocked IPs
	for _, b := range cfg.BlockedIPs {
		_ = exec.Command("iptables", "-A", "INPUT", "-s", b.IP, "-j", "DROP").Run()
	}

	// Allowed ports
	for _, r := range cfg.AllowedPorts {
		_ = exec.Command("iptables", "-A", "INPUT", "-p", r.Protocol, "--dport", strconv.Itoa(r.Port), "-j", "ACCEPT").Run()
	}
}

func flushFirewallRules() {
	if _, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command("nft", "flush", "ruleset").Run()
	}
	_ = exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
	_ = exec.Command("iptables", "-F").Run()
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

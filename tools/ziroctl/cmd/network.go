package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	netSetupIface   string
	netSetupMode    string
	netSetupIP      string
	netSetupGateway string
	netSetupDNS     string
	netSetupApply   bool
)

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Network configuration, status, and CNI management",
}

var networkListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active network interfaces and CNI plugins",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("=== Network Interfaces ===")
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Error querying interfaces: %v\n", err)
		} else {
			for _, iface := range ifaces {
				addrs, _ := iface.Addrs()
				addrList := ""
				for _, a := range addrs {
					addrList += a.String() + " "
				}
				fmt.Printf("• %-12s Flags: %-20v IP: %s\n", iface.Name, iface.Flags, addrList)
			}
		}

		fmt.Println("\n=== CNI Configurations (/etc/cni/net.d) ===")
		configs, err := filepath.Glob("/etc/cni/net.d/*")
		if err != nil || len(configs) == 0 {
			fmt.Println("  (No CNI network configurations found)")
		} else {
			for _, cfg := range configs {
				fmt.Printf("• %s\n", filepath.Base(cfg))
			}
		}

		fmt.Println("\n=== CNI Plugin Binaries (/opt/cni/bin) ===")
		plugins, err := os.ReadDir("/opt/cni/bin")
		if err != nil || len(plugins) == 0 {
			fmt.Println("  (No CNI plugin binaries installed)")
		} else {
			for _, p := range plugins {
				fmt.Printf("• %s\n", p.Name())
			}
		}
	},
}

var networkStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show detailed network interfaces, default gateway, DNS, and connectivity",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("==================================================")
		fmt.Println(" 🌐 Ziro-OS Network Status")
		fmt.Println("==================================================")

		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Printf("❌ Failed to query interfaces: %v\n", err)
			return
		}

		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			ipStrs := []string{}
			for _, a := range addrs {
				ipStrs = append(ipStrs, a.String())
			}
			mac := iface.HardwareAddr.String()
			if mac == "" {
				mac = "(none/virtual)"
			}

			status := "DOWN"
			if iface.Flags&net.FlagUp != 0 {
				status = "UP"
			}

			fmt.Printf("Interface: %s [%s]\n", iface.Name, status)
			fmt.Printf("  MAC:       %s\n", mac)
			fmt.Printf("  MTU:       %d\n", iface.MTU)
			fmt.Printf("  Flags:     %v\n", iface.Flags)
			if len(ipStrs) > 0 {
				fmt.Printf("  Addresses: %s\n", strings.Join(ipStrs, ", "))
			} else {
				fmt.Printf("  Addresses: (none configured)\n")
			}
			fmt.Println()
		}

		// DNS Nameservers
		fmt.Println("--- DNS Resolvers (/etc/resolv.conf) ---")
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "nameserver") || strings.HasPrefix(l, "search") {
					fmt.Printf("  %s\n", l)
				}
			}
		} else {
			fmt.Println("  (None or /etc/resolv.conf inaccessible)")
		}

		// Gateway routes
		fmt.Println("\n--- Routing Table ---")
		if data, err := os.ReadFile("/proc/net/route"); err == nil {
			lines := strings.Split(string(data), "\n")
			hasRoute := false
			for i, l := range lines {
				if i == 0 || strings.TrimSpace(l) == "" {
					continue
				}
				fields := strings.Fields(l)
				if len(fields) >= 3 {
					dest := fields[1]
					gw := fields[2]
					if dest == "00000000" { // Default gateway
						// Decode little-endian hex IP
						gwIP := decodeHexIPv4(gw)
						fmt.Printf("  Default Gateway: %s on %s\n", gwIP, fields[0])
						hasRoute = true
					}
				}
			}
			if !hasRoute {
				fmt.Println("  (No default gateway route detected)")
			}
		} else {
			// Fallback to ip route
			out, err := exec.Command("ip", "route").Output()
			if err == nil && len(out) > 0 {
				fmt.Printf("  %s", string(out))
			} else {
				fmt.Println("  (Routing table unavailable)")
			}
		}

		// Internet connectivity check
		fmt.Print("\n--- Connectivity Check --- \n  Connecting to Cloudflare DNS (1.1.1.1:53)... ")
		conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
		if err == nil {
			conn.Close()
			fmt.Println("✅ Online (Outbound Internet Reachable)")
		} else {
			fmt.Printf("⚠️ Offline (%v)\n", err)
		}
		fmt.Println("==================================================")
	},
}

var networkSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure networking (Auto DHCP or Static IP setup wizard)",
	Long: `ziroctl network setup provides Rocky Linux / RHEL-style interactive
or automated network configuration for Ziro-OS.
It writes /etc/network/interfaces and /etc/resolv.conf and can immediately apply settings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		reader := bufio.NewReader(os.Stdin)

		if netSetupMode == "" {
			// Interactive Wizard
			fmt.Println("==================================================")
			fmt.Println(" 🌐 Ziro-OS Network Configuration Wizard")
			fmt.Println("==================================================")

			ifaces, err := net.Interfaces()
			if err != nil {
				return fmt.Errorf("failed to query interfaces: %w", err)
			}

			availIfaces := []string{}
			for _, ifc := range ifaces {
				if ifc.Name != "lo" {
					availIfaces = append(availIfaces, ifc.Name)
				}
			}

			if len(availIfaces) == 0 {
				return fmt.Errorf("no physical or virtual network interfaces detected")
			}

			fmt.Println("Available Network Interfaces:")
			for i, name := range availIfaces {
				fmt.Printf("  [%d] %s\n", i+1, name)
			}

			if netSetupIface == "" {
				fmt.Printf("Select interface [1-%d] (default: 1): ", len(availIfaces))
				choiceStr, _ := reader.ReadString('\n')
				choiceStr = strings.TrimSpace(choiceStr)
				choiceIdx := 0
				if choiceStr != "" {
					var idx int
					if _, err := fmt.Sscanf(choiceStr, "%d", &idx); err == nil && idx >= 1 && idx <= len(availIfaces) {
						choiceIdx = idx - 1
					}
				}
				netSetupIface = availIfaces[choiceIdx]
			}
			fmt.Printf("Configuring interface: %s\n\n", netSetupIface)

			fmt.Println("Configuration Mode:")
			fmt.Println("  [1] Auto (DHCP) - Recommended for Cloud / Proxmox [default]")
			fmt.Println("  [2] Static IP Configuration (IP, Netmask/CIDR, Gateway, DNS)")
			fmt.Print("Select mode [1-2] (default: 1): ")
			modeStr, _ := reader.ReadString('\n')
			modeStr = strings.TrimSpace(modeStr)

			if modeStr == "2" {
				netSetupMode = "static"

				fmt.Print("Enter IPv4 Address with CIDR (e.g. 192.168.1.50/24): ")
				ipStr, _ := reader.ReadString('\n')
				netSetupIP = strings.TrimSpace(ipStr)

				fmt.Print("Enter Default Gateway (e.g. 192.168.1.1): ")
				gwStr, _ := reader.ReadString('\n')
				netSetupGateway = strings.TrimSpace(gwStr)

				fmt.Print("Enter DNS Nameservers [default: 1.1.1.1 8.8.8.8]: ")
				dnsStr, _ := reader.ReadString('\n')
				dnsStr = strings.TrimSpace(dnsStr)
				if dnsStr == "" {
					dnsStr = "1.1.1.1 8.8.8.8"
				}
				netSetupDNS = dnsStr
			} else {
				netSetupMode = "dhcp"
			}

			netSetupApply = true
		}

		if netSetupIface == "" {
			netSetupIface = "eth0"
		}

		// Save to /etc/network/interfaces
		if err := os.MkdirAll("/etc/network", 0755); err != nil {
			return fmt.Errorf("failed to create /etc/network: %w", err)
		}

		var ifaceContent string
		if netSetupMode == "static" {
			if netSetupIP == "" {
				return fmt.Errorf("static configuration requires --ip (e.g. 192.168.1.50/24)")
			}
			ifaceContent = fmt.Sprintf("auto lo\niface lo inet loopback\n\nauto %s\niface %s inet static\n    address %s\n",
				netSetupIface, netSetupIface, netSetupIP)
			if netSetupGateway != "" {
				ifaceContent += fmt.Sprintf("    gateway %s\n", netSetupGateway)
			}

			// Write /etc/resolv.conf
			if netSetupDNS == "" {
				netSetupDNS = "1.1.1.1 8.8.8.8"
			}
			resolvContent := "# Generated by ziroctl network setup\n"
			for _, ns := range strings.Fields(netSetupDNS) {
				resolvContent += fmt.Sprintf("nameserver %s\n", ns)
			}
			if err := os.WriteFile("/etc/resolv.conf", []byte(resolvContent), 0644); err != nil {
				fmt.Printf("Warning: failed to write /etc/resolv.conf: %v\n", err)
			}
		} else {
			ifaceContent = fmt.Sprintf("auto lo\niface lo inet loopback\n\nauto %s\niface %s inet dhcp\n",
				netSetupIface, netSetupIface)
		}

		if err := os.WriteFile("/etc/network/interfaces", []byte(ifaceContent), 0644); err != nil {
			return fmt.Errorf("failed to write /etc/network/interfaces: %w", err)
		}

		fmt.Printf("✅ Saved network configuration to /etc/network/interfaces (%s)\n", netSetupMode)

		if netSetupApply {
			fmt.Printf("Applying network configuration to %s...\n", netSetupIface)
			if netSetupMode == "static" {
				_ = exec.Command("ip", "link", "set", netSetupIface, "up").Run()
				_ = exec.Command("ip", "-4", "addr", "flush", "dev", netSetupIface).Run()
				_ = exec.Command("ip", "-4", "addr", "add", netSetupIP, "dev", netSetupIface).Run()
				if netSetupGateway != "" {
					_ = exec.Command("ip", "-4", "route", "add", "default", "via", netSetupGateway, "dev", netSetupIface).Run()
				}
				fmt.Printf("✅ Static IP %s assigned to %s\n", netSetupIP, netSetupIface)
			} else {
				_ = exec.Command("ip", "link", "set", netSetupIface, "up").Run()
				_ = exec.Command("pkill", "-f", fmt.Sprintf("udhcpc.*%s", netSetupIface)).Run()
				go func() {
					_ = exec.Command("udhcpc", "-b", "-i", netSetupIface, "-s", "/usr/share/udhcpc/default.script").Run()
				}()
				fmt.Printf("✅ Launched DHCP client for %s\n", netSetupIface)
			}
		}

		return nil
	},
}

var networkRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart networking interfaces and DHCP clients",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Restarting network interfaces...")
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		for _, ifc := range ifaces {
			if ifc.Name == "lo" {
				continue
			}
			fmt.Printf("Cycling interface: %s...\n", ifc.Name)
			_ = exec.Command("ip", "link", "set", ifc.Name, "down").Run()
			_ = exec.Command("ip", "link", "set", ifc.Name, "up").Run()
			_ = exec.Command("pkill", "-f", fmt.Sprintf("udhcpc.*%s", ifc.Name)).Run()
			go func(name string) {
				_ = exec.Command("udhcpc", "-b", "-i", name, "-s", "/usr/share/udhcpc/default.script").Run()
			}(ifc.Name)
		}
		fmt.Println("✅ Network interfaces cycled.")
	},
}

func decodeHexIPv4(hexStr string) string {
	if len(hexStr) != 8 {
		return hexStr
	}
	var b0, b1, b2, b3 byte
	_, _ = fmt.Sscanf(hexStr, "%02x%02x%02x%02x", &b0, &b1, &b2, &b3)
	// /proc/net/route hex formatting yields least significant byte in b0, most in b3
	return fmt.Sprintf("%d.%d.%d.%d", b3, b2, b1, b0)
}

func init() {
	networkSetupCmd.Flags().StringVarP(&netSetupIface, "iface", "i", "", "Network interface (e.g. eth0)")
	networkSetupCmd.Flags().StringVarP(&netSetupMode, "mode", "m", "", "Network mode: 'dhcp' or 'static'")
	networkSetupCmd.Flags().StringVar(&netSetupIP, "ip", "", "Static IPv4 address and CIDR (e.g. 192.168.1.50/24)")
	networkSetupCmd.Flags().StringVar(&netSetupGateway, "gateway", "", "Default gateway IPv4 address")
	networkSetupCmd.Flags().StringVar(&netSetupDNS, "dns", "", "DNS nameservers (default: 1.1.1.1 8.8.8.8)")
	networkSetupCmd.Flags().BoolVarP(&netSetupApply, "apply", "a", false, "Immediately apply network configuration")

	networkCmd.AddCommand(networkListCmd)
	networkCmd.AddCommand(networkStatusCmd)
	networkCmd.AddCommand(networkSetupCmd)
	networkCmd.AddCommand(networkRestartCmd)

	rootCmd.AddCommand(networkCmd)
}

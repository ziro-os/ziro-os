package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
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
	Short: "Configure and inspect networking",
	Example: `  ziroctl network status
  ziroctl network set eth0 --mode static --address 192.168.1.50/24 --gateway 192.168.1.1
  ziroctl network apply --confirm-timeout 2m`,
}

var netStatusAll bool

var networkStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show interfaces, addresses, traffic, gateway and DNS",
	Long: `Show the host's interfaces with their addresses, MTU and traffic counters, the default
gateway and the resolvers. Container interfaces are left out unless --all is given, which
also adds MAC addresses, error and drop counters, the routing table, CNI plugins and a
connectivity check.`,
	Example: `  ziroctl network status
  ziroctl network status --all
  ziroctl network status --json | jq '.interfaces[] | select(.role == "primary")'`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := collectNetStatus(netStatusAll)
		if err != nil {
			return err
		}
		return printResult(st, func() { renderNetStatus(os.Stdout, st, netStatusAll) })
	},
}

type IfaceStatus struct {
	Name     string   `json:"name"`
	State    string   `json:"state"` // up, down
	Role     string   `json:"role"`  // primary, nic, mesh, pods, container, loopback
	Addrs    []string `json:"addresses"`
	MAC      string   `json:"mac,omitempty"`
	MTU      int      `json:"mtu"`
	RxBytes  uint64   `json:"rx_bytes"`
	TxBytes  uint64   `json:"tx_bytes"`
	RxErrors uint64   `json:"rx_errors"`
	TxErrors uint64   `json:"tx_errors"`
	RxDrops  uint64   `json:"rx_dropped"`
	TxDrops  uint64   `json:"tx_dropped"`
}

type RouteStatus struct {
	Dest    string `json:"destination"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface"`
	Metric  int    `json:"metric"`
}

type NetStatus struct {
	Interfaces   []IfaceStatus     `json:"interfaces"`
	Gateway      string            `json:"gateway,omitempty"`
	GatewayIface string            `json:"gateway_iface,omitempty"`
	DNS          []string          `json:"dns"`
	Search       []string          `json:"search,omitempty"`
	Routes       []RouteStatus     `json:"routes,omitempty"`
	CNI          []string          `json:"cni_plugins,omitempty"`
	Connectivity map[string]string `json:"connectivity,omitempty"` // check -> ok or the error
}

var sysClassNet = "/sys/class/net"

// collectNetStatus reads interfaces from the kernel (net.Interfaces, /sys/class/net, /proc/net/route);
// all adds container interfaces, routes, CNI plugins and a connectivity check.
func collectNetStatus(all bool) (NetStatus, error) {
	var st NetStatus
	ifaces, err := net.Interfaces()
	if err != nil {
		return st, fmt.Errorf("query interfaces: %w", err)
	}
	st.Routes = readRoutes()
	for _, r := range st.Routes {
		if r.Dest == "0.0.0.0/0" && st.Gateway == "" {
			st.Gateway, st.GatewayIface = r.Gateway, r.Iface
		}
	}
	order := map[string]int{"primary": 0, "nic": 1, "mesh": 2, "pods": 3, "container": 4, "loopback": 5}
	for _, ifc := range ifaces {
		role := ifaceRole(ifc.Name, st.GatewayIface)
		if role == "" {
			if !all {
				continue
			}
			role = map[bool]string{true: "loopback", false: "container"}[ifc.Flags&net.FlagLoopback != 0]
		}
		ni := IfaceStatus{Name: ifc.Name, State: "down", Role: role, MTU: ifc.MTU, MAC: ifc.HardwareAddr.String()}
		if ifc.Flags&net.FlagUp != 0 {
			ni.State = "up"
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			// The default view lists IPv4 only; --all adds IPv6 (link-local left out).
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() && (all || ipn.IP.To4() != nil) {
				ni.Addrs = append(ni.Addrs, a.String())
			}
		}
		stat := func(f string) uint64 { return readUint(filepath.Join(sysClassNet, ifc.Name, "statistics", f)) }
		ni.RxBytes, ni.TxBytes = stat("rx_bytes"), stat("tx_bytes")
		ni.RxErrors, ni.TxErrors, ni.RxDrops, ni.TxDrops = stat("rx_errors"), stat("tx_errors"), stat("rx_dropped"), stat("tx_dropped")
		st.Interfaces = append(st.Interfaces, ni)
	}
	sort.SliceStable(st.Interfaces, func(i, j int) bool { return order[st.Interfaces[i].Role] < order[st.Interfaces[j].Role] })
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) > 1 && f[0] == "nameserver" {
				st.DNS = append(st.DNS, f[1])
			} else if len(f) > 1 && f[0] == "search" {
				st.Search = append(st.Search, f[1:]...)
			}
		}
	}
	if !all {
		st.Routes = nil
		return st, nil
	}
	if plugins, err := os.ReadDir("/opt/cni/bin"); err == nil {
		for _, p := range plugins {
			st.CNI = append(st.CNI, p.Name())
		}
	}
	st.Connectivity = map[string]string{}
	check := func(name string, err error) {
		st.Connectivity[name] = "ok"
		if err != nil {
			st.Connectivity[name] = err.Error()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = net.DefaultResolver.LookupHost(ctx, "github.com")
	check("dns", err)
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err == nil {
		c.Close()
	}
	check("internet", err)
	return st, nil
}

// readRoutes parses the IPv4 routing table (/proc/net/route: little-endian hex fields).
func readRoutes() []RouteStatus {
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "route"))
	if err != nil {
		return nil
	}
	var out []RouteStatus
	for _, l := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		mask := net.ParseIP(decodeHexIPv4(f[7])).To4()
		ones, _ := net.IPMask(mask).Size()
		r := RouteStatus{Dest: fmt.Sprintf("%s/%d", decodeHexIPv4(f[1]), ones), Iface: f[0]}
		if gw := decodeHexIPv4(f[2]); gw != "0.0.0.0" {
			r.Gateway = gw
		}
		r.Metric, _ = strconv.Atoi(f[6])
		out = append(out, r)
	}
	return out
}

func renderNetStatus(out io.Writer, st NetStatus, all bool) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if all {
		fmt.Fprintln(tw, "INTERFACE\tSTATE\tADDRESS\tMAC\tMTU\tRX\tTX\tERR rx/tx\tDROP rx/tx\tROLE")
	} else {
		fmt.Fprintln(tw, "INTERFACE\tSTATE\tADDRESS\tMTU\tRX\tTX\tROLE")
	}
	for _, i := range st.Interfaces {
		addr := strings.Join(i.Addrs, ", ")
		if addr == "" {
			addr = "-"
		}
		if all {
			mac := i.MAC
			if mac == "" {
				mac = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d/%d\t%d/%d\t%s\n", i.Name, i.State, addr, mac, i.MTU,
				humanBytes(i.RxBytes), humanBytes(i.TxBytes), i.RxErrors, i.TxErrors, i.RxDrops, i.TxDrops, i.Role)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", i.Name, i.State, addr, i.MTU, humanBytes(i.RxBytes), humanBytes(i.TxBytes), i.Role)
		}
	}
	tw.Flush()
	fmt.Fprintln(out)
	gw := "none"
	if st.Gateway != "" {
		gw = st.Gateway + " via " + st.GatewayIface
	}
	dns := strings.Join(st.DNS, ", ")
	if len(st.DNS) == 1 && st.DNS[0] == "127.0.0.53" {
		dns += " (smart DNS: ziroctl dns status)"
	}
	if dns == "" {
		dns = "none"
	}
	fmt.Fprintf(out, "%-9s %s\n%-9s %s\n", "Gateway", gw, "DNS", dns)
	if len(st.Search) > 0 {
		fmt.Fprintf(out, "%-9s %s\n", "Search", strings.Join(st.Search, " "))
	}
	if !all {
		return
	}
	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ROUTE\tGATEWAY\tINTERFACE\tMETRIC")
	for _, r := range st.Routes {
		gw := r.Gateway
		if gw == "" {
			gw = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", r.Dest, gw, r.Iface, r.Metric)
	}
	tw.Flush()
	fmt.Fprintln(out)
	cni := strings.Join(st.CNI, " ")
	if cni == "" {
		cni = "none"
	}
	fmt.Fprintf(out, "%-9s %s\n", "CNI", cni)
	for _, k := range []string{"dns", "internet"} {
		fmt.Fprintf(out, "%-9s %s\n", map[string]string{"dns": "Lookup", "internet": "Internet"}[k], st.Connectivity[k])
	}
}

var networkSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure DHCP or a static address interactively",
	Example: `  ziroctl network setup
  ziroctl network setup -i eth0 -m static --ip 192.168.1.50/24 --gateway 192.168.1.1 --apply`,
	Long: `ziroctl network setup provides Rocky Linux / RHEL-style interactive
or automated network configuration for Ziro-OS.
It writes /etc/ziro/network.json (applied at every boot) and /etc/resolv.conf, and can apply immediately.`,
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
		if err := validateNetSetup(); err != nil {
			return err
		}

		// Save to /etc/ziro/network.json (applied at every boot by ziro-init), not
		// /etc/network/interfaces, which nothing reads at boot.
		if netSetupMode == "static" && netSetupIP == "" {
			return fmt.Errorf("static configuration requires --ip (e.g. 192.168.1.50/24)")
		}
		if err := editNetConfig(func(c *NetConfig) error {
			i := c.iface(netSetupIface)
			if i == nil {
				c.Interfaces = append(c.Interfaces, NetIface{Name: netSetupIface})
				i = &c.Interfaces[len(c.Interfaces)-1]
			}
			i.Mode, i.Addresses, i.Gateway = netSetupMode, nil, ""
			if netSetupMode == "static" {
				i.Addresses, i.Gateway = []string{netSetupIP}, netSetupGateway
			}
			return nil
		}); err != nil {
			return err
		}
		if netSetupMode == "static" {
			if netSetupDNS == "" {
				netSetupDNS = "1.1.1.1 8.8.8.8"
			}
			if err := setResolvers(strings.Fields(netSetupDNS), nil); err != nil {
				fmt.Printf("Warning: resolvers: %v\n", err)
			}
		}
		fmt.Printf("✅ Saved network configuration for %s (%s)\n", netSetupIface, netSetupMode)

		if netSetupApply {
			return startNetApply(0)
		}
		return nil
	},
}

var networkRestartCmd = &cobra.Command{
	Use:     "restart",
	Short:   "Restart interfaces and DHCP clients",
	Example: `  ziroctl network restart`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(netConfigPath); err == nil {
			fmt.Println("Re-applying", netConfigPath, "...")
			_ = os.Remove(netAppliedPath) // full re-apply, not a diff
			return startNetApply(0)
		}
		fmt.Println("Restarting network interfaces...")
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("list interfaces: %w", err)
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
		return nil
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

	networkStatusCmd.Flags().BoolVar(&netStatusAll, "all", false, "Include container interfaces, MACs, errors, routes, CNI plugins and a connectivity check")
	networkCmd.AddCommand(networkStatusCmd)
	networkCmd.AddCommand(networkSetupCmd)
	networkCmd.AddCommand(networkRestartCmd)

	rootCmd.AddCommand(networkCmd)
}

var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// validateNetSetup rejects malformed values before they reach /etc/network/interfaces,
// /etc/resolv.conf or ip(8): a newline in any of them would inject extra config lines.
func validateNetSetup() error {
	if !ifaceNameRe.MatchString(netSetupIface) {
		return fmt.Errorf("invalid interface name %q", netSetupIface)
	}
	if netSetupMode != "static" {
		return nil
	}
	if p, err := netip.ParsePrefix(netSetupIP); err != nil || !p.Addr().Is4() {
		return fmt.Errorf("invalid --ip %q (want IPv4 CIDR, e.g. 192.168.1.50/24)", netSetupIP)
	}
	if netSetupGateway != "" {
		if a, err := netip.ParseAddr(netSetupGateway); err != nil || !a.Is4() {
			return fmt.Errorf("invalid --gateway %q", netSetupGateway)
		}
	}
	for _, ns := range strings.Fields(netSetupDNS) {
		if _, err := netip.ParseAddr(ns); err != nil {
			return fmt.Errorf("invalid DNS server %q", ns)
		}
	}
	return nil
}

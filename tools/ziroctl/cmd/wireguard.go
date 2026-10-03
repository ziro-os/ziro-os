package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const (
	wireguardDir   = "/etc/wireguard"
	defaultWgIface = "wg0"
	defaultWgConf  = "/etc/wireguard/wg0.conf"
	defaultWgPeers = "/etc/wireguard/peers"
)

var (
	wgIface  string
	wgCIDR   string
	wgPort   int
	peerName string
	peerIP   string
	showQR   bool
)

var wireguardCmd = &cobra.Command{
	Use:     "wireguard",
	Aliases: []string{"wg", "vpn"},
	Short:   "Manage the WireGuard VPN",
	Example: `  ziroctl wireguard init
  ziroctl wireguard peer add --name laptop --qr
  ziroctl wireguard status`,
}

var wgInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up a WireGuard server on this host",
	Example: `  ziroctl wireguard init
  ziroctl wireguard init --cidr 10.100.0.0/24 --port 51820`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(wgIface); err != nil {
			return err
		}
		if _, _, err := net.ParseCIDR(wgCIDR); err != nil {
			return fmt.Errorf("invalid --cidr %q: %v", wgCIDR, err)
		}
		confPath := filepath.Join(wireguardDir, wgIface+".conf")
		if fileExists(confPath) {
			return fmt.Errorf("%s already exists; refusing to overwrite the server key", confPath)
		}
		if err := os.MkdirAll(defaultWgPeers, 0700); err != nil {
			return err
		}

		privKey, pubKey := generateWgKeypair()
		egress := defaultRouteIface()

		// No SaveConfig: 'wg-quick down' would rewrite the file from runtime state and drop
		// the '# Peer:' markers that 'peer add/remove' rely on. Peers are persisted by ziroctl.
		confContent := fmt.Sprintf(`# Ziro-OS WireGuard Cloud Mesh Interface
[Interface]
Address = %s
ListenPort = %d
PrivateKey = %s

# Cloud mesh routing & container overlay rules
PostUp = iptables -A FORWARD -i %s -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i %s -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true
`, wgCIDR, wgPort, privKey, wgIface, egress, wgIface, egress)

		if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		// Enable IPv4 packet forwarding
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		fmt.Println("================================================================")
		fmt.Printf(" 🛡️  Ziro-OS WireGuard Mesh initialized on %s!\n", wgIface)
		fmt.Println("================================================================")
		fmt.Printf(" Interface:    %s\n", wgIface)
		fmt.Printf(" Mesh Subnet:  %s\n", wgCIDR)
		fmt.Printf(" UDP Port:     %d\n", wgPort)
		fmt.Printf(" Public Key:   %s\n", pubKey)
		fmt.Printf(" Config File:  %s\n\n", confPath)
		fmt.Println("To bring the interface online, run:")
		fmt.Printf("  ziroctl wireguard up\n")
		fmt.Println("To add your first client or mesh peer:")
		fmt.Printf("  ziroctl wireguard peer add --name client1\n")
		return nil
	},
}

var wgUpCmd = &cobra.Command{
	Use:     "up",
	Short:   "Bring the WireGuard interface up",
	Example: `  ziroctl wireguard up`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(wgIface); err != nil {
			return err
		}
		confPath := filepath.Join(wireguardDir, wgIface+".conf")
		if !fileExists(confPath) {
			return fmt.Errorf("config %s not found; run 'ziroctl wireguard init' first", confPath)
		}

		if linkExists(wgIface) {
			if wgConfigured(wgIface) && linkUp(wgIface) {
				fmt.Printf("✓ WireGuard interface '%s' is already UP.\n", wgIface)
				return nil
			}
			// Half-built leftover (e.g. an earlier failed 'up'): wg-quick refuses to touch it.
			fmt.Printf("Removing stale interface '%s' left by an earlier attempt.\n", wgIface)
			_ = exec.Command("ip", "link", "del", "dev", wgIface).Run()
		}

		if _, err := exec.LookPath("wg-quick"); err == nil {
			out, err := exec.Command("wg-quick", "up", wgIface).CombinedOutput()
			if err == nil {
				fmt.Printf("✓ WireGuard interface '%s' is UP.\n", wgIface)
				return nil
			}
			fmt.Printf("wg-quick failed (%s); using ip/wg fallback\n", strings.TrimSpace(string(out)))
			_ = exec.Command("ip", "link", "del", "dev", wgIface).Run()
		}

		if err := wgFallbackUp(wgIface, confPath); err != nil {
			_ = exec.Command("ip", "link", "del", "dev", wgIface).Run()
			return err
		}
		fmt.Printf("✓ WireGuard interface '%s' is UP (ip/wg fallback).\n", wgIface)
		return nil
	},
}

// wgFallbackUp brings the interface up with plain ip + wg, for hosts without a working
// wg-quick. The config goes through a 0600 temp file: /dev/stdin may not exist.
func wgFallbackUp(iface, confPath string) error {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("/run", "ziro-wg-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(stripWgQuick(string(data)))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	if out, err := exec.Command("ip", "link", "add", "dev", iface, "type", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link add: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("wg", "setconf", iface, tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("wg setconf: %v: %s", err, strings.TrimSpace(string(out)))
	}
	c := parseWgConf(string(data))
	for _, a := range c.Address {
		if out, err := exec.Command("ip", "address", "add", a, "dev", iface).CombinedOutput(); err != nil {
			return fmt.Errorf("ip address add %s: %v: %s", a, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.Command("ip", "link", "set", "up", "dev", iface).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %v: %s", err, strings.TrimSpace(string(out)))
	}
	runWgHooks(c.PostUp, iface)
	return nil
}

// runWgHooks runs PostUp/PostDown like wg-quick does (same root-owned 0600 config, same trust).
func runWgHooks(hooks []string, iface string) {
	for _, h := range hooks {
		if out, err := exec.Command("sh", "-c", strings.ReplaceAll(h, "%i", iface)).CombinedOutput(); err != nil {
			fmt.Printf("warning: hook %q failed: %v: %s\n", h, err, strings.TrimSpace(string(out)))
		}
	}
}

var wgDownCmd = &cobra.Command{
	Use:     "down",
	Short:   "Bring the WireGuard interface down",
	Example: `  ziroctl wireguard down`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(wgIface); err != nil {
			return err
		}
		if !linkExists(wgIface) {
			fmt.Printf("WireGuard interface '%s' is already DOWN.\n", wgIface)
			return nil
		}
		if exec.Command("wg-quick", "down", wgIface).Run() != nil {
			if data, err := os.ReadFile(filepath.Join(wireguardDir, wgIface+".conf")); err == nil {
				runWgHooks(parseWgConf(string(data)).PostDown, wgIface)
			}
			if out, err := exec.Command("ip", "link", "del", "dev", wgIface).CombinedOutput(); err != nil && linkExists(wgIface) {
				return fmt.Errorf("ip link del: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
		fmt.Printf("✓ WireGuard interface '%s' is DOWN.\n", wgIface)
		return nil
	},
}

var wgStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show peers, handshakes and transfer",
	Example: `  ziroctl wireguard status`,
	Run: func(cmd *cobra.Command, args []string) {
		if jsonOutput {
			_ = printResult(wireguardStatus(), nil)
			return
		}
		out, err := exec.Command("wg", "show").CombinedOutput()
		if err != nil || len(out) == 0 {
			fmt.Println("WireGuard interface is not currently active.")
			fmt.Println("Run 'ziroctl wireguard up' to start it.")
			return
		}
		fmt.Println("=== Ziro-OS WireGuard Mesh Status ===")
		fmt.Print(string(out))
	},
}

var wgPeerAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a peer and print its config",
	Example: `  ziroctl wireguard peer add --name laptop --qr
  ziroctl wireguard peer add --name office --ip 10.100.0.20`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if peerName == "" {
			return fmt.Errorf("--name is required")
		}
		if err := validName(peerName); err != nil {
			return err
		}
		if err := validName(wgIface); err != nil {
			return err
		}
		serverConfPath := filepath.Join(wireguardDir, wgIface+".conf")
		serverConf, err := os.ReadFile(serverConfPath)
		if err != nil {
			return fmt.Errorf("server config %s not found; run 'ziroctl wireguard init' first", serverConfPath)
		}
		clientFilePath := filepath.Join(defaultWgPeers, peerName+".conf")
		if fileExists(clientFilePath) || strings.Contains(string(serverConf), "# Peer: "+peerName+"\n") {
			return fmt.Errorf("peer '%s' already exists", peerName)
		}
		sc := parseWgConf(string(serverConf))
		serverPub, err := wgPublicKey(sc.PrivateKey)
		if err != nil {
			return fmt.Errorf("server config %s: %w", serverConfPath, err)
		}
		if len(sc.Address) == 0 {
			return fmt.Errorf("server config %s has no Address", serverConfPath)
		}
		_, meshNet, err := net.ParseCIDR(sc.Address[0])
		if err != nil {
			return fmt.Errorf("server Address %q: %v", sc.Address[0], err)
		}
		port := sc.ListenPort
		if cmd.Flags().Changed("port") || port == 0 {
			port = wgPort
		}

		allocatedIP := peerIP
		if allocatedIP == "" {
			if allocatedIP, err = nextPeerIP(string(serverConf)); err != nil {
				return err
			}
		} else {
			ip := net.ParseIP(strings.TrimSuffix(allocatedIP, "/32"))
			if ip == nil || ip.To4() == nil || !meshNet.Contains(ip) {
				return fmt.Errorf("--ip %q must be an IPv4 address inside %s", peerIP, meshNet)
			}
			allocatedIP = ip.String() + "/32"
			if strings.Contains(string(serverConf), "AllowedIPs = "+allocatedIP+"\n") {
				return fmt.Errorf("%s is already assigned to another peer", allocatedIP)
			}
		}

		clientPriv, clientPub := generateWgKeypair()

		serverHost := getFirstNonLoopbackIPv4()
		if serverHost == "" {
			serverHost = "YOUR_SERVER_IP"
		}

		peerEntry := fmt.Sprintf("\n# Peer: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", peerName, clientPub, allocatedIP)
		if err := appendToFile(serverConfPath, peerEntry); err != nil {
			return fmt.Errorf("update %s: %w", serverConfPath, err)
		}

		// Apply live when the interface is up; otherwise 'up' picks it from the config.
		if linkExists(wgIface) {
			if out, err := exec.Command("wg", "set", wgIface, "peer", clientPub, "allowed-ips", allocatedIP).CombinedOutput(); err != nil {
				fmt.Printf("warning: live update failed (%v: %s); applied on next 'up'\n", err, strings.TrimSpace(string(out)))
			}
		}

		clientConf := fmt.Sprintf(`# Ziro-OS Client Mesh Configuration: %s
[Interface]
PrivateKey = %s
Address = %s
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = %s
PersistentKeepalive = 25
`, peerName, clientPriv, allocatedIP, serverPub, serverHost, port, meshNet)

		if err := os.MkdirAll(defaultWgPeers, 0700); err != nil {
			return err
		}
		if err := os.WriteFile(clientFilePath, []byte(clientConf), 0600); err != nil {
			return fmt.Errorf("write %s: %w", clientFilePath, err)
		}

		fmt.Println("================================================================")
		fmt.Printf(" ✓ Peer '%s' added successfully!\n", peerName)
		fmt.Println("================================================================")
		fmt.Printf(" Assigned IP:     %s\n", allocatedIP)
		fmt.Printf(" Client Config:   %s\n\n", clientFilePath)
		fmt.Println("--- Client Configuration ---")
		fmt.Println(clientConf)

		if showQR {
			if _, err := exec.LookPath("qrencode"); err == nil {
				qrCmd := exec.Command("qrencode", "-t", "ANSIUTF8")
				qrCmd.Stdin = strings.NewReader(clientConf)
				qrCmd.Stdout = os.Stdout
				_ = qrCmd.Run()
			}
		}
		return nil
	},
}

var wgPeerRemoveCmd = &cobra.Command{
	Use:     "remove <name>",
	Aliases: []string{"rm"},
	Short:   "Remove a peer",
	Example: `  ziroctl wireguard peer remove laptop`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := validName(name); err != nil {
			return err
		}
		if err := validName(wgIface); err != nil {
			return err
		}
		serverConfPath := filepath.Join(wireguardDir, wgIface+".conf")
		data, err := os.ReadFile(serverConfPath)
		if err != nil {
			return err
		}
		conf, pub, ok := removePeerBlock(string(data), name)
		if !ok {
			return fmt.Errorf("peer '%s' not found in %s", name, serverConfPath)
		}
		if err := writeFileAtomic(serverConfPath, []byte(conf), 0600); err != nil {
			return err
		}
		if pub != "" && linkExists(wgIface) {
			_ = exec.Command("wg", "set", wgIface, "peer", pub, "remove").Run()
		}
		_ = os.Remove(filepath.Join(defaultWgPeers, name+".conf"))
		fmt.Printf("✓ Peer '%s' removed.\n", name)
		return nil
	},
}

var wgPeerListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List peers",
	Example: `  ziroctl wireguard peer list`,
	Run: func(cmd *cobra.Command, args []string) {
		entries, err := os.ReadDir(defaultWgPeers)
		if err != nil || len(entries) == 0 {
			fmt.Println("No client peers found in", defaultWgPeers)
			return
		}

		fmt.Printf("%-20s %s\n", "PEER NAME", "CONFIG FILE")
		fmt.Println(strings.Repeat("-", 60))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				name := strings.TrimSuffix(e.Name(), ".conf")
				fmt.Printf("%-20s %s\n", name, filepath.Join(defaultWgPeers, e.Name()))
			}
		}
	},
}

func generateWgKeypair() (string, string) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // crypto/rand failure: nothing sane to continue with
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// wgPublicKey derives the base64 public key from a base64 WireGuard private key.
func wgPublicKey(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid PrivateKey")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

type wgConf struct {
	PrivateKey string
	ListenPort int
	Address    []string
	PostUp     []string
	PostDown   []string
}

// parseWgConf reads the [Interface] section of a wg-quick style config.
func parseWgConf(conf string) wgConf {
	var c wgConf
	inIface := false
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inIface = strings.EqualFold(line, "[Interface]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !inIface || !ok || strings.HasPrefix(line, "#") {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "PrivateKey":
			c.PrivateKey = v
		case "ListenPort":
			c.ListenPort, _ = strconv.Atoi(v)
		case "Address":
			for _, a := range strings.Split(v, ",") {
				if a = strings.TrimSpace(a); a != "" {
					c.Address = append(c.Address, a)
				}
			}
		case "PostUp":
			c.PostUp = append(c.PostUp, v)
		case "PostDown":
			c.PostDown = append(c.PostDown, v)
		}
	}
	return c
}

// removePeerBlock drops the '# Peer: <name>' marker and the [Peer] section after it.
func removePeerBlock(conf, name string) (string, string, bool) {
	lines := strings.Split(conf, "\n")
	var out []string
	pub, found, skipping := "", false, false
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if !found && l == "# Peer: "+name {
			found, skipping = true, true
			// also drop the blank separator line 'peer add' wrote before the marker
			if n := len(out); n > 0 && strings.TrimSpace(out[n-1]) == "" {
				out = out[:n-1]
			}
			continue
		}
		if skipping {
			if l == "[Peer]" && pub == "" {
				continue
			}
			if l == "" || strings.HasPrefix(l, "[") || strings.HasPrefix(l, "#") {
				skipping = false
			} else {
				if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "PublicKey" {
					pub = strings.TrimSpace(v)
				}
				continue
			}
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n"), pub, found
}

func linkExists(iface string) bool {
	return fileExists("/sys/class/net/" + iface)
}

// linkUp reports the IFF_UP flag (wireguard links report operstate "unknown").
func linkUp(iface string) bool {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/flags")
	if err != nil {
		return false
	}
	f, err := strconv.ParseUint(strings.TrimSpace(string(b)), 0, 32)
	return err == nil && f&1 == 1
}

// wgConfigured is true once a private key has been loaded into the interface.
func wgConfigured(iface string) bool {
	out, err := exec.Command("wg", "show", iface, "private-key").Output()
	k := strings.TrimSpace(string(out))
	return err == nil && k != "" && k != "(none)"
}

// defaultRouteIface returns the interface of the IPv4 default route (for NAT).
func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 1 && f[1] == "00000000" {
				return f[0]
			}
		}
	}
	return "eth0"
}

// nextPeerIP returns the first free /32 in the server's subnet, skipping the
// server address and every AllowedIPs already present in its config.
func nextPeerIP(serverConf string) (string, error) {
	var ipnet *net.IPNet
	used := map[string]bool{}
	for _, line := range strings.Split(serverConf, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Address":
			ip, n, err := net.ParseCIDR(strings.Split(v, ",")[0])
			if err == nil {
				ipnet = n
				used[ip.String()] = true
			}
		case "AllowedIPs":
			for _, c := range strings.Split(v, ",") {
				if ip, _, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
					used[ip.String()] = true
				}
			}
		}
	}
	if ipnet == nil || ipnet.IP.To4() == nil {
		return "", fmt.Errorf("no IPv4 Address in server config")
	}
	for n := binary.BigEndian.Uint32(ipnet.IP.To4()) + 1; ; n++ {
		c := make(net.IP, 4)
		binary.BigEndian.PutUint32(c, n)
		if !ipnet.Contains(c) {
			break
		}
		if c[3] == 0 || c[3] == 255 || used[c.String()] {
			continue
		}
		return c.String() + "/32", nil
	}
	return "", fmt.Errorf("mesh subnet %s is full", ipnet)
}

// stripWgQuick removes wg-quick-only keys so 'wg setconf' accepts the file.
func stripWgQuick(conf string) string {
	skip := map[string]bool{"Address": true, "DNS": true, "MTU": true, "Table": true, "SaveConfig": true,
		"PreUp": true, "PostUp": true, "PreDown": true, "PostDown": true}
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		k, _, _ := strings.Cut(line, "=")
		if !skip[strings.TrimSpace(k)] {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func init() {
	wgInitCmd.Flags().StringVarP(&wgIface, "interface", "i", defaultWgIface, "WireGuard interface name")
	wgInitCmd.Flags().StringVar(&wgCIDR, "cidr", "10.10.0.1/24", "Mesh VPN IPv4 subnet CIDR")
	wgInitCmd.Flags().IntVarP(&wgPort, "port", "p", 51820, "WireGuard UDP listen port")

	wgUpCmd.Flags().StringVarP(&wgIface, "interface", "i", defaultWgIface, "WireGuard interface name")
	wgDownCmd.Flags().StringVarP(&wgIface, "interface", "i", defaultWgIface, "WireGuard interface name")

	wgPeerAddCmd.Flags().StringVarP(&peerName, "name", "n", "", "Peer/client identifier name")
	wgPeerAddCmd.Flags().StringVar(&peerIP, "ip", "", "Peer mesh IP (default: next free address in the mesh subnet)")
	wgPeerAddCmd.Flags().StringVarP(&wgIface, "interface", "i", defaultWgIface, "Target WireGuard interface")
	wgPeerAddCmd.Flags().IntVarP(&wgPort, "port", "p", 51820, "Server UDP port for the client Endpoint (default: the server's ListenPort)")
	wgPeerAddCmd.Flags().BoolVar(&showQR, "qr", false, "Display ASCII QR code in terminal")
	wgPeerRemoveCmd.Flags().StringVarP(&wgIface, "interface", "i", defaultWgIface, "Target WireGuard interface")

	peerCmd := &cobra.Command{
		Use:   "peer",
		Short: "Manage WireGuard peers",
		Example: `  ziroctl wireguard peer add --name laptop --qr
  ziroctl wireguard peer list`,
	}
	peerCmd.AddCommand(wgPeerAddCmd)
	peerCmd.AddCommand(wgPeerRemoveCmd)
	peerCmd.AddCommand(wgPeerListCmd)

	wireguardCmd.AddCommand(wgInitCmd)
	wireguardCmd.AddCommand(wgUpCmd)
	wireguardCmd.AddCommand(wgDownCmd)
	wireguardCmd.AddCommand(wgStatusCmd)
	wireguardCmd.AddCommand(peerCmd)
	rootCmd.AddCommand(wireguardCmd)
}

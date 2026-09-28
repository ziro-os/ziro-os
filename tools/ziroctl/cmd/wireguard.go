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
	"strings"

	"github.com/spf13/cobra"
)

const (
	wireguardDir    = "/etc/wireguard"
	defaultWgIface  = "wg0"
	defaultWgConf   = "/etc/wireguard/wg0.conf"
	defaultWgPeers  = "/etc/wireguard/peers"
)

var (
	wgIface   string
	wgCIDR    string
	wgPort    int
	peerName  string
	peerIP    string
	showQR    bool
)

var wireguardCmd = &cobra.Command{
	Use:     "wireguard",
	Aliases: []string{"wg", "vpn"},
	Short:   "Manage WireGuard cloud mesh VPN, peer networking, and routing",
}

var wgInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize WireGuard server and cloud VPN mesh hub on this node",
	Run: func(cmd *cobra.Command, args []string) {
		_ = os.MkdirAll(wireguardDir, 0700)
		_ = os.MkdirAll(defaultWgPeers, 0700)

		privKey, pubKey := generateWgKeypair()
		egress := defaultRouteIface()

		confContent := fmt.Sprintf(`# Ziro-OS WireGuard Cloud Mesh Interface
[Interface]
Address = %s
ListenPort = %d
PrivateKey = %s
SaveConfig = true

# Cloud mesh routing & container overlay rules
PostUp = iptables -A FORWARD -i %s -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i %s -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true
`, wgCIDR, wgPort, privKey, wgIface, egress, wgIface, egress)

		confPath := filepath.Join(wireguardDir, wgIface+".conf")
		if fileExists(confPath) {
			fmt.Printf("%s already exists; refusing to overwrite the server key.\n", confPath)
			return
		}
		if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
			fmt.Printf("Failed to write config: %v\n", err)
			return
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
	},
}

var wgUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring up the WireGuard network interface",
	Run: func(cmd *cobra.Command, args []string) {
		confPath := filepath.Join(wireguardDir, wgIface+".conf")
		if !fileExists(confPath) {
			fmt.Printf("Config %s not found. Run 'ziroctl wireguard init' first.\n", confPath)
			return
		}

		// Try wg-quick first
		out, err := exec.Command("wg-quick", "up", wgIface).CombinedOutput()
		if err == nil {
			fmt.Printf("✓ WireGuard interface '%s' is UP.\n", wgIface)
			return
		}

		// Fallback without wg-quick: strip wg-quick keys, then ip + wg setconf
		fmt.Printf("wg-quick unavailable or failed (%s); using ip/wg fallback\n", strings.TrimSpace(string(out)))
		data, err := os.ReadFile(confPath)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", confPath, err)
			return
		}
		setconf := exec.Command("wg", "setconf", wgIface, "/dev/stdin")
		setconf.Stdin = strings.NewReader(stripWgQuick(string(data)))
		_ = exec.Command("ip", "link", "add", "dev", wgIface, "type", "wireguard").Run()
		if out, err := setconf.CombinedOutput(); err != nil {
			fmt.Printf("wg setconf failed: %v: %s\n", err, out)
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "Address" {
				_ = exec.Command("ip", "address", "add", strings.TrimSpace(v), "dev", wgIface).Run()
			}
		}
		_ = exec.Command("ip", "link", "set", "up", "dev", wgIface).Run()
		fmt.Printf("✓ WireGuard interface '%s' is UP (fallback).\n", wgIface)
	},
}

var wgDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Bring down the WireGuard network interface",
	Run: func(cmd *cobra.Command, args []string) {
		_ = exec.Command("wg-quick", "down", wgIface).Run()
		_ = exec.Command("ip", "link", "del", "dev", wgIface).Run()
		fmt.Printf("✓ WireGuard interface '%s' is DOWN.\n", wgIface)
	},
}

var wgStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display WireGuard interface status, peer transfers, and handshakes",
	Run: func(cmd *cobra.Command, args []string) {
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
	Short: "Add a client or node peer to the WireGuard mesh",
	Run: func(cmd *cobra.Command, args []string) {
		if peerName == "" {
			fmt.Println("Error: --name is required for adding a peer.")
			return
		}

		if err := validName(peerName); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		serverConfPath := filepath.Join(wireguardDir, wgIface+".conf")
		serverConf, err := os.ReadFile(serverConfPath)
		if err != nil {
			fmt.Printf("Server config %s not found. Run 'ziroctl wireguard init' first.\n", serverConfPath)
			return
		}
		if fileExists(filepath.Join(defaultWgPeers, peerName+".conf")) {
			fmt.Printf("Peer '%s' already exists.\n", peerName)
			return
		}

		allocatedIP := peerIP
		if allocatedIP == "" {
			if allocatedIP, err = nextPeerIP(string(serverConf)); err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
		} else if strings.Contains(string(serverConf), "AllowedIPs = "+allocatedIP+"\n") {
			fmt.Printf("Error: %s is already assigned to another peer.\n", allocatedIP)
			return
		}

		clientPriv, clientPub := generateWgKeypair()

		serverHost := getFirstNonLoopbackIPv4()
		if serverHost == "" {
			serverHost = "YOUR_SERVER_IP"
		}

		// Read server public key
		serverPub := "SERVER_PUBLIC_KEY"
		if out, err := exec.Command("wg", "show", wgIface, "public-key").Output(); err == nil {
			serverPub = strings.TrimSpace(string(out))
		}

		// Add peer to server config
		peerEntry := fmt.Sprintf("\n# Peer: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", peerName, clientPub, allocatedIP)
		_ = appendToFile(serverConfPath, peerEntry)

		// Also apply dynamically if interface is up
		_ = exec.Command("wg", "set", wgIface, "peer", clientPub, "allowed-ips", allocatedIP).Run()

		// Generate client configuration
		clientConf := fmt.Sprintf(`# Ziro-OS Client Mesh Configuration: %s
[Interface]
PrivateKey = %s
Address = %s
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
`, peerName, clientPriv, allocatedIP, serverPub, serverHost, wgPort)

		clientFilePath := filepath.Join(defaultWgPeers, fmt.Sprintf("%s.conf", peerName))
		_ = os.WriteFile(clientFilePath, []byte(clientConf), 0600)

		fmt.Println("================================================================")
		fmt.Printf(" ✓ Peer '%s' added successfully!\n", peerName)
		fmt.Println("================================================================")
		fmt.Printf(" Assigned IP:     %s\n", allocatedIP)
		fmt.Printf(" Client Config:   %s\n\n", clientFilePath)
		fmt.Println("--- Client Configuration ---")
		fmt.Println(clientConf)

		if showQR {
			// Check if qrencode is available
			if _, err := exec.LookPath("qrencode"); err == nil {
				qrCmd := exec.Command("qrencode", "-t", "ANSIUTF8")
				qrCmd.Stdin = strings.NewReader(clientConf)
				qrCmd.Stdout = os.Stdout
				_ = qrCmd.Run()
			}
		}
	},
}

var wgPeerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured WireGuard peers",
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
	wgPeerAddCmd.Flags().IntVarP(&wgPort, "port", "p", 51820, "Server UDP port")
	wgPeerAddCmd.Flags().BoolVar(&showQR, "qr", false, "Display ASCII QR code in terminal")

	peerCmd := &cobra.Command{
		Use:   "peer",
		Short: "Manage WireGuard mesh peers and clients",
	}
	peerCmd.AddCommand(wgPeerAddCmd)
	peerCmd.AddCommand(wgPeerListCmd)

	wireguardCmd.AddCommand(wgInitCmd)
	wireguardCmd.AddCommand(wgUpCmd)
	wireguardCmd.AddCommand(wgDownCmd)
	wireguardCmd.AddCommand(wgStatusCmd)
	wireguardCmd.AddCommand(peerCmd)
	rootCmd.AddCommand(wireguardCmd)
}

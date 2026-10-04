package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/zirocd/daemon"
)

// Mesh "anywhere": the cluster mesh (ziro0) runs on the zirocd engine instead of kernel
// WireGuard, so nodes behind NAT reach each other directly (hole punching, port mapping, hard-NAT
// probing) or through the router relays. Only the masters need a public address. The interface
// keeps its name and addresses, so the ziro_cluster nft policy, the pod network, DNS and gateway
// peers work unchanged; the engine's own packet filter, subnet routing and DNS are off.

const meshAnywhereMTU = 1280

func meshDiscoKeyPath() string { return filepath.Join(clusterDir, "disco.key") }
func nodeKeyPath() string      { return filepath.Join(clusterDir, "node.key") }
func nodeCertPath() string     { return filepath.Join(clusterDir, "node.crt") }

// meshDiscoKey loads this node's path-discovery key, creating it (0600) on first use.
func meshDiscoKey() (priv, pub string, err error) {
	if b, err := os.ReadFile(meshDiscoKeyPath()); err == nil {
		priv = strings.TrimSpace(string(b))
		pub, err = wgPublicKey(priv)
		return priv, pub, err
	}
	priv, pub = generateWgKeypair()
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return "", "", err
	}
	return priv, pub, writeFileAtomic(meshDiscoKeyPath(), []byte(priv+"\n"), 0600)
}

// nodeCSR returns a CSR when the node certificate (relay access) is missing or due for renewal.
func nodeCSR() (string, error) {
	if b, err := os.ReadFile(nodeCertPath()); err == nil {
		if c, err := parseCertPEM(string(b)); err == nil && time.Until(c.NotAfter) > 30*24*time.Hour {
			return "", nil
		}
	}
	keyPEM, err := os.ReadFile(nodeKeyPath())
	if err != nil {
		var csr []byte
		if keyPEM, csr, err = zr.NewTLSKey(); err != nil {
			return "", err
		}
		if err := writeFileAtomic(nodeKeyPath(), keyPEM, 0600); err != nil {
			return "", err
		}
		return string(csr), nil
	}
	csr, err := zr.CSR(keyPEM)
	return string(csr), err
}

// nodeRelayAuth gives the engine's relay connections the cluster CA and the node certificate.
func nodeRelayAuth() (*x509.Certificate, *tls.Certificate) {
	caPEM, err1 := os.ReadFile(clusterCAPath())
	certPEM, err2 := os.ReadFile(nodeCertPath())
	keyPEM, err3 := os.ReadFile(nodeKeyPath())
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, nil
	}
	b, _ := pem.Decode(caPEM)
	if b == nil {
		return nil, nil
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil
	}
	return ca, &c
}

type meshAnywhere struct {
	eng    *daemon.Engine
	relays string // last relay list applied
}

// meshPeers turns the master's mesh view into engine peers.
func meshPeers(peers []MeshPeer) []zr.Peer {
	out := make([]zr.Peer, 0, len(peers))
	for _, p := range peers {
		addr := p.MeshIP + "/32"
		zp := zr.Peer{ID: p.Node, Name: p.Node, NodeKey: p.PubKey, DiscoKey: p.DiscoKey, Addresses: []string{addr},
			AllowedIPs: []string{addr}, Endpoints: p.Endpoints, Relays: p.Relays, NAT: p.NAT}
		for _, r := range p.Routes {
			zp.AllowedIPs = append(zp.AllowedIPs, r+"/32")
		}
		if p.PodCIDR != "" {
			zp.AllowedIPs = append(zp.AllowedIPs, p.PodCIDR)
		}
		if len(zp.Endpoints) == 0 && p.Endpoint != "" { // a node still on direct mode reports none
			zp.Endpoints = []string{p.Endpoint}
		}
		if len(p.Relays) > 0 {
			zp.HomeRelay = p.Relays[0].Name
		}
		out = append(out, zp)
	}
	return out
}

func (m *meshAnywhere) apply(resp heartbeatResponse) error {
	if resp.MeshIP == "" || resp.MeshPrefix == 0 {
		return nil
	}
	ip, err := netip.ParseAddr(resp.MeshIP)
	if err != nil {
		return fmt.Errorf("invalid mesh IP %q", resp.MeshIP)
	}
	meshNet, err := ip.Prefix(resp.MeshPrefix)
	if err != nil {
		return err
	}
	if m.eng == nil {
		if linkExists(meshIface) { // the kernel WireGuard interface of direct mode
			_ = run("ip", "link", "del", "dev", meshIface)
		}
		keyPath, _, err := meshKeypair()
		if err != nil {
			return err
		}
		wg, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		disco, _, err := meshDiscoKey()
		if err != nil {
			return err
		}
		eng, err := daemon.NewEngineWith(daemon.Options{WGKey: strings.TrimSpace(string(wg)), DiscoKey: disco, Port: meshPort,
			Iface: meshIface, MTU: meshAnywhereMTU, NoFilter: true, NoSubnetRouting: true, Auth: nodeRelayAuth})
		if err != nil {
			return fmt.Errorf("mesh engine: %w", err)
		}
		m.eng, m.relays = eng, ""
	}
	msg := zr.MapMessage{Type: "full", Networks: []string{meshNet.String()},
		Self:  &zr.Peer{Name: "self", Addresses: []string{resp.MeshIP + "/32"}, AllowedIPs: []string{resp.MeshIP + "/32"}},
		Peers: meshPeers(resp.Peers)}
	names := make([]string, 0, len(resp.Relays))
	for _, r := range resp.Relays {
		names = append(names, r.Name+"="+r.Addr+"/"+r.STUN)
	}
	if key := strings.Join(names, ","); key != m.relays {
		msg.Relays, msg.RelaysChanged, m.relays = resp.Relays, true, key
	}
	return m.eng.Apply(msg)
}

// report is the soft state the next heartbeat carries.
func (m *meshAnywhere) report(hb *heartbeatRequest) {
	if m.eng == nil {
		return
	}
	r := m.eng.Report("")
	hb.MeshEPs, hb.Relays, hb.NAT = r.Endpoints, r.Relays, r.NAT
}

func (m *meshAnywhere) close() {
	if m.eng != nil {
		m.eng.Close()
		m.eng = nil
	}
}

// ---- CLI ----

var clusterMeshCmd = &cobra.Command{Use: "mesh", Short: "How cluster nodes reach each other",
	Example: "  ziroctl cluster mesh mode anywhere\n  ziroctl cluster mesh mode"}

var clusterMeshModeCmd = &cobra.Command{
	Use:   "mode [direct|anywhere]",
	Short: "Show or set the mesh mode",
	Long: `direct: kernel WireGuard between nodes that can reach each other (one network or public IPs).
anywhere: the zirocd engine (hole punching, port mapping, hard-NAT probing, UDP/TLS relays), so
workers need only outbound internet: only masters need a public address. Needs a router relay
(ziroctl router relay enable). Switching recreates pod-network containers one at a time (MTU).`,
	Example: "  ziroctl cluster mesh mode anywhere\n  ziroctl cluster mesh mode direct",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if len(args) == 0 {
			st, err := readState()
			if err != nil {
				return err
			}
			mode := st.MeshMode
			if mode == "" {
				mode = "direct"
			}
			return printResult(map[string]string{"mode": mode}, func() { fmt.Println(mode) })
		}
		want := args[0]
		if !slices.Contains([]string{"direct", "anywhere"}, want) {
			return errors.New("mode must be direct or anywhere")
		}
		if want == "direct" {
			want = ""
		}
		changed := false
		err := withState(func(st *ClusterState) error {
			var err error
			changed, err = setMeshMode(st, want)
			return err
		})
		if err != nil {
			return err
		}
		if changed {
			fmt.Printf("✓ mesh mode %s: nodes switch at their next heartbeat (seconds); pod-network apps roll out one replica at a time\n", args[0])
		} else {
			fmt.Printf("mesh mode is already %s\n", args[0])
		}
		return nil
	},
}

// setMeshMode switches the mesh mode ("" = direct); pod-network apps get a new NetEpoch, so
// their containers are recreated (new pod MTU) by the usual one-at-a-time rollout.
func setMeshMode(st *ClusterState, want string) (bool, error) {
	if want == "anywhere" && len(routerOf(st).Relays) == 0 {
		return false, errors.New("anywhere needs a relay for nodes behind NAT: ziroctl router relay enable <name> --public <host:port>")
	}
	if st.MeshMode == want {
		return false, nil
	}
	st.MeshMode = want
	for i := range st.Apps {
		if st.Apps[i].Network != "" {
			st.Apps[i].NetEpoch++
		}
	}
	return true, nil
}

func init() {
	clusterMeshCmd.AddCommand(clusterMeshModeCmd)
	clusterCmd.AddCommand(clusterMeshCmd)
}

package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Remote access: laptops, CI runners or other sites join the mesh as WireGuard clients of a
// hub (the first gateway node). The hub relays them into the mesh and every other node routes
// replies back through it. Under the default-deny policy a peer reaches only apps whose
// allow_from names it ("peer:<name>") or all peers ("peers").
// ponytail: one hub, so clients need a new config (`gateway peer add` again) if the first
// gateway node changes; add a hub per gateway with per-peer affinity if that becomes a problem.

// RemotePeer is a WireGuard client admitted to the mesh. Only its public key is stored.
type RemotePeer struct {
	Name      string `json:"name"`
	PubKey    string `json:"pubkey"`
	MeshIP    string `json:"mesh_ip"`
	CreatedAt string `json:"created_at"`
}

// peerHub is the gateway node remote peers connect to: the first one (by ID) on the mesh.
func peerHub(st *ClusterState) *ClusterNode {
	var hub *ClusterNode
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if n.Gateway && n.MeshIP != "" && n.WGPubKey != "" && n.IP != "" && (hub == nil || n.ID < hub.ID) {
			hub = n
		}
	}
	return hub
}

// peerClientConfig renders a wg-quick config for the client. The private key is only ever
// in this output (when the master generated it), never in cluster state.
func peerClientConfig(priv, meshIP, hubPub, endpoint, meshCIDR string) string {
	if priv == "" {
		priv = "<your private key>"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, priv, meshIP, hubPub, endpoint, meshCIDR)
}

var (
	peerPubKey   string
	peerEndpoint string
	peerOut      string
)

var gatewayPeerCmd = &cobra.Command{Use: "peer", Short: "WireGuard remote access to the mesh through the gateway (master only)"}

var gatewayPeerAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Admit a remote WireGuard client (again with the same name rotates its key) and print its config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		if err := validName(args[0]); err != nil {
			return err
		}
		priv, pub := "", peerPubKey
		if pub == "" {
			priv, pub = generateWgKeypair()
		} else if !validWGKey(pub) {
			return fmt.Errorf("invalid --pubkey (want a base64 WireGuard public key)")
		}
		if peerEndpoint != "" {
			if _, p, err := net.SplitHostPort(peerEndpoint); err != nil || !validPortNum(p) || strings.ContainsAny(peerEndpoint, " \t\r\n") {
				return fmt.Errorf("invalid --endpoint %q (want host:port)", peerEndpoint)
			}
		}
		var conf string
		err = withState(func(st *ClusterState) error {
			hub := peerHub(st)
			if hub == nil {
				return fmt.Errorf("no gateway node on the mesh yet: ziroctl gateway node enable <node>")
			}
			for _, rp := range st.Peers {
				if rp.PubKey == pub && rp.Name != args[0] {
					return fmt.Errorf("that key already belongs to peer %q", rp.Name)
				}
			}
			var rp *RemotePeer
			for i := range st.Peers {
				if st.Peers[i].Name == args[0] {
					rp = &st.Peers[i]
				}
			}
			if rp == nil {
				ip, err := allocMeshIP(st, meshCIDR(cfg))
				if err != nil {
					return err
				}
				st.Peers = append(st.Peers, RemotePeer{Name: args[0], MeshIP: ip})
				rp = &st.Peers[len(st.Peers)-1]
			}
			rp.PubKey, rp.CreatedAt = pub, time.Now().UTC().Format(time.RFC3339)
			sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].Name < st.Peers[j].Name })
			ep := peerEndpoint
			if ep == "" {
				port := hub.WGPort
				if port == 0 {
					port = meshPort
				}
				ep = net.JoinHostPort(hub.IP, strconv.Itoa(port))
			}
			ip := ""
			for _, p := range st.Peers {
				if p.Name == args[0] {
					ip = p.MeshIP
				}
			}
			allowed := meshCIDR(cfg)
			if st.PodCIDR != "" {
				allowed += ", " + st.PodCIDR
			}
			conf = peerClientConfig(priv, ip, hub.WGPubKey, ep, allowed)
			return nil
		})
		if err != nil {
			return err
		}
		if peerOut != "" {
			if err := os.WriteFile(peerOut, []byte(conf), 0600); err != nil {
				return err
			}
			fmt.Printf("✓ peer %s admitted; client config written to %s (0600)\n", args[0], peerOut)
		} else {
			fmt.Print(conf)
			fmt.Fprintf(os.Stderr, "✓ peer %s admitted. Save the config above now: its private key is not stored.\n", args[0])
		}
		fmt.Fprintf(os.Stderr, "  Allow it to reach an app: ziroctl cluster deploy --name <app> --allow-from <existing>,peer:%s\n", args[0])
		return nil
	},
}

var gatewayPeerRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Revoke a remote peer (its key stops working on the next heartbeat)", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			for i, rp := range st.Peers {
				if rp.Name == args[0] {
					st.Peers = append(st.Peers[:i], st.Peers[i+1:]...)
					fmt.Printf("✓ peer %s revoked\n", args[0])
					return nil
				}
			}
			return fmt.Errorf("peer %q not found", args[0])
		})
	},
}

var gatewayPeerLsCmd = &cobra.Command{
	Use: "ls", Short: "List remote peers",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		peers := st.Peers
		if peers == nil {
			peers = []RemotePeer{}
		}
		hub := "(none: enable a gateway node)"
		if h := peerHub(st); h != nil {
			hub = h.ID + " " + h.IP
		}
		return printResult(peers, func() {
			fmt.Printf("Hub: %s\n\n%-20s %-16s %-46s %s\n", hub, "NAME", "MESH IP", "PUBLIC KEY", "SINCE")
			for _, p := range peers {
				fmt.Printf("%-20s %-16s %-46s %s\n", p.Name, p.MeshIP, p.PubKey, p.CreatedAt)
			}
		})
	},
}

func init() {
	gatewayPeerAddCmd.Flags().StringVar(&peerPubKey, "pubkey", "", "Client's own public key (recommended: the private key then never leaves the client)")
	gatewayPeerAddCmd.Flags().StringVar(&peerEndpoint, "endpoint", "", "host:port clients dial (default: the hub node's IP and mesh port; set it behind NAT)")
	gatewayPeerAddCmd.Flags().StringVarP(&peerOut, "output", "o", "", "Write the client config to this file (0600) instead of stdout")
	gatewayPeerCmd.AddCommand(gatewayPeerAddCmd, gatewayPeerRmCmd, gatewayPeerLsCmd)
	gatewayCmd.AddCommand(gatewayPeerCmd)
}

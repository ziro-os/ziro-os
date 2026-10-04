package cmd

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/zirocd/relay"
)

// Router relays on planets (`ziroctl router relay enable`): the relay itself is the zirocd
// relay package, shared with moons (`zirocd moon`). Here it reads the member list from this
// master's replica of the cluster state.

const (
	relayConfPath = "/etc/ziro/router-relay.json"
	relayRefresh  = 5 * time.Second
)

type relayConf struct {
	Name    string `json:"name"`
	Listen  string `json:"listen"`             // TLS, e.g. :8443
	STUN    string `json:"stun"`               // UDP, e.g. :3478
	Mbps    int    `json:"mbps,omitempty"`     // per-device rate limit (default 1000)
	MaxMbps int    `json:"max_mbps,omitempty"` // relay-wide rate limit (default 10000)
}

// relayMemberSet is who may use a relay: authorized, unexpired members with a valid node key.
func relayMemberSet(st *zr.State) map[string]relay.Member {
	m := map[string]relay.Member{}
	now := time.Now()
	for _, mb := range st.Members {
		k, err := base64.StdEncoding.DecodeString(mb.NodeKey)
		if !mb.Authorized || err != nil || len(k) != 32 || memberExpired(&mb, now) {
			continue
		}
		m[mb.ID] = relay.Member{KeyHash: mb.KeyHash, NodeKey: [32]byte(k), Network: mb.Network}
	}
	return m
}

// runPlanetRelay serves a relay fed from load (re-read every 5s, and at once for an unknown
// device), until ctx ends.
func runPlanetRelay(ctx context.Context, s *relay.Server, load func() (*zr.State, error), listen, stun string, tlsConf *tls.Config) error {
	refresh := func() error {
		st, err := load()
		if err != nil {
			return err
		}
		s.SetMembers(relayMemberSet(st))
		return nil
	}
	if err := refresh(); err != nil {
		return err
	}
	s.Reload = func() { _ = refresh() }
	ln, err := tls.Listen("tcp", listen, tlsConf)
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(relayRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := refresh(); err != nil {
					fmt.Printf("[relay] refresh members: %v\n", err)
				}
			}
		}
	}()
	return s.Serve(ctx, ln, stun)
}

// relayTLS: the relay presents this master's certificate (verified by devices under the cluster
// CA) and requires a device certificate.
func relayTLS(caPEM string) (*tls.Config, error) {
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}, nil
}

// ---- CLI ----

var (
	relayPublic      string
	relayListen      string
	relaySTUN        int
	relayMbps        int
	relayMaxMbpsFlag int
)

var routerRelayCmd = &cobra.Command{Use: "relay", Aliases: []string{"relays"}, Short: "Relays for devices without a direct path",
	Example: "  ziroctl router relay enable sg-1 --public relay-sg.example.com:8443\n  ziroctl router relay ls"}

func listenPort(hostport string) (int, error) {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}

var routerRelayEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Run a relay on this master and announce it to devices",
	Example: `  ziroctl router relay enable sg-1 --public relay-sg.example.com:8443
  ziroctl router relay enable sg-1 --public 203.0.113.7:443 --listen :443 --stun-port 3478`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := validLabel(args[0]); err != nil {
			return err
		}
		h, p, err := net.SplitHostPort(relayPublic)
		if err != nil || h == "" || !validPortNum(p) || !(validHost(h) || net.ParseIP(h) != nil) {
			return fmt.Errorf("--public must be the host:port devices dial (got %q)", relayPublic)
		}
		lport, err := listenPort(relayListen)
		if err != nil || relaySTUN < 1 || relaySTUN > 65535 {
			return fmt.Errorf("invalid --listen or --stun-port")
		}
		r := zr.Relay{Name: args[0], Addr: relayPublic, STUN: net.JoinHostPort(h, strconv.Itoa(relaySTUN))}
		if relayMbps < 1 || relayMbps > 100000 {
			return fmt.Errorf("--rate-mbps must be 1 to 100000")
		}
		if relayMaxMbpsFlag < relayMbps {
			return fmt.Errorf("--max-mbps must be at least --rate-mbps")
		}
		conf := relayConf{Name: args[0], Listen: relayListen, STUN: ":" + strconv.Itoa(relaySTUN), Mbps: relayMbps, MaxMbps: relayMaxMbpsFlag}
		if err := writeJSONAtomic(relayConfPath, conf); err != nil {
			return err
		}
		if err := withState(func(st *ClusterState) error {
			R := routerOf(st)
			for i := range R.Relays {
				if R.Relays[i].Name == r.Name {
					R.Relays[i] = r
					return nil
				}
			}
			R.Relays = append(R.Relays, r)
			return nil
		}); err != nil {
			return err
		}
		allowFirewall([]FirewallRule{{Port: lport, Protocol: "tcp", Comment: "Ziro router relay"},
			{Port: relaySTUN, Protocol: "udp", Comment: "Ziro router relay STUN"}}, "")
		startClusterServices("router-relay")
		fmt.Printf("✓ relay %s serving on %s (STUN udp/%d); devices dial %s\n", r.Name, relayListen, relaySTUN, r.Addr)
		return nil
	},
}

var routerRelayDisableCmd = &cobra.Command{
	Use: "disable <name>", Short: "Stop announcing a relay and stop it here", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router relay disable sg-1",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		err := withState(func(st *ClusterState) error {
			R := routerOf(st)
			for i := range R.Relays {
				if R.Relays[i].Name == args[0] {
					R.Relays = append(R.Relays[:i], R.Relays[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no relay %q", args[0])
		})
		if err != nil {
			return err
		}
		var conf relayConf
		if readJSONFile(relayConfPath, &conf) == nil && conf.Name == args[0] {
			stopClusterServices("router-relay")
			_ = os.Remove(relayConfPath)
		}
		fmt.Printf("✓ relay %s removed; devices stop using it within a second\n", args[0])
		return nil
	},
}

var routerRelayLsCmd = &cobra.Command{
	Use: "ls", Short: "List relays", Example: "  ziroctl router relay ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		rs := append([]zr.Relay{}, routerOf(st).Relays...)
		return printResult(rs, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tADDRESS\tSTUN")
			for _, r := range rs {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, r.Addr, r.STUN)
			}
			tw.Flush()
		})
	},
}

var routerRelayServeCmd = &cobra.Command{
	Use: "serve", Short: "Run the relay (started by the router-relay service)", Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		var conf relayConf
		if err := readJSONFile(relayConfPath, &conf); err != nil {
			return fmt.Errorf("relay not enabled here (ziroctl router relay enable): %w", err)
		}
		st, err := readState()
		if err != nil {
			return err
		}
		tc, err := relayTLS(st.CACert)
		if err != nil {
			return err
		}
		s := relay.New()
		s.SetRates(cmp.Or(conf.Mbps, relay.DefaultRateMbps), cmp.Or(conf.MaxMbps, relay.DefaultMaxMbps))
		fmt.Printf("[relay] %s serving TLS on %s, STUN on udp %s\n", conf.Name, conf.Listen, conf.STUN)
		return runPlanetRelay(cmd.Context(), s, func() (*zr.State, error) {
			cur, err := readState()
			if err != nil {
				return nil, err
			}
			return relayMembers(cur), nil
		}, conf.Listen, conf.STUN, tc)
	},
}

func init() {
	routerRelayEnableCmd.Flags().StringVar(&relayPublic, "public", "", "host:port devices dial (required)")
	routerRelayEnableCmd.Flags().StringVar(&relayListen, "listen", ":8443", "TLS listen address")
	routerRelayEnableCmd.Flags().IntVar(&relaySTUN, "stun-port", 3478, "STUN UDP port")
	routerRelayEnableCmd.Flags().IntVar(&relayMbps, "rate-mbps", relay.DefaultRateMbps, "per-device relayed bandwidth limit")
	routerRelayEnableCmd.Flags().IntVar(&relayMaxMbpsFlag, "max-mbps", relay.DefaultMaxMbps, "relay-wide relayed bandwidth limit")
	routerRelayCmd.AddCommand(routerRelayEnableCmd, routerRelayDisableCmd, routerRelayLsCmd, routerRelayServeCmd)
	routerCmd.AddCommand(routerRelayCmd)
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// relayMembers is who may use the relay: router devices, and (mesh "anywhere") the cluster's
// nodes, as members "node:<id>" of their own network that only they share.
func relayMembers(st *ClusterState) *zr.State {
	r := *routerOf(st)
	if st.MeshMode != "anywhere" {
		return &r
	}
	r.Members = append([]zr.Member(nil), r.Members...)
	for _, n := range st.Nodes {
		if n.WGPubKey != "" && n.CertHash != "" {
			r.Members = append(r.Members, zr.Member{ID: "node:" + n.ID, Network: "cluster-mesh", NodeKey: n.WGPubKey,
				KeyHash: n.CertHash, Authorized: true})
		}
	}
	return &r
}

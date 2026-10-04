package cmd

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Router relays: a device that cannot reach a peer directly (both behind strict NATs, UDP
// blocked) sends its WireGuard packets over TLS to the peer's home relay, which hands them to
// the peer's connection. Relays run on masters (they read the replicated member list), only see
// WireGuard ciphertext, only connect devices of the same network, and drop a device within
// seconds of its removal. Each relay also answers STUN, so devices learn their public address.
// ponytail: TLS over TCP only (DERP-style); add QUIC datagrams if relayed throughput matters.

const (
	relayConfPath    = "/etc/ziro/router-relay.json"
	relayRefresh     = 5 * time.Second
	relayQueue       = 512             // frames buffered per receiving device
	relayRateMbps    = 200             // default per-device sustained rate
	relayBurstBytes  = 4 << 20         // per-device burst
	relayIdleTimeout = 2 * time.Minute // no frame (keepalives included) for this long: close
)

type relayConf struct {
	Name   string `json:"name"`
	Listen string `json:"listen"`         // TLS, e.g. :8443
	STUN   string `json:"stun"`           // UDP, e.g. :3478
	Mbps   int    `json:"mbps,omitempty"` // per-device rate limit (default 200)
}

// relayMember is what the relay needs to know about a device.
type relayMember struct {
	keyHash string
	nodeKey [32]byte
	network string
}

type relayClient struct {
	member  string
	network string
	key     [32]byte
	rc      *zr.RelayConn
	out     chan []byte // encoded frames to write
	done    chan struct{}
	once    sync.Once
	tokens  float64
	last    time.Time
	rate    float64 // bytes/s
}

func (c *relayClient) close() { c.once.Do(func() { close(c.done); c.rc.Close() }) }

// allow is a byte token bucket (sender side): a device cannot flood a relay.
func (c *relayClient) allow(n int, now time.Time) bool {
	c.tokens = min(c.tokens+now.Sub(c.last).Seconds()*c.rate, relayBurstBytes)
	c.last = now
	if c.tokens < float64(n) {
		return false
	}
	c.tokens -= float64(n)
	return true
}

type relayServer struct {
	load func() (*zr.State, error) // the replicated router state
	rate float64                   // per-device bytes/s

	refreshMu   sync.Mutex
	lastRefresh time.Time

	mu      sync.RWMutex
	members map[string]relayMember    // member ID -> identity
	byKey   map[[32]byte]*relayClient // connected devices
	dropped uint64
}

func newRelayServer(load func() (*zr.State, error)) *relayServer {
	return &relayServer{load: load, rate: relayRateMbps * 1e6 / 8, members: map[string]relayMember{}, byKey: map[[32]byte]*relayClient{}}
}

// refresh reloads the member list and disconnects devices that were removed or re-keyed.
func (s *relayServer) refresh() error {
	s.refreshMu.Lock()
	s.lastRefresh = time.Now()
	s.refreshMu.Unlock()
	st, err := s.load()
	if err != nil {
		return err
	}
	m := map[string]relayMember{}
	for _, mb := range st.Members {
		k, err := base64.StdEncoding.DecodeString(mb.NodeKey)
		if !mb.Authorized || err != nil || len(k) != 32 {
			continue
		}
		var key [32]byte
		copy(key[:], k)
		m[mb.ID] = relayMember{keyHash: mb.KeyHash, nodeKey: key, network: mb.Network}
	}
	s.mu.Lock()
	s.members = m
	var gone []*relayClient
	for k, c := range s.byKey {
		if cur, ok := m[c.member]; !ok || cur.nodeKey != k {
			gone = append(gone, c)
			delete(s.byKey, k)
		}
	}
	s.mu.Unlock()
	for _, c := range gone {
		c.close()
	}
	return nil
}

// serveConn runs one device connection until it closes.
func (s *relayServer) serveConn(conn *tls.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	cs := conn.ConnectionState()
	id, kh, ok := deviceFromTLS(&cs)
	s.mu.RLock()
	m, known := s.members[id]
	s.mu.RUnlock()
	if ok && !known && s.refreshDue() { // a device that joined since the last refresh
		_ = s.refresh()
		s.mu.RLock()
		m, known = s.members[id]
		s.mu.RUnlock()
	}
	if !ok || !known || subtle.ConstantTimeCompare([]byte(m.keyHash), []byte(kh)) != 1 {
		return
	}
	c := &relayClient{member: id, network: m.network, key: m.nodeKey, rc: zr.NewRelayConn(conn),
		out: make(chan []byte, relayQueue), done: make(chan struct{}), tokens: relayBurstBytes, last: time.Now(), rate: s.rate}
	s.mu.Lock()
	if old := s.byKey[c.key]; old != nil {
		old.close() // the newest connection of a device wins
	}
	s.byKey[c.key] = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.byKey[c.key] == c {
			delete(s.byKey, c.key)
		}
		s.mu.Unlock()
		c.close()
	}()

	go func() { // writer: frames queued for this device, plus keepalives
		t := time.NewTicker(zr.RelayKeepalive)
		defer t.Stop()
		for {
			select {
			case <-c.done:
				return
			case f := <-c.out:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(f); err != nil {
					c.close()
					return
				}
			case <-t.C:
				if c.rc.WriteFrame(zr.FrameKeepalive, nil, nil) != nil {
					c.close()
					return
				}
			}
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(relayIdleTimeout))
		typ, dst, payload, err := c.rc.ReadFrame()
		if err != nil {
			return
		}
		if typ != zr.FrameSend {
			continue
		}
		if !c.allow(len(payload), time.Now()) {
			s.drop()
			continue
		}
		s.mu.RLock()
		to := s.byKey[dst]
		s.mu.RUnlock()
		if to == nil || to.network != c.network { // only within one network
			s.drop()
			continue
		}
		n := 32 + len(payload)
		f := make([]byte, 4+n)
		f[0], f[1], f[2], f[3] = zr.FrameRecv, byte(n>>16), byte(n>>8), byte(n)
		copy(f[4:], c.key[:])
		copy(f[36:], payload)
		select {
		case to.out <- f:
		default: // receiver too slow: drop like a congested link would
			s.drop()
		}
	}
}

// refreshDue allows an on-demand refresh at most once a second (unknown devices cannot make the
// relay hammer the state).
func (s *relayServer) refreshDue() bool {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return time.Since(s.lastRefresh) >= time.Second
}

func (s *relayServer) drop() {
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

// serveSTUN answers STUN binding requests on pc.
func serveSTUN(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		tx, ok := zr.ParseSTUNRequest(buf[:n])
		ua, isUDP := from.(*net.UDPAddr)
		if !ok || !isUDP {
			continue
		}
		_, _ = pc.WriteTo(zr.STUNResponse(tx, ua.AddrPort()), from)
	}
}

// runRelay serves until ctx ends.
func runRelay(ctx context.Context, s *relayServer, listen, stun string, tlsConf *tls.Config) error {
	if err := s.refresh(); err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", listen, tlsConf)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", stun)
	if err != nil {
		ln.Close()
		return err
	}
	go serveSTUN(pc)
	go func() {
		t := time.NewTicker(relayRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				ln.Close()
				pc.Close()
				return
			case <-t.C:
				if err := s.refresh(); err != nil {
					fmt.Printf("[relay] refresh members: %v\n", err)
				}
			}
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		go s.serveConn(c.(*tls.Conn))
	}
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
	relayPublic string
	relayListen string
	relaySTUN   int
	relayMbps   int
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
		conf := relayConf{Name: args[0], Listen: relayListen, STUN: ":" + strconv.Itoa(relaySTUN), Mbps: relayMbps}
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
		s := newRelayServer(func() (*zr.State, error) {
			cur, err := readState()
			if err != nil {
				return nil, err
			}
			return routerOf(cur), nil
		})
		if conf.Mbps > 0 {
			s.rate = float64(conf.Mbps) * 1e6 / 8
		}
		fmt.Printf("[relay] %s serving TLS on %s, STUN on udp %s\n", conf.Name, conf.Listen, conf.STUN)
		return runRelay(cmd.Context(), s, conf.Listen, conf.STUN, tc)
	},
}

func init() {
	routerRelayEnableCmd.Flags().StringVar(&relayPublic, "public", "", "host:port devices dial (required)")
	routerRelayEnableCmd.Flags().StringVar(&relayListen, "listen", ":8443", "TLS listen address")
	routerRelayEnableCmd.Flags().IntVar(&relaySTUN, "stun-port", 3478, "STUN UDP port")
	routerRelayEnableCmd.Flags().IntVar(&relayMbps, "rate-mbps", relayRateMbps, "per-device relayed bandwidth limit")
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

package cmd

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Moons: relays that are not masters. `ziroctl router moon add` records one (Raft) and prints a
// one-time token; `zirocd moon` registers with it (CSR -> certificate, OU ziro-relay, name
// <moon>.moon.ziro, 7 days, renewed by the moon) and follows the relay map from any planet: the
// members it may forward for, and nothing else. Removing a moon ends its relay map stream at once
// and drops it from every netmap.

const (
	moonCertTTL  = 7 * 24 * time.Hour
	moonTokenTTL = time.Hour
	moonStateDir = "/var/lib/zirocd-moon"
	moonBuffer   = 256
)

var errBadMoonToken = httpError{http.StatusUnauthorized, "invalid, expired or used moon token"}

func findMoon(R *zr.State, name string) *zr.Moon {
	for i := range R.Moons {
		if R.Moons[i].Name == name {
			return &R.Moons[i]
		}
	}
	return nil
}

// issueMoonCert signs a moon's certificate: a server certificate for devices (under its own
// name, never the planets') and a client certificate for the planets. Identity comes from the
// router, never from the CSR.
func issueMoonCert(st *ClusterState, csr *x509.CertificateRequest, name string) (string, error) {
	ca, key, err := caSigner(st)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: name, OrganizationalUnit: []string{zr.MoonOU}},
		DNSNames:  []string{zr.MoonServerName(name)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(moonCertTTL),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, key)
	if err != nil {
		return "", err
	}
	return pemEncode("CERTIFICATE", der), nil
}

// moonFromTLS returns the name and key hash of a verified moon certificate.
func moonFromTLS(cs *tls.ConnectionState) (name, keyHash string, ok bool) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return "", "", false
	}
	c := cs.PeerCertificates[0]
	if len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != zr.MoonOU || c.Subject.CommonName == "" {
		return "", "", false
	}
	return c.Subject.CommonName, zr.PublicKeyHash(c.RawSubjectPublicKeyInfo), true
}

// moonRegister consumes a moon's token and certifies its key (pure state transition).
func moonRegister(st *ClusterState, req zr.MoonRegisterRequest, csr *x509.CertificateRequest, keyHash string, now time.Time) (zr.MoonRegisterResponse, error) {
	m := findMoon(routerOf(st), req.Name)
	if m == nil || m.TokenHash == "" || now.After(m.TokenExpires) ||
		subtle.ConstantTimeCompare([]byte(hashToken(req.Secret)), []byte(m.TokenHash)) != 1 {
		return zr.MoonRegisterResponse{}, errBadMoonToken
	}
	m.TokenHash, m.TokenExpires, m.KeyHash = "", time.Time{}, keyHash
	crt, err := issueMoonCert(st, csr, m.Name)
	if err != nil {
		return zr.MoonRegisterResponse{}, err
	}
	return zr.MoonRegisterResponse{Cert: crt, CA: st.CACert}, nil
}

// moonRenew certifies a registered moon again (a new key replaces the old one at once).
func moonRenew(st *ClusterState, name, curKeyHash string, csr *x509.CertificateRequest, keyHash string) (zr.MoonRegisterResponse, error) {
	m := findMoon(routerOf(st), name)
	if m == nil || m.KeyHash == "" || subtle.ConstantTimeCompare([]byte(m.KeyHash), []byte(curKeyHash)) != 1 {
		return zr.MoonRegisterResponse{}, errUnauthorized
	}
	m.KeyHash = keyHash
	crt, err := issueMoonCert(st, csr, m.Name)
	if err != nil {
		return zr.MoonRegisterResponse{}, err
	}
	return zr.MoonRegisterResponse{Cert: crt, CA: st.CACert}, nil
}

// announcedRelays are the relays devices are told about: planets' relays, and moons once they
// have registered (an unregistered moon has nothing listening yet).
func announcedRelays(R *zr.State) []zr.Relay {
	out := make([]zr.Relay, 0, len(R.Relays))
	for _, r := range R.Relays {
		if r.ServerName != "" {
			if m := findMoon(R, r.Name); m == nil || m.KeyHash == "" {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// ---- the relay map hub (every planet) ----

type moonSub struct {
	name, keyHash string
	ch            chan []byte
	done          chan struct{}
}

type moonHub struct {
	mu      sync.Mutex
	loaded  bool
	members map[string]zr.RelayMember
	moons   map[string]string // registered moon -> key hash
	subs    map[*moonSub]struct{}
}

func newMoonHub() *moonHub {
	return &moonHub{members: map[string]zr.RelayMember{}, moons: map[string]string{}, subs: map[*moonSub]struct{}{}}
}

// relayMapOf lists who may use a relay (relayMembers: devices, and cluster nodes in mesh
// "anywhere" mode), as the relay map carries them.
func relayMapOf(st *ClusterState) map[string]zr.RelayMember {
	out := map[string]zr.RelayMember{}
	now := time.Now()
	for _, mb := range relayMembers(st).Members {
		k, err := base64.StdEncoding.DecodeString(mb.NodeKey)
		if !mb.Authorized || err != nil || len(k) != 32 || memberExpired(&mb, now) {
			continue
		}
		out[mb.ID] = zr.RelayMember{ID: mb.ID, KeyHash: mb.KeyHash, NodeKey: mb.NodeKey, Network: mb.Network}
	}
	return out
}

// setState loads a committed state: streams get what changed; a removed or re-keyed moon's
// stream ends.
func (h *moonHub) setState(st *ClusterState) {
	next := relayMapOf(st)
	moons := map[string]string{}
	for _, m := range routerOf(st).Moons {
		if m.KeyHash != "" {
			moons[m.Name] = m.KeyHash
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var delta zr.RelayMapMessage
	if h.loaded {
		delta.Type = "delta"
		for id, m := range next {
			if h.members[id] != m {
				delta.Members = append(delta.Members, m)
			}
		}
		for id := range h.members {
			if _, ok := next[id]; !ok {
				delta.Removed = append(delta.Removed, id)
			}
		}
	}
	h.loaded, h.members, h.moons = true, next, moons
	var b []byte
	if delta.Members != nil || delta.Removed != nil {
		b, _ = json.Marshal(delta)
	}
	for s := range h.subs {
		if moons[s.name] != s.keyHash {
			h.dropLocked(s) // removed, or registered again with another key
			continue
		}
		if b != nil {
			select {
			case s.ch <- b:
			default: // too slow: it reconnects and gets the full map
				h.dropLocked(s)
			}
		}
	}
}

func (h *moonHub) dropLocked(s *moonSub) {
	if _, ok := h.subs[s]; ok {
		delete(h.subs, s)
		close(s.done)
	}
}

func (h *moonHub) subscribe(name, keyHash string) (*moonSub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		return nil, errRouterLoading
	}
	if kh, ok := h.moons[name]; !ok || subtle.ConstantTimeCompare([]byte(kh), []byte(keyHash)) != 1 {
		return nil, errUnauthorized
	}
	full := zr.RelayMapMessage{Type: "full", Members: make([]zr.RelayMember, 0, len(h.members))}
	for _, m := range h.members {
		full.Members = append(full.Members, m)
	}
	b, _ := json.Marshal(full)
	s := &moonSub{name: name, keyHash: keyHash, ch: make(chan []byte, moonBuffer), done: make(chan struct{})}
	s.ch <- b
	h.subs[s] = struct{}{}
	return s, nil
}

func (h *moonHub) unsubscribe(s *moonSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(s)
}

// connected lists the moons streaming from this planet (ziroctl router moon ls).
func (h *moonHub) connected() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]bool{}
	for s := range h.subs {
		out[s.name] = true
	}
	return out
}

// ---- HTTP (router server) ----

func (rt *routerServer) serveMoonRegister(w http.ResponseWriter, r *http.Request, who routerIdent) {
	var req zr.MoonRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rt.fail(w, who, r.URL.Path, httpError{http.StatusBadRequest, "invalid request"})
		return
	}
	csr, kh, err := parseCSR(req.CSR)
	var out zr.MoonRegisterResponse
	if err == nil {
		err = withState(func(st *ClusterState) error {
			var e error
			out, e = moonRegister(st, req, csr, kh, time.Now())
			return e
		})
	}
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	clusterAudit("ip:"+who.ip, "router moon register", req.Name, nil)
	rt.sync()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

func (rt *routerServer) serveMoonRenew(w http.ResponseWriter, r *http.Request, who routerIdent) {
	if who.moon == "" {
		rt.fail(w, who, r.URL.Path, errUnauthorized)
		return
	}
	var req zr.MoonRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rt.fail(w, who, r.URL.Path, httpError{http.StatusBadRequest, "invalid request"})
		return
	}
	csr, kh, err := parseCSR(req.CSR)
	var out zr.MoonRegisterResponse
	if err == nil {
		err = withState(func(st *ClusterState) error {
			var e error
			out, e = moonRenew(st, who.moon, who.moonKey, csr, kh)
			return e
		})
	}
	clusterAudit("moon:"+who.moon, "router moon renew", who.moon, err)
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	rt.sync()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

// serveRelayMap streams the relay map to a moon, from this planet's replica.
func (rt *routerServer) serveRelayMap(w http.ResponseWriter, r *http.Request, who routerIdent) {
	if who.moon == "" {
		rt.fail(w, who, r.URL.Path, errUnauthorized)
		return
	}
	s, err := rt.moons.subscribe(who.moon, who.moonKey)
	if err != nil {
		if !rt.isLeader() && !who.forwarded { // a moon registered a moment ago: the leader knows it
			rt.forward(w, r, who)
			return
		}
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	defer rt.moons.unsubscribe(s)
	streamLines(w, r, s.ch, s.done)
}

// ---- CLI ----

var (
	moonPublic   string
	moonSTUNPort int
	moonTTLFlag  time.Duration
	moonListen   string
	moonJoinFile string
)

var routerMoonCmd = &cobra.Command{Use: "moon", Aliases: []string{"moons"}, Short: "Regional relays that run on any Linux host",
	Example: "  ziroctl router moon add sg-1 --public relay-sg.example.com:8443\n  ziroctl router moon ls"}

// moonToken issues a registration token for moon name (only its hash is stored).
func moonToken(st *ClusterState, cfg *ClusterConfig, name string, ttl time.Duration) (string, error) {
	pin, err := pemHash(st.CACert)
	if err != nil {
		return "", fmt.Errorf("cluster CA: %w", err)
	}
	eps := routerEndpoints(st, cfg)
	if len(eps) == 0 {
		return "", errors.New("no router endpoints: ziroctl router endpoints set <host:port>")
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	m := findMoon(routerOf(st), name)
	m.TokenHash, m.TokenExpires = hashToken(secret), time.Now().Add(ttl).UTC()
	return zr.MoonToken{Endpoints: eps, Pin: pin, Name: name, Secret: secret}.String(), nil
}

func validMoonTTL(d time.Duration) error {
	if d < time.Minute || d > 7*24*time.Hour {
		return errors.New("--token-ttl must be 1m to 168h")
	}
	return nil
}

var routerMoonAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a moon and print its one-time registration token",
	Example: `  ziroctl router moon add sg-1 --public relay-sg.example.com:8443
  ziroctl router moon add fra-1 --public 203.0.113.7:443 --stun-port 3478`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		name := args[0]
		if err := validLabel(name); err != nil {
			return err
		}
		h, p, err := net.SplitHostPort(moonPublic)
		if err != nil || h == "" || !validPortNum(p) || !(validHost(h) || net.ParseIP(h) != nil) {
			return fmt.Errorf("--public must be the host:port devices dial (got %q)", moonPublic)
		}
		if moonSTUNPort < 1 || moonSTUNPort > 65535 {
			return errors.New("invalid --stun-port")
		}
		if err := validMoonTTL(moonTTLFlag); err != nil {
			return err
		}
		var tok string
		err = withState(func(st *ClusterState) error {
			R := routerOf(st)
			for _, r := range R.Relays {
				if r.Name == name {
					return fmt.Errorf("a relay named %q exists", name)
				}
			}
			R.Relays = append(R.Relays, zr.Relay{Name: name, Addr: moonPublic,
				STUN: net.JoinHostPort(h, strconv.Itoa(moonSTUNPort)), ServerName: zr.MoonServerName(name)})
			R.Moons = append(R.Moons, zr.Moon{Name: name, CreatedAt: time.Now().UTC()})
			var e error
			tok, e = moonToken(st, cfg, name, moonTTLFlag)
			return e
		})
		clusterAudit("cli", "router moon add", name, err)
		if err != nil {
			return err
		}
		return printResult(map[string]string{"name": name, "token": tok}, func() {
			fmt.Printf("✓ moon %s added; devices will use it once it registers. Token (shown once, valid %s):\n%s\n\n", name, moonTTLFlag, tok)
			fmt.Printf("On the moon:  ZIROCD_MOON_TOKEN=%s... zirocd moon   (or: ziroctl router moon join --token-file f)\n", tok[:12])
		})
	},
}

var routerMoonTokenCmd = &cobra.Command{
	Use:     "token <name>",
	Short:   "Issue a new registration token for a moon",
	Example: "  ziroctl router moon token sg-1",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		if err := validMoonTTL(moonTTLFlag); err != nil {
			return err
		}
		var tok string
		err = withState(func(st *ClusterState) error {
			if findMoon(routerOf(st), args[0]) == nil {
				return fmt.Errorf("no moon %q", args[0])
			}
			var e error
			tok, e = moonToken(st, cfg, args[0], moonTTLFlag)
			return e
		})
		clusterAudit("cli", "router moon token", args[0], err)
		if err != nil {
			return err
		}
		return printResult(map[string]string{"name": args[0], "token": tok}, func() { fmt.Println(tok) })
	},
}

var routerMoonRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Remove a moon: its relay map ends and devices stop using it", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router moon rm sg-1",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		err := withState(func(st *ClusterState) error {
			R := routerOf(st)
			if findMoon(R, args[0]) == nil {
				return fmt.Errorf("no moon %q", args[0])
			}
			var moons []zr.Moon
			for _, m := range R.Moons {
				if m.Name != args[0] {
					moons = append(moons, m)
				}
			}
			var relays []zr.Relay
			for _, r := range R.Relays {
				if r.Name != args[0] {
					relays = append(relays, r)
				}
			}
			R.Moons, R.Relays = moons, relays
			return nil
		})
		clusterAudit("cli", "router moon rm", args[0], err)
		if err != nil {
			return err
		}
		fmt.Printf("✓ moon %s removed; devices stop using it within a second\n", args[0])
		return nil
	},
}

var routerMoonLsCmd = &cobra.Command{
	Use: "ls", Short: "List moons", Example: "  ziroctl router moon ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		var connected map[string]bool
		_, _ = socketCall(http.MethodGet, "/router/moons", nil, &connected)
		type row struct {
			Name      string `json:"name"`
			Addr      string `json:"addr"`
			Status    string `json:"status"`
			Connected bool   `json:"connected_here"`
		}
		var rows []row
		R := routerOf(st)
		for _, m := range R.Moons {
			rw := row{Name: m.Name, Status: "registered", Connected: connected[m.Name]}
			for _, r := range R.Relays {
				if r.Name == m.Name {
					rw.Addr = r.Addr
				}
			}
			if m.KeyHash == "" {
				rw.Status = "waiting for registration"
				if !m.TokenExpires.IsZero() && time.Now().After(m.TokenExpires) {
					rw.Status = "token expired (ziroctl router moon token " + m.Name + ")"
				}
			}
			rows = append(rows, rw)
		}
		return printResult(rows, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tADDRESS\tSTATUS\tON THIS PLANET")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\n", r.Name, r.Addr, r.Status, r.Connected)
			}
			tw.Flush()
		})
	},
}

var routerMoonJoinCmd = &cobra.Command{
	Use:   "join",
	Short: "Run this host as a moon",
	Example: `  ziroctl router moon join --token-file /root/sg-1.token
  ZIROCD_MOON_TOKEN=zm1_... ziroctl router moon join --listen :443`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		tok := os.Getenv("ZIROCD_MOON_TOKEN")
		if moonJoinFile != "" {
			b, err := os.ReadFile(moonJoinFile)
			if err != nil {
				return err
			}
			tok = string(b)
		}
		if _, err := zr.ParseMoonToken(tok); err != nil {
			return err
		}
		if _, err := os.Stat(zirocdBin); err != nil {
			return fmt.Errorf("%s missing: this image predates moons (ziroctl update)", zirocdBin)
		}
		lport, err := listenPort(moonListen)
		if err != nil || moonSTUNPort < 1 || moonSTUNPort > 65535 {
			return errors.New("invalid --listen or --stun-port")
		}
		// Register in the foreground (errors show here), then run as a service.
		if err := zirocd([]string{"ZIROCD_MOON_TOKEN=" + tok}, "moon", "--dir", moonStateDir, "--listen", moonListen,
			"--stun-port", strconv.Itoa(moonSTUNPort), "--register-only"); err != nil {
			return err
		}
		allowFirewall([]FirewallRule{{Port: lport, Protocol: "tcp", Comment: "Ziro moon (relay TLS)"},
			{Port: moonSTUNPort, Protocol: "udp", Comment: "Ziro moon (relay UDP + STUN)"}}, "")
		startClusterServices("router-moon")
		fmt.Println("✓ moon registered and running (ziroctl service status router-moon)")
		return nil
	},
}

func init() {
	routerMoonAddCmd.Flags().StringVar(&moonPublic, "public", "", "host:port devices dial (required)")
	for _, c := range []*cobra.Command{routerMoonAddCmd, routerMoonJoinCmd} {
		c.Flags().IntVar(&moonSTUNPort, "stun-port", 3478, "UDP port for relayed datagrams and STUN")
	}
	for _, c := range []*cobra.Command{routerMoonAddCmd, routerMoonTokenCmd} {
		c.Flags().DurationVar(&moonTTLFlag, "token-ttl", moonTokenTTL, "how long the registration token is valid")
	}
	routerMoonJoinCmd.Flags().StringVar(&moonJoinFile, "token-file", "", "file holding the zm1_ token")
	routerMoonJoinCmd.Flags().StringVar(&moonListen, "listen", ":8443", "TLS listen address")
	routerMoonCmd.AddCommand(routerMoonAddCmd, routerMoonTokenCmd, routerMoonRmCmd, routerMoonLsCmd, routerMoonJoinCmd)
	routerCmd.AddCommand(routerMoonCmd)
}

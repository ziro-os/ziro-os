// Package moon runs a Ziro moon: a regional router relay on any Linux host or container. It
// registers once with a token from `ziroctl router moon add`, follows the relay map from the
// nearest planet, and relays WireGuard ciphertext between the devices of each network. It never
// needs inbound access to the planets, holds no cluster state, and fails closed: removed from
// the cluster, or cut off from every planet for 5 minutes, it stops relaying.
package moon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/zirocd/relay"
)

const (
	renewBefore = 3 * 24 * time.Hour // moon certificates last 7 days
	staleAfter  = 5 * time.Minute    // no planet for this long: stop relaying (fail closed)
	stateFile   = "moon.json"
)

// ErrRemoved: the cluster removed this moon (or registered it again elsewhere).
var ErrRemoved = errors.New("this moon was removed from the cluster (ziroctl router moon token <name> to register it again)")

// Options configure a moon. Listen, STUN port and rates given at registration are saved, so the
// service can run with just Dir.
type Options struct {
	Dir           string
	Token         string // zm1_..., needed only to register
	Listen        string // TLS address (default :8443)
	STUNPort      int    // UDP port for relayed datagrams and STUN (default 3478)
	RateMbps      int    // per device (default 1000)
	MaxMbps       int    // whole relay (default 10000)
	MetricsListen string // e.g. 127.0.0.1:9102: /healthz, /readyz, /metrics (off when empty)
	RegisterOnly  bool
}

type state struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
	CA        string   `json:"ca"`
	Cert      string   `json:"cert"`
	Key       string   `json:"key"`
	Listen    string   `json:"listen"`
	STUNPort  int      `json:"stun_port"`
	RateMbps  int      `json:"rate_mbps,omitempty"`
	MaxMbps   int      `json:"max_mbps,omitempty"`
	Metrics   string   `json:"metrics_listen,omitempty"`
}

func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	return &st, json.Unmarshal(b, &st)
}

func saveState(dir string, st *state) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// Run registers the moon if needed and relays until ctx ends or the moon is removed.
func Run(ctx context.Context, o Options) error {
	st, err := loadState(o.Dir)
	if err != nil {
		return err
	}
	if st == nil || o.Token != "" {
		if o.Token == "" {
			return errors.New("not registered: give the token (ZIROCD_MOON_TOKEN=zm1_... or --token-file)")
		}
		if st, err = register(ctx, o.Token); err != nil {
			return err
		}
		log.Printf("moon %s registered", st.Name)
	}
	if o.Listen != "" {
		st.Listen = o.Listen
	}
	if o.STUNPort != 0 {
		st.STUNPort = o.STUNPort
	}
	if o.RateMbps != 0 {
		st.RateMbps = o.RateMbps
	}
	if o.MaxMbps != 0 {
		st.MaxMbps = o.MaxMbps
	}
	if o.MetricsListen != "" {
		st.Metrics = o.MetricsListen
	}
	st.Listen = cmpOr(st.Listen, ":8443")
	if st.STUNPort == 0 {
		st.STUNPort = 3478
	}
	if err := saveState(o.Dir, st); err != nil {
		return err
	}
	if o.RegisterOnly {
		return nil
	}
	m, err := newMoon(o.Dir, st)
	if err != nil {
		return err
	}
	return m.run(ctx)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// register consumes the token: the planets certify a key generated here.
func register(ctx context.Context, token string) (*state, error) {
	t, err := zr.ParseMoonToken(token)
	if err != nil {
		return nil, err
	}
	var ca *x509.Certificate
	var last error
	for _, ep := range t.Endpoints {
		if ca, last = zr.PinCA(ctx, ep, t.Pin); last == nil {
			break
		}
	}
	if ca == nil {
		return nil, fmt.Errorf("reach a planet: %w", last)
	}
	keyPEM, csr, err := zr.NewTLSKey()
	if err != nil {
		return nil, err
	}
	resp, err := zr.NewClient(t.Endpoints, ca, nil).MoonRegister(ctx, zr.MoonRegisterRequest{Name: t.Name, Secret: t.Secret, CSR: string(csr)})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return &state{Name: t.Name, Endpoints: t.Endpoints, CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		Cert: resp.Cert, Key: string(keyPEM)}, nil
}

type moon struct {
	dir    string
	st     *state
	ca     *x509.Certificate
	cert   atomic.Pointer[tls.Certificate]
	client *zr.Client
	relay  *relay.Server

	mu       sync.Mutex
	members  map[string]zr.RelayMember
	synced   time.Time // last relay map message
	streamUp bool
}

func newMoon(dir string, st *state) (*moon, error) {
	b, _ := pem.Decode([]byte(st.CA))
	if b == nil {
		return nil, errors.New("moon state: no CA")
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair([]byte(st.Cert), []byte(st.Key))
	if err != nil {
		return nil, err
	}
	m := &moon{dir: dir, st: st, ca: ca, relay: relay.New(), members: map[string]zr.RelayMember{}}
	m.cert.Store(&c)
	m.client = zr.NewClient(st.Endpoints, ca, &c)
	m.relay.SetRates(cmpInt(st.RateMbps, relay.DefaultRateMbps), cmpInt(st.MaxMbps, relay.DefaultMaxMbps))
	return m, nil
}

func cmpInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func (m *moon) run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	pool := x509.NewCertPool()
	pool.AddCert(m.ca)
	ln, err := tls.Listen("tcp", m.st.Listen, &tls.Config{MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.cert.Load(), nil }})
	if err != nil {
		return err
	}
	if m.st.Metrics != "" {
		go m.serveMetrics(ctx)
	}
	go m.follow(ctx, cancel)
	go m.renewLoop(ctx)
	go m.watchStale(ctx)
	log.Printf("moon %s relaying on %s (TLS) and udp/%d", m.st.Name, m.st.Listen, m.st.STUNPort)
	err = m.relay.Serve(ctx, ln, ":"+strconv.Itoa(m.st.STUNPort))
	if cause := context.Cause(ctx); errors.Is(cause, ErrRemoved) {
		return cause
	}
	return err
}

// follow keeps the relay map stream open, on the nearest planet that answers.
func (m *moon) follow(ctx context.Context, cancel context.CancelCauseFunc) {
	backoff := time.Second
	var probed time.Time
	for ctx.Err() == nil {
		if time.Since(probed) > 10*time.Minute {
			m.client.Nearest(ctx)
			probed = time.Now()
		}
		err := m.client.RelayMap(ctx, func(msg zr.RelayMapMessage) error {
			m.apply(msg)
			backoff = time.Second
			return nil
		})
		m.setUp(false)
		var se *zr.StatusError
		if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
			m.relay.SetMembers(map[string]relay.Member{})
			log.Printf("moon: %v", ErrRemoved)
			cancel(ErrRemoved)
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("moon: relay map: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + rand.N(backoff)):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (m *moon) setUp(up bool) {
	m.mu.Lock()
	m.streamUp = up
	m.mu.Unlock()
}

// apply updates the member set from one relay map message.
func (m *moon) apply(msg zr.RelayMapMessage) {
	m.mu.Lock()
	if msg.Type == "full" {
		m.members = map[string]zr.RelayMember{}
	}
	for _, rm := range msg.Members {
		m.members[rm.ID] = rm
	}
	for _, id := range msg.Removed {
		delete(m.members, id)
	}
	set := make(map[string]relay.Member, len(m.members))
	for id, rm := range m.members {
		k, err := base64.StdEncoding.DecodeString(rm.NodeKey)
		if err != nil || len(k) != 32 {
			continue
		}
		set[id] = relay.Member{KeyHash: rm.KeyHash, NodeKey: [32]byte(k), Network: rm.Network}
	}
	m.synced, m.streamUp = time.Now(), true
	m.mu.Unlock()
	m.relay.SetMembers(set)
}

// watchStale stops relaying when no planet has been reachable for staleAfter: a moon cut off
// from the cluster can't learn revocations, so it must not keep forwarding on old membership.
func (m *moon) watchStale(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	cleared := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.mu.Lock()
		stale := !m.streamUp && time.Since(m.synced) > staleAfter
		if stale && !cleared {
			m.members = map[string]zr.RelayMember{}
		}
		m.mu.Unlock()
		if stale && !cleared {
			log.Printf("moon: no planet for %s: relaying stopped until the relay map is back", staleAfter)
			m.relay.SetMembers(map[string]relay.Member{})
		}
		cleared = stale
	}
}

// renewLoop renews the certificate (same key) when it is within renewBefore of expiry.
func (m *moon) renewLoop(ctx context.Context) {
	for {
		if exp := m.cert.Load().Leaf; exp != nil && time.Until(exp.NotAfter) < renewBefore {
			if err := m.renew(ctx); err != nil {
				log.Printf("moon: renew certificate: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func (m *moon) renew(ctx context.Context) error {
	csr, err := zr.CSR([]byte(m.st.Key))
	if err != nil {
		return err
	}
	resp, err := m.client.MoonRenew(ctx, csr)
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair([]byte(resp.Cert), []byte(m.st.Key))
	if err != nil {
		return err
	}
	m.st.Cert = resp.Cert
	if err := saveState(m.dir, m.st); err != nil {
		return err
	}
	m.cert.Store(&c)
	m.client.SetCert(&c)
	return nil
}

// serveMetrics: /healthz (process up), /readyz (relay map loaded and fresh), /metrics.
func (m *moon) serveMetrics(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		ready := !m.synced.IsZero() && (m.streamUp || time.Since(m.synced) < staleAfter)
		m.mu.Unlock()
		if !ready {
			http.Error(w, "relay map not loaded", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(m.metrics()))
	})
	srv := &http.Server{Addr: m.st.Metrics, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("moon: metrics: %v", err)
	}
}

func (m *moon) metrics() string {
	s := m.relay.Stats()
	m.mu.Lock()
	up := m.streamUp
	m.mu.Unlock()
	var exp float64
	if l := m.cert.Load().Leaf; l != nil {
		exp = time.Until(l.NotAfter).Seconds()
	}
	b2f := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	return fmt.Sprintf(`# HELP ziro_moon_members Devices allowed on this moon (relay map).
# TYPE ziro_moon_members gauge
ziro_moon_members %d
# HELP ziro_moon_connected Devices connected (TLS).
# TYPE ziro_moon_connected gauge
ziro_moon_connected %d
# HELP ziro_moon_udp_sessions Connected devices with a bound UDP session.
# TYPE ziro_moon_udp_sessions gauge
ziro_moon_udp_sessions %d
# HELP ziro_moon_dropped_total Packets refused (limits, wrong network, spoofed source).
# TYPE ziro_moon_dropped_total counter
ziro_moon_dropped_total %d
# HELP ziro_moon_relayed_bytes_total Bytes relayed.
# TYPE ziro_moon_relayed_bytes_total counter
ziro_moon_relayed_bytes_total %d
# HELP ziro_moon_relaymap_up The relay map stream from a planet is up.
# TYPE ziro_moon_relaymap_up gauge
ziro_moon_relaymap_up %d
# HELP ziro_moon_cert_expiry_seconds Seconds until the moon certificate expires.
# TYPE ziro_moon_cert_expiry_seconds gauge
ziro_moon_cert_expiry_seconds %.0f
`, s.Members, s.Connected, s.UDPSessions, s.Dropped, s.Relayed, b2f(up), exp)
}

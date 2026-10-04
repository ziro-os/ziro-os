// Package relay is the Ziro router relay, run by planets (`ziroctl router relay enable`) and by
// moons (`zirocd moon`). A device that cannot reach a peer directly (both behind hard NATs)
// sends its WireGuard packets to a relay the peer is connected to, which hands them on.
//
// Every device holds a TLS connection (authentication, session setup, and the transport of last
// resort where UDP is blocked) and, normally, a UDP session on the same relay (udp.go): relayed
// traffic then flows as plain datagrams, with no TCP head-of-line latency. A relay only sees
// WireGuard ciphertext, only connects devices of the same network, takes a sender's identity
// from its certificate or session (never from a packet), and drops a device as soon as it leaves
// the member set. It also answers STUN.
package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	DefaultRateMbps = 1000  // per-device sustained rate
	DefaultMaxMbps  = 10000 // relay-wide rate

	queueLen    = 128             // frames buffered per receiving device (TLS path): up to 8 MiB of burst
	burstBytes  = 4 << 20         // per-device burst
	idleTimeout = 2 * time.Minute // no frame (keepalives included) for this long: close
)

// Member is a device (or cluster node) allowed on the relay.
type Member struct {
	KeyHash string   // sha256 of its certificate's public key
	NodeKey [32]byte // WireGuard public key: what peers address it by
	Network string   // relaying happens only within one network
}

type client struct {
	member  string
	network string
	key     [32]byte
	rc      *zr.RelayConn
	out     chan []byte // encoded frames to write
	done    chan struct{}
	once    sync.Once
	bucket  byteBucket

	session uint32
	skey    [32]byte
	udp     atomic.Pointer[udpBinding] // set by a valid UDP hello
}

// udpBinding is where a device's UDP session lives (its NAT mapping towards the relay).
type udpBinding struct {
	addr netip.AddrPort
	ep   conn.Endpoint // for sends
	ms   uint64        // timestamp of the hello that bound it (replays must be newer)
	seen time.Time
}

// byteBucket limits bytes per second; the TLS reader and the UDP loop share a device's bucket.
type byteBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // bytes/s
	burst  float64
}

func newByteBucket(rate, burst float64) byteBucket {
	return byteBucket{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}

func (b *byteBucket) allow(n int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*b.rate, b.burst)
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

func (c *client) close() { c.once.Do(func() { close(c.done); c.rc.Close() }) }

// Server is one relay. Feed it the member set with SetMembers before and while serving.
type Server struct {
	// Reload, if set, is called (at most once a second) when an unknown device connects: a
	// device that joined since the member set was last fed. It should call SetMembers.
	Reload func()

	rate   float64    // per-device bytes/s
	global byteBucket // relay-wide
	udp    conn.Bind  // UDP port: relayed datagrams + STUN

	reloadMu   sync.Mutex
	lastReload time.Time

	mu       sync.RWMutex
	members  map[string]Member    // member ID -> identity
	byKey    map[[32]byte]*client // connected devices
	sessions map[uint32]*client   // UDP sessions
	dropped  uint64
	relayed  atomic.Uint64 // bytes forwarded
}

func New() *Server {
	s := &Server{members: map[string]Member{}, byKey: map[[32]byte]*client{}, sessions: map[uint32]*client{}}
	s.SetRates(DefaultRateMbps, DefaultMaxMbps)
	return s
}

// SetRates sets the per-device and relay-wide limits (Mbit/s). Call before serving.
func (s *Server) SetRates(perDevice, total int) {
	s.rate = float64(perDevice) * 1e6 / 8
	s.global = newByteBucket(float64(total)*1e6/8, 64<<20)
}

// SetMembers replaces the member set and disconnects devices that left or were re-keyed.
func (s *Server) SetMembers(m map[string]Member) {
	s.mu.Lock()
	s.members = m
	var gone []*client
	for k, c := range s.byKey {
		if cur, ok := m[c.member]; !ok || cur.NodeKey != k {
			gone = append(gone, c)
			delete(s.byKey, k)
		}
	}
	s.mu.Unlock()
	for _, c := range gone {
		c.close()
	}
}

// Stats is what a relay reports (metrics, `ziroctl router relay ls`).
type Stats struct {
	Members     int    `json:"members"`
	Connected   int    `json:"connected"`    // devices with a TLS connection
	UDPSessions int    `json:"udp_sessions"` // of those, with a bound UDP session
	Dropped     uint64 `json:"dropped"`      // packets refused (limits, wrong network, spoofed source)
	Relayed     uint64 `json:"relayed_bytes"`
}

func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Members: len(s.members), Connected: len(s.byKey), Dropped: s.dropped, Relayed: s.relayed.Load()}
	for _, c := range s.byKey {
		if b := c.udp.Load(); b != nil && time.Since(b.seen) < udpBindingTTL {
			st.UDPSessions++
		}
	}
	return st
}

// Identify returns the member ID and key hash a verified client certificate stands for: a router
// device (OU ziro-device) or a cluster node (OU ziro-node, member "node:<id>").
func Identify(cs *tls.ConnectionState) (id, keyHash string, ok bool) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return "", "", false
	}
	c := cs.PeerCertificates[0]
	if len(c.Subject.OrganizationalUnit) != 1 || c.Subject.CommonName == "" {
		return "", "", false
	}
	switch c.Subject.OrganizationalUnit[0] {
	case zr.DeviceOU:
		return c.Subject.CommonName, zr.PublicKeyHash(c.RawSubjectPublicKeyInfo), true
	case zr.NodeOU:
		return "node:" + c.Subject.CommonName, zr.PublicKeyHash(c.RawSubjectPublicKeyInfo), true
	}
	return "", "", false
}

func (s *Server) lookup(id string) (Member, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.members[id]
	return m, ok
}

// serveConn runs one device connection until it closes.
func (s *Server) serveConn(conn *tls.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	cs := conn.ConnectionState()
	id, kh, ok := Identify(&cs)
	m, known := s.lookup(id)
	if ok && !known && s.Reload != nil && s.reloadDue() { // a device that joined since the last load
		s.Reload()
		m, known = s.lookup(id)
	}
	if !ok || !known || subtle.ConstantTimeCompare([]byte(m.KeyHash), []byte(kh)) != 1 {
		return
	}
	c := &client{member: id, network: m.Network, key: m.NodeKey, rc: zr.NewRelayConn(conn),
		out: make(chan []byte, queueLen), done: make(chan struct{}), bucket: newByteBucket(s.rate, burstBytes)}
	_, _ = rand.Read(c.skey[:])
	s.mu.Lock()
	if old := s.byKey[c.key]; old != nil {
		old.close() // the newest connection of a device wins
	}
	s.byKey[c.key] = c
	for c.session == 0 || s.sessions[c.session] != nil {
		var b [4]byte
		_, _ = rand.Read(b[:])
		c.session = binary.BigEndian.Uint32(b[:])
	}
	s.sessions[c.session] = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.byKey[c.key] == c {
			delete(s.byKey, c.key)
		}
		delete(s.sessions, c.session)
		s.mu.Unlock()
		c.close()
	}()
	// The UDP session: its ID and key travel only inside this authenticated TLS connection.
	if c.rc.WriteFrame(zr.FrameSession, nil, zr.SessionFrame(c.session, c.skey)) != nil {
		return
	}

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
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		typ, dst, payload, err := c.rc.ReadFrame()
		if err != nil {
			return
		}
		if typ != zr.FrameSend {
			continue
		}
		if to, ok := s.route(c, dst, len(payload)); ok {
			s.deliver(c, to, payload)
		}
	}
}

// reloadDue allows an on-demand reload at most once a second (unknown devices cannot make the
// relay hammer its source).
func (s *Server) reloadDue() bool {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if time.Since(s.lastReload) < time.Second {
		return false
	}
	s.lastReload = time.Now()
	return true
}

func (s *Server) drop() {
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

// Serve accepts device connections on ln (a TLS listener that requires and verifies client
// certificates) and serves STUN and UDP relaying on udpAddr, until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener, udpAddr string) error {
	if err := s.listenUDP(udpAddr); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		s.closeUDP()
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
		tc, ok := c.(*tls.Conn)
		if !ok {
			c.Close()
			continue
		}
		go s.serveConn(tc)
	}
}

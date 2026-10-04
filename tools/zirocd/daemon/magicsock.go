package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/conn"
)

// MagicBind is the WireGuard socket layer. One UDP socket (wireguard-go's batched StdNetBind)
// carries three kinds of packets:
//
//   - WireGuard packets;
//   - disco ping/pong, NaCl-boxed between the two devices' disco keys, used to find and keep a
//     direct path (both sides ping each other's candidate endpoints at once: hole punching);
//   - STUN, to learn this device's public address from the relays.
//
// WireGuard addresses peers as "zrpeer:<key>". Send uses the direct path while the last pong on
// it is fresh, and the peer's home relay (TLS) otherwise, so traffic always flows while a direct
// path is being found.

const (
	discoMagic      = "ZRD1"
	discoHeader     = 4 + 32 + 24
	pingPong        = 1
	pongMsg         = 2
	trustBest       = 7 * time.Second // a direct path stays in use this long after a pong
	pingEvery       = 2 * time.Second
	callMeEvery     = 5 * time.Second // relayed pings ask the peer to punch towards us
	activeWindow    = 10 * time.Second
	stunEvery       = 20 * time.Second
	maxCandidates   = 16
	relayIdle       = 2 * time.Minute
	wgKeepaliveSize = 32 // an empty WireGuard transport message: not real traffic
)

type peerEP struct{ p *mpeer }

func (e *peerEP) ClearSrc()           {}
func (e *peerEP) SrcToString() string { return "" }
func (e *peerEP) DstToString() string { return "zrpeer:" + hex.EncodeToString(e.p.key[:]) }
func (e *peerEP) DstToBytes() []byte  { return e.p.key[:] }
func (e *peerEP) DstIP() netip.Addr   { return netip.Addr{} }
func (e *peerEP) SrcIP() netip.Addr   { return netip.Addr{} }

type pingSent struct {
	to       netip.AddrPort // zero: sent through the relay
	at       time.Time
	viaRelay bool
}

type mpeer struct {
	key, disco [32]byte
	shared     [32]byte
	name, home string
	cands      []netip.AddrPort
	learned    []netip.AddrPort // sources of pings it sent us
	best       netip.AddrPort
	bestUntil  time.Time
	rtt        time.Duration
	lastSend   time.Time
	lastPing   time.Time
	lastCallMe time.Time
	pings      map[[12]byte]pingSent
	ep         *peerEP
}

type relayPkt struct {
	from [32]byte
	data []byte
}

type stunProbe struct {
	relay string
	at    time.Time
}

// RelayAuth supplies what relay connections need: the router CA and this device's certificate.
type RelayAuth func() (*x509.Certificate, *tls.Certificate)

type MagicBind struct {
	std       conn.Bind
	discoPriv [32]byte
	discoPub  [32]byte
	auth      RelayAuth
	onChange  func() // public endpoints or home relay changed

	mu       sync.RWMutex
	peers    map[[32]byte]*mpeer
	byDisco  map[[32]byte]*mpeer
	byAddr   map[netip.AddrPort]*mpeer
	stdEPs   map[netip.AddrPort]conn.Endpoint
	relays   []zr.Relay
	links    map[string]*relayLink
	home     string
	stun     map[[12]byte]stunProbe
	mapped   map[string]netip.AddrPort
	stunRTT  map[string]time.Duration
	open     bool
	recv     chan relayPkt
	closed   chan struct{}
	kick     chan *mpeer
	stopLoop context.CancelFunc
	pings    atomic.Uint64 // disco pings sent (tests guard against ping storms)
	overlay  atomic.Pointer[[]netip.Prefix]
}

// SetOverlay is the set of prefixes routed through the tunnel (the network and approved subnet
// routes). An underlay address inside it is never used: WireGuard packets sent there would be
// routed back into WireGuard (a subnet router's own LAN address, for example).
func (b *MagicBind) SetOverlay(ps []netip.Prefix) {
	cp := append([]netip.Prefix(nil), ps...)
	b.overlay.Store(&cp)
}

func (b *MagicBind) underlay(a netip.AddrPort) bool {
	if ps := b.overlay.Load(); ps != nil {
		for _, p := range *ps {
			if p.Contains(a.Addr()) {
				return false
			}
		}
	}
	return a.IsValid()
}

func NewMagicBind(discoPrivB64 string, auth RelayAuth, onChange func()) (*MagicBind, error) {
	k, err := base64.StdEncoding.DecodeString(discoPrivB64)
	if err != nil || len(k) != 32 {
		return nil, errors.New("invalid disco key")
	}
	b := &MagicBind{std: conn.NewDefaultBind(), auth: auth, onChange: onChange,
		peers: map[[32]byte]*mpeer{}, byDisco: map[[32]byte]*mpeer{}, byAddr: map[netip.AddrPort]*mpeer{},
		stdEPs: map[netip.AddrPort]conn.Endpoint{}, links: map[string]*relayLink{}, stun: map[[12]byte]stunProbe{},
		mapped: map[string]netip.AddrPort{}, stunRTT: map[string]time.Duration{}, kick: make(chan *mpeer, 256)}
	copy(b.discoPriv[:], k)
	pub, err := publicOf(discoPrivB64)
	if err != nil {
		return nil, err
	}
	pk, _ := base64.StdEncoding.DecodeString(pub)
	copy(b.discoPub[:], pk)
	return b, nil
}

// ---- conn.Bind ----

func (b *MagicBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.std.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	b.open, b.recv, b.closed = true, make(chan relayPkt, 1024), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	b.stopLoop = cancel
	closed := b.closed
	recv := b.recv
	b.mu.Unlock()
	out := make([]conn.ReceiveFunc, 0, len(fns)+1)
	for _, fn := range fns {
		out = append(out, b.wrapRecv(fn))
	}
	out = append(out, b.relayRecv(recv, closed))
	go b.loop(ctx)
	return out, actual, nil
}

func (b *MagicBind) Close() error {
	b.mu.Lock()
	if b.open {
		b.open = false
		close(b.closed)
		b.stopLoop()
	}
	links := b.links
	b.links = map[string]*relayLink{}
	b.mu.Unlock()
	for _, l := range links {
		l.close()
	}
	return b.std.Close()
}

func (b *MagicBind) SetMark(mark uint32) error { return b.std.SetMark(mark) }
func (b *MagicBind) BatchSize() int            { return b.std.BatchSize() }

func (b *MagicBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if h, ok := strings.CutPrefix(s, "zrpeer:"); ok {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("invalid peer endpoint")
		}
		var k [32]byte
		copy(k[:], raw)
		b.mu.RLock()
		p := b.peers[k]
		b.mu.RUnlock()
		if p == nil {
			return nil, errors.New("unknown peer")
		}
		return p.ep, nil
	}
	return b.std.ParseEndpoint(s)
}

func addrOf(ep conn.Endpoint) netip.AddrPort {
	if s, ok := ep.(*conn.StdNetEndpoint); ok {
		return netip.AddrPortFrom(s.AddrPort.Addr().Unmap(), s.AddrPort.Port())
	}
	ap, _ := netip.ParseAddrPort(ep.DstToString())
	return ap
}

// wrapRecv takes STUN and disco packets out of a UDP batch and labels WireGuard packets from a
// known direct path with their peer. wireguard-go reads packets from its own buffer array, so
// kept packets are copied down rather than reordered.
func (b *MagicBind) wrapRecv(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			j := 0
			for i := 0; i < n; i++ {
				pkt := bufs[i][:sizes[i]]
				src := addrOf(eps[i])
				switch {
				case zr.IsSTUN(pkt):
					b.handleSTUN(pkt)
					continue
				case isDisco(pkt):
					b.handleDisco(pkt, src, nil)
					continue
				}
				b.mu.RLock()
				p := b.byAddr[src]
				b.mu.RUnlock()
				if p != nil {
					eps[i] = p.ep
				}
				if j != i {
					sizes[j] = copy(bufs[j], pkt)
					eps[j] = eps[i]
				}
				j++
			}
			if j > 0 {
				return j, nil
			}
		}
	}
}

// relayRecv hands WireGuard packets that arrived over relays to wireguard-go.
func (b *MagicBind) relayRecv(recv chan relayPkt, closed chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n := 0
		put := func(pk relayPkt) {
			b.mu.RLock()
			p := b.peers[pk.from]
			b.mu.RUnlock()
			if p == nil {
				return
			}
			sizes[n] = copy(bufs[n], pk.data)
			eps[n] = p.ep
			n++
		}
		for n == 0 {
			select {
			case <-closed:
				return 0, net.ErrClosed
			case pk := <-recv:
				put(pk)
			}
		}
		for n < len(bufs) {
			select {
			case pk := <-recv:
				put(pk)
			default:
				return n, nil
			}
		}
		return n, nil
	}
}

func (b *MagicBind) stdEP(a netip.AddrPort) (conn.Endpoint, error) {
	b.mu.RLock()
	ep := b.stdEPs[a]
	b.mu.RUnlock()
	if ep != nil {
		return ep, nil
	}
	ep, err := b.std.ParseEndpoint(a.String())
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if len(b.stdEPs) > 4096 {
		b.stdEPs = map[netip.AddrPort]conn.Endpoint{}
	}
	b.stdEPs[a] = ep
	b.mu.Unlock()
	return ep, nil
}

func (b *MagicBind) sendUDP(a netip.AddrPort, pkt []byte) error {
	ep, err := b.stdEP(a)
	if err != nil {
		return err
	}
	return b.std.Send([][]byte{pkt}, ep)
}

func (b *MagicBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	pe, ok := ep.(*peerEP)
	if !ok {
		return b.std.Send(bufs, ep)
	}
	p, now := pe.p, time.Now()
	active := false
	for _, buf := range bufs {
		if len(buf) > wgKeepaliveSize {
			active = true
			break
		}
	}
	b.mu.Lock()
	if active {
		p.lastSend = now
	}
	best, valid := p.best, now.Before(p.bestUntil)
	needPing := active && (!valid || p.bestUntil.Sub(now) < 3*time.Second) && now.Sub(p.lastPing) >= pingEvery
	home := p.home
	b.mu.Unlock()
	if needPing {
		select {
		case b.kick <- p:
		default:
		}
	}
	if valid {
		dst, err := b.stdEP(best)
		if err != nil {
			return err
		}
		return b.std.Send(bufs, dst)
	}
	l := b.link(home)
	if l == nil {
		return nil // no path yet: WireGuard retransmits its handshake
	}
	for _, buf := range bufs {
		l.send(p.key, buf)
	}
	return nil
}

// ---- disco ----

func isDisco(b []byte) bool {
	return len(b) >= discoHeader+box.Overhead+13 && string(b[:4]) == discoMagic
}

func (b *MagicBind) seal(p *mpeer, msg []byte) []byte {
	var nonce [24]byte
	_, _ = rand.Read(nonce[:])
	out := make([]byte, 0, discoHeader+len(msg)+box.Overhead)
	out = append(out, discoMagic...)
	out = append(out, b.discoPub[:]...)
	out = append(out, nonce[:]...)
	return box.SealAfterPrecomputation(out, msg, &nonce, &p.shared)
}

func encodeAddrPort(a netip.AddrPort) []byte {
	ip := a.Addr().As16()
	return append(ip[:], byte(a.Port()>>8), byte(a.Port()))
}

// sendPing pings p at addr, or through its home relay when addr is zero.
func (b *MagicBind) sendPing(p *mpeer, to netip.AddrPort) {
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	b.mu.Lock()
	if len(p.pings) >= 256 { // bounded; the maintenance loop expires entries after 10s
		b.mu.Unlock()
		return
	}
	p.pings[tx] = pingSent{to: to, at: time.Now(), viaRelay: !to.IsValid()}
	home := p.home
	b.mu.Unlock()
	b.pings.Add(1)
	pkt := b.seal(p, append([]byte{pingPong}, tx[:]...))
	if to.IsValid() {
		_ = b.sendUDP(to, pkt)
	} else if l := b.link(home); l != nil {
		l.send(p.key, pkt)
	}
}

// handleDisco processes a ping or pong from src (direct) or relayed from the WireGuard key from.
func (b *MagicBind) handleDisco(pkt []byte, src netip.AddrPort, from *[32]byte) {
	var sender [32]byte
	copy(sender[:], pkt[4:36])
	var nonce [24]byte
	copy(nonce[:], pkt[36:60])
	b.mu.RLock()
	p := b.byDisco[sender]
	b.mu.RUnlock()
	if p == nil || (from != nil && *from != p.key) { // a relayed packet must come from that peer's key
		return
	}
	if from == nil && !b.underlay(src) { // arrived through our own tunnel: never a path
		return
	}
	msg, ok := box.OpenAfterPrecomputation(nil, pkt[discoHeader:], &nonce, &p.shared)
	if !ok || len(msg) < 13 {
		return
	}
	var tx [12]byte
	copy(tx[:], msg[1:13])
	now := time.Now()
	switch msg[0] {
	case pingPong:
		reply := b.seal(p, append(append([]byte{pongMsg}, tx[:]...), encodeAddrPort(src)...))
		if from != nil { // relayed: "call me maybe", punch towards its endpoints now
			if l := b.link(p.home); l != nil {
				l.send(p.key, reply)
			}
		} else {
			_ = b.sendUDP(src, reply)
		}
		// Punch back, but only while no direct path is trusted: answering every ping with a
		// round of pings would make two peers amplify each other.
		b.mu.Lock()
		if from == nil && !containsAddr(p.learned, src) && len(p.learned) < maxCandidates {
			p.learned = append(p.learned, src)
		}
		punch := !now.Before(p.bestUntil)
		b.mu.Unlock()
		if punch {
			select {
			case b.kick <- p:
			default:
			}
		}
	case pongMsg:
		b.mu.Lock()
		ps, ok := p.pings[tx]
		delete(p.pings, tx)
		if ok && !ps.viaRelay {
			rtt := now.Sub(ps.at)
			if !now.Before(p.bestUntil) || ps.to == p.best || float64(rtt) < 0.8*float64(p.rtt) {
				if p.best.IsValid() && p.best != ps.to && b.byAddr[p.best] == p {
					delete(b.byAddr, p.best)
				}
				p.best, p.rtt = ps.to, rtt
				b.byAddr[ps.to] = p
			}
			if ps.to == p.best {
				p.bestUntil = now.Add(trustBest)
			}
		}
		b.mu.Unlock()
	}
}

func containsAddr(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// pingPeer pings every candidate path of p, and through the relay when no direct path is
// trusted (the peer then pings us back: both NATs open at the same time).
func (b *MagicBind) pingPeer(p *mpeer) {
	now := time.Now()
	b.mu.Lock()
	if now.Sub(p.lastPing) < pingEvery/2 { // kicks arrive in bursts: one round per second at most
		b.mu.Unlock()
		return
	}
	targets := append(append([]netip.AddrPort{}, p.cands...), p.learned...)
	if p.best.IsValid() && !containsAddr(targets, p.best) {
		targets = append(targets, p.best)
	}
	callMe := !now.Before(p.bestUntil) && now.Sub(p.lastCallMe) >= callMeEvery
	if callMe {
		p.lastCallMe = now
	}
	p.lastPing = now
	b.mu.Unlock()
	for _, t := range targets {
		if b.underlay(t) {
			b.sendPing(p, t)
		}
	}
	if callMe {
		b.sendPing(p, netip.AddrPort{})
	}
}

// ---- STUN, home relay, maintenance ----

func (b *MagicBind) probeSTUN() {
	b.mu.RLock()
	relays := append([]zr.Relay{}, b.relays...)
	b.mu.RUnlock()
	for _, r := range relays {
		ua, err := net.ResolveUDPAddr("udp", r.STUN)
		if err != nil {
			continue
		}
		var tx [12]byte
		_, _ = rand.Read(tx[:])
		b.mu.Lock()
		for k, v := range b.stun {
			if time.Since(v.at) > 10*time.Second {
				delete(b.stun, k)
			}
		}
		b.stun[tx] = stunProbe{relay: r.Name, at: time.Now()}
		b.mu.Unlock()
		ap := ua.AddrPort()
		_ = b.sendUDP(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), zr.STUNRequest(tx))
	}
}

func (b *MagicBind) handleSTUN(pkt []byte) {
	tx, mapped, ok := zr.ParseSTUNResponse(pkt)
	if !ok {
		return
	}
	b.mu.Lock()
	probe, ok := b.stun[tx]
	if !ok {
		b.mu.Unlock()
		return
	}
	delete(b.stun, tx)
	changed := b.mapped[probe.relay] != mapped
	b.mapped[probe.relay] = mapped
	b.stunRTT[probe.relay] = time.Since(probe.at)
	changed = b.pickHomeLocked() || changed
	b.mu.Unlock()
	if changed && b.onChange != nil {
		b.onChange()
	}
}

// pickHomeLocked chooses the relay with the lowest STUN RTT (keeping the current one unless
// another is clearly better), or the first relay when UDP gets no answers at all.
func (b *MagicBind) pickHomeLocked() bool {
	best, bestRTT := "", time.Duration(math.MaxInt64)
	exists := false
	for _, r := range b.relays {
		if r.Name == b.home {
			exists = true
		}
		if rtt, ok := b.stunRTT[r.Name]; ok && rtt < bestRTT {
			best, bestRTT = r.Name, rtt
		}
	}
	if best == "" && len(b.relays) > 0 {
		best = b.relays[0].Name
	}
	if exists && best != b.home {
		if cur, ok := b.stunRTT[b.home]; ok && float64(cur) <= 1.5*float64(bestRTT) {
			return false
		}
	}
	if best == b.home {
		return false
	}
	b.home = best
	return true
}

func (b *MagicBind) loop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastSTUN := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-b.kick:
			b.pingPeer(p)
		case now := <-tick.C:
			if now.Sub(lastSTUN) >= stunEvery {
				lastSTUN = now
				b.probeSTUN()
			}
			var due []*mpeer
			b.mu.Lock()
			for _, p := range b.peers {
				active := now.Sub(p.lastSend) < activeWindow
				if active && p.bestUntil.Sub(now) < 3*time.Second && now.Sub(p.lastPing) >= pingEvery {
					due = append(due, p)
				}
				for tx, ps := range p.pings {
					if now.Sub(ps.at) > 10*time.Second {
						delete(p.pings, tx)
					}
				}
			}
			home := b.home
			var idle []*relayLink
			for name, l := range b.links {
				if name != home && now.Sub(l.lastUsed()) > relayIdle {
					idle = append(idle, l)
					delete(b.links, name)
				}
			}
			b.mu.Unlock()
			for _, l := range idle {
				l.close()
			}
			for _, p := range due {
				b.pingPeer(p)
			}
			_ = b.link(home) // stay reachable through the home relay
		}
	}
}

// ---- netmap input ----

// SetPeers replaces the peer set (keys, disco keys, endpoints, home relays).
func (b *MagicBind) SetPeers(peers []zr.Peer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[[32]byte]bool{}
	for _, pp := range peers {
		k, err1 := base64.StdEncoding.DecodeString(pp.NodeKey)
		d, err2 := base64.StdEncoding.DecodeString(pp.DiscoKey)
		if err1 != nil || err2 != nil || len(k) != 32 || len(d) != 32 {
			continue
		}
		var key, disco [32]byte
		copy(key[:], k)
		copy(disco[:], d)
		seen[key] = true
		p := b.peers[key]
		if p == nil {
			p = &mpeer{key: key, pings: map[[12]byte]pingSent{}}
			p.ep = &peerEP{p: p}
			b.peers[key] = p
		}
		if p.disco != disco {
			delete(b.byDisco, p.disco)
			p.disco = disco
			box.Precompute(&p.shared, &disco, &b.discoPriv)
		}
		b.byDisco[disco] = p
		p.name, p.home = pp.Name, pp.HomeRelay
		p.cands = p.cands[:0]
		for _, e := range pp.Endpoints {
			if a, err := netip.ParseAddrPort(e); err == nil && len(p.cands) < maxCandidates {
				p.cands = append(p.cands, netip.AddrPortFrom(a.Addr().Unmap(), a.Port()))
			}
		}
	}
	for k, p := range b.peers {
		if !seen[k] {
			delete(b.peers, k)
			delete(b.byDisco, p.disco)
			for a, q := range b.byAddr {
				if q == p {
					delete(b.byAddr, a)
				}
			}
		}
	}
}

// SetRelays updates the relay list from the netmap.
func (b *MagicBind) SetRelays(relays []zr.Relay) {
	b.mu.Lock()
	b.relays = append([]zr.Relay{}, relays...)
	sort.Slice(b.relays, func(i, j int) bool { return b.relays[i].Name < b.relays[j].Name })
	names := map[string]bool{}
	for _, r := range b.relays {
		names[r.Name] = true
	}
	var gone []*relayLink
	for name, l := range b.links {
		if !names[name] {
			gone = append(gone, l)
			delete(b.links, name)
		}
	}
	for name := range b.mapped {
		if !names[name] {
			delete(b.mapped, name)
			delete(b.stunRTT, name)
		}
	}
	changed := b.pickHomeLocked()
	b.mu.Unlock()
	for _, l := range gone {
		l.close()
	}
	go b.probeSTUN()
	_ = b.link("") // be reachable through the home relay at once: a first handshake is not lost
	if changed && b.onChange != nil {
		b.onChange()
	}
}

// PublicEndpoints are the addresses relays saw this device's WireGuard socket come from.
func (b *MagicBind) PublicEndpoints() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []string
	for _, a := range b.mapped {
		if s := a.String(); !containsString(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (b *MagicBind) Home() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.home
}

// Path describes how traffic to the peer with WireGuard key k flows right now.
func (b *MagicBind) Path(k [32]byte) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	p := b.peers[k]
	if p == nil {
		return ""
	}
	if time.Now().Before(p.bestUntil) {
		return fmt.Sprintf("direct %s (%s)", p.best, p.rtt.Round(100*time.Microsecond))
	}
	home := p.home
	if home == "" {
		home = b.home
	}
	if home == "" {
		return "no path"
	}
	return "relay " + home
}

// ---- relay links ----

func (b *MagicBind) relayByName(name string) (zr.Relay, bool) {
	for _, r := range b.relays {
		if r.Name == name {
			return r, true
		}
	}
	return zr.Relay{}, false
}

// link returns the (lazily connected) link to relay name, or to the home relay for "".
func (b *MagicBind) link(name string) *relayLink {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open || b.auth == nil {
		return nil
	}
	if name == "" {
		name = b.home
	}
	r, ok := b.relayByName(name)
	if !ok {
		if r, ok = b.relayByName(b.home); !ok {
			return nil
		}
		name = r.Name
	}
	if l := b.links[name]; l != nil {
		return l
	}
	l := newRelayLink(r, b)
	b.links[name] = l
	return l
}

func (b *MagicBind) onRelayFrame(from [32]byte, data []byte) {
	if isDisco(data) {
		b.handleDisco(data, netip.AddrPort{}, &from)
		return
	}
	b.mu.RLock()
	recv, closed := b.recv, b.closed
	b.mu.RUnlock()
	select {
	case recv <- relayPkt{from: from, data: data}:
	case <-closed:
	default: // wireguard-go is behind: drop
	}
}

type relayLink struct {
	r    zr.Relay
	b    *MagicBind
	out  chan []byte
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	used time.Time
	rc   *zr.RelayConn
}

func newRelayLink(r zr.Relay, b *MagicBind) *relayLink {
	l := &relayLink{r: r, b: b, out: make(chan []byte, 1024), done: make(chan struct{}), used: time.Now()}
	go l.run()
	return l
}

func (l *relayLink) lastUsed() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

func (l *relayLink) close() {
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		if l.rc != nil {
			l.rc.Close()
		}
		l.mu.Unlock()
	})
}

// send queues a frame for key (the packet is copied: WireGuard reuses its buffers).
func (l *relayLink) send(key [32]byte, pkt []byte) {
	n := 32 + len(pkt)
	f := make([]byte, 4+n)
	f[0], f[1], f[2], f[3] = zr.FrameSend, byte(n>>16), byte(n>>8), byte(n)
	copy(f[4:], key[:])
	copy(f[36:], pkt)
	l.mu.Lock()
	l.used = time.Now()
	l.mu.Unlock()
	select {
	case l.out <- f:
	default:
	}
}

func (l *relayLink) run() {
	backoff := time.Second
	for {
		select {
		case <-l.done:
			return
		default:
		}
		ca, cert := l.b.auth()
		if ca != nil && cert != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			rc, err := zr.DialRelay(ctx, l.r.Addr, ca, cert)
			cancel()
			if err == nil {
				backoff = time.Second
				l.mu.Lock()
				l.rc = rc
				l.mu.Unlock()
				l.serve(rc)
				rc.Close()
			}
		}
		select {
		case <-l.done:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (l *relayLink) serve(rc *zr.RelayConn) {
	stop := make(chan struct{})
	go func() { // writer
		t := time.NewTicker(zr.RelayKeepalive)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-l.done:
				rc.Close()
				return
			case f := <-l.out:
				_ = rc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := rc.Conn.Write(f); err != nil {
					rc.Close()
					return
				}
			case <-t.C:
				if rc.WriteFrame(zr.FrameKeepalive, nil, nil) != nil {
					rc.Close()
					return
				}
			}
		}
	}()
	defer close(stop)
	for {
		_ = rc.Conn.SetReadDeadline(time.Now().Add(2 * zr.RelayKeepalive))
		typ, from, payload, err := rc.ReadFrame()
		if err != nil {
			return
		}
		if typ == zr.FrameRecv {
			l.b.onRelayFrame(from, payload)
		}
	}
}

// ---- netcheck ----

type RelayCheck struct {
	Name    string `json:"name"`
	STUNms  int64  `json:"stun_ms,omitempty"` // UDP round trip (0 = no answer)
	TLSms   int64  `json:"tls_ms,omitempty"`  // TLS connect time (0 = unreachable)
	Mapped  string `json:"mapped,omitempty"`  // public address it saw
	Error   string `json:"error,omitempty"`
	Current bool   `json:"home"`
}

type Netcheck struct {
	UDP          bool         `json:"udp"`
	Public       []string     `json:"public_endpoints"`
	VariesByDest bool         `json:"mapping_varies_by_destination"` // symmetric NAT: direct paths are unlikely
	Home         string       `json:"home_relay"`
	Relays       []RelayCheck `json:"relays"`
}

// Netcheck probes every relay now (STUN over the WireGuard socket, a TLS connect).
func (b *MagicBind) Netcheck(ctx context.Context) Netcheck {
	b.mu.Lock()
	b.mapped, b.stunRTT = map[string]netip.AddrPort{}, map[string]time.Duration{}
	relays := append([]zr.Relay{}, b.relays...)
	b.mu.Unlock()
	b.probeSTUN()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	ca, cert := (*x509.Certificate)(nil), (*tls.Certificate)(nil)
	if b.auth != nil {
		ca, cert = b.auth()
	}
	var nc Netcheck
	ports := map[uint16]bool{}
	for _, r := range relays {
		rc := RelayCheck{Name: r.Name}
		b.mu.RLock()
		if rtt, ok := b.stunRTT[r.Name]; ok {
			rc.STUNms, rc.Mapped, nc.UDP = max(rtt.Milliseconds(), 1), b.mapped[r.Name].String(), true
			ports[b.mapped[r.Name].Port()] = true
		}
		b.mu.RUnlock()
		if ca != nil && cert != nil {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			t0 := time.Now()
			c, err := zr.DialRelay(cctx, r.Addr, ca, cert)
			cancel()
			if err == nil {
				rc.TLSms = max(time.Since(t0).Milliseconds(), 1)
				c.Close()
			} else {
				rc.Error = err.Error()
			}
		}
		nc.Relays = append(nc.Relays, rc)
	}
	b.mu.Lock()
	b.pickHomeLocked()
	nc.Home = b.home
	b.mu.Unlock()
	for i := range nc.Relays {
		nc.Relays[i].Current = nc.Relays[i].Name == nc.Home
	}
	nc.Public = b.PublicEndpoints()
	nc.VariesByDest = len(ports) > 1
	return nc
}

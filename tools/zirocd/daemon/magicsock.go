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
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
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
	keepAliveBest   = 6 * time.Second // an active peer's direct path is re-pinged once its trust drops below this (~every 1s)
	maxMissed       = 3               // pings to the best path without a pong: drop it (~3s on an active peer)
	sprayRadius     = 32              // hard-NAT probing: ports around each public port the peer reported
	sprayEvery      = 15 * time.Second
	stunEvery       = 20 * time.Second
	stunStale       = 50 * time.Second // no STUN answer for ~2.5 rounds: the round trip is unknown again
	linkGrace       = 5 * time.Second  // a relay link still down this long after dialing counts as down
	maxCandidates   = 16
	relayIdle       = 2 * time.Minute
	wgKeepaliveSize = 32 // an empty WireGuard transport message: not real traffic
)

// debugDisco logs path discovery (ZIROCD_DEBUG=disco): pings, pongs, path changes.
var debugDisco = strings.Contains(os.Getenv("ZIROCD_DEBUG"), "disco")

func dlog(format string, args ...any) {
	if debugDisco {
		log.Printf("disco: "+format, args...)
	}
}

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
	relays     []zr.RelayRTT // relays the peer is registered with, and how far it is from each
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
	nat        string // "easy", "hard" or ""
	missed     int    // pings sent to best since its last pong
	rounds     int    // ping rounds while a path is trusted (every 5th also probes the other candidates)
	lastSpray  time.Time
}

type relayPkt struct {
	from [32]byte
	data []byte
}

type stunProbe struct {
	relay string // relay name; mapped addresses are kept per relay and family ("r1/4", "r1/6")
	fam   string
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
	homes    []string                      // the relays this device registers with, nearest first
	relayUDP map[netip.AddrPort]*relayLink // relay UDP address -> link (relayed datagrams come from here)
	stun     map[[12]byte]stunProbe
	mapped   map[string]netip.AddrPort
	stunRTT  map[string]time.Duration
	stunAt   map[string]time.Time // last STUN answer per relay
	open     bool
	recv     chan relayPkt
	closed   chan struct{}
	kick     chan *mpeer
	stopLoop context.CancelFunc
	pings    atomic.Uint64  // disco pings sent (tests guard against ping storms)
	portMap  netip.AddrPort // external address a router mapped for us (PCP / NAT-PMP / UPnP)
	mapProto string
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
		stdEPs: map[netip.AddrPort]conn.Endpoint{}, links: map[string]*relayLink{}, stun: map[[12]byte]stunProbe{}, relayUDP: map[netip.AddrPort]*relayLink{},
		mapped: map[string]netip.AddrPort{}, stunRTT: map[string]time.Duration{}, stunAt: map[string]time.Time{}, kick: make(chan *mpeer, 256)}
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
				case len(pkt) > 0 && (pkt[0] == zr.UDPAck || pkt[0] == zr.UDPRecv):
					b.mu.RLock()
					l := b.relayUDP[src]
					b.mu.RUnlock()
					if l == nil { // relay datagrams only from relays
						continue
					}
					if pkt[0] == zr.UDPAck {
						l.acked(pkt)
						continue
					}
					if len(pkt) <= zr.UDPRecvHdr {
						continue
					}
					from, payload := [32]byte(pkt[1:33]), pkt[zr.UDPRecvHdr:]
					if isDisco(payload) {
						b.handleDisco(payload, netip.AddrPort{}, &from)
						continue
					}
					b.mu.RLock()
					p := b.peers[from]
					b.mu.RUnlock()
					if p == nil {
						continue
					}
					sizes[j] = copy(bufs[j], payload) // overlapping copies are fine
					eps[j] = p.ep
					j++
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
	needPing := active && (!valid || p.bestUntil.Sub(now) < keepAliveBest) && now.Sub(p.lastPing) >= pingEvery/2
	relay := ""
	if !valid {
		relay = b.relayForLocked(p)
	}
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
	l := b.link(relay)
	if l == nil {
		return nil // no path yet: WireGuard retransmits its handshake
	}
	l.sendBatch(p.key, bufs)
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
	if to.IsValid() && to == p.best {
		p.missed++
	}
	relay := b.relayForLocked(p)
	b.mu.Unlock()
	b.pings.Add(1)
	dlog("ping %s -> %v", p.name, to)
	pkt := b.seal(p, append([]byte{pingPong}, tx[:]...))
	if to.IsValid() {
		_ = b.sendUDP(to, pkt)
	} else if l := b.link(relay); l != nil {
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
	dlog("%s from %s src=%v relayed=%v", map[byte]string{pingPong: "ping", pongMsg: "pong"}[msg[0]], p.name, src, from != nil)
	switch msg[0] {
	case pingPong:
		reply := b.seal(p, append(append([]byte{pongMsg}, tx[:]...), encodeAddrPort(src)...))
		if from != nil { // relayed: "call me maybe", punch towards its endpoints now
			b.mu.RLock()
			relay := b.relayForLocked(p)
			b.mu.RUnlock()
			if l := b.link(relay); l != nil {
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
			if ps.to == p.best {
				p.missed = 0
			}
			if !now.Before(p.bestUntil) || ps.to == p.best || betterPath(ps.to, rtt, p.best, p.rtt) {
				if ps.to != p.best {
					p.missed = 0
				}
				if p.best.IsValid() && p.best != ps.to && b.byAddr[p.best] == p {
					delete(b.byAddr, p.best)
				}
				p.best, p.rtt = ps.to, rtt
				b.byAddr[ps.to] = p
				dlog("path %s -> direct %v (%v)", p.name, ps.to, rtt)
			}
			if ps.to == p.best {
				p.bestUntil = now.Add(trustBest)
			}
		}
		b.mu.Unlock()
	}
}

// pathRank orders direct paths: same LAN first, then IPv6 (rarely NATed), then public IPv4.
func pathRank(a netip.AddrPort) int {
	ip := a.Addr()
	switch {
	case ip.IsPrivate() || ip.IsLinkLocalUnicast():
		return 0
	case ip.Is6():
		return 1
	}
	return 2
}

// betterPath: a better-ranked path wins unless more than 20% slower; an equal-ranked one must be
// 20% faster (no flapping between near-equal paths).
func betterPath(a netip.AddrPort, rttA time.Duration, b netip.AddrPort, rttB time.Duration) bool {
	ra, rb := pathRank(a), pathRank(b)
	switch {
	case ra < rb:
		return float64(rttA) <= 1.2*float64(rttB)
	case ra > rb:
		return 1.2*float64(rttA) < float64(rttB)
	}
	return float64(rttA) < 0.8*float64(rttB)
}

// sprayTargets are the ports around each IPv4 candidate the peer showed the relays (sprayRadius
// either side), capped at 256 probes per round. Private addresses are kept: behind carrier-grade
// NAT the "public" side is private space, and probes only go to addresses the router listed for
// this peer.
func sprayTargets(cands []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for _, c := range cands {
		if !c.Addr().Is4() || !c.Addr().IsGlobalUnicast() {
			continue
		}
		for d := -sprayRadius; d <= sprayRadius && len(out) < 256; d++ {
			port := int(c.Port()) + d
			if d != 0 && port > 1024 && port < 65536 {
				out = append(out, netip.AddrPortFrom(c.Addr(), uint16(port)))
			}
		}
	}
	return out
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
	if p.missed >= maxMissed && now.Before(p.bestUntil) { // the direct path went quiet: relay now
		p.bestUntil, p.missed = time.Time{}, 0
		dlog("path %s: %v went quiet, relaying", p.name, p.best)
	}
	trusted := now.Before(p.bestUntil)
	var targets []netip.AddrPort
	if trusted && p.rounds%5 != 0 {
		targets = []netip.AddrPort{p.best} // keep the path alive; look for a better one every 5th round
	} else {
		targets = append(append([]netip.AddrPort{}, p.cands...), p.learned...)
		if p.best.IsValid() && !containsAddr(targets, p.best) {
			targets = append(targets, p.best)
		}
	}
	if trusted {
		p.rounds++
	} else {
		p.rounds = 0
	}
	// Hard NAT on the other side (its port varies by destination) and an easy one here: probe the
	// ports around the ones it showed the relays. Its own pings towards us open a port near them;
	// one of ours lands on it. Budgeted, and only at addresses the router gave us for this peer.
	if !trusted && p.nat == "hard" && b.natTypeLocked() == "easy" && now.Sub(p.lastSpray) >= sprayEvery {
		p.lastSpray = now
		targets = append(targets, sprayTargets(p.cands)...)
	}
	callMe := !trusted && now.Sub(p.lastCallMe) >= callMeEvery
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
		host, port, err := net.SplitHostPort(r.STUN)
		if err != nil {
			continue
		}
		pn, _ := strconv.Atoi(port)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host) // both families: IPv6 paths too
		cancel()
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, ip := range ips {
			ip = ip.Unmap()
			fam := "4"
			if ip.Is6() {
				fam = "6"
			}
			if seen[fam] {
				continue
			}
			seen[fam] = true
			var tx [12]byte
			_, _ = rand.Read(tx[:])
			b.mu.Lock()
			for k, v := range b.stun {
				if time.Since(v.at) > 10*time.Second {
					delete(b.stun, k)
				}
			}
			b.stun[tx] = stunProbe{relay: r.Name, fam: fam, at: time.Now()}
			b.mu.Unlock()
			_ = b.sendUDP(netip.AddrPortFrom(ip, uint16(pn)), zr.STUNRequest(tx))
		}
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
	key := probe.relay + "/" + probe.fam
	changed := b.mapped[key] != mapped
	b.mapped[key] = mapped
	if rtt, ok := b.stunRTT[probe.relay]; !ok || time.Since(probe.at) < rtt || probe.fam == "4" {
		b.stunRTT[probe.relay] = time.Since(probe.at)
	}
	b.stunAt[probe.relay] = time.Now()
	changed = b.pickHomeLocked() || changed
	b.mu.Unlock()
	if changed && b.onChange != nil {
		b.onChange()
	}
}

// pickHomeLocked ranks the relays and registers with the best two: the first is the home relay,
// kept unless another is clearly better (no flapping). Ranking: relays answering STUN, by round
// trip; then relays not heard from lately (by name: without any UDP answer they still work over
// TLS); last, relays whose link is down. A relay that dies stops being a home within seconds, so
// peers move to a live one instead of trying to reach this device through it.
func (b *MagicBind) pickHomeLocked() bool {
	ranked := make([]string, 0, len(b.relays))
	for _, r := range b.relays {
		ranked = append(ranked, r.Name)
	}
	tier := func(n string) int {
		if l := b.links[n]; l != nil && !l.up() && time.Since(l.born) > linkGrace {
			return 2
		}
		if at, ok := b.stunAt[n]; !ok || time.Since(at) > stunStale {
			return 1
		}
		return 0
	}
	rtt := func(n string) time.Duration {
		if d, ok := b.stunRTT[n]; ok && tier(n) == 0 {
			return d
		}
		return time.Duration(math.MaxInt64)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ti, tj := tier(ranked[i]), tier(ranked[j]); ti != tj {
			return ti < tj
		}
		return rtt(ranked[i]) < rtt(ranked[j])
	})
	if b.home != "" && len(ranked) > 0 && ranked[0] != b.home && slices.Contains(ranked, b.home) && tier(b.home) == tier(ranked[0]) {
		if cur, ok := b.stunRTT[b.home]; ok && float64(cur) <= 1.5*float64(rtt(ranked[0])) {
			ranked = append([]string{b.home}, slices.DeleteFunc(ranked, func(n string) bool { return n == b.home })...)
		}
	}
	homes := ranked[:min(2, len(ranked))]
	home := ""
	if len(homes) > 0 {
		home = homes[0]
	}
	changed := home != b.home || !slices.Equal(homes, b.homes)
	b.home, b.homes = home, homes
	return changed
}

// relayForLocked picks the relay for traffic to p: among the relays p is registered with, the one
// with the lowest round trip for the pair (ours + p's), preferring relays we are connected to.
func (b *MagicBind) relayForLocked(p *mpeer) string {
	best, bestCost := "", math.MaxInt
	for _, r := range p.relays {
		if _, ok := b.relayByName(r.Name); !ok {
			continue
		}
		mine := 500 // ms, when we have not measured it
		if d, ok := b.stunRTT[r.Name]; ok {
			mine = int(d.Milliseconds())
		}
		cost := mine + r.RTT
		if l := b.links[r.Name]; l == nil || !l.up() {
			cost += 1000 // connecting first costs a round trip or two
		}
		if cost < bestCost {
			best, bestCost = r.Name, cost
		}
	}
	if best != "" {
		return best
	}
	if p.home != "" {
		return p.home
	}
	return b.home
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
				if active && p.bestUntil.Sub(now) < keepAliveBest && now.Sub(p.lastPing) >= pingEvery/2 {
					due = append(due, p)
				}
				for tx, ps := range p.pings {
					if now.Sub(ps.at) > 10*time.Second {
						delete(p.pings, tx)
					}
				}
			}
			homes := append([]string(nil), b.homes...)
			var idle, live []*relayLink
			for name, l := range b.links {
				if !slices.Contains(homes, name) && now.Sub(l.lastUsed()) > relayIdle {
					idle = append(idle, l)
					delete(b.links, name)
					delete(b.relayUDP, l.udpAddr)
				} else {
					live = append(live, l)
				}
			}
			b.mu.Unlock()
			for _, l := range idle {
				l.close()
			}
			for _, p := range due {
				b.pingPeer(p)
			}
			for _, l := range live {
				l.maybeHello(now)
			}
			b.mu.Lock()
			changed := b.pickHomeLocked() // a home relay may have died since the last STUN round
			homes = append(homes[:0], b.homes...)
			b.mu.Unlock()
			if changed && b.onChange != nil {
				b.onChange()
			}
			for _, h := range homes {
				_ = b.link(h) // stay reachable through the nearest relays
			}
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
		p.name, p.home, p.relays, p.nat = pp.Name, pp.HomeRelay, pp.Relays, pp.NAT
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
			delete(b.relayUDP, l.udpAddr)
		}
	}
	for key := range b.mapped {
		if name, _, _ := strings.Cut(key, "/"); !names[name] {
			delete(b.mapped, key)
		}
	}
	for name := range b.stunRTT {
		if !names[name] {
			delete(b.stunRTT, name)
			delete(b.stunAt, name)
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
	if b.portMap.IsValid() { // a router-mapped port is the most reliable way in: first
		out = append(out, b.portMap.String())
	}
	keys := make([]string, 0, len(b.mapped))
	for k := range b.mapped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if s := b.mapped[k].String(); !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// NATType is "easy" when every relay saw the same public IPv4 port, "hard" when they saw
// different ones (symmetric NAT), "" when fewer than two relays answered. A router-mapped port
// makes it easy.
func (b *MagicBind) NATType() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.natTypeLocked()
}

func (b *MagicBind) natTypeLocked() string {
	if b.portMap.IsValid() {
		return "easy"
	}
	ports := map[uint16]bool{}
	n := 0
	for k, a := range b.mapped {
		if strings.HasSuffix(k, "/4") {
			ports[a.Port()] = true
			n++
		}
	}
	switch {
	case len(ports) > 1:
		return "hard"
	case n >= 2:
		return "easy"
	}
	return ""
}

// SetPortMapping records the external address a gateway mapped to our WireGuard port ("" proto
// and an invalid address: no mapping).
func (b *MagicBind) SetPortMapping(ext netip.AddrPort, proto string) {
	b.mu.Lock()
	changed := b.portMap != ext
	b.portMap, b.mapProto = ext, proto
	b.mu.Unlock()
	if changed && b.onChange != nil {
		b.onChange()
	}
}

// Rebind is the reaction to a network change (another Wi-Fi, LTE, a new address): forget what
// was learned about the old network, rediscover the public address, re-bind relay sessions and
// find new paths to every active peer at once.
func (b *MagicBind) Rebind() {
	dlog("network changed: rebinding")
	now := time.Now()
	b.mu.Lock()
	b.mapped = map[string]netip.AddrPort{}
	b.stdEPs = map[netip.AddrPort]conn.Endpoint{}
	var active []*mpeer
	for _, p := range b.peers {
		if p.best.IsValid() && b.byAddr[p.best] == p {
			delete(b.byAddr, p.best)
		}
		p.bestUntil, p.best, p.learned, p.missed, p.lastPing, p.lastCallMe = time.Time{}, netip.AddrPort{}, nil, 0, time.Time{}, time.Time{}
		if now.Sub(p.lastSend) < activeWindow {
			active = append(active, p)
		}
	}
	links := make([]*relayLink, 0, len(b.links))
	for _, l := range b.links {
		links = append(links, l)
	}
	b.mu.Unlock()
	for _, l := range links {
		l.mu.Lock()
		l.helloAt = time.Time{} // re-bind the UDP session from the new address now
		rc := l.rc
		l.mu.Unlock()
		if rc != nil {
			rc.Close() // its TCP connection went through the old network: redial at once
		}
		l.maybeHello(now)
	}
	b.probeSTUN()
	for _, p := range active {
		b.pingPeer(p)
	}
	if b.onChange != nil {
		b.onChange()
	}
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
	relay := b.relayForLocked(p)
	if relay == "" {
		return "no path"
	}
	transport := "tls"
	if l := b.links[relay]; l != nil && l.udpUp() {
		transport = "udp"
	}
	return "relay " + relay + " " + transport
}

// Relays are the relays this device is registered with and its round trip to each, for the
// router to pass to peers.
func (b *MagicBind) Relays() []zr.RelayRTT {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]zr.RelayRTT, 0, len(b.homes))
	for _, h := range b.homes {
		ms := 0
		if d, ok := b.stunRTT[h]; ok {
			ms = int(max(d.Milliseconds(), 1))
		}
		out = append(out, zr.RelayRTT{Name: h, RTT: ms})
	}
	return out
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
	if l.udpAddr.IsValid() {
		b.relayUDP[l.udpAddr] = l
	}
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

// relayLink is this device's connection to one relay: a TLS connection (session setup, and the
// transport where UDP is blocked) and a UDP session on the WireGuard socket, used once the
// relay acknowledges its hello.
type relayLink struct {
	r       zr.Relay
	b       *MagicBind
	out     chan []byte
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	used    time.Time
	born    time.Time // when the link was created (it may take a moment to come up)
	rc      *zr.RelayConn
	udpAddr netip.AddrPort
	session uint32
	skey    [32]byte
	helloAt time.Time
	unacked time.Time    // first hello sent since the last ack (zero: none outstanding)
	ackAt   atomic.Int64 // unix nanos of the last hello ack (the UDP session is live)
}

func newRelayLink(r zr.Relay, b *MagicBind) *relayLink {
	l := &relayLink{r: r, b: b, out: make(chan []byte, 1024), done: make(chan struct{}), used: time.Now(), born: time.Now()}
	if ua, err := net.ResolveUDPAddr("udp", r.STUN); err == nil {
		ap := ua.AddrPort()
		l.udpAddr = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	go l.run()
	return l
}

// udpUp: the relay acknowledged a hello recently and no hello is overdue (UDP to the relay was
// blocked or the NAT mapping changed: traffic falls back to TLS within seconds).
func (l *relayLink) udpUp() bool {
	ack := time.Unix(0, l.ackAt.Load())
	if time.Since(ack) >= 60*time.Second {
		return false
	}
	l.mu.Lock()
	pending := l.unacked
	l.mu.Unlock()
	return pending.IsZero() || time.Since(pending) <= 3*time.Second
}

func (l *relayLink) up() bool {
	l.mu.Lock()
	tls := l.rc != nil
	l.mu.Unlock()
	return tls || l.udpUp()
}

// maybeHello (re)binds the UDP session: every 25s when idle, every 5s while it carries traffic
// (a lost session is noticed within seconds), every 2s until acknowledged.
func (l *relayLink) maybeHello(now time.Time) {
	up := l.udpUp()
	l.mu.Lock()
	session, key := l.session, l.skey
	every := 25 * time.Second
	if now.Sub(l.used) < 10*time.Second {
		every = 5 * time.Second
	}
	due := session != 0 && l.udpAddr.IsValid() && (now.Sub(l.helloAt) >= every || (!up && now.Sub(l.helloAt) >= 2*time.Second))
	if due {
		l.helloAt = now
		if l.unacked.IsZero() {
			l.unacked = now
		}
	}
	l.mu.Unlock()
	if due {
		_ = l.b.sendUDP(l.udpAddr, zr.UDPHelloPacket(session, key, uint64(now.UnixMilli())))
	}
}

func (l *relayLink) acked(pkt []byte) {
	session, _, _, ok := zr.ParseUDPAck(pkt)
	l.mu.Lock()
	match := ok && session == l.session && session != 0
	l.mu.Unlock()
	if match {
		l.ackAt.Store(time.Now().UnixNano())
		l.mu.Lock()
		l.unacked = time.Time{}
		l.mu.Unlock()
	}
}

// sendBatch relays WireGuard packets to key: as UDP datagrams in one batch when the session is
// live, otherwise over TLS.
func (l *relayLink) sendBatch(key [32]byte, bufs [][]byte) {
	l.mu.Lock()
	l.used = time.Now()
	session := l.session
	l.mu.Unlock()
	if !l.udpUp() || session == 0 {
		for _, buf := range bufs {
			l.send(key, buf)
		}
		return
	}
	total := 0
	for _, buf := range bufs {
		total += zr.UDPSendHdr + len(buf)
	}
	slab := make([]byte, 0, total) // one allocation for the whole batch
	frames := make([][]byte, len(bufs))
	for i, buf := range bufs {
		start := len(slab)
		slab = zr.AppendUDPSend(slab, session, key, buf)
		frames[i] = slab[start:len(slab):len(slab)]
	}
	if ep, err := l.b.stdEP(l.udpAddr); err == nil {
		_ = l.b.std.Send(frames, ep)
	}
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

// send relays one packet to key (copied: WireGuard reuses its buffers): UDP when live, else TLS.
func (l *relayLink) send(key [32]byte, pkt []byte) {
	l.mu.Lock()
	session := l.session
	l.mu.Unlock()
	if session != 0 && l.udpUp() {
		l.mu.Lock()
		l.used = time.Now()
		l.mu.Unlock()
		_ = l.b.sendUDP(l.udpAddr, zr.AppendUDPSend(nil, session, key, pkt))
		return
	}
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
			rc, err := zr.DialRelay(ctx, l.r, ca, cert)
			cancel()
			if err == nil {
				backoff = time.Second
				l.mu.Lock()
				l.rc = rc
				l.mu.Unlock()
				l.serve(rc)
				rc.Close()
				l.mu.Lock()
				l.rc, l.session = nil, 0 // the session dies with its TLS connection
				l.mu.Unlock()
				l.ackAt.Store(0)
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
		switch typ {
		case zr.FrameRecv:
			l.b.onRelayFrame(from, payload)
		case zr.FrameSession: // a new UDP session for this connection: bind it now
			if session, key, ok := zr.ParseSessionFrame(payload); ok {
				l.mu.Lock()
				l.session, l.skey, l.helloAt, l.unacked = session, key, time.Time{}, time.Time{}
				l.mu.Unlock()
				l.ackAt.Store(0)
				l.maybeHello(time.Now())
			}
		}
	}
}

// ---- netcheck ----

type RelayCheck struct {
	Name    string `json:"name"`
	STUNms  int64  `json:"stun_ms,omitempty"` // UDP round trip (0 = no answer)
	TLSms   int64  `json:"tls_ms,omitempty"`  // TLS connect time (0 = unreachable)
	UDP     bool   `json:"udp_relay"`         // relayed traffic flows as UDP datagrams (else TLS)
	Mapped  string `json:"mapped,omitempty"`  // public address it saw
	Error   string `json:"error,omitempty"`
	Current bool   `json:"home"`
}

type Netcheck struct {
	UDP          bool         `json:"udp"`
	IPv6         bool         `json:"ipv6"`             // a relay saw us over IPv6
	NAT          string       `json:"nat"`              // easy, hard or "" (unknown)
	PortMap      string       `json:"port_mapping"`     // pcp, nat-pmp, upnp or "" (none)
	Mapped       string       `json:"mapped,omitempty"` // the external address the router mapped
	Public       []string     `json:"public_endpoints"`
	VariesByDest bool         `json:"mapping_varies_by_destination"` // symmetric NAT: direct paths are unlikely
	Home         string       `json:"home_relay"`
	Relays       []RelayCheck `json:"relays"`
}

// Netcheck probes every relay now (STUN over the WireGuard socket, a TLS connect).
func (b *MagicBind) Netcheck(ctx context.Context) Netcheck {
	b.mu.Lock()
	b.mapped, b.stunRTT, b.stunAt = map[string]netip.AddrPort{}, map[string]time.Duration{}, map[string]time.Time{}
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
		if l := b.links[r.Name]; l != nil {
			rc.UDP = l.udpUp()
		}
		if rtt, ok := b.stunRTT[r.Name]; ok {
			m := b.mapped[r.Name+"/4"]
			if !m.IsValid() {
				m = b.mapped[r.Name+"/6"]
			}
			rc.STUNms, rc.Mapped, nc.UDP = max(rtt.Milliseconds(), 1), m.String(), true
			if m4, ok := b.mapped[r.Name+"/4"]; ok {
				ports[m4.Port()] = true
			}
		}
		b.mu.RUnlock()
		if ca != nil && cert != nil {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			t0 := time.Now()
			c, err := zr.DialRelay(cctx, r, ca, cert)
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
	nc.NAT = b.NATType()
	b.mu.RLock()
	nc.PortMap = b.mapProto
	if b.portMap.IsValid() {
		nc.Mapped = b.portMap.String()
	}
	for k := range b.mapped {
		nc.IPv6 = nc.IPv6 || strings.HasSuffix(k, "/6")
	}
	b.mu.RUnlock()
	nc.VariesByDest = len(ports) > 1
	return nc
}

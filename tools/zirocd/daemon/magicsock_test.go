package daemon

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/conn"
)

type testDev struct {
	bind  *MagicBind
	wgPub string
	disco string
	port  uint16
	got   chan []byte
}

// newTestDev opens a bind on a loopback port and pumps its receive functions like wireguard-go.
func newTestDev(t *testing.T) *testDev {
	t.Helper()
	_, wgPub, _ := newCurveKey()
	dPriv, dPub, _ := newCurveKey()
	b, err := NewMagicBind(dPriv, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	d := &testDev{bind: b, wgPub: wgPub, disco: dPub, port: port, got: make(chan []byte, 16)}
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			bs := b.BatchSize()
			bufs, sizes, eps := make([][]byte, bs), make([]int, bs), make([]conn.Endpoint, bs)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					d.got <- append([]byte(nil), bufs[i][:sizes[i]]...)
				}
			}
		}(fn)
	}
	return d
}

func (d *testDev) peer(name string) zr.Peer {
	return zr.Peer{ID: name, Name: name, NodeKey: d.wgPub, DiscoKey: d.disco,
		Endpoints: []string{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), d.port).String()}}
}

func keyOf(b64 string) [32]byte {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	return [32]byte(raw)
}

func TestMagicDirectPath(t *testing.T) {
	a, b := newTestDev(t), newTestDev(t)
	a.bind.SetPeers([]zr.Peer{b.peer("b")})
	b.bind.SetPeers([]zr.Peer{a.peer("a")})

	if got := a.bind.Path(keyOf(b.wgPub)); got != "no path" {
		t.Fatalf("before discovery: %q", got)
	}
	// WireGuard sends to b through its zrpeer endpoint: no direct path yet, so discovery starts.
	ep, err := a.bind.ParseEndpoint("zrpeer:" + strings.ToLower(hexKey(b.wgPub)))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 100)
	copy(payload, "wireguard data")
	_ = a.bind.Send([][]byte{payload}, ep)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasPrefix(a.bind.Path(keyOf(b.wgPub)), "direct 127.0.0.1:") {
		if time.Now().After(deadline) {
			t.Fatalf("no direct path: %q", a.bind.Path(keyOf(b.wgPub)))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Now data flows directly, and b labels it as coming from peer a (disco never leaks to WireGuard).
	if err := a.bind.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-b.got:
		if string(p[:14]) != "wireguard data" {
			t.Fatalf("b received %q", p[:14])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct packet not delivered")
	}
	// b learned a's address from the ping and punched back: it has a direct path too.
	deadline = time.Now().Add(5 * time.Second)
	for !strings.HasPrefix(b.bind.Path(keyOf(a.wgPub)), "direct") {
		if time.Now().After(deadline) {
			t.Fatalf("b has no direct path back: %q", b.bind.Path(keyOf(a.wgPub)))
		}
		_ = b.bind.Send([][]byte{payload}, mustEP(t, b.bind, a.wgPub))
		time.Sleep(50 * time.Millisecond)
	}
}

// Two active peers with a direct path must not amplify each other's pings (a ping storm once
// overflowed the outstanding-ping table and kept the path from ever forming).
func TestMagicNoPingStorm(t *testing.T) {
	a, b := newTestDev(t), newTestDev(t)
	a.bind.SetPeers([]zr.Peer{b.peer("b")})
	b.bind.SetPeers([]zr.Peer{a.peer("a")})
	epA, epB := mustEP(t, a.bind, b.wgPub), mustEP(t, b.bind, a.wgPub)
	payload := make([]byte, 100)
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		_ = a.bind.Send([][]byte{payload}, epA)
		_ = b.bind.Send([][]byte{payload}, epB)
	}
	// 2 candidates (endpoint + learned) per round, at most one round a second, plus relayed
	// call-me-maybes: a handful per second, never hundreds.
	if n := a.bind.pings.Load() + b.bind.pings.Load(); n > 40 {
		t.Fatalf("%d pings in 3s: peers are amplifying each other", n)
	}
	if !strings.HasPrefix(a.bind.Path(keyOf(b.wgPub)), "direct") {
		t.Fatalf("no direct path: %s", a.bind.Path(keyOf(b.wgPub)))
	}
}

// An endpoint inside a prefix routed through the tunnel (a subnet router's own LAN address) is
// never pinged or used: WireGuard would be sent into WireGuard.
func TestMagicSkipsOverlayEndpoints(t *testing.T) {
	a, b := newTestDev(t), newTestDev(t)
	a.bind.SetOverlay([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}) // b's only endpoint is "inside the tunnel"
	a.bind.SetPeers([]zr.Peer{b.peer("b")})
	b.bind.SetPeers([]zr.Peer{a.peer("a")})
	a.bind.pingPeer(a.bind.peers[keyOf(b.wgPub)])
	time.Sleep(300 * time.Millisecond)
	a.bind.mu.RLock()
	for _, ps := range a.bind.peers[keyOf(b.wgPub)].pings {
		if ps.to.IsValid() { // only the relayed call-me-maybe may go out
			t.Fatalf("pinged %s, an endpoint routed through the tunnel", ps.to)
		}
	}
	a.bind.mu.RUnlock()
	b.bind.pingPeer(b.bind.peers[keyOf(a.wgPub)]) // and pings arriving from such an address are ignored
	time.Sleep(300 * time.Millisecond)
	if strings.HasPrefix(a.bind.Path(keyOf(b.wgPub)), "direct") || len(a.bind.peers[keyOf(b.wgPub)].learned) != 0 {
		t.Fatal("a path through the tunnel itself was learned")
	}
}

func TestMagicRejectsForgedDisco(t *testing.T) {
	a, b, evil := newTestDev(t), newTestDev(t), newTestDev(t)
	a.bind.SetPeers([]zr.Peer{b.peer("b")})
	evil.bind.SetPeers([]zr.Peer{a.peer("a")}) // evil knows a, but a does not know evil
	evil.bind.pingPeer(evil.bind.peers[keyOf(a.wgPub)])
	time.Sleep(300 * time.Millisecond)
	a.bind.mu.RLock()
	defer a.bind.mu.RUnlock()
	if len(a.bind.byAddr) != 0 || len(a.bind.peers[keyOf(b.wgPub)].learned) != 0 {
		t.Fatal("a ping from an unknown disco key changed state")
	}
	// A relayed frame claiming another peer's disco key is ignored.
	var forged [32]byte
	a.bind.handleDisco(append([]byte(discoMagic), make([]byte, 100)...), netip.AddrPort{}, &forged)
}

func hexKey(b64 string) string {
	k, _ := keyHex(b64)
	return k
}

func mustEP(t *testing.T, b *MagicBind, wgPub string) conn.Endpoint {
	ep, err := b.ParseEndpoint("zrpeer:" + hexKey(wgPub))
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

// The relay for a peer is the one with the lowest round trip for the pair, among the relays the
// peer is registered with; this device registers with its two nearest relays.
func TestRelayChoice(t *testing.T) {
	b, _ := NewMagicBind(func() string { k, _, _ := newCurveKey(); return k }(), nil, nil)
	b.relays = []zr.Relay{{Name: "eu"}, {Name: "sg"}, {Name: "us"}}
	b.stunRTT = map[string]time.Duration{"eu": 180 * time.Millisecond, "sg": 20 * time.Millisecond, "us": 150 * time.Millisecond}
	now := time.Now()
	b.stunAt = map[string]time.Time{"eu": now, "sg": now, "us": now}
	b.pickHomeLocked()
	if b.home != "sg" || strings.Join(b.homes, ",") != "sg,us" {
		t.Fatalf("homes %v", b.homes)
	}
	// The peer sits next to eu, far from sg: eu (180+5) beats sg (20+300).
	p := &mpeer{relays: []zr.RelayRTT{{Name: "eu", RTT: 5}, {Name: "sg", RTT: 300}}}
	if got := b.relayForLocked(p); got != "eu" {
		t.Fatalf("pair relay %s", got)
	}
	// A relay the peer reports but we don't know is skipped; with nothing usable: its home relay.
	if got := b.relayForLocked(&mpeer{relays: []zr.RelayRTT{{Name: "mars", RTT: 1}}, home: "us"}); got != "us" {
		t.Fatalf("fallback %s", got)
	}
	// Hysteresis: a slightly faster relay doesn't take over the home.
	b.stunRTT["us"] = 18 * time.Millisecond
	if b.pickHomeLocked(); b.home != "sg" {
		t.Fatalf("home flapped to %s", b.home)
	}
	b.stunRTT["us"] = 5 * time.Millisecond
	if b.pickHomeLocked(); b.home != "us" {
		t.Fatalf("home should move to a clearly nearer relay, got %s", b.home)
	}
	// A relay that stopped answering STUN loses its old round trip: the live ones rank first.
	b.stunAt["us"] = now.Add(-2 * stunStale)
	if b.pickHomeLocked(); strings.Join(b.homes, ",") != "sg,eu" {
		t.Fatalf("stale relay still a home: %v", b.homes)
	}
	// A relay whose link is down (past the dialing grace) ranks last, even if STUN still answers.
	b.stunAt["us"] = now
	dead := &relayLink{r: zr.Relay{Name: "sg"}, b: b, born: now.Add(-time.Minute), done: make(chan struct{})} // never connected
	b.links = map[string]*relayLink{"sg": dead}
	if b.pickHomeLocked(); b.home == "sg" || slices.Contains(b.homes, "sg") {
		t.Fatalf("dead relay still a home: %v", b.homes)
	}
}

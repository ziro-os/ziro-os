package daemon

import (
	"encoding/base64"
	"net/netip"
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

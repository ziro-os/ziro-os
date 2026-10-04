package router

import (
	"net"
	"net/netip"
	"testing"
)

func TestSTUNAndFrames(t *testing.T) {
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := STUNRequest(tx)
	if got, ok := ParseSTUNRequest(req); !ok || got != tx || !IsSTUN(req) {
		t.Fatal("request round trip")
	}
	for _, a := range []string{"203.0.113.9:41641", "[2001:db8::7]:5000"} {
		ap := netip.MustParseAddrPort(a)
		gtx, got, ok := ParseSTUNResponse(STUNResponse(tx, ap))
		if !ok || gtx != tx || got != ap {
			t.Fatalf("%s: got %v %v", a, got, ok)
		}
	}
	if _, _, ok := ParseSTUNResponse(req); ok {
		t.Fatal("a request parsed as a response")
	}
	if IsSTUN([]byte("ZRD1 not stun at all......")) || IsSTUN(make([]byte, 19)) {
		t.Fatal("non-STUN classified as STUN")
	}
	// truncated / hostile lengths never panic
	resp := STUNResponse(tx, netip.MustParseAddrPort("1.2.3.4:5"))
	for i := range resp {
		ParseSTUNResponse(resp[:i])
	}
	resp[3] = 0xff
	ParseSTUNResponse(resp)

	a, b := net.Pipe()
	ca, cb := NewRelayConn(a), NewRelayConn(b)
	key := [32]byte{9}
	go ca.WriteFrame(FrameSend, key[:], []byte("hello"))
	typ, k, p, err := cb.ReadFrame()
	if err != nil || typ != FrameSend || k != key || string(p) != "hello" {
		t.Fatalf("frame: %v %v %q %v", typ, k, p, err)
	}
	if err := ca.WriteFrame(FrameSend, key[:], make([]byte, MaxFrame)); err == nil {
		t.Fatal("oversized frame written")
	}
}

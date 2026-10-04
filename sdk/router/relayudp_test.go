package router

import (
	"net/netip"
	"testing"
)

func TestRelayUDPCodec(t *testing.T) {
	key := [32]byte{1, 2, 3}
	h := UDPHelloPacket(42, key, 1700000000000)
	if s, ms, ok := ParseUDPHello(h); !ok || s != 42 || ms != 1700000000000 || len(h) != UDPHelloLen || !VerifyUDPHello(h, key) {
		t.Fatal("hello round trip")
	}
	h[20] ^= 1
	if VerifyUDPHello(h, key) {
		t.Fatal("tampered hello verified")
	}
	if VerifyUDPHello(UDPHelloPacket(42, key, 1), [32]byte{9}) {
		t.Fatal("hello verified under another key")
	}
	obs := netip.MustParseAddrPort("[2001:db8::5]:41641")
	a := UDPAckPacket(42, 7, obs)
	if s, ms, got, ok := ParseUDPAck(a); !ok || s != 42 || ms != 7 || got != obs || len(a) >= UDPHelloLen {
		t.Fatal("ack round trip (and no amplification)")
	}
	f := AppendUDPSend(nil, 42, key, []byte("wg"))
	if len(f) != UDPSendHdr+2 || f[0] != UDPSend || [32]byte(f[5:37]) != key {
		t.Fatal("send header")
	}
	if s, k, ok := ParseSessionFrame(SessionFrame(9, key)); !ok || s != 9 || k != key {
		t.Fatal("session frame")
	}
	for _, b := range [][]byte{nil, {UDPHello}, {UDPAck, 0, 0}, make([]byte, 44)} {
		ParseUDPHello(b)
		ParseUDPAck(b)
	}
}

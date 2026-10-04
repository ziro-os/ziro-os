package daemon

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/tun"
)

// ipv4 builds a minimal IPv4 packet with a TCP/UDP header (ports) or an ICMP one.
func ipv4(proto uint8, src, dst string, sport, dport uint16) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	return p
}

func ipv6(proto uint8, src, dst string, sport, dport uint16) []byte {
	p := make([]byte, 48)
	p[0] = 0x60
	p[6] = proto
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(p[8:], s[:])
	copy(p[24:], d[:])
	binary.BigEndian.PutUint16(p[40:], sport)
	binary.BigEndian.PutUint16(p[42:], dport)
	return p
}

// fakeTUN records what reaches the OS and hands out queued outbound packets.
type fakeTUN struct {
	written [][]byte
	out     [][]byte
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return MTU, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 1 }
func (f *fakeTUN) Write(bufs [][]byte, off int) (int, error) {
	f.written = append(f.written, bufs...)
	return len(bufs), nil
}
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, off int) (int, error) {
	n := copy(bufs[0][off:], f.out[0])
	sizes[0], f.out = n, f.out[1:]
	return 1, nil
}

func TestFilter(t *testing.T) {
	ft := &fakeTUN{}
	f := NewFilter(ft)
	me, peer, other := "100.64.0.1", "100.64.0.2", "100.64.0.3"
	deliver := func(p []byte) bool {
		n := len(ft.written)
		if _, err := f.Write([][]byte{p}, 0); err != nil {
			t.Fatal(err)
		}
		return len(ft.written) > n
	}
	ssh := ipv4(protoTCP, peer, me, 40000, 22)
	if deliver(ssh) {
		t.Fatal("default deny: unsolicited packet delivered before any rule")
	}
	f.SetRules([]zr.FilterRule{
		{Src: []string{peer + "/32"}, Dst: []string{me + "/32"}, Proto: "tcp", Ports: []zr.PortRange{{First: 22, Last: 22}}},
		{Src: []string{"0.0.0.0/0", "::/0"}, Dst: []string{me + "/32", "fd7a::1/128"}, Proto: "icmp"},
		{Src: []string{"bogus"}, Dst: []string{me + "/32"}, Proto: "sctp"},
	})
	for _, tc := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"allowed ssh", ssh, true},
		{"wrong port", ipv4(protoTCP, peer, me, 40000, 23), false},
		{"wrong proto", ipv4(protoUDP, peer, me, 40000, 22), false},
		{"wrong source", ipv4(protoTCP, other, me, 40000, 22), false},
		{"icmp any source", ipv4(protoICMP, other, me, 0, 0), true},
		{"icmpv6", ipv6(protoICMPv6, "fd7a::2", "fd7a::1", 0, 0), true},
		{"garbage", []byte{0x45, 0}, false},
		{"not ip", []byte{0x10, 0, 0, 0}, false},
	} {
		if got := deliver(tc.p); got != tc.want {
			t.Errorf("%s: delivered=%v want %v", tc.name, got, tc.want)
		}
	}
	// A reply to a connection this device opened gets in; the same port from elsewhere doesn't.
	ft.out = [][]byte{ipv4(protoTCP, me, other, 50000, 443)}
	buf := [][]byte{make([]byte, 1500)}
	if _, err := f.Read(buf, []int{0}, 0); err != nil {
		t.Fatal(err)
	}
	if !deliver(ipv4(protoTCP, other, me, 443, 50000)) {
		t.Fatal("reply to an outbound flow dropped")
	}
	if deliver(ipv4(protoTCP, other, me, 443, 50001)) {
		t.Fatal("packet to another port passed as a reply")
	}
	// Mixed batch: only allowed packets reach the OS, the count covers the whole batch.
	ft.written = nil
	n, _ := f.Write([][]byte{ssh, ipv4(protoTCP, other, me, 1, 22), ssh}, 0)
	if n != 3 || len(ft.written) != 2 {
		t.Fatalf("batch: n=%d delivered=%d", n, len(ft.written))
	}
	if f.Dropped() == 0 {
		t.Fatal("drops not counted")
	}
	// IPv4 fragment (no ports): passes only when addresses and protocol match a rule.
	frag := ipv4(protoTCP, peer, me, 0, 0)
	binary.BigEndian.PutUint16(frag[6:], 10)
	if !deliver(frag) {
		t.Fatal("later fragment of an allowed flow dropped")
	}
	frag2 := ipv4(protoTCP, other, me, 0, 0)
	binary.BigEndian.PutUint16(frag2[6:], 10)
	if deliver(frag2) {
		t.Fatal("fragment from a disallowed source delivered")
	}
}

func TestPickEndpoint(t *testing.T) {
	if got := pickEndpoint([]string{"10.0.0.5:41641", "203.0.113.7:41641", "[2001:db8::1]:41641"}); got != "203.0.113.7:41641" {
		t.Fatalf("got %s", got)
	}
	if got := pickEndpoint([]string{"127.0.0.1:1", "junk", "192.168.1.2:41641"}); got != "192.168.1.2:41641" {
		t.Fatalf("got %s", got)
	}
	if pickEndpoint(nil) != "" {
		t.Fatal("endpoint from nothing")
	}
}

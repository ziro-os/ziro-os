package cmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// TestRouterRelayUDP: devices get a UDP session over TLS, bind it with an authenticated hello and
// exchange relayed datagrams; spoofed sources, replayed hellos and bad MACs are refused; a
// device without a UDP session still receives over TLS.
func TestRouterRelayUDP(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	certA, khA := relayDevice(t, st, "a")
	certB, khB := relayDevice(t, st, "b")
	certC, khC := relayDevice(t, st, "c")
	state := &zr.State{Members: []zr.Member{
		{ID: "a", Network: n.ID, NodeKey: wgKey(1), KeyHash: khA, Authorized: true},
		{ID: "b", Network: n.ID, NodeKey: wgKey(2), KeyHash: khB, Authorized: true},
		{ID: "c", Network: n.ID, NodeKey: wgKey(3), KeyHash: khC, Authorized: true},
	}}
	s := newRelayServer(func() (*zr.State, error) { return state, nil })
	tc, _ := relayTLS(st.CACert)
	free := func(network string) string {
		if network == "udp" {
			pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
			defer pc.Close()
			return pc.LocalAddr().String()
		}
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		return ln.Addr().String()
	}
	tlsAddr, udpAddr := free("tcp"), free("udp")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runRelay(ctx, s, tlsAddr, udpAddr, tc)
	ca, _ := parseCertPEM(st.CACert)
	relayUDP := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(udpAddr))

	type dev struct {
		rc      *zr.RelayConn
		session uint32
		key     [32]byte
		udp     *net.UDPConn
	}
	open := func(cert *tls.Certificate) *dev {
		t.Helper()
		var d dev
		for i := 0; i < 50; i++ {
			rc, err := zr.DialRelay(ctx, tlsAddr, ca, cert)
			if err == nil {
				d.rc = rc
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if d.rc == nil {
			t.Fatal("relay unreachable")
		}
		typ, _, p, err := d.rc.ReadFrame()
		var ok bool
		if d.session, d.key, ok = zr.ParseSessionFrame(p); err != nil || typ != zr.FrameSession || !ok {
			t.Fatalf("session frame: %v %v", typ, err)
		}
		d.udp, _ = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		t.Cleanup(func() { d.udp.Close() })
		return &d
	}
	read := func(c *net.UDPConn) ([]byte, bool) {
		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		return buf[:n], err == nil
	}
	hello := func(d *dev, from *net.UDPConn, ms uint64, key [32]byte) bool {
		from.WriteToUDP(zr.UDPHelloPacket(d.session, key, ms), relayUDP)
		b, ok := read(from)
		sess, gotMS, obs, ok2 := zr.ParseUDPAck(b)
		return ok && ok2 && sess == d.session && gotMS == ms && obs.Port() == uint16(from.LocalAddr().(*net.UDPAddr).Port)
	}
	key := func(n byte) [32]byte { raw, _ := base64.StdEncoding.DecodeString(wgKey(n)); return [32]byte(raw) }
	a, b, c := open(certA), open(certB), open(certC)
	time.Sleep(100 * time.Millisecond)

	now := uint64(time.Now().UnixMilli())
	var bad [32]byte
	if hello(a, a.udp, now, bad) {
		t.Fatal("hello with a wrong key acknowledged")
	}
	if !hello(a, a.udp, now, a.key) || !hello(b, b.udp, now, b.key) {
		t.Fatal("hello not acknowledged")
	}
	// a -> b over UDP: b receives a datagram carrying a's key (taken from a's session).
	a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("wg-data")), relayUDP)
	got, ok := read(b.udp)
	if !ok || got[0] != zr.UDPRecv || [32]byte(got[1:33]) != key(1) || string(got[33:]) != "wg-data" {
		t.Fatalf("relayed datagram: %v %q", ok, got)
	}
	// A spoofed source with a's session is dropped.
	evil, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer evil.Close()
	evil.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("spoof")), relayUDP)
	if p, ok := read(b.udp); ok {
		t.Fatalf("spoofed datagram delivered: %q", p)
	}
	// A replayed hello from another address neither moves the session nor gets an ack.
	evil.WriteToUDP(zr.UDPHelloPacket(a.session, a.key, now), relayUDP)
	if _, ok := read(evil); ok {
		t.Fatal("replayed hello acknowledged")
	}
	a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("still-a")), relayUDP)
	if got, ok := read(b.udp); !ok || string(got[33:]) != "still-a" {
		t.Fatal("session moved by a replay")
	}
	// c never said hello: it gets a's packet over TLS.
	a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(3), []byte("to-c")), relayUDP)
	_ = c.rc.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		typ, from, p, err := c.rc.ReadFrame()
		if err != nil {
			t.Fatalf("TLS delivery: %v", err)
		}
		if typ == zr.FrameRecv {
			if from != key(1) || string(p) != "to-c" {
				t.Fatalf("TLS frame: %v %q", from, p)
			}
			break
		}
	}
	// STUN on the same port.
	tx := [12]byte{7}
	a.udp.WriteToUDP(zr.STUNRequest(tx), relayUDP)
	if p, ok := read(a.udp); !ok {
		t.Fatal("no STUN answer")
	} else if gtx, _, ok := zr.ParseSTUNResponse(p); !ok || gtx != tx {
		t.Fatal("bad STUN answer")
	}
}

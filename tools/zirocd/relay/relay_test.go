package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// pki is a throwaway cluster CA for tests.
type pki struct {
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{ca: ca, key: k}
}

// issue returns a certificate (and its key hash) with the given CN, OU, DNS names and usages.
func (p *pki) issue(t *testing.T, cn, ou string, dns []string, eku ...x509.ExtKeyUsage) (tls.Certificate, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn, OrganizationalUnit: []string{ou}},
		DNSNames: dns, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, zr.PublicKeyHash(leaf.RawSubjectPublicKeyInfo)
}

func (p *pki) device(t *testing.T, id string) (*tls.Certificate, string) {
	c, kh := p.issue(t, id, zr.DeviceOU, nil, x509.ExtKeyUsageClientAuth)
	return &c, kh
}

func key(b byte) [32]byte {
	var k [32]byte
	k[31] = b
	return k
}

// serve starts a relay presenting cert; it returns the TLS and UDP addresses.
func serve(t *testing.T, ctx context.Context, p *pki, s *Server, cert tls.Certificate) (string, string) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	udpAddr := pc.LocalAddr().String()
	pc.Close()
	go s.Serve(ctx, ln, udpAddr)
	return ln.Addr().String(), udpAddr
}

func dialRelay(t *testing.T, ctx context.Context, r zr.Relay, ca *x509.Certificate, c *tls.Certificate) *zr.RelayConn {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		var rc *zr.RelayConn
		if rc, err = zr.DialRelay(ctx, r, ca, c); err == nil {
			return rc
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

func TestRelay(t *testing.T) {
	p := newPKI(t)
	certA, khA := p.device(t, "a")
	certB, khB := p.device(t, "b")
	certC, khC := p.device(t, "c")
	s := New()
	s.SetMembers(map[string]Member{
		"a": {KeyHash: khA, NodeKey: key(1), Network: "n1"},
		"b": {KeyHash: khB, NodeKey: key(2), Network: "n1"},
		"c": {KeyHash: khC, NodeKey: key(3), Network: "other"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	planetCert, _ := p.issue(t, "m1", zr.MasterOU, []string{zr.ServerName}, x509.ExtKeyUsageServerAuth)
	addr, _ := serve(t, ctx, p, s, planetCert)
	r := zr.Relay{Name: "r1", Addr: addr}
	a, b, c := dialRelay(t, ctx, r, p.ca, certA), dialRelay(t, ctx, r, p.ca, certB), dialRelay(t, ctx, r, p.ca, certC)
	time.Sleep(100 * time.Millisecond) // registered
	recv := func(rc *zr.RelayConn) ([32]byte, string, error) {
		_ = rc.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			typ, from, pl, err := rc.ReadFrame()
			if err != nil || typ == zr.FrameRecv {
				return from, string(pl), err
			}
		}
	}
	kb := key(2)
	if err := a.WriteFrame(zr.FrameSend, kb[:], []byte("wg-packet")); err != nil {
		t.Fatal(err)
	}
	if from, pl, err := recv(b); err != nil || from != key(1) || pl != "wg-packet" {
		t.Fatalf("relayed: %v %q %v (the sender key must come from its certificate)", from, pl, err)
	}
	// Another network's device is never reached.
	kc := key(3)
	_ = a.WriteFrame(zr.FrameSend, kc[:], []byte("leak"))
	if _, pl, err := recv(c); err == nil {
		t.Fatalf("cross-network packet delivered: %q", pl)
	}
	// A certificate another CA signed is refused at the handshake.
	certX, _ := newPKI(t).device(t, "a")
	if rc, err := zr.DialRelay(ctx, r, p.ca, certX); err == nil {
		if _, _, _, err := rc.ReadFrame(); err == nil {
			t.Fatal("foreign certificate served")
		}
	}
	if st := s.Stats(); st.Connected != 3 || st.Relayed == 0 {
		t.Fatalf("stats: %+v", st)
	}
	// Removal drops the device at once.
	s.SetMembers(map[string]Member{"b": {KeyHash: khB, NodeKey: key(2), Network: "n1"}})
	_ = a.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, _, err := a.ReadFrame(); err != nil {
			break
		}
	}
}

// Devices verify a moon by its own name and OU, and a planet's relay as a planet: neither kind of
// certificate passes for the other.
func TestRelayServerIdentity(t *testing.T) {
	p := newPKI(t)
	dev, kh := p.device(t, "a")
	s := New()
	s.SetMembers(map[string]Member{"a": {KeyHash: kh, NodeKey: key(1), Network: "n1"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	moonCert, _ := p.issue(t, "sg-1", zr.MoonOU, []string{zr.MoonServerName("sg-1")}, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	moonAddr, _ := serve(t, ctx, p, s, moonCert)
	forged, _ := p.issue(t, "sg-2", zr.MoonOU, []string{zr.ServerName}, x509.ExtKeyUsageServerAuth) // a moon claiming the planet name
	forgedAddr, _ := serve(t, ctx, p, New(), forged)                                                // a Server owns one UDP socket: one per listener
	time.Sleep(50 * time.Millisecond)

	if _, err := zr.DialRelay(ctx, zr.Relay{Addr: moonAddr, ServerName: zr.MoonServerName("sg-1")}, p.ca, dev); err != nil {
		t.Fatalf("moon refused: %v", err)
	}
	if _, err := zr.DialRelay(ctx, zr.Relay{Addr: moonAddr, ServerName: zr.MoonServerName("other")}, p.ca, dev); err == nil {
		t.Fatal("a moon accepted under another moon's name")
	}
	if _, err := zr.DialRelay(ctx, zr.Relay{Addr: forgedAddr}, p.ca, dev); err == nil {
		t.Fatal("a moon certificate passed as a planet's relay")
	}
}

// TestRelayUDP: devices get a UDP session over TLS, bind it with an authenticated hello and
// exchange relayed datagrams; spoofed sources, replayed hellos and bad MACs are refused; a
// device without a UDP session still receives over TLS.
func TestRelayUDP(t *testing.T) {
	p := newPKI(t)
	certA, khA := p.device(t, "a")
	certB, khB := p.device(t, "b")
	certC, khC := p.device(t, "c")
	s := New()
	s.SetMembers(map[string]Member{
		"a": {KeyHash: khA, NodeKey: key(1), Network: "n1"},
		"b": {KeyHash: khB, NodeKey: key(2), Network: "n1"},
		"c": {KeyHash: khC, NodeKey: key(3), Network: "n1"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	planetCert, _ := p.issue(t, "m1", zr.MasterOU, []string{zr.ServerName}, x509.ExtKeyUsageServerAuth)
	tlsAddr, udpAddr := serve(t, ctx, p, s, planetCert)
	r := zr.Relay{Name: "r1", Addr: tlsAddr}
	relayUDP := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(udpAddr))

	type dev struct {
		rc      *zr.RelayConn
		session uint32
		key     [32]byte
		udp     *net.UDPConn
	}
	open := func(cert *tls.Certificate) *dev {
		t.Helper()
		d := dev{rc: dialRelay(t, ctx, r, p.ca, cert)}
		typ, _, pl, err := d.rc.ReadFrame()
		var ok bool
		if d.session, d.key, ok = zr.ParseSessionFrame(pl); err != nil || typ != zr.FrameSession || !ok {
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
	hello := func(d *dev, from *net.UDPConn, ms uint64, k [32]byte) bool {
		_, _ = from.WriteToUDP(zr.UDPHelloPacket(d.session, k, ms), relayUDP)
		b, ok := read(from)
		sess, gotMS, obs, ok2 := zr.ParseUDPAck(b)
		return ok && ok2 && sess == d.session && gotMS == ms && obs.Port() == uint16(from.LocalAddr().(*net.UDPAddr).Port)
	}
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
	_, _ = a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("wg-data")), relayUDP)
	got, ok := read(b.udp)
	if !ok || got[0] != zr.UDPRecv || [32]byte(got[1:33]) != key(1) || string(got[33:]) != "wg-data" {
		t.Fatalf("relayed datagram: %v %q", ok, got)
	}
	// A spoofed source with a's session is dropped.
	evil, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer evil.Close()
	_, _ = evil.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("spoof")), relayUDP)
	if pl, ok := read(b.udp); ok {
		t.Fatalf("spoofed datagram delivered: %q", pl)
	}
	// A replayed hello from another address neither moves the session nor gets an ack.
	_, _ = evil.WriteToUDP(zr.UDPHelloPacket(a.session, a.key, now), relayUDP)
	if _, ok := read(evil); ok {
		t.Fatal("replayed hello acknowledged")
	}
	_, _ = a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(2), []byte("still-a")), relayUDP)
	if got, ok := read(b.udp); !ok || string(got[33:]) != "still-a" {
		t.Fatal("session moved by a replay")
	}
	// c never said hello: it gets a's packet over TLS.
	_, _ = a.udp.WriteToUDP(zr.AppendUDPSend(nil, a.session, key(3), []byte("to-c")), relayUDP)
	_ = c.rc.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		typ, from, pl, err := c.rc.ReadFrame()
		if err != nil {
			t.Fatalf("TLS delivery: %v", err)
		}
		if typ == zr.FrameRecv {
			if from != key(1) || string(pl) != "to-c" {
				t.Fatalf("TLS frame: %v %q", from, pl)
			}
			break
		}
	}
	if st := s.Stats(); st.UDPSessions != 2 {
		t.Fatalf("stats: %+v, want 2 UDP sessions", st)
	}
	// STUN on the same port.
	tx := [12]byte{7}
	_, _ = a.udp.WriteToUDP(zr.STUNRequest(tx), relayUDP)
	if pl, ok := read(a.udp); !ok {
		t.Fatal("no STUN answer")
	} else if gtx, _, ok := zr.ParseSTUNResponse(pl); !ok || gtx != tx {
		t.Fatal("bad STUN answer")
	}
}

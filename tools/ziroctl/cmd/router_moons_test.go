package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/zirocd/moon"
)

func moonFreeAddr(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().String()
}

// A moon's whole life against a real router: add, register with the one-time token, follow the
// relay map, relay between two devices, renew, and stop at once when removed.
func TestMoonLifecycle(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	certA, khA := relayDevice(t, st, "a")
	certB, khB := relayDevice(t, st, "b")
	routerOf(st).Members = []zr.Member{
		{ID: "a", Network: n.ID, NodeKey: wgKey(1), KeyHash: khA, Authorized: true},
		{ID: "b", Network: n.ID, NodeKey: wgKey(2), KeyHash: khB, Authorized: true},
	}
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	hub := newRouterHub()
	rt := newRouterServer(hub, st.CACert)
	var ver atomic.Uint64
	rt.sync = func() {
		if cur, err := readState(); err == nil {
			hub.setState(routerOf(cur), ver.Add(1))
			rt.moons.setState(cur)
		}
	}
	rt.sync()
	pool, _ := caPool(st.CACert)
	srv := httptest.NewUnstartedServer(rt)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}
	srv.StartTLS()
	defer srv.Close()
	planet := strings.TrimPrefix(srv.URL, "https://")
	listen, stun := moonFreeAddr(t, "tcp"), moonFreeAddr(t, "udp")

	// ziroctl router moon add sg-1 --public <listen>
	var tok string
	if err := withState(func(cur *ClusterState) error {
		R := routerOf(cur)
		R.Endpoints = []string{planet}
		R.Relays = append(R.Relays, zr.Relay{Name: "sg-1", Addr: listen, STUN: stun, ServerName: zr.MoonServerName("sg-1")})
		R.Moons = append(R.Moons, zr.Moon{Name: "sg-1", CreatedAt: time.Now()})
		var e error
		tok, e = moonToken(cur, nil, "sg-1", time.Hour)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	rt.sync()
	hub.mu.Lock()
	announced := len(hub.relays)
	hub.mu.Unlock()
	if announced != 0 {
		t.Fatal("an unregistered moon was announced to devices")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	_, port, _ := net.SplitHostPort(stun)
	stunPort, _ := strconv.Atoi(port)
	done := make(chan error, 1)
	go func() { done <- moon.Run(ctx, moon.Options{Dir: dir, Token: tok, Listen: listen, STUNPort: stunPort}) }()
	waitFor(t, "moon registered and following the relay map", func() bool { rt.sync(); return rt.moons.connected()["sg-1"] })
	if fi, err := os.Stat(filepath.Join(dir, "moon.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("moon state file: %v %v", fi, err)
	}
	hub.mu.Lock()
	announced = len(hub.relays)
	hub.mu.Unlock()
	if announced != 1 {
		t.Fatal("the registered moon is not announced")
	}

	// The token was single use.
	ca, _ := parseCertPEM(st.CACert)
	parsed, _ := zr.ParseMoonToken(tok)
	_, csr, _ := zr.NewTLSKey()
	var se *zr.StatusError
	if _, err := zr.NewClient([]string{planet}, ca, nil).MoonRegister(ctx, zr.MoonRegisterRequest{Name: "sg-1", Secret: parsed.Secret, CSR: string(csr)}); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("token reused: %v", err)
	}

	// Two devices relay through the moon, verified under its own name.
	r := zr.Relay{Addr: listen, ServerName: zr.MoonServerName("sg-1")}
	var a, b *zr.RelayConn
	waitFor(t, "devices on the moon", func() bool {
		var err error
		if a == nil {
			a, _ = zr.DialRelay(ctx, r, ca, certA)
		}
		if b == nil {
			b, err = zr.DialRelay(ctx, r, ca, certB)
		}
		return a != nil && b != nil && err == nil
	})
	kb := keyOf32(wgKey(2))
	got := ""
	waitFor(t, "a relays to b through the moon", func() bool {
		_ = a.WriteFrame(zr.FrameSend, kb[:], []byte("via-moon"))
		got = readRecv(t, b)
		return got == "via-moon"
	})

	// The moon's certificate: renewable, but no device map; a device certificate gets no relay map.
	var ms struct{ Cert, Key string }
	raw, _ := os.ReadFile(filepath.Join(dir, "moon.json"))
	_ = json.Unmarshal(raw, &ms)
	moonCert, _ := tls.X509KeyPair([]byte(ms.Cert), []byte(ms.Key))
	mc := zr.NewClient([]string{planet}, ca, &moonCert)
	csr2, _ := zr.CSR([]byte(ms.Key))
	if out, err := mc.MoonRenew(ctx, csr2); err != nil || !strings.Contains(out.Cert, "BEGIN CERTIFICATE") {
		t.Fatalf("renew: %v", err)
	}
	if err := mc.Map(ctx, zr.MapRequest{}, func(zr.MapMessage) error { return nil }); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("a moon certificate got a device netmap: %v", err)
	}
	dc := zr.NewClient([]string{planet}, ca, certA)
	if err := dc.RelayMap(ctx, func(zr.RelayMapMessage) error { return nil }); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("a device certificate got the relay map: %v", err)
	}

	// ziroctl router moon rm sg-1: the moon stops at once and drops its devices.
	if err := withState(func(cur *ClusterState) error {
		R := routerOf(cur)
		R.Moons, R.Relays = nil, nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rt.sync()
	select {
	case err := <-done:
		if !errors.Is(err, moon.ErrRemoved) {
			t.Fatalf("moon after removal: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("moon kept running after removal")
	}
	_ = a.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, _, err := a.ReadFrame(); err != nil {
			break
		}
	}
}

// moonRegister: a token works once, before it expires, for its own moon only.
func TestMoonRegisterRules(t *testing.T) {
	clusterDir = t.TempDir()
	st, _ := routerTestState(t, zr.ACL{})
	routerOf(st).Endpoints = []string{"planet:7443"}
	routerOf(st).Moons = []zr.Moon{{Name: "sg-1"}, {Name: "fra-1"}}
	tok, err := moonToken(st, nil, "sg-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := zr.ParseMoonToken(tok)
	_, csrPEM, _ := zr.NewTLSKey()
	csr, kh, _ := parseCSR(string(csrPEM))
	now := time.Now()
	if _, err := moonRegister(st, zr.MoonRegisterRequest{Name: "fra-1", Secret: p.Secret}, csr, kh, now); err == nil {
		t.Fatal("sg-1's token registered fra-1")
	}
	if _, err := moonRegister(st, zr.MoonRegisterRequest{Name: "sg-1", Secret: p.Secret}, csr, kh, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired token accepted")
	}
	out, err := moonRegister(st, zr.MoonRegisterRequest{Name: "sg-1", Secret: p.Secret}, csr, kh, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := parseCertPEM(out.Cert)
	if leaf.Subject.OrganizationalUnit[0] != zr.MoonOU || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "sg-1.moon.ziro" ||
		verifyMaster(leaf, st.CACert) == nil {
		t.Fatalf("moon certificate: OU %v, names %v", leaf.Subject.OrganizationalUnit, leaf.DNSNames)
	}
	if _, err := moonRegister(st, zr.MoonRegisterRequest{Name: "sg-1", Secret: p.Secret}, csr, kh, now); err == nil {
		t.Fatal("token used twice")
	}
	if _, err := moonRenew(st, "sg-1", "other-key", csr, kh); err == nil {
		t.Fatal("renewed with a key the moon never registered")
	}
}

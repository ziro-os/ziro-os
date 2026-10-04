package cmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"sync"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// relayDevice issues a device certificate for member id, as the router would.
func relayDevice(t *testing.T, st *ClusterState, id string) (*tls.Certificate, string) {
	t.Helper()
	keyPEM, csrPEM, _ := zr.NewTLSKey()
	csr, kh, err := parseCSR(string(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	crt, err := issueDeviceCert(st, csr, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.X509KeyPair([]byte(crt), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &c, kh
}

func TestRouterRelay(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	certA, khA := relayDevice(t, st, "a")
	certB, khB := relayDevice(t, st, "b")
	certC, khC := relayDevice(t, st, "c")
	var mu sync.Mutex
	state := &zr.State{Members: []zr.Member{
		{ID: "a", Network: n.ID, NodeKey: wgKey(1), KeyHash: khA, Authorized: true},
		{ID: "b", Network: n.ID, NodeKey: wgKey(2), KeyHash: khB, Authorized: true},
		{ID: "c", Network: "other", NodeKey: wgKey(3), KeyHash: khC, Authorized: true},
	}}
	s := newRelayServer(func() (*zr.State, error) {
		mu.Lock()
		defer mu.Unlock()
		cp := *state
		return &cp, nil
	})
	tc, err := relayTLS(st.CACert)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runRelay(ctx, s, addr, "127.0.0.1:0", tc)
	ca, _ := parseCertPEM(st.CACert)
	dial := func(c *tls.Certificate) *zr.RelayConn {
		t.Helper()
		var rc *zr.RelayConn
		var err error
		for i := 0; i < 50; i++ {
			if rc, err = zr.DialRelay(ctx, addr, ca, c); err == nil {
				return rc
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal(err)
		return nil
	}
	key := func(b byte) [32]byte {
		raw, _ := base64.StdEncoding.DecodeString(wgKey(b))
		return [32]byte(raw)
	}
	a, b, c := dial(certA), dial(certB), dial(certC)
	time.Sleep(100 * time.Millisecond) // registered
	recv := func(rc *zr.RelayConn) ([32]byte, string, error) {
		_ = rc.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			typ, from, p, err := rc.ReadFrame()
			if err != nil || typ == zr.FrameRecv {
				return from, string(p), err
			}
		}
	}
	kb := key(2)
	if err := a.WriteFrame(zr.FrameSend, kb[:], []byte("wg-packet")); err != nil {
		t.Fatal(err)
	}
	from, p, err := recv(b)
	if err != nil || from != key(1) || p != "wg-packet" {
		t.Fatalf("relayed: %v %q %v (the sender key must come from its certificate)", from, p, err)
	}
	// Another network's device is never reached.
	kc := key(3)
	a.WriteFrame(zr.FrameSend, kc[:], []byte("leak"))
	if _, p, err := recv(c); err == nil {
		t.Fatalf("cross-network packet delivered: %q", p)
	}
	// A certificate the CA did not sign is refused at the handshake.
	other := &ClusterState{}
	_ = ensureCA(other)
	certX, _ := relayDevice(t, other, "a")
	if rc, err := zr.DialRelay(ctx, addr, ca, certX); err == nil {
		if _, _, _, err := rc.ReadFrame(); err == nil {
			t.Fatal("foreign certificate served")
		}
	}
	// Removal: the relay drops the device at its next refresh.
	mu.Lock()
	state.Members = state.Members[1:]
	mu.Unlock()
	if err := s.refresh(); err != nil {
		t.Fatal(err)
	}
	_ = a.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, _, err := a.ReadFrame(); err != nil {
			break
		}
	}
	ka := key(1)
	b.WriteFrame(zr.FrameSend, ka[:], []byte("to-removed"))
}

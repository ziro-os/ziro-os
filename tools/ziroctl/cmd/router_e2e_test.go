package cmd

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// TestRouterServeE2E runs a standalone router for tests/router/e2e.sh (skipped otherwise):
// network "e2e" where every device may ping every device and only tag:web serves tcp/8080.
// It writes two invites (a plain key and a web-tagged key) and serves until killed.
//
//	ZIRO_E2E_LISTEN=0.0.0.0:7443 ZIRO_E2E_ADVERTISE=router:7443 ZIRO_E2E_OUT=/shared go test -run TestRouterServeE2E
func TestRouterServeE2E(t *testing.T) {
	listen, adv, out := os.Getenv("ZIRO_E2E_LISTEN"), os.Getenv("ZIRO_E2E_ADVERTISE"), os.Getenv("ZIRO_E2E_OUT")
	if listen == "" {
		t.Skip("set ZIRO_E2E_LISTEN to run the e2e router")
	}
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{Rules: []zr.Rule{
		{Src: []string{"*"}, Dst: []string{"*:*"}, Proto: "icmp"},
		{Src: []string{"*"}, Dst: []string{"tag:web:8080"}, Proto: "tcp"},
		{Src: []string{"*"}, Dst: []string{"172.31.2.0/24:*"}, Proto: "icmp"}, // web's LAN, routed by web
	}})
	n.Name = "e2e"
	if err := ensureMasterCert(st, "router", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	relayIP := os.Getenv("ZIRO_E2E_RELAY") // also run a relay (TLS :8443, STUN :3478) announced at this IP
	if relayIP != "" {
		routerOf(st).Relays = []zr.Relay{{Name: "r1", Addr: relayIP + ":8443", STUN: relayIP + ":3478"}}
	}
	plain, web := addJoinKey(st, true, time.Now().Add(time.Hour)), addJoinKey(st, true, time.Now().Add(time.Hour), "web")
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	pin, _ := pemHash(st.CACert)
	for name, key := range map[string]string{"plain": plain, "web": web} {
		inv := zr.Invite{Endpoints: []string{adv}, Pin: pin, Network: n.ID, Key: key}.String()
		if err := os.WriteFile(out+"/key-"+name, []byte(inv), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hub := newRouterHub()
	rt := newRouterServer(hub, st.CACert)
	var ver atomic.Uint64
	rt.sync = func() {
		if cur, err := readState(); err == nil {
			hub.setState(routerOf(cur), ver.Add(1))
		}
	}
	rt.sync()
	if relayIP != "" {
		tc, err := relayTLS(st.CACert)
		if err != nil {
			t.Fatal(err)
		}
		rs := newRelayServer(func() (*zr.State, error) {
			cur, err := readState()
			if err != nil {
				return nil, err
			}
			return routerOf(cur), nil
		})
		go func() { t.Log(runRelay(context.Background(), rs, ":8443", ":3478", tc)) }()
	}
	// Stand-in for `ziroctl router route approve`: approve every advertised route.
	go func() {
		for range time.Tick(time.Second) {
			changed := false
			_ = withState(func(cur *ClusterState) error {
				for i := range routerOf(cur).Members {
					m := &routerOf(cur).Members[i]
					if len(m.Routes) > 0 && len(m.Approved) != len(m.Routes) {
						m.Approved, changed = append([]string(nil), m.Routes...), true
					}
				}
				return nil
			})
			if changed {
				rt.sync()
			}
		}
	}()
	pool, _ := caPool(st.CACert)
	srv := &http.Server{Addr: listen, Handler: rt, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}}
	t.Log("router serving on", listen)
	t.Fatal(srv.ListenAndServeTLS("", ""))
}

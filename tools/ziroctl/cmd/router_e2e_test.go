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
	"github.com/ziro-os/zirocd/relay"
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
		// Two relays: a device compares the ports both saw to tell an easy NAT from a hard one.
		routerOf(st).Relays = []zr.Relay{{Name: "r1", Addr: relayIP + ":8443", STUN: relayIP + ":3478"},
			{Name: "r2", Addr: relayIP + ":8444", STUN: relayIP + ":3479"}}
	}
	// A moon ("m1", zirocd moon in a container at this IP) registers with the token written below.
	moonIP := os.Getenv("ZIRO_E2E_MOON")
	if moonIP != "" {
		R := routerOf(st)
		R.Endpoints = []string{adv}
		R.Relays = append(R.Relays, zr.Relay{Name: "m1", Addr: moonIP + ":8443", STUN: moonIP + ":3478", ServerName: zr.MoonServerName("m1")})
		R.Moons = append(R.Moons, zr.Moon{Name: "m1", CreatedAt: time.Now()})
	}
	// Sign-in: a fake OIDC provider that approves alice@example.com at once.
	idp := newFakeIdP(t, "ziro-router")
	idp.approve(map[string]any{"email": "alice@example.com", "email_verified": true})
	routerOf(st).SSO = &zr.SSO{Issuer: idp.srv.URL, ClientID: "ziro-router"}
	n.SSO = &zr.NetworkSSO{Domains: []string{"example.com"}, Tags: []string{"laptop"}}
	plain, web := addJoinKey(st, true, time.Now().Add(time.Hour)), addJoinKey(st, true, time.Now().Add(time.Hour), "web")
	var moonTok string
	if moonIP != "" {
		var err error
		if moonTok, err = moonToken(st, nil, "m1", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	if moonTok != "" {
		if err := os.WriteFile(out+"/moon-token", []byte(moonTok), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pin, _ := pemHash(st.CACert)
	for name, key := range map[string]string{"plain": plain, "web": web, "sso": ""} { // "sso": a network invite
		inv := zr.Invite{Endpoints: []string{adv}, Pin: pin, Network: n.ID, Key: key}.String()
		if err := os.WriteFile(out+"/key-"+name, []byte(inv), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hub := newRouterHub()
	rt := newRouterServer(hub, st.CACert)
	rt.sso.hc = idp.srv.Client()
	var ver atomic.Uint64
	rt.sync = func() {
		if cur, err := readState(); err == nil {
			hub.setState(routerOf(cur), ver.Add(1))
			rt.moons.setState(cur)
		}
	}
	rt.sync()
	if relayIP != "" {
		tc, err := relayTLS(st.CACert)
		if err != nil {
			t.Fatal(err)
		}
		for _, ports := range [][2]string{{":8443", ":3478"}, {":8444", ":3479"}} {
			rs := relay.New()
			rs.SetRates(10000, 10000) // measure the relay, not the default per-device limit (1 Gbit/s)
			load := func() (*zr.State, error) {
				cur, err := readState()
				if err != nil {
					return nil, err
				}
				return routerOf(cur), nil
			}
			go func(tls, udp string) { t.Log(runPlanetRelay(context.Background(), rs, load, tls, udp, tc)) }(ports[0], ports[1])
		}
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

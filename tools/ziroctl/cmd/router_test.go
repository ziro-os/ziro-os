package cmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

func wgKey(b byte) string { return base64.StdEncoding.EncodeToString(append(make([]byte, 31), b)) }

func testDevice(t *testing.T, name string, n byte) (zr.RegisterRequest, []byte) {
	t.Helper()
	keyPEM, csr, err := zr.NewTLSKey()
	if err != nil {
		t.Fatal(err)
	}
	return zr.RegisterRequest{Name: name, Hostname: name + ".local", OS: "linux", NodeKey: wgKey(n), DiscoKey: wgKey(n + 100), CSR: string(csr)}, keyPEM
}

func registerDev(st *ClusterState, req zr.RegisterRequest, now time.Time) (zr.RegisterResponse, error) {
	if err := checkRegister(&req); err != nil {
		return zr.RegisterResponse{}, err
	}
	csr, kh, err := parseCSR(req.CSR)
	if err != nil {
		return zr.RegisterResponse{}, err
	}
	return routerRegister(st, req, csr, kh, now, nil)
}

func routerTestState(t *testing.T, acl zr.ACL) (*ClusterState, *zr.Network) {
	t.Helper()
	st := &ClusterState{}
	if err := ensureCA(st); err != nil {
		t.Fatal(err)
	}
	R := routerOf(st)
	v4, v6, err := allocNetwork(R, "")
	if err != nil || v4 != "100.64.0.0/16" || !strings.HasPrefix(v6, "fd7a:5a72:") {
		t.Fatalf("alloc: %s %s %v", v4, v6, err)
	}
	R.Networks = append(R.Networks, zr.Network{ID: "aaaabbbbccccdddd", Name: "office", IPv4: v4, IPv6: v6, ACL: acl})
	return st, &R.Networks[0]
}

func addJoinKey(st *ClusterState, reusable bool, exp time.Time, tags ...string) string {
	id, full, hash := routerKeySecret()
	R := routerOf(st)
	R.Keys = append(R.Keys, zr.JoinKey{ID: id, Network: R.Networks[0].ID, Hash: hash, Reusable: reusable, Expires: exp, Tags: tags})
	return full
}

func TestRouterAddressing(t *testing.T) {
	R := &zr.State{Networks: []zr.Network{{IPv4: "100.64.0.0/16"}, {IPv4: "100.65.0.0/16"}}}
	if v4, _, _ := allocNetwork(R, ""); v4 != "100.66.0.0/16" {
		t.Fatalf("next free /16: %s", v4)
	}
	if _, _, err := allocNetwork(R, "100.64.128.0/24"); err == nil {
		t.Fatal("an overlapping --cidr was accepted")
	}
	for _, bad := range []string{"10.0.0.1/16", "10.0.0.0/30", "fd00::/48", "nope"} {
		if _, _, err := allocNetwork(R, bad); err == nil {
			t.Fatalf("--cidr %s accepted", bad)
		}
	}
	n := &zr.Network{ID: "n", IPv4: "100.70.0.0/30", IPv6: "fd7a:5a72:1::/48"}
	v4, v6, err := allocMemberIP(&zr.State{}, n)
	if err != nil || v4 != "100.70.0.1" || v6 != "fd7a:5a72:1::6446:1" {
		t.Fatalf("member ip: %s %s %v", v4, v6, err)
	}
	full := &zr.State{Members: []zr.Member{{Network: "n", IPv4: "100.70.0.1"}, {Network: "n", IPv4: "100.70.0.2"}}}
	if _, _, err := allocMemberIP(full, n); err == nil {
		t.Fatal("a full /30 handed out its broadcast address")
	}
}

func TestRouterACL(t *testing.T) {
	acl := zr.ACL{
		Groups: map[string][]string{"admins": {"alice"}},
		Rules: []zr.Rule{
			{Src: []string{"group:admins"}, Dst: []string{"*:*"}},
			{Src: []string{"tag:web"}, Dst: []string{"tag:db:5432"}, Proto: "tcp"},
			{Src: []string{"tag:web"}, Dst: []string{"10.9.0.0/16:443"}},
		},
	}
	if err := validateACL(acl); err != nil {
		t.Fatal(err)
	}
	m := func(id, ip string, tags ...string) *zr.Member {
		return &zr.Member{ID: id, Name: id, IPv4: ip, Tags: tags, Authorized: true}
	}
	alice, web, db, gw, other := m("alice", "100.64.0.1"), m("web", "100.64.0.2", "web"), m("db", "100.64.0.3", "db"),
		m("gw", "100.64.0.4"), m("other", "100.64.0.5")
	gw.Approved = []string{"10.9.0.0/16"}
	c := compileACL(acl, []*zr.Member{alice, web, db, gw, other})

	for _, tc := range []struct {
		src, dst *zr.Member
		proto    string
		port     uint16
		want     bool
	}{
		{alice, db, "tcp", 22, true},
		{web, db, "tcp", 5432, true},
		{web, db, "udp", 5432, false}, // proto
		{web, db, "tcp", 22, false},   // port
		{db, web, "tcp", 80, false},   // direction
		{other, db, "tcp", 5432, false},
	} {
		if got := c.allowed(tc.src, tc.dst, tc.proto, tc.port); got != tc.want {
			t.Errorf("%s -> %s %d/%s = %v, want %v", tc.src.ID, tc.dst.ID, tc.port, tc.proto, got, tc.want)
		}
	}
	// Least visibility: "other" is only a destination of the admins, so it sees alice and no one else.
	if vis, filter := c.view(other); len(vis) != 1 || !vis["alice"] || len(filter) != 1 {
		t.Fatalf("other sees %v / %v", vis, filter)
	}
	if vis, _ := c.view(db); vis["other"] || !vis["web"] || !vis["alice"] {
		t.Fatalf("db sees %v", vis)
	}
	// web reaches the subnet behind gw; gw filters for the routed /16 on 443 only.
	if vis, _ := c.view(web); !vis["gw"] {
		t.Fatalf("web must see the subnet router: %v", vis)
	}
	_, gf := c.view(gw)
	found := false
	for _, f := range gf {
		if len(f.Dst) == 1 && f.Dst[0] == "10.9.0.0/16" && len(f.Ports) == 1 && f.Ports[0].First == 443 {
			found = true
		}
	}
	if !found {
		t.Fatalf("gw filter lacks the routed subnet: %+v", gf)
	}

	for _, bad := range []zr.ACL{
		{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*"}}}},            // no ports
		{Rules: []zr.Rule{{Src: []string{"group:nope"}, Dst: []string{"*:*"}}}}, // unknown group
		{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:0"}}}},
		{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:90-80"}}}},
		{Rules: []zr.Rule{{Src: []string{"Tag:X"}, Dst: []string{"*:*"}}}},
		{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:*"}, Proto: "sctp"}}},
	} {
		if validateACL(bad) == nil {
			t.Errorf("accepted %+v", bad.Rules)
		}
	}
}

func TestRouterRegister(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{})
	now := time.Now()
	single := addJoinKey(st, false, now.Add(time.Hour), "ci")

	a, _ := testDevice(t, "alpha", 1)
	a.Key = single
	out, err := registerDev(st, a, now)
	if err != nil || out.Status != "authorized" || out.IPv4 != "100.64.0.1" || out.Cert == "" {
		t.Fatalf("register: %+v %v", out, err)
	}
	crt, _ := parseCertPEM(out.Cert)
	if crt.Subject.CommonName != out.Member || verifyMaster(crt, st.CACert) == nil {
		t.Fatal("a device certificate must never pass as a master")
	}
	if m := findMember(routerOf(st), n.ID, "alpha"); m == nil || m.Tags[0] != "ci" {
		t.Fatal("key tags not applied")
	}
	// Lost reply: the same device retries with the consumed key and gets the same member.
	again, err := registerDev(st, a, now)
	if err != nil || again.Member != out.Member {
		t.Fatalf("retry: %+v %v", again, err)
	}
	// Another device cannot reuse a single-use key.
	b, _ := testDevice(t, "alpha", 2)
	b.Key = single
	if _, err := registerDev(st, b, now); !errors.Is(err, errBadJoinKey) {
		t.Fatalf("single-use key reused: %v", err)
	}
	// Wrong secret, expired key.
	b.Key = strings.Split(single, ".")[0] + ".00"
	if _, err := registerDev(st, b, now); !errors.Is(err, errBadJoinKey) {
		t.Fatal("wrong secret accepted")
	}
	b.Key = addJoinKey(st, true, now.Add(-time.Second))
	if _, err := registerDev(st, b, now); !errors.Is(err, errBadJoinKey) {
		t.Fatal("expired key accepted")
	}
	// A reused node key is refused.
	c, _ := testDevice(t, "gamma", 1)
	c.Key = addJoinKey(st, true, now.Add(time.Hour))
	if _, err := registerDev(st, c, now); err == nil {
		t.Fatal("duplicate node key accepted")
	}
	// Same name: the newcomer gets a suffix.
	b.Key = c.Key
	outB, err := registerDev(st, b, now)
	if err != nil || findMember(routerOf(st), n.ID, outB.Member).Name == "alpha" {
		t.Fatalf("name clash: %v", err)
	}

	// Approval flow: by network ID only, pending until approved, then the same CSR gets a cert.
	d, _ := testDevice(t, "delta", 4)
	d.Network = "office"
	if _, err := registerDev(st, d, now); err == nil {
		t.Fatal("joined by network name (guessable)")
	}
	d.Network = n.ID
	p, err := registerDev(st, d, now)
	if err != nil || p.Status != "pending" || p.Cert != "" {
		t.Fatalf("pending: %+v %v", p, err)
	}
	findMember(routerOf(st), n.ID, p.Member).Authorized = true
	if p2, err := registerDev(st, d, now); err != nil || p2.Status != "authorized" || p2.Member != p.Member {
		t.Fatalf("approved: %+v %v", p2, err)
	}

	// Advertised routes are kept; a withdrawn route loses its approval.
	e, _ := testDevice(t, "gw", 5)
	e.Key, e.Routes = c.Key, []string{"10.9.0.0/16"}
	oe, _ := registerDev(st, e, now)
	findMember(routerOf(st), n.ID, oe.Member).Approved = []string{"10.9.0.0/16"}
	e.Routes = nil
	registerDev(st, e, now)
	if m := findMember(routerOf(st), n.ID, oe.Member); len(m.Approved) != 0 {
		t.Fatal("withdrawn route kept its approval")
	}

	// Housekeeping: stale pending requests and offline ephemeral members go.
	routerOf(st).Members = append(routerOf(st).Members, zr.Member{ID: "old", Network: n.ID, CreatedAt: now.Add(-8 * 24 * time.Hour)},
		zr.Member{ID: "eph", Network: n.ID, Authorized: true, Ephemeral: true})
	gone := routerHousekeeping(st, func(string) time.Time { return now.Add(-time.Hour) }, now)
	if strings.Join(gone, ",") != "old,eph" {
		t.Fatalf("housekeeping removed %v", gone)
	}
}

func TestRouterHub(t *testing.T) {
	st := &zr.State{Networks: []zr.Network{{ID: "n1", Name: "office", IPv4: "100.64.0.0/16",
		ACL: zr.ACL{Rules: []zr.Rule{{Src: []string{"tag:a"}, Dst: []string{"tag:b:*"}}}}}}}
	for i, id := range []string{"a1", "b1", "c1"} {
		st.Members = append(st.Members, zr.Member{ID: id, Name: id, Network: "n1", IPv4: "100.64.0." + string(rune('1'+i)),
			Tags: []string{id[:1]}, Authorized: true, KeyHash: "h" + id})
	}
	h := newRouterHub()
	h.setState(st, 1)
	read := func(s *routerSub) zr.MapMessage {
		t.Helper()
		select {
		case b := <-s.ch:
			var m zr.MapMessage
			_ = json.Unmarshal(b, &m)
			return m
		case <-time.After(time.Second):
			t.Fatal("no message")
		}
		return zr.MapMessage{}
	}
	none := func(s *routerSub) {
		t.Helper()
		select {
		case b := <-s.ch:
			t.Fatalf("unexpected message %s", b)
		default:
		}
	}
	if _, err := h.authorize("a1", "wrong"); err == nil {
		t.Fatal("wrong key hash authorized")
	}
	sa, _ := h.subscribe("a1")
	full := read(sa)
	if full.Type != "full" || len(full.Peers) != 1 || full.Peers[0].ID != "b1" || full.Domain != "office.ziro" {
		t.Fatalf("a1 full map: %+v", full)
	}
	sc, _ := h.subscribe("c1")
	if m := read(sc); len(m.Peers) != 0 || len(m.Filter) != 0 {
		t.Fatalf("c1 is in no rule and must see nobody: %+v", m)
	}
	sb, _ := h.subscribe("b1")
	if m := read(sb); len(m.Peers) != 1 || m.Peers[0].ID != "a1" || len(m.Filter) != 1 {
		t.Fatalf("b1 full map: %+v", m)
	}
	if m := read(sa); len(m.Peers) != 1 || !m.Peers[0].Online { // b1 came online
		t.Fatalf("a1 must hear b1 come online: %+v", m)
	}
	none(sc)

	// Endpoint change: only viewers of b1 hear it.
	h.updateSoft("b1", zr.MapRequest{Endpoints: []string{"203.0.113.9:41641"}})
	if m := read(sa); m.Peers[0].Endpoints[0] != "203.0.113.9:41641" {
		t.Fatalf("endpoint delta: %+v", m)
	}
	none(sc)
	if m := read(sb); m.Self == nil || m.Self.Endpoints[0] != "203.0.113.9:41641" {
		t.Fatalf("b1 must see its own endpoints: %+v", m)
	}

	// ACL change: c1 becomes reachable from a1.
	st2 := *st
	st2.Networks = []zr.Network{st.Networks[0]}
	st2.Networks[0].ACL.Rules = append(st2.Networks[0].ACL.Rules, zr.Rule{Src: []string{"tag:a"}, Dst: []string{"tag:c:22"}})
	h.setState(&st2, 2)
	if m := read(sa); len(m.Peers) != 1 || m.Peers[0].ID != "c1" {
		t.Fatalf("a1 delta: %+v", m)
	}
	if m := read(sc); len(m.Peers) != 1 || !m.FilterChanged {
		t.Fatalf("c1 delta: %+v", m)
	}
	// Revocation: b1 removed -> its stream closes, a1 gets a removal.
	st3 := st2
	st3.Members = []zr.Member{st.Members[0], st.Members[2]}
	h.setState(&st3, 3)
	select {
	case <-sb.done:
	default:
		t.Fatal("revoked device's stream still open")
	}
	if m := read(sa); len(m.Removed) != 1 || m.Removed[0] != "b1" {
		t.Fatalf("a1 removal: %+v", m)
	}
	// A slow client is dropped, not waited for.
	for i := 0; i < subBuffer+1; i++ {
		h.updateSoft("c1", zr.MapRequest{Endpoints: []string{"198.51.100.1:" + string(rune('1'+i%9)) + "000"}})
	}
	select {
	case <-sa.done:
	default:
		t.Fatal("a stalled stream was kept")
	}
}

// TestRouterEndToEnd runs the real handler over TLS with the SDK client: pin the CA, join with a
// key, stream the netmap, see a second device arrive, renew, and get cut off on removal.
func TestRouterEndToEnd(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:*"}}}})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	key := addJoinKey(st, true, time.Now().Add(time.Hour))
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}

	hub := newRouterHub()
	rt := newRouterServer(hub, st.CACert)
	var ver atomic.Uint64
	rt.sync = func() {
		cur, err := readState()
		if err != nil {
			t.Error(err)
			return
		}
		hub.setState(routerOf(cur), ver.Add(1))
	}
	rt.sync()
	pool, _ := caPool(st.CACert)
	srv := httptest.NewUnstartedServer(rt)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	pin, _ := pemHash(st.CACert)
	inv, err := zr.ParseInvite(zr.Invite{Endpoints: []string{addr}, Pin: pin, Network: n.ID, Key: key}.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := zr.PinCA(ctx, addr, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("a wrong pin was accepted")
	}
	ca, err := zr.PinCA(ctx, addr, inv.Pin)
	if err != nil {
		t.Fatal(err)
	}

	join := func(name string, n byte) (*zr.Client, zr.RegisterResponse, []byte) {
		req, keyPEM := testDevice(t, name, n)
		req.Key = inv.Key
		c := zr.NewClient(inv.Endpoints, ca, nil)
		out, err := c.Register(ctx, req)
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		cert, err := tls.X509KeyPair([]byte(out.Cert), keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		c.SetCert(&cert)
		return c, out, keyPEM
	}
	c1, r1, key1 := join("laptop", 1)

	// No certificate, no map.
	anon := zr.NewClient(inv.Endpoints, ca, nil)
	var se *zr.StatusError
	if err := anon.Map(ctx, zr.MapRequest{}, func(zr.MapMessage) error { return nil }); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous map: %v", err)
	}

	msgs := make(chan zr.MapMessage, 16)
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- c1.Map(ctx, zr.MapRequest{Endpoints: []string{"192.0.2.1:41641"}, Version: "1.0.20"}, func(m zr.MapMessage) error {
			msgs <- m
			return nil
		})
	}()
	next := func() zr.MapMessage {
		t.Helper()
		select {
		case m := <-msgs:
			return m
		case err := <-streamErr:
			t.Fatalf("stream ended: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("no netmap message")
		}
		return zr.MapMessage{}
	}
	if m := next(); m.Type != "full" || m.Self == nil || m.Self.Addresses[0] != r1.IPv4+"/32" || len(m.Peers) != 0 {
		t.Fatalf("full map: %+v", m)
	}
	_, r2, _ := join("server", 2)
	m := next()
	for len(m.Peers) == 0 {
		m = next()
	}
	if m.Peers[0].ID != r2.Member || m.Peers[0].NodeKey != wgKey(2) {
		t.Fatalf("second device delta: %+v", m)
	}

	// Renewal with a new key: the old certificate stops working at once.
	newKey, csr, _ := zr.NewTLSKey()
	crtPEM, err := c1.Renew(ctx, csr)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := tls.X509KeyPair([]byte(r1.Cert), key1)
	stale := zr.NewClient(inv.Endpoints, ca, &old)
	if err := stale.UpdateEndpoints(ctx, zr.MapRequest{}); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("old certificate after rotation: %v", err)
	}
	fresh, _ := tls.X509KeyPair([]byte(crtPEM), newKey)
	c1.SetCert(&fresh)
	if err := c1.UpdateEndpoints(ctx, zr.MapRequest{Endpoints: []string{"192.0.2.1:41642"}}); err != nil {
		t.Fatalf("renewed certificate: %v", err)
	}

	// Removal ends the stream within the hub's next load.
	if err := withState(func(cur *ClusterState) error {
		R := routerOf(cur)
		var keep []zr.Member
		for _, m := range R.Members {
			if m.ID != r1.Member {
				keep = append(keep, m)
			}
		}
		R.Members = keep
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rt.sync()
	select {
	case <-streamErr:
	case <-time.After(10 * time.Second):
		t.Fatal("removed device kept its stream")
	}
	if err := c1.UpdateEndpoints(ctx, zr.MapRequest{}); !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("removed device still authorized: %v", err)
	}
}

// BenchmarkRouterHub: 10k devices in 100 teams (each team a full mesh, plus admins reaching
// all), every device streaming. Reports a state reload and an endpoint change fan-out.
//
//	go test ./cmd -run x -bench RouterHub -benchtime 3x
func BenchmarkRouterHub(b *testing.B) {
	st := &zr.State{Networks: []zr.Network{{ID: "n1", Name: "corp", IPv4: "100.64.0.0/10",
		ACL: zr.ACL{Rules: []zr.Rule{{Src: []string{"tag:admin"}, Dst: []string{"*:22"}}}}}}}
	for t := 0; t < 100; t++ {
		tag := "team" + strconv.Itoa(t)
		st.Networks[0].ACL.Rules = append(st.Networks[0].ACL.Rules, zr.Rule{Src: []string{"tag:" + tag}, Dst: []string{"tag:" + tag + ":*"}})
	}
	for i := 0; i < 10000; i++ {
		tags := []string{"team" + strconv.Itoa(i%100)}
		if i < 10 {
			tags = append(tags, "admin")
		}
		ip := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})
		st.Members = append(st.Members, zr.Member{ID: "m" + strconv.Itoa(i), Name: "m" + strconv.Itoa(i), Network: "n1",
			IPv4: ip.String(), Tags: tags, Authorized: true})
	}
	h := newRouterHub()
	h.setState(st, 1)
	var subs []*routerSub
	for i := range st.Members {
		s, _ := h.subscribe(st.Members[i].ID)
		subs = append(subs, s)
	}
	drain := func() {
		for _, s := range subs {
			for len(s.ch) > 0 {
				<-s.ch
			}
		}
	}
	drain()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		h.updateSoft("m42", zr.MapRequest{Endpoints: []string{"192.0.2.1:" + strconv.Itoa(1000+i)}})
		fan := time.Since(t0)
		drain()
		st.Networks[0].ClientVersion = "1.0." + strconv.Itoa(i)
		t0 = time.Now()
		h.setState(st, uint64(i+2))
		b.ReportMetric(float64(fan.Microseconds()), "endpoint-fanout-µs")
		b.ReportMetric(float64(time.Since(t0).Milliseconds()), "reload-ms")
		drain()
	}
}

func TestRouterKeyRedacted(t *testing.T) {
	got := strings.Join(redactArgs([]string{"router", "join", "--key", "zr1_secret", "--key=zr1_s2", "--name", "gw",
		"zr1_positional", "ZIROCD_KEY=zr1_env"}), " ")
	if strings.Contains(got, "secret") || strings.Contains(got, "zr1_") || !strings.Contains(got, "--name gw") {
		t.Fatalf("router key leaked into the audit log: %s", got)
	}
}

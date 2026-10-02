package cmd

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
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

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/bcrypt"
)

func echoUpstream(t testing.TB, name string, h func(w http.ResponseWriter, r *http.Request)) string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, name+" "+r.URL.Path)
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func v2Server(t testing.TB, routes ...GatewayRouteState) *gatewayServer {
	t.Helper()
	g := newGatewayServer()
	g.log = func(any) {}
	if err := g.load(&GatewayConfig{Routes: routes}); err != nil {
		t.Fatal(err)
	}
	return g
}

func rs(r GatewayRoute, targets ...string) GatewayRouteState {
	if r.TLS == "" {
		r.TLS = "off"
	}
	if len(r.To) == 0 && r.Redirect == "" && r.Respond == nil {
		r.To = []GatewayUpstream{{App: "x"}}
	}
	out := GatewayRouteState{GatewayRoute: r, Upstreams: targets}
	for _, a := range targets {
		out.Targets = append(out.Targets, GatewayTarget{Addr: a, Weight: 1})
	}
	return out
}

func body(w *httptest.ResponseRecorder) string { return w.Body.String() }

func TestGatewayV2Matching(t *testing.T) {
	a := echoUpstream(t, "A", nil)
	b := echoUpstream(t, "B", nil)
	c := echoUpstream(t, "C", nil)
	d := echoUpstream(t, "D", nil)
	g := v2Server(t,
		rs(GatewayRoute{Name: "wild", Hosts: []string{"*.example.test"}}, a),
		rs(GatewayRoute{Name: "exact", Hosts: []string{"api.example.test"}, PathPrefix: "/health", PathExact: true}, b),
		rs(GatewayRoute{Name: "post", Hosts: []string{"api.example.test"}, Methods: []string{"POST"}}, c),
		rs(GatewayRoute{Name: "beta", Hosts: []string{"api.example.test"}, Headers: map[string]string{"X-Beta": "1"}}, d),
	)
	h := g.handler(false)
	cl := "10.0.0.1:1"
	for _, tc := range []struct{ method, host, path, hdr, want string }{
		{"GET", "app.example.test", "/x", "", "A /x"},           // wildcard, one label
		{"GET", "api.example.test", "/health", "", "B /health"}, // exact path beats wildcard
		{"GET", "api.example.test", "/healthz", "", "A /healthz"},
		{"POST", "api.example.test", "/y", "", "C /y"},   // method matcher
		{"GET", "api.example.test", "/y", "1", "D /y"},   // header matcher
		{"GET", "a.b.example.test", "/", "", "no route"}, // wildcard is one label only
	} {
		r := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
		r.RemoteAddr = cl
		if tc.hdr != "" {
			r.Header.Set("X-Beta", tc.hdr)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !strings.HasPrefix(body(w), tc.want) {
			t.Errorf("%s %s%s: got %d %q, want %q", tc.method, tc.host, tc.path, w.Code, body(w), tc.want)
		}
	}
}

func TestGatewayV2LoadBalancing(t *testing.T) {
	a := echoUpstream(t, "A", nil)
	b := echoUpstream(t, "B", nil)
	weighted := rs(GatewayRoute{Name: "w", Hosts: []string{"w.test"}})
	weighted.Targets = []GatewayTarget{{Addr: a, Weight: 9}, {Addr: b, Weight: 1}}
	ipHash := rs(GatewayRoute{Name: "ih", Hosts: []string{"ih.test"}, LB: "ip_hash"}, a, b)
	sticky := rs(GatewayRoute{Name: "ck", Hosts: []string{"ck.test"}, LB: "cookie", TLS: "internal"}, a, b)
	g := v2Server(t, weighted, ipHash, sticky)
	h := g.handler(false)
	hs := g.handler(true)
	count := map[string]int{}
	for i := 0; i < 100; i++ {
		count[strings.Fields(body(gwGet(h, "GET", "w.test", "/", "10.0.0.1:1", "")))[0]]++
	}
	if count["A"] != 90 || count["B"] != 10 {
		t.Fatalf("weights 9:1: %v", count)
	}
	first := body(gwGet(h, "GET", "ih.test", "/", "10.0.0.7:1", ""))
	for i := 0; i < 10; i++ {
		if body(gwGet(h, "GET", "ih.test", "/", "10.0.0.7:2", "")) != first {
			t.Fatal("ip_hash must keep a client on one upstream")
		}
	}
	w := gwGet(hs, "GET", "ck.test", "/", "10.0.0.1:1", "")
	ck := w.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || !ck[0].Secure {
		t.Fatalf("sticky cookie: %v", ck)
	}
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "http://ck.test/", nil)
		r.RemoteAddr = "10.0.0.1:1"
		r.AddCookie(ck[0])
		rec := httptest.NewRecorder()
		hs.ServeHTTP(rec, r)
		if body(rec) != body(w) {
			t.Fatal("cookie must pin the upstream")
		}
	}
	// least_conn: a slow upstream holding a request makes the next one go elsewhere.
	release := make(chan struct{})
	slow := echoUpstream(t, "S", func(w http.ResponseWriter, r *http.Request) { <-release; io.WriteString(w, "S") })
	fast := echoUpstream(t, "F", nil)
	g2 := v2Server(t, rs(GatewayRoute{Name: "lc", Hosts: []string{"lc.test"}, LB: "least_conn"}, slow, fast))
	h2 := g2.handler(false)
	done := make(chan struct{})
	go func() { gwGet(h2, "GET", "lc.test", "/", "10.0.0.1:1", ""); close(done) }()
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if got := body(gwGet(h2, "GET", "lc.test", "/", "10.0.0.1:1", "")); !strings.HasPrefix(got, "F") {
			t.Fatalf("least_conn sent a request to the busy upstream: %q", got)
		}
	}
	close(release)
	<-done
}

func TestGatewayV2HealthAndRetries(t *testing.T) {
	var sick atomic.Bool
	sick.Store(true)
	a := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && sick.Load() {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, "A")
	})
	b := echoUpstream(t, "B", nil)
	route := rs(GatewayRoute{Name: "h", Hosts: []string{"h.test"}, Health: &GatewayHealth{Path: "/healthz", Interval: "1s"}}, a, b)
	g := v2Server(t, route)
	defer func() {
		for _, c := range g.checks {
			c()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	h := g.handler(false)
	for i := 0; i < 6; i++ {
		if got := body(gwGet(h, "GET", "h.test", "/", "10.0.0.1:1", "")); strings.HasPrefix(got, "A") {
			t.Fatal("unhealthy upstream received traffic")
		}
	}
	sick.Store(false)
	time.Sleep(1500 * time.Millisecond)
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		seen[body(gwGet(h, "GET", "h.test", "/", "10.0.0.1:1", ""))[:1]] = true
	}
	if !seen["A"] {
		t.Fatal("recovered upstream not used again")
	}

	// Retries: a dead upstream costs no failed GET; a POST is never resent.
	dead := "127.0.0.1:1"
	r := rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}, Retries: 1}, dead, b)
	g2 := v2Server(t, r)
	h2 := g2.handler(false)
	for i := 0; i < 4; i++ {
		if w := gwGet(h2, "GET", "r.test", "/", "10.0.0.1:1", ""); w.Code != 200 {
			t.Fatalf("GET with retries got %d", w.Code)
		}
	}
	g3 := v2Server(t, rs(GatewayRoute{Name: "p", Hosts: []string{"p.test"}, Retries: 1}, dead))
	if w := gwGet(g3.handler(false), "POST", "p.test", "/", "10.0.0.1:1", "x"); w.Code != http.StatusBadGateway {
		t.Fatalf("POST to a dead upstream: %d", w.Code)
	}
}

func TestGatewayV2Transforms(t *testing.T) {
	up := echoUpstream(t, "U", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "secret-version")
		io.WriteString(w, `{"path":"`+r.URL.Path+`","x":"`+r.Header.Get("X-Env")+`","rid":"`+r.Header.Get("X-Request-ID")+`","pad":"`+strings.Repeat("z", 2000)+`"}`)
	})
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret-pass"), bcrypt.MinCost)
	g := v2Server(t,
		rs(GatewayRoute{Name: "api", Hosts: []string{"t.test"}, PathPrefix: "/api", StripPrefix: "/api", Compress: true,
			RequestHeaders: &HeaderRules{Set: map[string]string{"X-Env": "prod"}}, ResponseHeaders: &HeaderRules{Remove: []string{"Server"}},
			BasicAuth: map[string]string{"admin": string(hash)}}, up),
		rs(GatewayRoute{Name: "old", Hosts: []string{"old.test"}, Redirect: "https://new.test{uri}", RedirectCode: 301}),
		rs(GatewayRoute{Name: "maint", Hosts: []string{"m.test"}, Respond: &GatewayRespond{Status: 503, Body: "maintenance"}}),
	)
	h := g.handler(false)
	if w := gwGet(h, "GET", "t.test", "/api/users", "10.0.0.1:1", ""); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("basic auth: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "http://t.test/api/users", nil)
	r.RemoteAddr = "10.0.0.1:1"
	r.SetBasicAuth("admin", "s3cret-pass")
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || w.Header().Get("Server") != "" || w.Header().Get("X-Request-ID") == "" {
		t.Fatalf("transforms: %d %v", w.Code, w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.NewDecoder(zr).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["path"] != "/users" || got["x"] != "prod" || got["rid"] != w.Header().Get("X-Request-ID") {
		t.Fatalf("upstream saw %v", got)
	}
	if w := gwGet(h, "GET", "old.test", "/a?b=1", "10.0.0.1:1", ""); w.Code != 301 || w.Header().Get("Location") != "https://new.test/a?b=1" {
		t.Fatalf("redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := gwGet(h, "GET", "m.test", "/", "10.0.0.1:1", ""); w.Code != 503 || body(w) != "maintenance" {
		t.Fatalf("respond: %d %q", w.Code, body(w))
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestGatewayV2TCPAndSNIPassthrough(t *testing.T) {
	// TCP route: an echo upstream behind a gateway listener.
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := freePort(t)
	tcp := rs(GatewayRoute{Name: "db", Kind: "tcp", Listen: port}, echo.Addr().String())
	tcp.TLS = ""
	g := v2Server(t, tcp)
	g.syncL4Listeners()
	defer func() {
		for _, l := range g.l4 {
			l.Close()
		}
	}()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "ping\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "ping\n" {
		t.Fatalf("tcp route echo: %q", line)
	}

	// TLS passthrough: SNI pass.test reaches the upstream's own certificate; anything else goes
	// to the HTTPS server.
	upTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "passthrough") }))
	defer upTLS.Close()
	pt := rs(GatewayRoute{Name: "pt", Kind: "tls", Hosts: []string{"pass.test"}}, strings.TrimPrefix(upTLS.URL, "https://"))
	pt.TLS = ""
	g2 := v2Server(t, pt)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	https := &chanListener{ch: make(chan net.Conn, 4), addr: ln.Addr(), done: make(chan struct{})}
	go g2.splitTLS(ln, https)
	defer ln.Close()
	pool := x509.NewCertPool()
	pool.AddCert(upTLS.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }}}
	// httptest certificates are for example.com; send SNI pass.test but verify example.com.
	cl.Transport.(*http.Transport).TLSClientConfig.ServerName = "pass.test"
	cl.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	resp, err := cl.Get("https://pass.test/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "passthrough" || !resp.TLS.PeerCertificates[0].Equal(upTLS.Certificate()) {
		t.Fatalf("passthrough reached %q", b)
	}
	go func() {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "other.test", InsecureSkipVerify: true})
		if err == nil {
			c.Close()
		}
	}()
	select {
	case c := <-https.ch:
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("non-passthrough SNI not handed to the HTTPS server")
	}
}

func TestGatewayV2InternalCA(t *testing.T) {
	dir := t.TempDir()
	old := gatewayCertDir
	gatewayCertDir = dir
	defer func() { gatewayCertDir = old }()
	g := v2Server(t, rs(GatewayRoute{Name: "in", Hosts: []string{"grafana.internal"}, TLS: "internal"}, "127.0.0.1:9"))
	cert, err := g.getCertificate(&tls.ClientHelloInfo{ServerName: "grafana.internal"})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "internal-ca.crt"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no CA written")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "grafana.internal"}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "internal-ca.key")); fi.Mode().Perm() != 0600 {
		t.Fatal("CA key must be 0600")
	}
	if _, err := g.getCertificate(&tls.ClientHelloInfo{ServerName: "unknown.test"}); err == nil {
		t.Fatal("certificate for a host without a route")
	}
}

func TestGatewayLocalStoreAndAPI(t *testing.T) {
	stubApps(t)
	dir := t.TempDir()
	oldDir := gatewayLocalDir
	gatewayLocalDir = dir
	oldSync := syncLocalGatewayService
	var running bool
	syncLocalGatewayService = func(on bool) error { running = on; return nil }
	defer func() { gatewayLocalDir, syncLocalGatewayService = oldDir, oldSync }()
	saveAppInstance(&AppInstance{Name: "web", App: "web", Mode: "local", Publish: "0.0.0.0:8080"})
	s := localRouteStore{dir: dir}

	r, err := exposeRoute("web", "www.test", "/", "auto", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := putRoute(s, r); err != nil {
		t.Fatal(err)
	}
	if !running {
		t.Fatal("gateway service not started with the first route")
	}
	cfg, _ := s.config()
	if len(cfg.Routes) != 1 || strings.Join(cfg.Routes[0].Upstreams, ",") != "127.0.0.1:8080" {
		t.Fatalf("local resolution: %+v", cfg.Routes)
	}
	dup := GatewayRoute{Name: "web2", Hosts: []string{"www.test"}, To: []GatewayUpstream{{App: "web"}}}
	if _, err := putRoute(s, dup); err == nil || !strings.Contains(err.Error(), "already serves") {
		t.Fatalf("duplicate route: %v", err)
	}
	if _, err := putRoute(s, GatewayRoute{Name: "x", Hosts: []string{"x.test"}, To: []GatewayUpstream{{App: "missing"}}}); err == nil {
		t.Fatal("route to an unknown app accepted")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "routes.json")); fi.Mode().Perm() != 0600 {
		t.Fatal("routes file must be 0600")
	}

	// API: viewers read, admins change.
	var role string
	api := newAPIHarness(t, registerGatewayRoutes)
	do := func(method, path, body string) *httptest.ResponseRecorder { return api.req(role, method, path, body) }
	role = "viewer"
	if w := do("GET", "/api/v1/gateway/routes", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "www.test") {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if w := do("DELETE", "/api/v1/gateway/routes/web", ""); w.Code != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", w.Code)
	}
	role = "admin"
	if w := do("PUT", "/api/v1/gateway/routes/api", `{"hosts":["api.test"],"to":[{"address":"10.0.0.5:9000"}],"lb":"least_conn"}`); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if w := do("PUT", "/api/v1/gateway/routes/bad", `{"hosts":["b.test"],"to":[{"address":"10.0.0.5:9000"}],"evil":true}`); w.Code != 400 {
		t.Fatalf("unknown field accepted: %d", w.Code)
	}
	if w := do("DELETE", "/api/v1/gateway/routes/web", ""); w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := do("DELETE", "/api/v1/gateway/routes/api", ""); w.Code != 200 || running {
		t.Fatalf("last route removed: %d running=%v", w.Code, running)
	}
}

func TestGatewayMetrics(t *testing.T) {
	a := echoUpstream(t, "A", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "m", Hosts: []string{"m.test"}}, a))
	h := g.handler(false)
	gwGet(h, "GET", "m.test", "/", "10.0.0.1:1", "")
	gwGet(h, "GET", "nope.test", "/", "10.0.0.1:1", "")
	rec := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{`zirogate_requests_total{route="m",code="200"} 1`, `zirogate_requests_total{route="_none",code="404"} 1`,
		`zirogate_request_duration_seconds_count{route="m"} 1`} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics lack %s:\n%s", want, out)
		}
	}
}

// BenchmarkGatewayProxy measures the proxy hot path (match, pick, forward) against a loopback
// upstream with keep-alive.
func BenchmarkGatewayProxy(b *testing.B) {
	up := echoUpstream(b, "A", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	g := v2Server(b, rs(GatewayRoute{Name: "b", Hosts: []string{"b.test"}}, up))
	srv := httptest.NewServer(g.handler(false))
	defer srv.Close()
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", srv.URL+"/", nil)
			req.Host = "b.test"
			resp, err := cl.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// Reloading the route table under load never fails a request.
func TestGatewayReloadUnderLoad(t *testing.T) {
	a := echoUpstream(t, "A", nil)
	b := echoUpstream(t, "B", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}}, a))
	srv := httptest.NewServer(g.handler(false))
	defer srv.Close()
	var failed, total atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for {
				select {
				case <-stop:
					done <- struct{}{}
					return
				default:
				}
				req, _ := http.NewRequest("GET", srv.URL+"/", nil)
				req.Host = "r.test"
				resp, err := http.DefaultClient.Do(req)
				total.Add(1)
				if err != nil || resp.StatusCode != 200 {
					failed.Add(1)
				}
				if resp != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		up := a
		if i%2 == 1 {
			up = b
		}
		if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}}, up)}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	for i := 0; i < 8; i++ {
		<-done
	}
	if failed.Load() != 0 || total.Load() < 100 {
		t.Fatalf("%d of %d requests failed during reloads", failed.Load(), total.Load())
	}
}

// HTTP/3: a QUIC client gets the routed response over UDP.
func TestGatewayHTTP3(t *testing.T) {
	dir := t.TempDir()
	old := gatewayCertDir
	gatewayCertDir = dir
	defer func() { gatewayCertDir = old }()
	up := echoUpstream(t, "H3", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "q", Hosts: []string{"q.internal"}, TLS: "internal"}, up))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: g.getCertificate}
	g.h3 = &http3.Server{Handler: g.handler(true), TLSConfig: http3.ConfigureTLSConfig(tlsCfg)}
	go g.h3.Serve(pc)
	defer g.h3.Close()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "internal-ca.crt"))
	if len(caPEM) == 0 { // the CA is created with the first internal certificate
		g.getCertificate(&tls.ClientHelloInfo{ServerName: "q.internal"})
		caPEM, _ = os.ReadFile(filepath.Join(dir, "internal-ca.crt"))
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "q.internal"}}
	defer tr.Close()
	req, _ := http.NewRequest("GET", "https://"+pc.LocalAddr().String()+"/hello", nil)
	req.Host = "q.internal"
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 3 || string(b) != "H3 /hello" {
		t.Fatalf("HTTP/3: proto %s body %q", resp.Proto, b)
	}
}

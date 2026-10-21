package cmd

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tget(h http.Handler, method, host, target string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+target, nil)
	r.RemoteAddr = "10.0.0.1:1111"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (g *gatewayServer) metricsText() string {
	rec := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

// ---- matching ----

func TestParseMatcher(t *testing.T) {
	for in, want := range map[string]GatewayMatcher{
		"X-Debug":      {Name: "X-Debug", Op: "present"},
		"X-Env=prod":   {Name: "X-Env", Op: "eq", Value: "prod"},
		"X-Env^=pre":   {Name: "X-Env", Op: "prefix", Value: "pre"},
		"ua~=^curl/.*": {Name: "ua", Op: "regex", Value: "^curl/.*"},
		"a=b=c":        {Name: "a", Op: "eq", Value: "b=c"},
	} {
		got, err := parseMatcher(in)
		if err != nil || got != want {
			t.Errorf("parseMatcher(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "=x", "^=x"} {
		if _, err := parseMatcher(bad); err == nil {
			t.Errorf("parseMatcher(%q) accepted", bad)
		}
	}
}

func TestQueryAndCookieLookup(t *testing.T) {
	for _, c := range []struct {
		raw, name, want string
		ok              bool
	}{
		{"a=1&b=2", "b", "2", true},
		{"a=1&b=2", "c", "", false},
		{"a=%41%20b&x=1", "a", "A b", true},
		{"a+b=1", "a b", "1", true},
		{"flag", "flag", "", true},
		{"", "a", "", false},
	} {
		if v, ok := queryGet(c.raw, c.name); v != c.want || ok != c.ok {
			t.Errorf("queryGet(%q, %q) = %q, %v", c.raw, c.name, v, ok)
		}
	}
	h := http.Header{"Cookie": {"a=1; session=abc", `q="x y"`}}
	if v, ok := cookieGet(h, "session"); !ok || v != "abc" {
		t.Errorf("session = %q %v", v, ok)
	}
	if v, ok := cookieGet(h, "q"); !ok || v != "x y" {
		t.Errorf("q = %q %v", v, ok)
	}
	if _, ok := cookieGet(h, "missing"); ok {
		t.Error("found a cookie that is not there")
	}
}

func TestGatewayAdvancedMatching(t *testing.T) {
	plain := echoUpstream(t, "PLAIN", nil)
	beta := echoUpstream(t, "BETA", nil)
	reg := echoUpstream(t, "REGEX", nil)
	g := v2Server(t,
		rs(GatewayRoute{Name: "plain", Hosts: []string{"m.test"}}, plain),
		rs(GatewayRoute{Name: "beta", Hosts: []string{"m.test"}, QueryMatchers: []GatewayMatcher{{Name: "beta", Op: "present"}},
			CookieMatchers: []GatewayMatcher{{Name: "tier", Op: "prefix", Value: "gold"}}}, beta),
		rs(GatewayRoute{Name: "re", Hosts: []string{"m.test"}, PathRegex: `^/v[0-9]+/items/[0-9]+$`,
			HeaderMatchers: []GatewayMatcher{{Name: "User-Agent", Op: "regex", Value: `^curl/`}}}, reg))
	h := g.handler(false)
	who := func(target string, hdr map[string]string) string {
		w := tget(h, "GET", "m.test", target, hdr)
		return strings.SplitN(body(w), " ", 2)[0]
	}
	if got := who("/x", nil); got != "PLAIN" {
		t.Errorf("no matcher hit: %s", got)
	}
	if got := who("/x?beta", map[string]string{"Cookie": "tier=gold-1"}); got != "BETA" {
		t.Errorf("query+cookie route: %s", got)
	}
	if got := who("/x?beta", map[string]string{"Cookie": "tier=silver"}); got != "PLAIN" {
		t.Errorf("cookie prefix must fail: %s", got)
	}
	if got := who("/x?beta", nil); got != "PLAIN" {
		t.Errorf("missing cookie must fail: %s", got)
	}
	if got := who("/v2/items/42", map[string]string{"User-Agent": "curl/8.0"}); got != "REGEX" {
		t.Errorf("path+header regex route: %s", got)
	}
	if got := who("/v2/items/42", map[string]string{"User-Agent": "firefox"}); got != "PLAIN" {
		t.Errorf("header regex must fail: %s", got)
	}
	if got := who("/v2/items/abc", map[string]string{"User-Agent": "curl/8.0"}); got != "PLAIN" {
		t.Errorf("path regex must fail: %s", got)
	}
}

// ---- retries, ejection, shedding ----

func TestRetryBudget(t *testing.T) {
	b := newRetryBudget(20)
	n := 0
	for b.take() {
		n++
	}
	if n != 10 {
		t.Fatalf("reserve = %d retries, want 10", n)
	}
	for i := 0; i < 5; i++ {
		b.request()
	}
	if !b.take() || b.take() {
		t.Fatal("5 requests at 20% earn exactly one retry")
	}
	for i := 0; i < 10000; i++ {
		b.request()
	}
	m := 0
	for b.take() {
		m++
	}
	if m != 10 {
		t.Fatalf("the balance must be capped at the reserve, got %d", m)
	}
}

func TestGatewayRetryOn5xx(t *testing.T) {
	var aHits, bHits atomic.Int32
	a := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) { aHits.Add(1); w.WriteHeader(503) })
	b := echoUpstream(t, "B", func(w http.ResponseWriter, r *http.Request) { bHits.Add(1); io.WriteString(w, "B ok") })
	g := v2Server(t, rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}, Retries: 1, RetryOn: []string{"5xx"}}, a, b))
	h := g.handler(false)
	if w := tget(h, "GET", "r.test", "/", nil); w.Code != 200 || !strings.HasPrefix(body(w), "B ok") {
		t.Fatalf("GET after a 503: %d %q", w.Code, body(w))
	}
	if aHits.Load() != 1 || bHits.Load() != 1 {
		t.Fatalf("hits a=%d b=%d", aHits.Load(), bHits.Load())
	}
	// A request that may have side effects is never replayed.
	g.routeNamed("r").next.Store(0)
	if w := tget(h, "POST", "r.test", "/", nil); w.Code != 503 {
		t.Fatalf("POST must not be retried: %d", w.Code)
	}
	if !strings.Contains(g.metricsText(), `zirogate_retries_total{route="r"} 1`) {
		t.Errorf("retries not counted:\n%s", g.metricsText())
	}
	// Without retry_on the 503 is the answer.
	g2 := v2Server(t, rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}, Retries: 1}, a, b))
	if w := tget(g2.handler(false), "GET", "r.test", "/", nil); w.Code != 503 {
		t.Fatalf("a 503 without retry_on: %d", w.Code)
	}
}

func TestGatewayRetryOnTimeout(t *testing.T) {
	slow := echoUpstream(t, "SLOW", func(w http.ResponseWriter, r *http.Request) { time.Sleep(1600 * time.Millisecond) })
	fast := echoUpstream(t, "FAST", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "t", Hosts: []string{"t.test"}, Retries: 1, RetryOn: []string{"timeout"},
		Timeouts: &GatewayTimeouts{ResponseHeader: "1s"}}, slow, fast))
	w := tget(g.handler(false), "GET", "t.test", "/", nil)
	if w.Code != 200 || !strings.HasPrefix(body(w), "FAST") {
		t.Fatalf("after a response timeout: %d %q", w.Code, body(w))
	}
}

func TestGatewayOutlierEjection(t *testing.T) {
	var badHits atomic.Int32
	bad := echoUpstream(t, "BAD", func(w http.ResponseWriter, r *http.Request) { badHits.Add(1); w.WriteHeader(503) })
	good := echoUpstream(t, "GOOD", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "o", Hosts: []string{"o.test"},
		Outlier: &GatewayOutlier{Consecutive: 3, EjectFor: "30s"}}, bad, good))
	h := g.handler(false)
	var codes []int
	for i := 0; i < 20; i++ {
		codes = append(codes, tget(h, "GET", "o.test", "/", nil).Code)
	}
	if badHits.Load() != 3 {
		t.Fatalf("the failing upstream took %d requests, want exactly 3 before ejection (codes %v)", badHits.Load(), codes)
	}
	for _, c := range codes[len(codes)-8:] {
		if c != 200 {
			t.Fatalf("after ejection every request must succeed: %v", codes)
		}
	}
	if !strings.Contains(g.metricsText(), `zirogate_outlier_ejections_total{route="o"} 1`) {
		t.Error("ejection not counted")
	}
	// The last upstream standing is never ejected.
	solo := v2Server(t, rs(GatewayRoute{Name: "s", Hosts: []string{"s.test"}, Outlier: &GatewayOutlier{Consecutive: 2}}, bad))
	before := badHits.Load()
	for i := 0; i < 6; i++ {
		tget(solo.handler(false), "GET", "s.test", "/", nil)
	}
	if badHits.Load()-before != 6 {
		t.Errorf("a single upstream must keep receiving traffic, got %d of 6", badHits.Load()-before)
	}
}

func TestOutlierEjectionGrowsAndSlowStart(t *testing.T) {
	g := newGatewayServer()
	up := g.upstreamFor("10.0.0.1:80")
	other := g.upstreamFor("10.0.0.2:80")
	r := &gwRoute{outlier: newOutlier(&GatewayOutlier{Consecutive: 1, EjectFor: "10s", MaxEjectPercent: 100, SlowStart: "20s"}),
		m: &routeMetrics{}, targets: []*gwTarget{{addr: "a", weight: 10, up: up}, {addr: "b", weight: 10, up: other}}}
	now := time.Now()
	g.recordFailure(r, r.targets[0], now, true)
	first := time.Duration(up.downUntil.Load() - now.UnixNano())
	g.recordFailure(r, r.targets[0], now, true)
	second := time.Duration(up.downUntil.Load() - now.UnixNano())
	if first != 10*time.Second || second != 20*time.Second {
		t.Fatalf("ejection times %v then %v, want 10s then 20s", first, second)
	}
	p := picker{slowStart: 20 * time.Second, now: up.rampStart.Load()}
	if w := p.effWeight(r.targets[0]); w != 1 {
		t.Errorf("weight at the start of the ramp = %d, want 1 (10%% of 10)", w)
	}
	p.now += int64(10 * time.Second)
	if w := p.effWeight(r.targets[0]); w < 5 || w > 6 {
		t.Errorf("weight half way = %d, want about 5", w)
	}
	p.now += int64(10 * time.Second)
	if w := p.effWeight(r.targets[0]); w != 10 {
		t.Errorf("weight after the ramp = %d", w)
	}
	// An ejection cap keeps the pool alive.
	r.outlier = newOutlier(&GatewayOutlier{Consecutive: 1, MaxEjectPercent: 50})
	other.downUntil.Store(0)
	up.downUntil.Store(0)
	g.recordFailure(r, r.targets[0], now, true)
	g.recordFailure(r, r.targets[1], now, true)
	if other.downUntil.Load() > now.UnixNano() {
		t.Error("a second ejection exceeded max_eject_percent")
	}
}

func TestGatewayShedsLoad(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		io.WriteString(w, "done")
	})
	g := v2Server(t, rs(GatewayRoute{Name: "c", Hosts: []string{"c.test"}, MaxConcurrent: 1}, up),
		rs(GatewayRoute{Name: "u", Hosts: []string{"u.test"}, MaxUpstreamConns: 1}, up))
	h := g.handler(false)
	for _, host := range []string{"c.test", "u.test"} {
		done := make(chan int)
		go func() { done <- tget(h, "GET", host, "/", nil).Code }()
		<-started
		w := tget(h, "GET", host, "/", nil)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
			t.Errorf("%s: second request: %d (Retry-After %q)", host, w.Code, w.Header().Get("Retry-After"))
		}
		release <- struct{}{}
		if c := <-done; c != 200 {
			t.Errorf("%s: the first request: %d", host, c)
		}
	}
	m := g.metricsText()
	for _, route := range []string{"c", "u"} {
		if !strings.Contains(m, fmt.Sprintf(`zirogate_denied_total{route=%q,reason="shed"} 1`, route)) {
			t.Errorf("shed not counted for %s", route)
		}
	}
}

// ---- load balancing ----

func TestGatewayP2CAndHashBalancing(t *testing.T) {
	g := v2Server(t,
		rs(GatewayRoute{Name: "p", Hosts: []string{"p.test"}, LB: "p2c"}, "10.0.0.1:80", "10.0.0.2:80"),
		rs(GatewayRoute{Name: "h", Hosts: []string{"h.test"}, LB: "hash", HashKey: "header:X-User"}, "10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80", "10.0.0.4:80"))
	p := g.routeNamed("p")
	p.targets[0].up.active.Store(100)
	for i := 0; i < 50; i++ {
		if tg := g.pick(p, "ip", time.Now(), nil); tg != p.targets[1] {
			t.Fatal("p2c picked the busy upstream")
		}
	}
	p.targets[0].up.active.Store(0)
	hits := map[*gwTarget]int{}
	for i := 0; i < 2000; i++ {
		hits[g.pick(p, "ip", time.Now(), nil)]++
	}
	if hits[p.targets[0]] < 800 || hits[p.targets[1]] < 800 {
		t.Errorf("p2c split %v / %v of 2000", hits[p.targets[0]], hits[p.targets[1]])
	}

	h := g.routeNamed("h")
	owner := map[string]*gwTarget{}
	spread := map[*gwTarget]int{}
	for i := 0; i < 400; i++ {
		k := fmt.Sprintf("user-%d", i)
		tg := g.pick(h, k, time.Now(), nil)
		if again := g.pick(h, k, time.Now(), nil); again != tg {
			t.Fatalf("key %s moved between requests", k)
		}
		owner[k] = tg
		spread[tg]++
	}
	for _, tg := range h.targets {
		if spread[tg] < 50 {
			t.Errorf("target %s got only %d of 400 keys", tg.addr, spread[tg])
		}
	}
	// Losing a target moves only the keys it owned.
	h.targets[2].unhealthy.Store(true)
	moved := 0
	for k, was := range owner {
		now := g.pick(h, k, time.Now(), nil)
		if was != h.targets[2] && now != was {
			t.Fatalf("key %s moved though its target is fine", k)
		}
		if now != was {
			moved++
		}
	}
	if moved != spread[h.targets[2]] {
		t.Errorf("moved %d keys, want the %d the lost target owned", moved, spread[h.targets[2]])
	}
	// The request supplies the key: a header, falling back to the address.
	up := echoUpstream(t, "X", nil)
	g2 := v2Server(t, rs(GatewayRoute{Name: "h", Hosts: []string{"h.test"}, LB: "hash", HashKey: "header:X-User"}, up))
	if w := tget(g2.handler(false), "GET", "h.test", "/", map[string]string{"X-User": "alice"}); w.Code != 200 {
		t.Errorf("hash by header: %d", w.Code)
	}
}

// ---- rate limits ----

func TestGatewayRateKeyAndHeaders(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "r", Hosts: []string{"r.test"}, RateRPS: 2, RateBurst: 3, RateKey: "header:X-Api-Key"}, up))
	h := g.handler(false)
	get := func(key string) *httptest.ResponseRecorder {
		return tget(h, "GET", "r.test", "/", map[string]string{"X-Api-Key": key})
	}
	for i := 0; i < 3; i++ {
		if w := get("k1"); w.Code != 200 {
			t.Fatalf("request %d within the burst: %d", i, w.Code)
		}
	}
	w := get("k1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the burst: %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" || w.Header().Get("RateLimit-Limit") != "2" || w.Header().Get("RateLimit-Remaining") != "0" {
		t.Errorf("headers: %v", w.Header())
	}
	if w := get("k2"); w.Code != 200 {
		t.Errorf("another key must have its own bucket: %d", w.Code)
	}
}

// ---- mirroring ----

func TestGatewayMirror(t *testing.T) {
	var mu sync.Mutex
	var mirrored []string
	mirrorAddr := echoUpstream(t, "M", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		mirrored = append(mirrored, r.Method+" "+r.URL.RequestURI()+" "+string(b)+" mirror="+r.Header.Get("X-Mirror"))
		mu.Unlock()
		w.WriteHeader(500) // the mirror's answer never reaches the client
	})
	primary := echoUpstream(t, "P", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "P got %q", b)
	})
	route := rs(GatewayRoute{Name: "m", Hosts: []string{"m.test"}, Mirror: &GatewayMirror{Address: mirrorAddr}}, primary)
	route.MirrorTargets = []GatewayTarget{{Addr: mirrorAddr, Weight: 1}}
	g := v2Server(t, route)
	h := g.handler(false)
	r := httptest.NewRequest("POST", "http://m.test/orders?x=1", strings.NewReader("payload"))
	r.RemoteAddr = "10.0.0.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || body(w) != `P got "payload"` {
		t.Fatalf("primary: %d %q", w.Code, body(w))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(mirrored)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if len(mirrored) != 1 || mirrored[0] != "POST /orders?x=1 payload mirror=1" {
		t.Fatalf("mirror saw %v", mirrored)
	}
	mu.Unlock()

	// A body too large to copy is skipped, not buffered; the request itself is unaffected.
	big := strings.Repeat("x", mirrorMaxBody+1)
	r = httptest.NewRequest("POST", "http://m.test/big", strings.NewReader(big))
	r.RemoteAddr = "10.0.0.1:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(body(w), "P got") {
		t.Fatalf("large body: %d", w.Code)
	}
	if !strings.Contains(g.metricsText(), `zirogate_mirror_requests_total{route="m",result="skipped"} 1`) {
		t.Errorf("skipped mirror not counted:\n%s", g.metricsText())
	}

	// A dead mirror costs the client nothing.
	dead := rs(GatewayRoute{Name: "d", Hosts: []string{"d.test"}, Mirror: &GatewayMirror{Address: "127.0.0.1:1"}}, primary)
	dead.MirrorTargets = []GatewayTarget{{Addr: "127.0.0.1:1", Weight: 1}}
	g2 := v2Server(t, dead)
	if w := tget(g2.handler(false), "GET", "d.test", "/", nil); w.Code != 200 {
		t.Errorf("dead mirror broke the request: %d", w.Code)
	}
}

// ---- rewrite, CORS, headers ----

func TestGatewayRewriteCORSAndSecurityHeaders(t *testing.T) {
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/own" {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		fmt.Fprint(w, r.URL.Path)
	})
	g := v2Server(t, rs(GatewayRoute{Name: "x", Hosts: []string{"x.test"},
		Rewrite:         &GatewayRewrite{Pattern: `^/api/(.*)$`, Replace: "/v2/$1"},
		SecurityHeaders: true,
		CORS:            &GatewayCORS{Origins: []string{"https://app.example.com"}, Methods: []string{"GET", "PUT"}, Credentials: true, MaxAge: 60, Expose: []string{"X-Request-ID"}}}, up))
	h := g.handler(false)
	if w := tget(h, "GET", "x.test", "/api/users/1", nil); body(w) != "/v2/users/1" {
		t.Errorf("rewrite: %q", body(w))
	}
	if w := tget(h, "GET", "x.test", "/plain", nil); body(w) != "/plain" {
		t.Errorf("a path the pattern does not match is left alone: %q", body(w))
	}
	w := tget(h, "GET", "x.test", "/own", nil)
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" ||
		w.Header().Get("Referrer-Policy") == "" {
		t.Errorf("security headers must fill gaps and respect the app's: %v", w.Header())
	}
	pre := tget(h, "OPTIONS", "x.test", "/api/x", map[string]string{"Origin": "https://app.example.com",
		"Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "content-type"})
	if pre.Code != 204 || pre.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		pre.Header().Get("Access-Control-Allow-Methods") != "GET, PUT" || pre.Header().Get("Access-Control-Allow-Headers") != "content-type" ||
		pre.Header().Get("Access-Control-Max-Age") != "60" || pre.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("preflight: %d %v", pre.Code, pre.Header())
	}
	bad := tget(h, "OPTIONS", "x.test", "/api/x", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "PUT"})
	if bad.Code != 204 || bad.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("a foreign origin must get no allow headers: %v", bad.Header())
	}
	ok := tget(h, "GET", "x.test", "/own", map[string]string{"Origin": "https://app.example.com"})
	if ok.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || ok.Header().Get("Access-Control-Expose-Headers") != "X-Request-ID" {
		t.Errorf("actual request: %v", ok.Header())
	}
	if no := tget(h, "GET", "x.test", "/own", map[string]string{"Origin": "https://evil.example"}); no.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign origin allowed: %v", no.Header())
	}
}

// ---- upstream TLS ----

func TestGatewayUpstreamHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "tls=%v proto=%s", r.TLS != nil, r.Proto)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	trusted := v2Server(t, rs(GatewayRoute{Name: "s", Hosts: []string{"s.test"}, UpstreamProto: "https",
		UpstreamTLS: &GatewayUpstreamTLS{CAPEM: caPEM}}, addr))
	w := tget(trusted.handler(false), "GET", "s.test", "/", nil)
	if w.Code != 200 || !strings.Contains(body(w), "tls=true") {
		t.Fatalf("verified https upstream: %d %q", w.Code, body(w))
	}
	// Without the CA the certificate is not trusted: the gateway never skips verification.
	untrusted := v2Server(t, rs(GatewayRoute{Name: "s", Hosts: []string{"s.test"}, UpstreamProto: "https"}, addr))
	if w := tget(untrusted.handler(false), "GET", "s.test", "/", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("unverifiable upstream certificate: %d", w.Code)
	}
	// A wrong server name fails too.
	wrong := v2Server(t, rs(GatewayRoute{Name: "s", Hosts: []string{"s.test"}, UpstreamProto: "https",
		UpstreamTLS: &GatewayUpstreamTLS{CAPEM: caPEM, ServerName: "not-the-cert.example"}}, addr))
	if w := tget(wrong.handler(false), "GET", "s.test", "/", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("wrong server name: %d", w.Code)
	}
}

func TestGatewayUpstreamH2C(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Proto) }))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	g := v2Server(t, rs(GatewayRoute{Name: "g", Hosts: []string{"g.test"}, UpstreamProto: "h2c"}, strings.TrimPrefix(srv.URL, "http://")))
	if w := tget(g.handler(false), "GET", "g.test", "/", nil); w.Code != 200 || body(w) != "HTTP/2.0" {
		t.Fatalf("h2c upstream: %d %q", w.Code, body(w))
	}
}

// ---- timeouts ----

func TestGatewayRequestAndIdleTimeouts(t *testing.T) {
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			time.Sleep(2 * time.Second)
		case "/stall":
			io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}
		io.WriteString(w, "done")
	})
	g := v2Server(t, rs(GatewayRoute{Name: "t", Hosts: []string{"t.test"},
		Timeouts: &GatewayTimeouts{Request: "1s", Idle: "1s"}}, up))
	srv := httptest.NewServer(g.handler(false))
	defer srv.Close()
	get := func(path string) (int, string, error) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Host = "t.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), err
	}
	if code, _, _ := get("/slow"); code != http.StatusGatewayTimeout {
		t.Errorf("a request over its time limit: %d, want 504", code)
	}
	t0 := time.Now()
	_, b, err := get("/stall")
	if err == nil && strings.HasSuffix(b, "done") {
		t.Errorf("a stalled stream was not cut: %q", b)
	}
	if time.Since(t0) > 2500*time.Millisecond {
		t.Errorf("idle timeout took %v", time.Since(t0))
	}
	if code, b, err := get("/ok"); code != 200 || b != "done" || err != nil {
		t.Errorf("normal request: %d %q %v", code, b, err)
	}
}

// ---- tracing ----

func TestTraceContext(t *testing.T) {
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tid, out := traceContext(in)
	if tid != "4bf92f3577b34da6a3ce929d0e0e4736" || !strings.HasPrefix(out, "00-"+tid+"-") || !strings.HasSuffix(out, "-01") {
		t.Fatalf("continued trace: %s %s", tid, out)
	}
	if out == in || out[36:52] == "00f067aa0ba902b7" {
		t.Error("the upstream hop needs its own span id")
	}
	for _, bad := range []string{"", "garbage", "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"} {
		tid, out := traceContext(bad)
		if len(tid) != 32 || len(out) != 55 || tid == "4bf92f3577b34da6a3ce929d0e0e4736" || tid == strings.Repeat("0", 32) {
			t.Errorf("traceContext(%q) = %q, %q", bad, tid, out)
		}
	}
	// End to end: the upstream receives the continued trace.
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Header.Get("Traceparent")) })
	g := v2Server(t, rs(GatewayRoute{Name: "t", Hosts: []string{"t.test"}}, up))
	w := tget(g.handler(false), "GET", "t.test", "/", map[string]string{"Traceparent": in})
	if got := body(w); !strings.HasPrefix(got, "00-4bf92f3577b34da6a3ce929d0e0e4736-") || got == in {
		t.Errorf("upstream traceparent %q", got)
	}
	w = tget(g.handler(false), "GET", "t.test", "/", nil)
	if got := body(w); len(got) != 55 {
		t.Errorf("a trace must be started when none arrives: %q", got)
	}
}

// ---- flags and schema ----

func TestTrafficFlags(t *testing.T) {
	f := routeFlags{r: GatewayRoute{Hosts: []string{"a.test"}}, apps: []string{"web"}, traffic: trafficFlags{
		headerMatch: []string{"X-Env=prod", "X-Beta"}, query: []string{"v^=2"}, cookie: []string{"s~=^a"},
		requestTimeout: "30s", retryOn: []string{"5xx"}, outlierConsecutive: 4, outlierSlowStart: "20s",
		mirror: "10.0.0.9:80@25", rewrite: `^/a/(.*)=>/b/$1`, corsOrigins: []string{"https://a.example"}, corsCredentials: true}}
	f.r.Retries = 1
	r, err := routeFromFlags("t", f)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.HeaderMatchers) != 2 || r.QueryMatchers[0].Op != "prefix" || r.CookieMatchers[0].Op != "regex" ||
		r.Timeouts.Request != "30s" || r.Outlier.Consecutive != 4 || r.Mirror.Address != "10.0.0.9:80" || r.Mirror.Percent != 25 ||
		r.Rewrite.Pattern != "^/a/(.*)" || r.Rewrite.Replace != "/b/$1" || !r.CORS.Credentials {
		t.Fatalf("%+v", r)
	}
	r.Normalize()
	if err := validateRoute(&r); err != nil {
		t.Fatalf("flags produced an invalid route: %v", err)
	}
	if _, err := routeFromFlags("t", routeFlags{traffic: trafficFlags{mirror: "web@x"}}); err == nil {
		t.Error("bad mirror percent accepted")
	}
	if _, err := routeFromFlags("t", routeFlags{traffic: trafficFlags{corsCredentials: true}}); err == nil {
		t.Error("--cors-credentials without an origin accepted")
	}
	if _, err := routeFromFlags("t", routeFlags{traffic: trafficFlags{rewrite: "nope"}}); err == nil {
		t.Error("--rewrite without => accepted")
	}
}

func TestTrafficValidation(t *testing.T) {
	base := func() GatewayRoute {
		return GatewayRoute{Name: "v", Hosts: []string{"v.test"}, To: []GatewayUpstream{{Address: "10.0.0.1:80"}}}
	}
	bad := map[string]func(r *GatewayRoute){
		"bad path regex":      func(r *GatewayRoute) { r.PathRegex = "(" },
		"long regex":          func(r *GatewayRoute) { r.PathRegex = strings.Repeat("a", 300) },
		"bad matcher op":      func(r *GatewayRoute) { r.QueryMatchers = []GatewayMatcher{{Name: "a", Op: "like", Value: "x"}} },
		"present with value":  func(r *GatewayRoute) { r.CookieMatchers = []GatewayMatcher{{Name: "a", Op: "present", Value: "x"}} },
		"bad regex matcher":   func(r *GatewayRoute) { r.HeaderMatchers = []GatewayMatcher{{Name: "X", Op: "regex", Value: "["}} },
		"too many matchers":   func(r *GatewayRoute) { r.QueryMatchers = make([]GatewayMatcher, 17) },
		"bad timeout":         func(r *GatewayRoute) { r.Timeouts = &GatewayTimeouts{Connect: "1ns"} },
		"retry_on w/o retry":  func(r *GatewayRoute) { r.RetryOn = []string{"5xx"} },
		"unknown retry_on":    func(r *GatewayRoute) { r.Retries = 1; r.RetryOn = []string{"always"} },
		"hash without key":    func(r *GatewayRoute) { r.LB = "hash" },
		"key without hash":    func(r *GatewayRoute) { r.HashKey = "ip" },
		"bad hash key":        func(r *GatewayRoute) { r.LB = "hash"; r.HashKey = "body:x" },
		"rate key w/o rate":   func(r *GatewayRoute) { r.RateKey = "ip" },
		"mirror both":         func(r *GatewayRoute) { r.Mirror = &GatewayMirror{App: "a", Address: "10.0.0.1:80"} },
		"mirror bad address":  func(r *GatewayRoute) { r.Mirror = &GatewayMirror{Address: "host:80"} },
		"rewrite bad pattern": func(r *GatewayRoute) { r.Rewrite = &GatewayRewrite{Pattern: "(", Replace: "/x"} },
		"rewrite with query":  func(r *GatewayRoute) { r.Rewrite = &GatewayRewrite{Pattern: "a", Replace: "/x?y=1"} },
		"cors wildcard creds": func(r *GatewayRoute) { r.CORS = &GatewayCORS{Origins: []string{"*"}, Credentials: true} },
		"cors bad origin":     func(r *GatewayRoute) { r.CORS = &GatewayCORS{Origins: []string{"app.example.com"}} },
		"tls without https":   func(r *GatewayRoute) { r.UpstreamTLS = &GatewayUpstreamTLS{ServerName: "a.test"} },
		"unknown proto":       func(r *GatewayRoute) { r.UpstreamProto = "ftp" },
		"bad ca":              func(r *GatewayRoute) { r.UpstreamProto = "https"; r.UpstreamTLS = &GatewayUpstreamTLS{CAPEM: "nope"} },
		"outlier percent":     func(r *GatewayRoute) { r.Outlier = &GatewayOutlier{MaxEjectPercent: 101} },
		"on a tcp route": func(r *GatewayRoute) {
			r.Kind, r.Listen, r.Hosts, r.TLS = "tcp", 5432, nil, ""
			r.Rewrite = &GatewayRewrite{Pattern: "a", Replace: "/b"}
		},
	}
	for name, mut := range bad {
		r := base()
		mut(&r)
		r.Normalize()
		if err := validateRoute(&r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := base()
	ok.LB, ok.HashKey = "hash", "cookie:sid"
	ok.Retries, ok.RetryOn = 2, []string{"5xx", "timeout"}
	ok.Timeouts = &GatewayTimeouts{Connect: "2s", ResponseHeader: "10s", Request: "1m", Idle: "30s"}
	ok.UpstreamProto = "https"
	ok.Outlier = &GatewayOutlier{Consecutive: 3, EjectFor: "20s", MaxEjectPercent: 30, SlowStart: "30s"}
	ok.Normalize()
	if err := validateRoute(&ok); err != nil {
		t.Fatalf("a valid route was refused: %v", err)
	}
}

// Conflicts consider the new matchers: two routes that differ only by a query match coexist.
func TestRoutesConflictWithMatchers(t *testing.T) {
	a := GatewayRoute{Name: "a", Kind: "http", Hosts: []string{"x.test"}, PathPrefix: "/"}
	b := a
	b.Name = "b"
	if routesConflict(a, b) == nil {
		t.Fatal("identical routes must conflict")
	}
	b.QueryMatchers = []GatewayMatcher{{Name: "v", Op: "present"}}
	if err := routesConflict(a, b); err != nil {
		t.Fatalf("routes with different query matchers conflict: %v", err)
	}
}

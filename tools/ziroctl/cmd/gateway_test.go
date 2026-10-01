package cmd

import (
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func upstream(t *testing.T, name string) (*httptest.Server, string) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, name+" "+html.EscapeString(r.Host)+" xff="+html.EscapeString(r.Header.Get("X-Forwarded-For")))
	}))
	t.Cleanup(s.Close)
	return s, strings.TrimPrefix(s.URL, "http://")
}

func gwGet(h http.Handler, method, host, path, remote string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-For", "6.6.6.6") // spoofed; must not reach the upstream
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGatewayRouting(t *testing.T) {
	_, a := upstream(t, "A")
	_, b := upstream(t, "B")
	_, api := upstream(t, "API")
	dead := "127.0.0.1:1" // nothing listens: dial fails
	g := newGatewayServer()
	g.log = func(any) {}
	route := func(name, host, path, app string, ups ...string) GatewayRouteState {
		return GatewayRouteState{GatewayRoute: GatewayRoute{Name: name, Host: host, PathPrefix: path, App: app, TLS: "off"}, Upstreams: ups}
	}
	lim := route("lim", "lim.test", "/", "web", a)
	lim.RateRPS, lim.MaxBodyMB, lim.AllowCIDRs = 1, 1, []string{"192.0.2.0/24"}
	tlsRoute := route("sec", "sec.test", "/", "web", a)
	tlsRoute.TLS = "auto"
	if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{
		route("web", "www.test", "/", "web", a, b, dead),
		route("api", "www.test", "/api", "api", api),
		lim, tlsRoute,
	}}); err != nil {
		t.Fatal(err)
	}
	h := g.handler(false)
	c := "192.0.2.7:5555"

	if w := gwGet(h, "GET", "WWW.test:80", "/api/v1", c, ""); !strings.HasPrefix(w.Body.String(), "API WWW.test:80") ||
		!strings.Contains(w.Body.String(), "xff=192.0.2.7") {
		t.Fatalf("longest prefix + host + XFF: %d %q", w.Code, w.Body.String())
	}
	if w := gwGet(h, "GET", "www.test", "/apix", c, ""); strings.HasPrefix(w.Body.String(), "API") {
		t.Fatal("/api must not match /apix")
	}
	// Round robin across A, B and a dead upstream: after one 502 the dead one is skipped.
	seen := map[string]int{}
	for i := 0; i < 12; i++ {
		w := gwGet(h, "GET", "www.test", "/", c, "")
		seen[strings.SplitN(w.Body.String(), " ", 2)[0]]++
		if w.Code == http.StatusBadGateway {
			seen["502"]++
		}
	}
	if seen["A"] < 4 || seen["B"] < 4 || seen["502"] != 1 {
		t.Fatalf("round robin / passive health: %v", seen)
	}
	if w := gwGet(h, "GET", "nope.test", "/", c, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", w.Code)
	}
	if w := gwGet(h, "GET", "sec.test", "/x?y=1", c, ""); w.Code != http.StatusPermanentRedirect ||
		w.Header().Get("Location") != "https://sec.test/x?y=1" {
		t.Fatalf("https redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := gwGet(h, "GET", "lim.test", "/", "198.51.100.1:1", ""); w.Code != http.StatusForbidden {
		t.Fatalf("allow CIDR: %d", w.Code)
	}
	if w := gwGet(h, "POST", "lim.test", "/", c, strings.Repeat("x", 2<<20)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit: %d", w.Code)
	}
	codes := map[int]int{}
	for i := 0; i < 15; i++ {
		codes[gwGet(h, "GET", "lim.test", "/", c, "").Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 || codes[http.StatusOK] > 10 {
		t.Fatalf("rate limit (burst 10): %v", codes)
	}
}

func TestGatewayRejectsBadConfig(t *testing.T) {
	g := newGatewayServer()
	for _, rs := range []GatewayRouteState{
		{GatewayRoute: GatewayRoute{Name: "x", Host: "bad host", App: "web"}},
		{GatewayRoute: GatewayRoute{Name: "x", Host: "ok.test", App: "web", PathPrefix: "/../etc"}},
		{GatewayRoute: GatewayRoute{Name: "x", Host: "ok.test", App: "web"}, Upstreams: []string{"evil.example:80"}},
		{GatewayRoute: GatewayRoute{Name: "x", Host: "ok.test", App: "web", AllowCIDRs: []string{"nope"}}},
	} {
		if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{rs}}); err == nil {
			t.Fatalf("accepted %+v", rs)
		}
	}
}

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(5)
	now := time.Now()
	ok := 0
	for i := 0; i < 20; i++ {
		if b.allow("c", now) {
			ok++
		}
	}
	if ok != 10 || !b.allow("c", now.Add(time.Second)) || !b.allow("other", now) {
		t.Fatalf("burst=%d", ok)
	}
}

func TestGatewayConfigAndPolicy(t *testing.T) {
	st := policyCluster("deny") // api (8080) on a, web on b, other on c
	st.Nodes[2].Gateway = true  // c is a gateway
	st.Routes = []GatewayRoute{{Name: "api", Host: "api.test", PathPrefix: "/", App: "api", TLS: "auto"}}
	markRunning(st)
	st.Nodes[0].Status = "Ready"
	for i := range st.Nodes {
		st.Nodes[i].Status = "Ready"
	}
	cfg := gatewayConfigFor(st)
	if len(cfg.Routes) != 1 || strings.Join(cfg.Routes[0].Upstreams, ",") != net.JoinHostPort("10.200.0.1", "8080") {
		t.Fatalf("upstreams: %+v", cfg.Routes)
	}
	// Routing api admits the gateway node (c) in addition to allow_from (web on b).
	if got := strings.Join(policyFor(st, "a").Rules[0].Sources, ","); got != "10.200.0.2,10.200.0.3" {
		t.Fatalf("sources = %s", got)
	}
}

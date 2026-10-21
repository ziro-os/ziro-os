package cmd

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// validateExposition checks Prometheus text format rules a scraper enforces: every sample belongs
// to a declared family, a family's samples are contiguous, and no series repeats.
func validateExposition(t *testing.T, text string) {
	t.Helper()
	sample := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (-?[0-9.eE+-]+|NaN|\+Inf)$`)
	types := map[string]string{}
	closed := map[string]bool{}
	seen := map[string]bool{}
	cur := ""
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# HELP "):
		case strings.HasPrefix(l, "# TYPE "):
			f := strings.Fields(l)
			if len(f) != 4 {
				t.Fatalf("line %d: %q", i, l)
			}
			if _, dup := types[f[2]]; dup {
				t.Fatalf("line %d: family %s declared twice", i, f[2])
			}
			if cur != "" {
				closed[cur] = true
			}
			types[f[2]], cur = f[3], f[2]
		default:
			m := sample.FindStringSubmatch(l)
			if m == nil {
				t.Fatalf("line %d is not a sample: %q", i, l)
			}
			base := m[1]
			if types[base] == "" {
				for _, suf := range []string{"_bucket", "_sum", "_count"} {
					if strings.HasSuffix(base, suf) && types[strings.TrimSuffix(base, suf)] == "histogram" {
						base = strings.TrimSuffix(base, suf)
					}
				}
			}
			if types[base] == "" {
				t.Fatalf("line %d: sample of an undeclared family: %q", i, l)
			}
			if base != cur || closed[base] {
				t.Fatalf("line %d: samples of %s are not contiguous: %q", i, base, l)
			}
			key := m[1] + m[2]
			if seen[key] {
				t.Fatalf("line %d: duplicate series %s", i, key)
			}
			seen[key] = true
		}
	}
}

func TestGatewayMetricsExposition(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := fwServer(t, GatewaySettings{WAF: &GatewayWAF{Mode: "block"}, AutoBan: &GatewayAutoBan{Strikes: 1}},
		rs(GatewayRoute{Name: "a", Hosts: []string{"a.test"}, Retries: 1, Mirror: nil}, up, "127.0.0.1:9"),
		rs(GatewayRoute{Name: "b", Hosts: []string{"b.test"}}, up))
	h := g.handler(false)
	fwDo(h, fwReq{target: "/", hdr: map[string]string{"Host": "a.test"}})
	for _, host := range []string{"a.test", "b.test", "none.test"} {
		r := httptest.NewRequest("GET", "http://"+host+"/?q=1", nil)
		r.RemoteAddr = "203.0.113.4:1"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	r := httptest.NewRequest("GET", "http://a.test/?q=<script>", nil)
	r.RemoteAddr = "203.0.113.5:1"
	h.ServeHTTP(httptest.NewRecorder(), r)
	g.ready.Store(true)
	g.countHandshake(tls.ConnectionState{Version: tls.VersionTLS13})
	g.countHandshake(tls.ConnectionState{Version: tls.VersionTLS12})
	g.countHandshake(tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h3"})
	g.trackConn(nil, http.StateNew)
	text := g.metricsText()
	validateExposition(t, text)
	for _, want := range []string{`zirogate_tls_handshakes_total{version="1.3"} 1`, `zirogate_tls_handshakes_total{version="1.2"} 1`,
		`zirogate_http3_handshakes_total 1`, `zirogate_connections{kind="http"} 1`, `zirogate_ready 1`, `zirogate_bans_active`,
		`zirogate_route_info{route="a",kind="http"} 1`, `zirogate_upstream_available{route="a",upstream="127.0.0.1:9"} 1`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestGatewayCertExpiryMetric(t *testing.T) {
	dir := t.TempDir()
	old := gatewayCertDir
	gatewayCertDir = dir
	defer func() { gatewayCertDir = old }()
	g := newGatewayServer()
	if _, err := g.internalLeaf("x.example.internal"); err != nil { // creates the internal CA
		t.Fatal(err)
	}
	ex := g.certExpiries()
	if len(ex) != 1 || ex[0].name != "internal-ca" || time.Until(ex[0].at) < 9*365*24*time.Hour {
		t.Fatalf("%+v", ex)
	}
	text := g.metricsText()
	validateExposition(t, text)
	if !strings.Contains(text, `zirogate_cert_expiry_seconds{name="internal-ca"} `) {
		t.Errorf("no expiry series:\n%s", text)
	}
}

func TestGatewayProbes(t *testing.T) {
	g := newGatewayServer()
	h := g.adminHandler()
	code := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code
	}
	if code("/healthz") != 200 {
		t.Error("liveness")
	}
	if code("/readyz") != 503 {
		t.Error("a gateway with no configuration is not ready")
	}
	g.ready.Store(true)
	if code("/readyz") != 200 {
		t.Error("ready")
	}
	g.draining.Store(true)
	if code("/readyz") != 503 || code("/healthz") != 200 {
		t.Error("a draining gateway fails readiness but stays alive")
	}
}

func TestMetricsAuth(t *testing.T) {
	h := metricsAuth("0123456789abcdef", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	for auth, want := range map[string]int{"": 401, "Bearer wrong": 401, "Bearer 0123456789abcdef": 200, "0123456789abcdef": 401, "Basic 0123456789abcdef": 401} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Authorization %q: %d, want %d", auth, w.Code, want)
		}
	}
}

func TestGatewayMetricsAggregation(t *testing.T) {
	g := newGatewayServer()
	srv := httptest.NewServer(g.adminHandler())
	defer srv.Close()
	old := gatewayAdminAddr
	gatewayAdminAddr = strings.TrimPrefix(srv.URL, "http://")
	defer func() { gatewayAdminAddr = old }()
	if out := gatewayMetricsText(); !strings.Contains(out, "zirogate_build_info") {
		t.Errorf("gateway series missing from the API scrape: %q", out)
	}
	gatewayAdminAddr = "127.0.0.1:1"
	if out := gatewayMetricsText(); out != "" {
		t.Errorf("no gateway running, got %q", out)
	}
}

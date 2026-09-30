package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The alerting routes expose webhook URLs and mint signing secrets: every method needs admin,
// and bans need admin to change. wrap here stands in for wrapHandler's authentication step.
func TestSecurityRoutesRBAC(t *testing.T) {
	alertConfigPath = filepath.Join(t.TempDir(), "alerting.json")
	alertSpoolDir = t.TempDir()
	mux := http.NewServeMux()
	var role string
	wrap := func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), apiCallerKey{}, "api-token:t("+role+")")
			h(w, r.WithContext(context.WithValue(ctx, apiRoleKey{}, role)))
		}
	}
	registerSecurityRoutes(mux, wrap)
	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	add := `{"name":"soc","url":"https://hooks.example.com/x"}`
	for _, r := range []string{"viewer", "operator"} {
		role = r
		for _, c := range []struct{ m, p, b string }{
			{"GET", "/api/v1/security/alerting", ""}, {"POST", "/api/v1/security/alerting", add},
			{"DELETE", "/api/v1/security/alerting/soc", ""}, {"POST", "/api/v1/security/bans", `{"ip":"203.0.113.1"}`},
			{"DELETE", "/api/v1/security/bans/203.0.113.1", ""},
		} {
			if code := do(c.m, c.p, c.b); code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d, want 403", r, c.m, c.p, code)
			}
		}
	}
	role = "admin"
	if code := do("POST", "/api/v1/security/alerting", add); code != http.StatusOK {
		t.Fatalf("admin add endpoint: %d", code)
	}
	if code := do("POST", "/api/v1/security/bans", `{"ip":"127.0.0.1"}`); code != http.StatusBadRequest {
		t.Fatalf("banning an allowlisted address must be refused, got %d", code)
	}
	if code := do("DELETE", "/api/v1/security/alerting/soc", ""); code != http.StatusOK {
		t.Fatalf("admin remove endpoint: %d", code)
	}
}

func TestHostRoutesRBAC(t *testing.T) {
	dir := t.TempDir()
	hostnamePath, hostsPath, kernelHostnamePath = filepath.Join(dir, "hostname"), filepath.Join(dir, "hosts"), filepath.Join(dir, "khost")
	netConfigPath, netAppliedPath, netRollbackPath = filepath.Join(dir, "n.json"), filepath.Join(dir, "a.json"), filepath.Join(dir, "r.json")
	mux := http.NewServeMux()
	var role string
	wrap := func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), apiRoleKey{}, role)))
		}
	}
	registerHostRoutes(mux, wrap)
	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	role = "viewer"
	if c := do("GET", "/api/v1/network", ""); c != http.StatusOK {
		t.Errorf("viewer GET network: %d", c)
	}
	role = "operator"
	for _, c := range []struct{ m, p, b string }{
		{"PUT", "/api/v1/network", `{}`}, {"POST", "/api/v1/network/confirm", ""}, {"GET", "/api/v1/ssh/keys", ""},
		{"POST", "/api/v1/ssh/keys", `{"source":"gh:x"}`}, {"POST", "/api/v1/disks", `{"device":"/dev/vdb","mount":"/data"}`},
		{"POST", "/api/v1/disks/expand", ""},
	} {
		if code := do(c.m, c.p, c.b); code != http.StatusForbidden {
			t.Errorf("operator %s %s: %d, want 403", c.m, c.p, code)
		}
	}
	if c := do("POST", "/api/v1/network/hostname", `{"hostname":"api-node"}`); c != http.StatusOK {
		t.Errorf("operator hostname: %d", c)
	}
	if b, _ := os.ReadFile(hostnamePath); string(b) != "api-node\n" {
		t.Errorf("hostname file %q", b)
	}
	role = "admin"
	// Applying a network config over the API without a rollback timer is refused.
	if c := do("PUT", "/api/v1/network", `{"config":{"interfaces":[{"name":"eth0","mode":"dhcp"}]}}`); c != http.StatusBadRequest {
		t.Errorf("PUT without confirm_timeout: %d", c)
	}
}

func TestDNSRoutesRBAC(t *testing.T) {
	dir := t.TempDir()
	dnsConfigPath, dnsStatsPath = filepath.Join(dir, "dns.json"), filepath.Join(dir, "stats.json")
	resolvPinned = filepath.Join(dir, "udhcpc.conf")
	mux := http.NewServeMux()
	var role string
	wrap := func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), apiRoleKey{}, role)))
		}
	}
	registerDNSRoutes(mux, wrap)
	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	role = "viewer"
	if c := do("GET", "/api/v1/dns", ""); c != http.StatusOK {
		t.Errorf("viewer read: %d", c)
	}
	if c := do("POST", "/api/v1/dns/records", `{"name":"a.internal","type":"A","value":"10.0.0.1"}`); c != http.StatusForbidden {
		t.Errorf("viewer write: %d", c)
	}
	role = "operator"
	if c := do("POST", "/api/v1/dns/records", `{"name":"a.internal","type":"A","value":"10.0.0.1"}`); c != http.StatusOK {
		t.Errorf("operator record: %d", c)
	}
	if c := do("POST", "/api/v1/dns/records", `{"name":"a.internal","type":"A","value":"not-an-ip"}`); c != http.StatusBadRequest {
		t.Errorf("invalid record accepted: %d", c)
	}
	if c := do("PUT", "/api/v1/dns/upstreams", `{"upstreams":[{"addr":"198.51.100.53"}]}`); c != http.StatusForbidden {
		t.Errorf("operator redirected all DNS: %d", c)
	}
	role = "admin"
	if c := do("PUT", "/api/v1/dns/upstreams", `{"upstreams":[{"addr":"1.1.1.1","tls_name":"cloudflare-dns.com"}]}`); c != http.StatusOK {
		t.Errorf("admin upstreams: %d", c)
	}
	cfg, _ := loadDNSConfig()
	if len(cfg.Records) != 1 || len(cfg.Upstreams) != 1 {
		t.Fatalf("config %+v", cfg)
	}
}

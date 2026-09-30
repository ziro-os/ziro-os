package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestModuleRoutesRBAC(t *testing.T) {
	mux := http.NewServeMux()
	var role string
	wrap := func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), apiRoleKey{}, role)))
		}
	}
	registerModuleRoutes(mux, wrap)
	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	for _, r := range []string{"viewer", "operator"} {
		role = r
		if code := do("POST", "/api/v1/modules/clamav/enable"); code != http.StatusForbidden {
			t.Errorf("%s enable: %d, want 403", r, code)
		}
	}
	role = "viewer"
	if code := do("GET", "/api/v1/modules"); code != http.StatusOK {
		t.Errorf("viewer list: %d", code)
	}
	role = "admin"
	for _, p := range []string{"/api/v1/modules/nope/enable", "/api/v1/modules/clamav/rm-rf"} {
		if code := do("POST", p); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
	// ServeMux cleans ".." and redirects before any handler runs.
	if code := do("POST", "/api/v1/modules/../../etc/enable"); code == http.StatusAccepted || code == http.StatusOK {
		t.Error("traversal path accepted")
	}
}

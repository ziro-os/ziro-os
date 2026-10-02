package cmd

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// apiHarness serves routes through the real middleware (authentication, roles, audit) with one
// token per role, so tests exercise exactly what the server does.
type apiHarness struct {
	h   http.Handler
	tok map[string]string
}

func newAPIHarness(t *testing.T, reg ...func(*apiRouter)) *apiHarness {
	t.Helper()
	dir := t.TempDir()
	oldTok, oldAudit := apiTokensFile, auditPath
	apiTokensFile, auditPath = filepath.Join(dir, "tokens.json"), filepath.Join(dir, "audit.log")
	t.Cleanup(func() { apiTokensFile, auditPath = oldTok, oldAudit })
	h := &apiHarness{tok: map[string]string{}}
	for _, role := range []string{"viewer", "operator", "admin"} {
		tok, _, err := createAPIToken("t-"+role, role, 0)
		if err != nil {
			t.Fatal(err)
		}
		h.tok[role] = tok
	}
	a := &apiRouter{}
	if len(reg) == 0 {
		a = apiRoutes()
	}
	for _, r := range reg {
		r(a)
	}
	h.h = newAPIHandler(a, apiServerConfig{})
	return h
}

// req sends a request as role ("" = no token).
func (h *apiHarness) req(role, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if role != "" {
		r.Header.Set("Authorization", "Bearer "+h.tok[role])
	}
	h.h.ServeHTTP(rec, r)
	return rec
}

func (h *apiHarness) code(role, method, path, body string) int {
	return h.req(role, method, path, body).Code
}

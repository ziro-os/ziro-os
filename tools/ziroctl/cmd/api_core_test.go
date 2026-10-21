package cmd

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// whoami and the API description are open to every valid token, scoped or not; nothing else is.
func TestWhoAmIAndOpenAPI(t *testing.T) {
	api := newAPIHarness(t, registerOpsRoutes)
	agent, _, err := createAPIToken("agent", "deployer", 0, "sandboxes")
	if err != nil {
		t.Fatal(err)
	}
	get := func(tok, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		api.h.ServeHTTP(w, r)
		return w
	}
	w := get(agent, "/api/v1/whoami")
	var me sdkapi.Token
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &me) != nil || me.Name != "agent" || me.Role != "deployer" ||
		len(me.Scopes) != 1 || me.Scopes[0] != "sandboxes" || me.ID == "" || me.Secret != "" {
		t.Fatalf("whoami: %d %s", w.Code, w.Body)
	}
	if w := get(agent, "/api/v1/openapi.yaml"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), sdk.OpenAPI) ||
		w.Header().Get("Content-Type") != "application/yaml" {
		t.Errorf("openapi: %d %s", w.Code, w.Header())
	}
	if w := get(agent, "/api/v1/tokens"); w.Code != 403 {
		t.Errorf("a scoped token reached the token list: %d", w.Code)
	}
	if w := get("ziro_00000000_"+strings.Repeat("0", 48), "/api/v1/whoami"); w.Code != 401 {
		t.Errorf("unknown token: %d", w.Code)
	}
}

// Rotating keeps the token's name, role and scopes and kills the old secret at once.
func TestRotateToken(t *testing.T) {
	api := newAPIHarness(t, registerOpsRoutes)
	old, before, err := createAPIToken("ci", "operator", 0, "sandboxes")
	if err != nil {
		t.Fatal(err)
	}
	w := api.req("admin", "POST", "/api/v1/tokens/ci/rotate", "")
	var v sdkapi.Token
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Secret == "" || v.Secret == old ||
		v.Name != "ci" || v.Role != "operator" || len(v.Scopes) != 1 || v.Created != before.Created || v.ID == before.ID {
		t.Fatalf("rotate: %d %s", w.Code, w.Body)
	}
	if _, _, _, ok := apiIdentity(old, "", time.Now()); ok {
		t.Error("the old secret still works")
	}
	if name, role, _, ok := apiIdentity(v.Secret, "", time.Now()); !ok || name != "ci" || role != "operator" {
		t.Errorf("the new secret: %s %s %v", name, role, ok)
	}
	if code := api.code("admin", "POST", "/api/v1/tokens/nope/rotate", ""); code != 404 {
		t.Errorf("unknown token: %d", code)
	}
	if code := api.code("operator", "POST", "/api/v1/tokens/ci/rotate", ""); code != 403 {
		t.Errorf("operator rotated a token: %d", code)
	}
}

// Every answer carries a request id: the client's when well formed, else a new one; changes
// record it in the audit log.
func TestRequestID(t *testing.T) {
	api := newAPIHarness(t, registerOpsRoutes)
	send := func(id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"name":"x`+id[:1]+`","role":"viewer"}`))
		r.Header.Set("Authorization", "Bearer "+api.tok["admin"])
		r.Header.Set("X-Request-Id", id)
		w := httptest.NewRecorder()
		api.h.ServeHTTP(w, r)
		return w
	}
	if w := send("trace-1.a_B"); w.Header().Get("X-Request-Id") != "trace-1.a_B" {
		t.Errorf("echo: %q", w.Header().Get("X-Request-Id"))
	}
	if got := send("bad id\nwith newline").Header().Get("X-Request-Id"); !requestIDRe.MatchString(got) || strings.Contains(got, "bad") {
		t.Errorf("replaced: %q", got)
	}
	if got := api.req("viewer", "GET", "/api/v1/whoami", "").Header().Get("X-Request-Id"); len(got) != 16 {
		t.Errorf("generated: %q", got)
	}
	b, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(b), `"request_id":"trace-1.a_B"`) {
		t.Errorf("audit: %s", b)
	}
}

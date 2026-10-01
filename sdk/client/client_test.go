package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

func TestClient(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.RequestURI(), r.Method
		switch r.URL.Path {
		case "/api/v1/modules":
			json.NewEncoder(w).Encode([]api.ModuleInfo{{Name: "clamav", Status: "enabled"}})
		case "/api/v1/apps/db":
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(api.Message{Status: "error", Message: "Forbidden: requires the admin role"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "tok123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mods, err := c.Modules(ctx)
	if err != nil || len(mods) != 1 || mods[0].Name != "clamav" || gotAuth != "Bearer tok123" {
		t.Fatalf("modules: %v %v auth=%q", mods, err, gotAuth)
	}
	_, err = c.RemoveApp(ctx, "db", true)
	var e *Error
	if !errorsAs(err, &e) || e.Status != 403 || e.Message != "Forbidden: requires the admin role" || gotPath != "/api/v1/apps/db?purge=true" || gotMethod != "DELETE" {
		t.Fatalf("error mapping: %v path=%s", err, gotPath)
	}
	if _, err := c.GatewayRoute(ctx, "missing"); !IsNotFound(err) {
		t.Fatalf("404: %v", err)
	}
	// Invalid routes fail locally, before any request.
	gotPath = ""
	if _, err := c.PutGatewayRoute(ctx, schema.GatewayRoute{Name: "x", Hosts: []string{"bad host"}, To: []schema.GatewayUpstream{{App: "a"}}}); err == nil || gotPath != "" {
		t.Fatalf("local validation: %v (sent %q)", err, gotPath)
	}
	if _, err := New("http://10.0.0.5:8443", "t"); err == nil {
		t.Fatal("token over plain HTTP to a remote host accepted")
	}
}

func errorsAs(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

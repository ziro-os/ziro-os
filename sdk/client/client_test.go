package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

func TestPushSource(t *testing.T) {
	archive := []byte("not really a tarball, the server here only checks the digest")
	var spec api.SourceSpec
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/deployments/site/source" || r.Header.Get("Authorization") != "Bearer dep" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		p, _ := mr.NextPart()
		json.NewDecoder(p).Decode(&spec)
		p, _ = mr.NextPart()
		got, _ = io.ReadAll(p)
		json.NewEncoder(w).Encode(map[string]string{"id": "b1"})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "dep")
	r := bytes.NewReader(archive)
	r.Seek(0, io.SeekEnd) // as left by whoever wrote the archive: PushSource reads from the start
	out, err := c.PushSource(context.Background(), "site", api.SourceSpec{Port: 3000}, r)
	sum := sha256.Sum256(archive)
	if err != nil || out["id"] != "b1" || !bytes.Equal(got, archive) || spec.Port != 3000 || spec.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("push: %v %v spec=%+v got=%d bytes", out, err, spec, len(got))
	}
}

func TestTailscaleAndInterfaceRuleCalls(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotMethod, gotBody = r.URL.Path, r.Method, string(b)
		w.Write([]byte(`{"enabled":true,"state":"Running","status":"ok"}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "t")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if st, err := c.Tailscale(ctx); err != nil || st["state"] != "Running" || gotMethod != "GET" || gotPath != "/api/v1/tailscale" {
		t.Fatalf("status: %v %v %s %s", st, err, gotMethod, gotPath)
	}
	if _, err := c.TailscaleJoin(ctx, TailscaleUp{AuthKey: "tskey-auth-abc", Hostname: "web1", Tags: []string{"tag:server"}}); err != nil ||
		gotMethod != "POST" || gotPath != "/api/v1/tailscale/up" ||
		gotBody != `{"auth_key":"tskey-auth-abc","hostname":"web1","tags":["tag:server"]}` {
		t.Fatalf("join: %v %s %s %s", err, gotMethod, gotPath, gotBody)
	}
	for path, call := range map[string]func() error{
		"/api/v1/tailscale/down":   func() error { _, err := c.TailscaleDown(ctx); return err },
		"/api/v1/tailscale/logout": func() error { _, err := c.TailscaleLogout(ctx); return err },
	} {
		if err := call(); err != nil || gotPath != path || gotMethod != "POST" {
			t.Errorf("%s: %v %s %s", path, err, gotMethod, gotPath)
		}
	}
	if _, err := c.FirewallPortOn(ctx, "allow", "22/tcp", "tailnet ssh", "tailscale0"); err != nil ||
		gotPath != "/api/v1/firewall/allow" || gotBody != `{"comment":"tailnet ssh","iface":"tailscale0","port":"22/tcp"}` {
		t.Errorf("firewall on an interface: %v %s %s", err, gotPath, gotBody)
	}
}

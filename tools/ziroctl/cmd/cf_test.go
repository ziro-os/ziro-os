package cmd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeCF is the slice of the Cloudflare API ziroctl cf uses, with its state in memory.
type fakeCF struct {
	mu      sync.Mutex
	ingress []cfIngress
	dns     map[string]cfDNSRecord // name -> record
	apps    map[string]cfAccessApp // domain -> app
	auth    string
	scoped  bool // a least-privilege token: Tunnel Edit only, can't list accounts
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	ok := func(v any) { json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v}) }
	var body map[string]any
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		json.Unmarshal(b, &body)
	}
	p := r.URL.Path
	switch {
	case p == "/accounts" && f.scoped:
		ok([]cfAccount{})
	case p == "/accounts":
		ok([]cfAccount{{ID: "acc1", Name: "Acme"}})
	case strings.HasSuffix(p, "/cfd_tunnel") && r.Method == "GET":
		if p != "/accounts/0123456789abcdef0123456789abcdef/cfd_tunnel" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "Authentication error"}}})
			return
		}
		ok([]cfTunnel{})
	case strings.HasSuffix(p, "/configurations") && r.Method == "GET":
		ok(map[string]any{"config": map[string]any{"ingress": f.ingress}})
	case strings.HasSuffix(p, "/configurations") && r.Method == "PUT":
		b, _ := json.Marshal(body["config"].(map[string]any)["ingress"])
		f.ingress = nil
		json.Unmarshal(b, &f.ingress)
		ok(nil)
	case p == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			ok([]cfZone{{ID: "z1", Name: "example.com"}})
		} else {
			ok([]cfZone{})
		}
	case p == "/zones/z1/dns_records" && r.Method == "GET":
		if rec, found := f.dns[r.URL.Query().Get("name")]; found {
			ok([]cfDNSRecord{rec})
		} else {
			ok([]cfDNSRecord{})
		}
	case p == "/zones/z1/dns_records" && r.Method == "POST":
		n := body["name"].(string)
		f.dns[n] = cfDNSRecord{ID: "r-" + n, Type: "CNAME", Name: n, Content: body["content"].(string)}
		ok(nil)
	case strings.HasPrefix(p, "/zones/z1/dns_records/") && r.Method == "DELETE":
		for n, rec := range f.dns {
			if rec.ID == strings.TrimPrefix(p, "/zones/z1/dns_records/") {
				delete(f.dns, n)
			}
		}
		ok(nil)
	case p == "/accounts/acc1/access/apps" && r.Method == "GET":
		var out []cfAccessApp
		if a, found := f.apps[r.URL.Query().Get("domain")]; found {
			out = append(out, a)
		}
		ok(out)
	case p == "/accounts/acc1/access/apps" && r.Method == "POST":
		d := body["domain"].(string)
		f.apps[d] = cfAccessApp{ID: "app-" + d, Name: body["name"].(string), Domain: d}
		ok(nil)
	case strings.HasPrefix(p, "/accounts/acc1/access/apps/") && r.Method == "DELETE":
		delete(f.apps, strings.TrimPrefix(strings.TrimPrefix(p, "/accounts/acc1/access/apps/"), "app-"))
		ok(nil)
	default:
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 7003, "message": "no route " + p}}})
	}
}

func setupCF(t *testing.T) *fakeCF {
	t.Helper()
	f := &fakeCF{dns: map[string]cfDNSRecord{}, apps: map[string]cfAccessApp{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	oldBase, oldDir, oldTPM, oldMods := cfAPIBase, cfDir, tpmDevice, moduleStateDir
	t.Cleanup(func() { cfAPIBase, cfDir, tpmDevice, moduleStateDir = oldBase, oldDir, oldTPM, oldMods })
	cfAPIBase, cfDir, tpmDevice = srv.URL, filepath.Join(dir, "cloudflared"), filepath.Join(dir, "no-tpm")
	moduleStateDir = filepath.Join(dir, "modules")
	return f
}

func TestCFGateAndEnvScrub(t *testing.T) {
	setupCF(t)
	t.Setenv("CF_API_TOKEN", "secret-token")
	t.Setenv("TUNNEL_TOKEN", "x")
	if err := cfCmd.PersistentPreRunE(cfStatusCmd, nil); err == nil || !strings.Contains(err.Error(), "module enable cloudflared") {
		t.Fatalf("disabled module: %v", err)
	}
	os.MkdirAll(moduleStateDir, 0755)
	os.WriteFile(filepath.Join(moduleStateDir, "cloudflared.json"), []byte(`{"name":"cloudflared","status":"disabling"}`), 0644)
	if cfCmd.PersistentPreRunE(cfStatusCmd, nil) == nil {
		t.Fatal("status allowed while disabling")
	}
	if err := cfCmd.PersistentPreRunE(cfDownCmd, nil); err != nil {
		t.Fatalf("disable must be able to run cf down: %v", err)
	}
	os.WriteFile(filepath.Join(moduleStateDir, "cloudflared.json"), []byte(`{"name":"cloudflared","status":"enabled"}`), 0644)
	if err := cfCmd.PersistentPreRunE(cfStatusCmd, nil); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CF_API_TOKEN") != "" || os.Getenv("TUNNEL_TOKEN") != "" || cfEnvToken != "secret-token" {
		t.Fatal("secrets left in the environment daemons inherit")
	}
}

func TestCFLoginAndRoutes(t *testing.T) {
	f := setupCF(t)
	cfEnvToken, cfAccountID, cfTokenFile = "tok-123", "", ""
	t.Cleanup(func() { cfEnvToken = "" })
	if err := cfLoginCmd.RunE(cfLoginCmd, nil); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(cfLoginPath())
	di, _ := os.Stat(cfDir)
	if fi.Mode().Perm() != 0600 || di.Mode().Perm() != 0700 {
		t.Fatalf("token file %v, dir %v", fi.Mode(), di.Mode())
	}
	if l, _ := loadCFLogin(); l.Account != "acc1" || l.Provider != "file" {
		t.Fatalf("%+v", l)
	}
	if _, _, err := cfRouteAPI(); err == nil {
		t.Fatal("routes without a tunnel")
	}
	cfWrite(cfTunnelPath(), []byte(`{"id":"tid","name":"h1","account":"acc1"}`))

	cfAccess = "alice@example.com,@example.com"
	t.Cleanup(func() { cfAccess = "" })
	for range 2 { // idempotent
		if err := cfRouteAddCmd.RunE(cfRouteAddCmd, []string{"App.Example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	cfAccess = ""
	if err := cfRouteAddCmd.RunE(cfRouteAddCmd, []string{"grafana.example.com", "3000"}); err != nil {
		t.Fatal(err)
	}
	if f.auth != "Bearer tok-123" {
		t.Fatalf("auth header %q", f.auth)
	}
	want := []cfIngress{{Hostname: "app.example.com", Service: cfDefaultURL}, {Hostname: "grafana.example.com", Service: "http://127.0.0.1:3000"}, {Service: cfCatchAll}}
	if b1, b2 := mustJSON(f.ingress), mustJSON(want); b1 != b2 {
		t.Fatalf("ingress %s\nwant %s", b1, b2)
	}
	if f.dns["app.example.com"].Content != "tid.cfargotunnel.com" || len(f.dns) != 2 {
		t.Fatalf("dns %+v", f.dns)
	}
	if len(f.apps) != 1 || f.apps["app.example.com"].Name != "ziro: app.example.com" {
		t.Fatalf("access %+v", f.apps)
	}

	// A hostname that already points elsewhere is never taken over.
	f.dns["www.example.com"] = cfDNSRecord{ID: "r-www", Type: "A", Name: "www.example.com", Content: "192.0.2.1"}
	if err := cfRouteAddCmd.RunE(cfRouteAddCmd, []string{"www.example.com"}); err == nil || !strings.Contains(err.Error(), "already has a DNS record") {
		t.Fatalf("took over a record: %v", err)
	}
	if err := cfRouteAddCmd.RunE(cfRouteAddCmd, []string{"x.other.org"}); err == nil {
		t.Fatal("hostname outside the account's zones accepted")
	}

	if err := cfRouteRmCmd.RunE(cfRouteRmCmd, []string{"app.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.dns["app.example.com"]; ok || len(f.apps) != 0 || len(f.ingress) != 2 || f.ingress[1].Service != cfCatchAll {
		t.Fatalf("after rm: dns %v apps %v ingress %v", f.dns, f.apps, f.ingress)
	}
	if _, ok := f.dns["www.example.com"]; !ok {
		t.Fatal("removed a record ziroctl didn't make")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestCFInputChecks(t *testing.T) {
	for in, want := range map[string]string{"8080": "http://127.0.0.1:8080", "https://10.0.0.5:8443": "https://10.0.0.5:8443", "ssh://127.0.0.1:22": "ssh://127.0.0.1:22"} {
		if got, err := cfOrigin(in); err != nil || got != want {
			t.Errorf("cfOrigin(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "70000", "file:///etc/shadow", "http://", "http://a b", "localhost"} {
		if _, err := cfOrigin(bad); err == nil {
			t.Errorf("cfOrigin(%q) accepted", bad)
		}
	}
	for _, bad := range []string{"example", "-a.example.com", "a..example.com", "*.example.com", "a.example.com/x"} {
		if _, err := cfHostname(bad); err == nil {
			t.Errorf("hostname %q accepted", bad)
		}
	}
	if _, err := cfAccessList("alice@example.com, @corp.example"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"alice", "@", "a@b", "@-x.com"} {
		if _, err := cfAccessList(bad); err == nil {
			t.Errorf("--access %q accepted", bad)
		}
	}
	tok := base64.StdEncoding.EncodeToString([]byte(`{"a":"acc1","t":"tid","s":"c2VjcmV0"}`))
	if a, id, err := tunnelIDFromToken(tok); err != nil || a != "acc1" || id != "tid" {
		t.Fatalf("%s %s %v", a, id, err)
	}
	if _, _, err := tunnelIDFromToken("not-a-token"); err == nil {
		t.Fatal("bad tunnel token accepted")
	}
	line := `2026-10-05T01:02:03Z INF |  https://quiet-river-1234.trycloudflare.com                                     |`
	if quickRe.FindString(line) != "https://quiet-river-1234.trycloudflare.com" {
		t.Fatal("quick URL not found")
	}
}

func TestCFTunnelRequest(t *testing.T) {
	dir := t.TempDir()
	old := servicesDir
	t.Cleanup(func() { servicesDir = old; cfTrust.at = cfTrust.at.AddDate(-1, 0, 0) })
	servicesDir = dir
	req := func(remote string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = remote
		r.Header.Set("CF-Connecting-IP", "203.0.113.7")
		r.Header.Set("CF-Visitor", `{"scheme":"https"}`)
		return r
	}
	cfTrust.at = cfTrust.at.AddDate(-1, 0, 0)
	r := req("127.0.0.1:5000")
	if cfTunnelRequest(r) || r.RemoteAddr != "127.0.0.1:5000" || r.Header.Get("CF-Connecting-IP") != "" {
		t.Fatal("trusted the header with no tunnel running")
	}
	os.WriteFile(filepath.Join(dir, "cloudflared.conf"), nil, 0644)
	cfTrust.at = cfTrust.at.AddDate(-1, 0, 0)
	r = req("127.0.0.1:5000")
	if !cfTunnelRequest(r) || r.RemoteAddr != "203.0.113.7:5000" {
		t.Fatalf("tunnel request: %s", r.RemoteAddr)
	}
	r = req("198.51.100.9:5000") // straight from the internet: spoofed
	if cfTunnelRequest(r) || r.RemoteAddr != "198.51.100.9:5000" || r.Header.Get("CF-Connecting-IP") != "" {
		t.Fatal("trusted a spoofed header")
	}
}

func TestCFLoginLeastPrivilege(t *testing.T) {
	f := setupCF(t)
	f.scoped = true
	if _, err := cfPickAccount("tok", ""); err == nil || !strings.Contains(err.Error(), "--account") {
		t.Fatalf("no account and no way to ask: %v", err)
	}
	if _, err := cfPickAccount("tok", "not-an-id"); err == nil {
		t.Fatal("bad account id accepted")
	}
	if _, err := cfPickAccount("tok", "ffffffffffffffffffffffffffffffff"); err == nil || !strings.Contains(err.Error(), "can't manage tunnels") {
		t.Fatalf("account the token can't use: %v", err)
	}
	acc, err := cfPickAccount("tok", "0123456789abcdef0123456789abcdef")
	if err != nil || acc.ID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("%+v %v", acc, err)
	}
	f.scoped = false
	if acc, err := cfPickAccount("tok", ""); err != nil || acc.ID != "acc1" {
		t.Fatalf("listable account: %+v %v", acc, err)
	}
}

func TestTraversableArtifactDirs(t *testing.T) {
	root := t.TempDir()
	old := traversableRoot
	t.Cleanup(func() { traversableRoot = old })
	traversableRoot = filepath.Join(root, "ziro")
	bin := filepath.Join(traversableRoot, "plugins", "x", "bin")
	os.MkdirAll(filepath.Dir(bin), 0700)
	os.Chmod(traversableRoot, 0700) // created root-only, as an upgrade does
	os.Chmod(filepath.Join(traversableRoot, "plugins"), 0750)
	os.WriteFile(bin, nil, 0755)
	if err := traversable(bin); err != nil {
		t.Fatal(err)
	}
	for d, want := range map[string]os.FileMode{traversableRoot: 0711, filepath.Join(traversableRoot, "plugins"): 0751, filepath.Dir(bin): 0711} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", d, fi.Mode().Perm(), want)
		}
	}
	if err := traversable(filepath.Join(root, "elsewhere", "bin")); err != nil {
		t.Fatal("paths outside the plugin root must be left alone")
	}
}

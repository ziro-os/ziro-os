package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestTailscaleAPI(t *testing.T) {
	dir := tsStub(t)
	oldEnsure, oldRun := tsEnsureRunning, tsIsRunning
	tsEnsureRunning, tsIsRunning = func() error { return nil }, func() bool { return true }
	t.Cleanup(func() { tsEnsureRunning, tsIsRunning = oldEnsure, oldRun })
	h := newAPIHarness(t, registerTailscaleRoutes)

	// module not enabled: status says so, changes are refused
	if rec := h.req("viewer", "GET", "/api/v1/tailscale", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("status without the module: %d %s", rec.Code, rec.Body)
	}
	const key = "tskey-auth-kAbCdEfGhI-abcdefghijklmnop"
	if rec := h.req("admin", "POST", "/api/v1/tailscale/up", `{"auth_key":"`+key+`"}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "not enabled") {
		t.Errorf("up without the module: %d %s", rec.Code, rec.Body)
	}
	saveModuleState(&ModuleState{Name: tsModule, Status: "enabled"})

	// roles: a viewer reads status; every change is admin only
	for _, c := range []struct {
		role, method, path string
		want               int
	}{
		{"", "GET", "/api/v1/tailscale", 401},
		{"viewer", "POST", "/api/v1/tailscale/up", 403},
		{"operator", "POST", "/api/v1/tailscale/up", 403},
		{"viewer", "POST", "/api/v1/tailscale/down", 403},
		{"operator", "POST", "/api/v1/tailscale/logout", 403},
	} {
		if got := h.code(c.role, c.method, c.path, `{}`); got != c.want {
			t.Errorf("%s %s as %q: %d, want %d", c.method, c.path, c.role, got, c.want)
		}
	}

	// the fake CLI records what it is asked and answers `status --json`
	log := dir + "/cli.log"
	script := `#!/bin/sh
echo "$*" >> ` + log + `
case "$2" in status) echo '{"BackendState":"Running","Version":"1.98.5","Self":{"DNSName":"web1.tail.ts.net.","TailscaleIPs":["100.101.102.103"]},"Peer":{}}';; esac
case "$*" in *"up --reset"*) f=$(echo "$*" | sed -n 's/.*--auth-key=file:\([^ ]*\).*/\1/p'); echo "KEYFILE=$(cat "$f")" >> ` + log + `;; esac
`
	os.WriteFile(tsCLI, []byte(script), 0755)
	rec := h.req("viewer", "GET", "/api/v1/tailscale", "")
	var v TailscaleView
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil || !v.Enabled || v.State != "Running" || v.Name != "web1.tail.ts.net" {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}

	// bad requests never reach the CLI, and never echo a key
	for body, want := range map[string]string{
		`{}`:                                      "auth_key",
		`{"auth_key":"hunter2-secret"}`:           "not a Tailscale auth key",
		`{"auth_key":"` + key + `","oops":1}`:     "unknown field",
		`{"auth_key":"` + key + `","tags":["x"]}`: "invalid --tag",
	} {
		rec := h.req("admin", "POST", "/api/v1/tailscale/up", body)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("body %s: %d %s (want %q)", body, rec.Code, rec.Body, want)
		}
		if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), key) {
			t.Errorf("the response echoed the key: %s", rec.Body)
		}
	}

	// a real join: the key reaches the CLI as a file, the response and the audit log have no key
	rec = h.req("admin", "POST", "/api/v1/tailscale/up", `{"auth_key":"`+key+`","hostname":"web1","tags":["tag:server"]}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Running") {
		t.Fatalf("up: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), key) {
		t.Errorf("the response holds the key: %s", rec.Body)
	}
	b, _ := os.ReadFile(log)
	out := string(b)
	if !strings.Contains(out, "--hostname=web1") || !strings.Contains(out, "--advertise-tags=tag:server") || !strings.Contains(out, "KEYFILE="+key) {
		t.Errorf("the CLI was called with:\n%s", out)
	}
	if strings.Contains(strings.ReplaceAll(out, "KEYFILE="+key, ""), key) {
		t.Errorf("the key appears outside the key file:\n%s", out)
	}
	if a, _ := os.ReadFile(auditPath); strings.Contains(string(a), key) {
		t.Errorf("the audit log holds the key")
	}

	// down and logout reach the CLI
	for _, p := range []string{"down", "logout"} {
		if rec := h.req("admin", "POST", "/api/v1/tailscale/"+p, ""); rec.Code != 200 {
			t.Errorf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	b, _ = os.ReadFile(log)
	if !strings.Contains(string(b), "--socket="+tsSocket+" down") || !strings.Contains(string(b), "--socket="+tsSocket+" logout") {
		t.Errorf("the CLI was not asked to go down and log out:\n%s", b)
	}
}

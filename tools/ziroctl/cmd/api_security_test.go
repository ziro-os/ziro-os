package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// The alerting routes expose webhook URLs and mint signing secrets: every method needs admin,
// and bans need admin to change. wrap here stands in for wrapHandler's authentication step.
func TestSecurityRoutesRBAC(t *testing.T) {
	alertConfigPath = filepath.Join(t.TempDir(), "alerting.json")
	alertSpoolDir = t.TempDir()
	var role string
	api := newAPIHarness(t, registerSecurityRoutes)
	do := func(method, path, body string) int { return api.code(role, method, path, body) }
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
	var role string
	api := newAPIHarness(t, registerHostRoutes)
	do := func(method, path, body string) int { return api.code(role, method, path, body) }
	role = "viewer"
	if c := do("GET", "/api/v1/network", ""); c != http.StatusOK {
		t.Errorf("viewer GET network: %d", c)
	}
	role = "operator"
	for _, c := range []struct{ m, p, b string }{
		{"PUT", "/api/v1/network", `{}`}, {"POST", "/api/v1/network/confirm", ""}, {"GET", "/api/v1/ssh/keys", ""},
		{"POST", "/api/v1/ssh/keys", `{"source":"gh:x"}`}, {"POST", "/api/v1/disks", `{"device":"/dev/vdb","mount":"/data"}`},
		{"POST", "/api/v1/disks/expand", ""},
		// How the host is named and which resolvers it trusts: admin, like DNS upstreams.
		{"POST", "/api/v1/network/hostname", `{"hostname":"api-node"}`}, {"POST", "/api/v1/network/dns", `{"servers":["198.51.100.53"]}`},
	} {
		if code := do(c.m, c.p, c.b); code != http.StatusForbidden {
			t.Errorf("operator %s %s: %d, want 403", c.m, c.p, code)
		}
	}
	role = "admin"
	if c := do("POST", "/api/v1/network/hostname", `{"hostname":"api-node"}`); c != http.StatusOK {
		t.Errorf("admin hostname: %d", c)
	}
	if b, _ := os.ReadFile(hostnamePath); string(b) != "api-node\n" {
		t.Errorf("hostname file %q", b)
	}
	// Applying a network config over the API without a rollback timer is refused.
	if c := do("PUT", "/api/v1/network", `{"config":{"interfaces":[{"name":"eth0","mode":"dhcp"}]}}`); c != http.StatusBadRequest {
		t.Errorf("PUT without confirm_timeout: %d", c)
	}
}

func TestDNSRoutesRBAC(t *testing.T) {
	dir := t.TempDir()
	dnsConfigPath, dnsStatsPath = filepath.Join(dir, "dns.json"), filepath.Join(dir, "stats.json")
	resolvPinned = filepath.Join(dir, "udhcpc.conf")
	var role string
	api := newAPIHarness(t, registerDNSRoutes)
	do := func(method, path, body string) int { return api.code(role, method, path, body) }
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

func TestModuleRoutesRBAC(t *testing.T) {
	var role string
	api := newAPIHarness(t, registerModuleRoutes)
	do := func(method, path string) int { return api.code(role, method, path, "") }
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

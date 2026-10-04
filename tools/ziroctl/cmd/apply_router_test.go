package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// The router section: the first apply creates, the second changes nothing, an edit changes only
// its item, a bad value changes nothing, and what the file doesn't mention is left alone.
func TestApplyRouter(t *testing.T) {
	clusterDir = t.TempDir()
	old := appliedHostConfig
	appliedHostConfig = filepath.Join(t.TempDir(), "applied.yaml")
	t.Cleanup(func() { appliedHostConfig = old })
	st, _ := routerTestState(t, zr.ACL{}) // has network "office"
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(clusterConfigPath(), ClusterConfig{Role: "master", MasterAddr: "10.0.0.1:7443"}); err != nil {
		t.Fatal(err)
	}
	host := func(webPort string) []byte {
		return []byte(`host:
  version: 1
  router:
    endpoints: [router.example.com:7443]
    networks:
      - name: lab
        client_version: 1.0.30
        acl:
          rules:
            - {src: ["tag:web"], dst: ["tag:db:` + webPort + `"], proto: tcp}
        sso: {domains: ["@Example.com"], tags: [laptop], key_expiry_hours: 2160}
    moons:
      - {name: sg-1, public: relay-sg.example.com:8443}
`)
	}
	dir := t.TempDir()
	plan, err := applyHostFile(host("5432"), dir, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("plan: %+v", plan)
	}
	for _, c := range plan {
		if c.Action != "update" {
			t.Errorf("first apply: %+v", c)
		}
	}
	cur, _ := readState()
	R := routerOf(cur)
	lab := findNetwork(R, "lab")
	if lab == nil || lab.ClientVersion != "1.0.30" || len(lab.ACL.Rules) != 1 || lab.SSO == nil || lab.SSO.Domains[0] != "example.com" ||
		strings.Join(R.Endpoints, ",") != "router.example.com:7443" || findMoon(R, "sg-1") == nil || findMoon(R, "sg-1").TokenHash == "" {
		t.Fatalf("not applied: %+v", R)
	}
	if findNetwork(R, "office") == nil {
		t.Fatal("a network the file doesn't mention was removed")
	}
	tokenHash := findMoon(R, "sg-1").TokenHash

	plan, _ = applyHostFile(host("5432"), dir, false, 0)
	for _, c := range plan {
		if c.Action != "unchanged" {
			t.Errorf("second apply plans %+v", c)
		}
	}
	cur, _ = readState()
	if findMoon(routerOf(cur), "sg-1").TokenHash != tokenHash {
		t.Fatal("re-applying issued a new moon token")
	}

	plan, _ = applyHostFile(host("5433"), dir, false, 0)
	changed := 0
	for _, c := range plan {
		if c.Action == "update" {
			changed++
			if c.Item != "network lab" {
				t.Errorf("unexpected change %+v", c)
			}
		}
	}
	cur, _ = readState()
	if changed != 1 || findNetwork(routerOf(cur), "lab").ACL.Rules[0].Dst[0] != "tag:db:5433" {
		t.Fatalf("ACL edit: %d changes", changed)
	}

	bad := strings.Replace(string(host("5434")), "@Example.com", "not a domain", 1)
	if _, err := applyHostFile([]byte(bad), dir, false, 0); err == nil {
		t.Fatal("an invalid sign-in domain was accepted")
	}
	cur, _ = readState()
	if findNetwork(routerOf(cur), "lab").ACL.Rules[0].Dst[0] != "tag:db:5433" {
		t.Fatal("a rejected file changed the router")
	}
}

// The router file in docs/router-deploy.md is valid: it parses strictly and plans cleanly.
func TestApplyRouterGuideExample(t *testing.T) {
	clusterDir = t.TempDir()
	old := appliedHostConfig
	appliedHostConfig = filepath.Join(t.TempDir(), "applied.yaml")
	t.Cleanup(func() { appliedHostConfig = old })
	st, _ := routerTestState(t, zr.ACL{})
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(clusterConfigPath(), ClusterConfig{Role: "master", MasterAddr: "10.0.0.1:7443"}); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile("../../../docs/router-deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, _ := strings.Cut(string(md), "```yaml\n# router.yaml\n")
	example, _, ok := strings.Cut(rest, "```")
	if !ok || !strings.Contains(example, "router:") {
		t.Fatal("router.yaml example not found in the guide")
	}
	secret := filepath.Join(t.TempDir(), "oidc.secret")
	_ = os.WriteFile(secret, []byte("s3cret\n"), 0600)
	example = strings.Replace(example, "/root/oidc.secret", secret, 1)
	plan, err := applyHostFile([]byte(example), t.TempDir(), true, 0) // dry run: no provider contacted
	if err != nil {
		t.Fatalf("guide example: %v", err)
	}
	if len(plan) < 5 {
		t.Fatalf("guide example plans %+v", plan)
	}
}

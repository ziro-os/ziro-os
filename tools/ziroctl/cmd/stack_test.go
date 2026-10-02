package cmd

import (
	"encoding/json"
	"github.com/ziro-os/ziro-os/sdk/catalog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStackUpPlanApplyIdempotent(t *testing.T) {
	calls := stubApps(t)
	old := stackStateDir
	stackStateDir = t.TempDir()
	defer func() { stackStateDir = old }()
	oldDefs := loadAppDefsFn
	loadAppDefsFn = func() map[string]AppDef { return map[string]AppDef{"postgres": testPostgresDef()} }
	defer func() { loadAppDefsFn = oldDefs }()

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "apps"), 0755)
	web := `{"schema":1,"name":"web","description":"w","default":"1","versions":{"1":{"images":{"web":"docker.io/library/nginx:1@sha256:` +
		strings.Repeat("a", 64) + `"}}},"components":[{"name":"web","port":8080}]}`
	os.WriteFile(filepath.Join(dir, "apps", "web.json"), []byte(web), 0644)
	file := filepath.Join(dir, "shop.yaml")
	os.WriteFile(file, []byte(`
stack: shop
version: 1
apps:
  web: {app: ./apps/web.json, depends_on: [db], resources: {memory: 128Mi}}
  db: {app: "postgres:18", set: {user: shop}}
`), 0644)

	s, apps, err := loadStackFile(file)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planStack(s, apps, nil)
	if err != nil || len(plan) != 2 || plan[0].Key != "db" || plan[0].Action != "create" || plan[1].Action != "create" {
		t.Fatalf("first plan %+v %v", plan, err)
	}
	if err := applyStack(s, apps, plan, nil); err != nil {
		t.Fatal(err)
	}
	// The stack's resources reach the web container.
	var webRun []string
	for _, c := range *calls {
		if c[0] == "run" && slices.Contains(c, "ziro-app-shop-web") {
			webRun = c
		}
	}
	if !slices.Contains(webRun, "134217728") {
		t.Errorf("web run args lack the memory limit: %v", webRun)
	}

	// Same file again: nothing to do.
	prev, _ := loadStackState("shop")
	plan, _ = planStack(s, apps, prev)
	for _, c := range plan {
		if c.Action != "unchanged" {
			t.Errorf("second run plans %+v", c)
		}
	}
	// Change a setting and drop web: db updates, web is removed.
	os.WriteFile(file, []byte("stack: shop\nversion: 1\napps:\n  db: {app: \"postgres:18\", set: {user: other}}\n"), 0644)
	s2, apps2, _ := loadStackFile(file)
	plan, _ = planStack(s2, apps2, prev)
	if len(plan) != 2 || plan[0].Action != "update" || plan[1].Action != "remove" || plan[1].Instance != "shop-web" {
		t.Fatalf("change plan %+v", plan)
	}

	// Local definitions can't leave the stack's directory, and aren't accepted without one.
	if _, err := resolveStackApps(Stack{Stack: "x", Version: 1, Apps: map[string]StackApp{"a": {App: "./apps/web.json"}}}, ""); err == nil {
		t.Error("local definition accepted without a directory")
	}
	if err := stackDown("shop", false); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStackState("shop"); err == nil {
		t.Error("state kept after down")
	}
}

// A link passes the dependency's output (with its password) through the env file only, using
// the dependency's container name on the stack network.
func TestStackLinksDelivered(t *testing.T) {
	stubApps(t)
	old := stackStateDir
	stackStateDir = t.TempDir()
	defer func() { stackStateDir = old }()
	oldDefs := loadAppDefsFn
	loadAppDefsFn = func() map[string]AppDef { return map[string]AppDef{"postgres": testPostgresDef()} }
	defer func() { loadAppDefsFn = oldDefs }()
	var webRun []string
	var webEnv string
	stubbed := appNerdctl
	appNerdctl = func(args ...string) error {
		if args[0] == "run" && slices.Contains(args, "ziro-app-shop-web") {
			webRun = args
			for i, a := range args {
				if a == "--env-file" {
					b, _ := os.ReadFile(args[i+1])
					webEnv = string(b)
				}
			}
		}
		return stubbed(args...)
	}
	dir := t.TempDir()
	web := `{"schema":1,"name":"web","description":"w","default":"1","versions":{"1":{"images":{"web":"docker.io/library/nginx:1@sha256:` +
		strings.Repeat("a", 64) + `"}}},"components":[{"name":"web","port":8080}]}`
	os.WriteFile(filepath.Join(dir, "web.json"), []byte(web), 0644)
	os.WriteFile(filepath.Join(dir, "s.yaml"), []byte("stack: shop\nversion: 1\napps:\n  db: {app: postgres}\n"+
		"  web: {app: ./web.json, depends_on: [db], links: {DATABASE_URL: db.url}}\n"), 0644)
	s, apps, err := loadStackFile(filepath.Join(dir, "s.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := planStack(s, apps, nil)
	if err := applyStack(s, apps, plan, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(webEnv, "DATABASE_URL=postgres://app:") || !strings.Contains(webEnv, "@ziro-app-shop-db:5432/app") {
		t.Errorf("env file: %q", webEnv)
	}
	for _, a := range webRun {
		if strings.Contains(a, "DATABASE_URL") {
			t.Errorf("the link leaked into argv: %v", webRun)
		}
	}
	if !slices.Contains(webRun, "ziro-stack-shop") {
		t.Errorf("web not on the stack network: %v", webRun)
	}
	// A link to an output the dependency doesn't have is refused before anything deploys.
	os.WriteFile(filepath.Join(dir, "s.yaml"), []byte("stack: shop\nversion: 1\napps:\n  db: {app: postgres}\n"+
		"  web: {app: ./web.json, depends_on: [db], links: {X: db.nope}}\n"), 0644)
	if _, _, err := loadStackFile(filepath.Join(dir, "s.yaml")); err == nil || !strings.Contains(err.Error(), "no output") {
		t.Errorf("bad link: %v", err)
	}
}

// A stack published in a signed app catalog is found, separate from the apps, and only uses
// catalog apps.
func TestCatalogStacks(t *testing.T) {
	stubModules(t)
	pub, priv := testCatalogKey(t)
	dir, _ := serveCatalog(t, pub)
	repo := CatalogRepo{Name: "ziro-apps", URL: officialRepos[0].URL, Kind: "app", Key: pub, Official: true}
	officialRepos = []CatalogRepo{repo}
	src := t.TempDir()
	app, _ := json.Marshal(testPostgresDef())
	os.MkdirAll(filepath.Join(src, "apps", "postgres"), 0755)
	os.WriteFile(filepath.Join(src, "apps", "postgres", "app.json"), app, 0644)
	os.MkdirAll(filepath.Join(src, "stacks", "pgstack"), 0755)
	os.WriteFile(filepath.Join(src, "stacks", "pgstack", "stack.yaml"), []byte("stack: pgstack\nversion: 1\ndescription: a db\napps:\n  db: {app: postgres}\n"), 0644)
	if _, err := catalog.Build(src, dir, "ziro-apps", "app", 24*time.Hour, catalogNow(), catalogCheckers["app"]); err != nil {
		t.Fatal(err)
	}
	catalog.Sign(dir, priv)
	if _, err := refreshRepo(repo); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadAppDefs()["postgres"]; !ok {
		t.Fatal("app missing")
	}
	s, ok := loadCatalogStacks()["pgstack"]
	if !ok || s.Apps["db"].App != "postgres" || len(loadAppDefs()) != 1 {
		t.Fatalf("stacks %+v", loadCatalogStacks())
	}
}

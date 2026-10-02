package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

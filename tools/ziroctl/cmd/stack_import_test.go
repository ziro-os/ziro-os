package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStackImportCompose(t *testing.T) {
	old := resolveDigest
	resolveDigest = func(img string) (string, error) {
		return "docker.io/library/" + strings.Split(img, ":")[0] + ":" + strings.Split(img, ":")[1] + "@sha256:" + strings.Repeat("b", 64), nil
	}
	defer func() { resolveDigest = old }()
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  web_app:
    image: nginx:1.27
    ports: ["8080:80"]
    environment:
      MODE: prod
    command: ["nginx", "-g", "daemon off;"]
    healthcheck: {test: ["CMD", "wget", "-qO-", "http://127.0.0.1/"]}
    depends_on: [db]
  db:
    image: postgres:18
    environment:
      - POSTGRES_PASSWORD=hunter2
    volumes: [pgdata:/var/lib/postgresql/data, ./init:/docker-entrypoint-initdb.d]
    privileged: true
volumes: {pgdata: {}}
`), 0644)
	svcs, err := parseComposeFile(compose)
	if err != nil || len(svcs) != 2 {
		t.Fatalf("%+v %v", svcs, err)
	}
	st, defs, warn, err := importCompose("shop", svcs)
	if err != nil {
		t.Fatal(err)
	}
	web, db := defs["web-app"], defs["db"]
	if web.Components[0].Port != 80 || st.Apps["web-app"].Publish != 8080 || web.Components[0].Env["MODE"] != "prod" ||
		strings.Join(web.Components[0].Args, " ") != "nginx -g daemon off;" || web.Components[0].Health[0] != "wget" {
		t.Errorf("web %+v %+v", web.Components[0], st.Apps["web-app"])
	}
	if len(db.Components[0].Data) != 1 || db.Components[0].Data[0] != "/var/lib/postgresql/data" || st.Apps["web-app"].DependsOn[0] != "db" {
		t.Errorf("db %+v", db.Components[0])
	}
	all := strings.Join(warn, "\n")
	for _, w := range []string{"bind mount ./init", "POSTGRES_PASSWORD holds a credential", `"privileged"`, "db: no healthcheck"} {
		if !strings.Contains(all, w) {
			t.Errorf("missing warning %q in:\n%s", w, all)
		}
	}
	if !strings.HasSuffix(db.Versions["1"].Images["db"], "@sha256:"+strings.Repeat("b", 64)) {
		t.Errorf("image not pinned: %s", db.Versions["1"].Images["db"])
	}
}

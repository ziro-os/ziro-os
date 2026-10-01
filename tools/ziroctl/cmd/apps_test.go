package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testDigest = "@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"

func testPostgresDef() AppDef {
	return AppDef{Schema: 1, Name: "postgres", Description: "pg", Default: "18",
		Versions: map[string]AppVersion{"17": {Images: map[string]string{"db": "docker.io/library/postgres:17" + testDigest}},
			"18": {Images: map[string]string{"db": "docker.io/library/postgres:18" + testDigest}}},
		Settings: []Setting{{Name: "user", Default: "app", Pattern: `^[a-z_][a-z0-9_]{0,62}$`}},
		Secrets:  map[string]string{"POSTGRES_PASSWORD": "alnum:32"},
		Components: []AppComponent{{Name: "db", Port: 5432, Env: map[string]string{"POSTGRES_USER": "{{setting.user}}"},
			Secrets: []string{"POSTGRES_PASSWORD"}, Data: []string{"/var/lib/postgresql/data"}, Health: []string{"pg_isready"}}},
		Outputs: map[string]string{"url": "postgres://{{setting.user}}:{{secret.POSTGRES_PASSWORD}}@{{host}}:{{port}}/app"}}
}

// stubApps puts every path an app touches in a temp dir and records nerdctl calls.
func stubApps(t *testing.T) *[][]string {
	root := t.TempDir()
	oldState, oldData, oldSecrets, oldCluster, oldNerd, oldGW := appStateDir, appDataRoot, secretEnvDir, clusterDir, appNerdctl, gatewayLocalDir
	appStateDir, appDataRoot, secretEnvDir, clusterDir = filepath.Join(root, "apps"), filepath.Join(root, "data"), filepath.Join(root, "run"), filepath.Join(root, "cluster")
	gatewayLocalDir = filepath.Join(root, "gateway")
	var calls [][]string
	appNerdctl = func(args ...string) error {
		if args[0] == "run" { // the env file must exist while the container is created
			for i, a := range args {
				if a == "--env-file" {
					if _, err := os.Stat(args[i+1]); err != nil {
						t.Errorf("env file missing at run: %v", err)
					}
				}
			}
		}
		calls = append(calls, args)
		return nil
	}
	t.Cleanup(func() {
		appStateDir, appDataRoot, secretEnvDir, clusterDir, appNerdctl, gatewayLocalDir = oldState, oldData, oldSecrets, oldCluster, oldNerd, oldGW
	})
	return &calls
}

func TestAppDeployLocal(t *testing.T) {
	calls := stubApps(t)
	in := &AppInstance{Name: "db", App: "postgres", Version: "18", Mode: "local", Def: testPostgresDef(), Settings: map[string]string{"user": "app"}}
	if err := deployAppLocal(in, appDeployOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := saveAppInstance(in); err != nil {
		t.Fatal(err)
	}
	var run []string
	for _, c := range *calls {
		if c[0] == "run" {
			run = c
		}
	}
	secrets, _ := loadOrCreateSecrets(appSecretsPath("db"), nil)
	pw := secrets["POSTGRES_PASSWORD"]
	joined := strings.Join(run, " ")
	for _, want := range []string{"--name ziro-app-db", "--security-opt no-new-privileges", "--cap-drop NET_RAW", "-p 127.0.0.1:5432:5432",
		"--label ziro.apps=db", "ZIRO_REPLICA=0", "--env-file", dataDir("db", 0, "/var/lib/postgresql/data") + ":/var/lib/postgresql/data",
		"-- docker.io/library/postgres:18"} {
		if !strings.Contains(joined, want) {
			t.Errorf("run args lack %q: %s", want, joined)
		}
	}
	if len(pw) != 32 || strings.Contains(joined, pw) {
		t.Fatalf("password must be generated and never in argv: %s", joined)
	}
	if strings.Contains(joined, "ziro.cluster=true") {
		t.Fatal("a local app must not carry the cluster label (the agent would remove it)")
	}
	if ents, _ := os.ReadDir(secretEnvDir); len(ents) != 0 {
		t.Fatal("env file left behind after the container was created")
	}
	if !slices.ContainsFunc(*calls, func(c []string) bool { return c[0] == "exec" && c[2] == "pg_isready" }) {
		t.Fatal("no readiness check")
	}
	out, err := appOutputs(in)
	if err != nil || out["url"] != "postgres://app:"+pw+"@127.0.0.1:5432/app" {
		t.Fatalf("outputs %v %v", out, err)
	}

	// Redeploy keeps the password; another version line is refused without --new-version.
	d := testPostgresDef()
	in2 := &AppInstance{Name: "db", App: "postgres", Version: "18", Mode: "local", Def: d, Settings: in.Settings}
	if err := deployAppLocal(in2, appDeployOpts{}); err != nil {
		t.Fatal(err)
	}
	if s, _ := loadOrCreateSecrets(appSecretsPath("db"), nil); s["POSTGRES_PASSWORD"] != pw {
		t.Fatal("redeploy changed the password")
	}

	// rm keeps data and credentials; --purge deletes them.
	os.MkdirAll(dataDir("db", 0, "/var/lib/postgresql/data"), 0700)
	if err := removeAppInstance("db", false); err != nil {
		t.Fatal(err)
	}
	if !fileExists(appSecretsPath("db")) || !fileExists(dataDir("db", 0, "/var/lib/postgresql/data")) {
		t.Fatal("rm without --purge lost data or credentials")
	}
	saveAppInstance(in)
	if err := removeAppInstance("db", true); err != nil {
		t.Fatal(err)
	}
	if fileExists(appSecretsPath("db")) || fileExists(filepath.Join(appDataRoot, "db")) {
		t.Fatal("--purge left data or credentials")
	}
}

func TestAppDeployRefusesVersionChange(t *testing.T) {
	stubApps(t)
	in := &AppInstance{Name: "postgres", App: "postgres", Version: "17", Mode: "local", Def: testPostgresDef()}
	saveAppInstance(in)
	defs := map[string]AppDef{"postgres": testPostgresDef()}
	loadDefs := loadAppDefsFn
	loadAppDefsFn = func() map[string]AppDef { return defs }
	defer func() { loadAppDefsFn = loadDefs }()
	if err := deployAppRef("postgres:18", appDeployOpts{}); err == nil || !strings.Contains(err.Error(), "--new-version") {
		t.Fatalf("version change: %v", err)
	}
	if err := deployAppRef("postgres:15", appDeployOpts{}); err == nil || !strings.Contains(err.Error(), "available: 17, 18") {
		t.Fatalf("unknown version: %v", err)
	}
}

func TestAppDeployCluster(t *testing.T) {
	stubApps(t)
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1"}); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.Nodes = []ClusterNode{{ID: "m1", Role: "master"}}
		return nil
	})
	d := AppDef{Schema: 1, Name: "mysql-cluster", Default: "8.4", Cluster: true,
		Versions: map[string]AppVersion{"8.4": {Images: map[string]string{"mysql": "docker.io/library/mysql:8.4" + testDigest}}},
		Secrets:  map[string]string{"GR_PASSWORD": "alnum:32", "GR_GROUP": "hex:16"},
		Components: []AppComponent{{Name: "mysql", Replicas: 3, MaxReplicas: 9, Port: 3306, Secrets: []string{"GR_PASSWORD", "GR_GROUP"},
			Data: []string{"/var/lib/mysql"}, Args: []string{"bash", "-c", "exec mysqld"}}}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	in := &AppInstance{Name: "mc", App: d.Name, Version: "8.4", Mode: "cluster", Def: d}
	if err := deployAppCluster(in, appDeployOpts{AllowFrom: []string{"web"}}); err != nil {
		t.Fatal(err)
	}
	st, _ := readState()
	a := st.app("mc")
	if a == nil || a.Replicas != 3 || !slices.Equal(a.Data, []string{"/var/lib/mysql"}) || !slices.Equal(a.Secrets, []string{"app-mc"}) ||
		a.Env["ZIRO_PEERS"] != "0.mc.cluster.ziro,1.mc.cluster.ziro,2.mc.cluster.ziro" || !slices.Contains(a.AllowFrom, "mc") || !slices.Contains(a.AllowFrom, "web") {
		t.Fatalf("app %+v", a)
	}
	pw := st.Secrets["app-mc"]["GR_PASSWORD"]
	if len(pw) != 32 || len(st.Secrets["app-mc"]["GR_GROUP"]) != 32 {
		t.Fatalf("secrets %v", st.Secrets["app-mc"])
	}
	for _, v := range a.Env {
		if strings.Contains(v, pw) {
			t.Fatal("secret in the app spec")
		}
	}
	// Redeploy keeps the secrets; --replicas is bounded by max_replicas.
	in2 := &AppInstance{Name: "mc", App: d.Name, Version: "8.4", Mode: "cluster", Def: d, Components: []string{"mc"}}
	saveAppInstance(in2)
	if err := deployAppCluster(in2, appDeployOpts{Replicas: 5}); err != nil {
		t.Fatal(err)
	}
	st, _ = readState()
	if st.Secrets["app-mc"]["GR_PASSWORD"] != pw || st.app("mc").Replicas != 5 {
		t.Fatal("redeploy lost secrets or ignored --replicas")
	}
	if err := deployAppCluster(in2, appDeployOpts{Replicas: 10}); err == nil {
		t.Fatal("replicas above max_replicas accepted")
	}

	// Each placed replica gets its index, its node-local data dir and a stable DNS name.
	st.Replicas = []Replica{{App: "mc", Index: 1, Node: "m1", IP: "10.201.0.7"}}
	as := assignmentsFor(st, "m1", st.Secrets)
	if len(as) != 1 || as[0].Replica != 1 || !slices.Equal(as[0].Data, []string{"/var/lib/mysql"}) {
		t.Fatalf("assignment %+v", as)
	}
	if args := strings.Join(runArgs(as[0]), " "); !strings.Contains(args, "ZIRO_REPLICA=1") || !strings.Contains(args, dataDir("mc", 1, "/var/lib/mysql")+":/var/lib/mysql") {
		t.Fatalf("run args %s", args)
	}
	if eps := podEndpoints(st); !slices.Equal(eps["1.mc"], []string{"10.201.0.7"}) {
		t.Fatalf("per-replica DNS %v", eps)
	}
	d2 := &podDNS{eps: podEndpoints(st)}
	if resp := d2.answer(dnsQuery("1.mc.cluster.ziro", 1)); resp == nil || resp[3]&0x0f != 0 || resp[7] != 1 {
		t.Fatalf("pod DNS must answer 1.mc.cluster.ziro: %v", resp)
	}
	if resp := d2.answer(dnsQuery("evil.1.mc.cluster.ziro", 1)); resp == nil || resp[3]&0x0f != 3 {
		t.Fatal("unknown names must be NXDOMAIN")
	}

	if err := removeAppInstance("mc", true); err != nil {
		t.Fatal(err)
	}
	st, _ = readState()
	if st.app("mc") != nil || st.Secrets["app-mc"] != nil {
		t.Fatal("rm --purge left the app or its secret")
	}
}

func TestDataPathsAreValidatedOnTheAgent(t *testing.T) {
	appDataRoot = t.TempDir()
	defer func() { appDataRoot = "/var/lib/ziro/apps" }()
	for _, a := range []Assignment{
		{App: "x", Data: []string{"relative"}},
		{App: "x", Data: []string{"/a/../../etc"}},
		{App: "../x", Data: []string{"/data"}},
		{App: "x", Data: []string{"/data:/etc"}},
	} {
		if ensureDataDirs(a) == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	if err := ensureDataDirs(Assignment{App: "x", Replica: 2, Data: []string{"/var/lib/mysql"}}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(appDataRoot, "x", "2", "var_lib_mysql")); err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("data dir: %v", err)
	}
}

func TestAppDeployRequestArgs(t *testing.T) {
	args, err := deployJobArgs(AppDeployRequest{App: "postgres:18", Name: "db", Set: map[string]string{"user": "x"}, Publish: 5433})
	if err != nil || strings.Join(args, " ") != "apps deploy --name=db --set=user=x --publish=5433 -- postgres:18" {
		t.Fatalf("%v %v", args, err)
	}
	for _, bad := range []AppDeployRequest{
		{App: "--privileged"}, {App: "pg; rm -rf /"}, {App: "pg", Name: "../x"},
		{App: "pg", Set: map[string]string{"a\nb": "1"}}, {App: "pg", Set: map[string]string{"a": "1\n2"}},
		{App: "pg", Publish: 70000}, {App: "pg", AllowFrom: []string{"-x"}},
	} {
		if _, err := deployJobArgs(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestAppRoutesRBAC(t *testing.T) {
	stubApps(t)
	mux := http.NewServeMux()
	var role string
	wrap := func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), apiRoleKey{}, role)))
		}
	}
	registerAppRoutes(mux, wrap)
	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	for _, r := range []string{"viewer", "operator"} {
		role = r
		if code := do("POST", "/api/v1/apps/deploy", `{"app":"postgres"}`); code != http.StatusForbidden {
			t.Errorf("%s deploy: %d, want 403", r, code)
		}
	}
	role = "viewer"
	if code := do("GET", "/api/v1/apps", ""); code != http.StatusOK {
		t.Errorf("viewer list: %d", code)
	}
	role = "admin"
	if code := do("POST", "/api/v1/apps/deploy", `{"app":"--privileged"}`); code == http.StatusAccepted {
		t.Error("flag-like app ref accepted")
	}
}

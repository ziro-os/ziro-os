package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T, files map[string]string) *os.Root {
	dir := t.TempDir()
	writeTree(t, dir, files)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestDetectBuild(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		kind  string
		port  int
		has   []string // in the generated Dockerfile
		err   string
	}{
		{"dockerfile", map[string]string{"Dockerfile": "FROM x\nEXPOSE 5000\n"}, "dockerfile", 5000, nil, ""},
		{"next+pnpm", map[string]string{"package.json": `{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"15"}}`, "pnpm-lock.yaml": ""},
			"next", 3000, []string{"pnpm install --frozen-lockfile", "pnpm run build", `CMD ["sh","-c","exec pnpm start"]`, "USER node"}, ""},
		{"vite", map[string]string{"package.json": `{"scripts":{"build":"vite build"},"devDependencies":{"vite":"6"}}`, "package-lock.json": ""},
			"static", 8080, []string{"npm ci", "npm run build", "COPY --from=build /app/dist /usr/share/nginx/html", "nginx-unprivileged"}, ""},
		{"node", map[string]string{"package.json": `{"scripts":{"start":"node server.js"}}`}, "node", 3000, []string{"npm install", `exec npm start`}, ""},
		{"node without start", map[string]string{"package.json": `{}`}, "", 0, nil, "no start script"},
		{"go root", map[string]string{"go.mod": "module x", "main.go": "package main\nfunc main(){}"}, "go", 8080, []string{"-o /out/app .", "distroless", "USER nonroot"}, ""},
		{"go cmd", map[string]string{"go.mod": "module x", "lib.go": "package x", "cmd/api/main.go": "package main"}, "go", 8080, []string{"-o /out/app ./cmd/api"}, ""},
		{"python", map[string]string{"requirements.txt": "flask", "Procfile": "web: gunicorn app:app --bind 0.0.0.0:$PORT"}, "python", 8000,
			[]string{"pip install -r requirements.txt", "exec gunicorn app:app --bind 0.0.0.0:$PORT", "USER app"}, ""},
		{"python without start", map[string]string{"requirements.txt": ""}, "", 0, nil, "Procfile"},
		{"static files", map[string]string{"index.html": "<h1>hi</h1>"}, "static", 8080, []string{"COPY . /usr/share/nginx/html"}, ""},
		{"compose", map[string]string{"compose.yaml": "services: {}"}, "", 0, nil, "Compose project"},
		{"nothing", map[string]string{"README.md": ""}, "", 0, nil, "can't tell"},
		{"ziro.yaml port", map[string]string{"index.html": "", "ziro.yaml": "port: 9000\nhealth: /healthz\n"}, "static", 9000, nil, ""},
		{"ziro.yaml typo", map[string]string{"index.html": "", "ziro.yaml": "prot: 9000\n"}, "", 0, nil, "ziro.yaml"},
		{"ziro.yaml escape", map[string]string{"index.html": "", "ziro.yaml": "output: ../../etc\n"}, "", 0, nil, "relative path"},
	}
	for _, c := range cases {
		p, err := detectBuild(repoRoot(t, c.files))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil || p.Kind != c.kind || p.Port != c.port {
			t.Errorf("%s: %+v %v", c.name, p, err)
			continue
		}
		for _, h := range c.has {
			if !strings.Contains(p.Dockerfile, h) {
				t.Errorf("%s: Dockerfile lacks %q:\n%s", c.name, h, p.Dockerfile)
			}
		}
		if strings.Contains(p.Dockerfile, "<no value>") || strings.Contains(p.Dockerfile, "syntax=") {
			t.Errorf("%s: template leftovers:\n%s", c.name, p.Dockerfile)
		}
	}

	// A symlink in the repository can't make the daemon read outside it.
	dir := t.TempDir()
	os.Symlink("/etc/passwd", filepath.Join(dir, "package.json"))
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	if _, err := detectBuild(root); err == nil {
		t.Error("followed a symlink out of the repository")
	}
}

func TestValidateDeployment(t *testing.T) {
	ok := Deployment{Name: "web", Repo: "https://github.com/acme/web.git", Ref: "release/1.2", Path: "apps/site"}
	if err := validateDeployment(&ok); err != nil {
		t.Fatal(err)
	}
	for _, d := range []Deployment{
		{Name: "web", Repo: "http://github.com/acme/web"},
		{Name: "web", Repo: "https://user:tok@github.com/acme/web"},
		{Name: "web", Repo: "file:///etc"},
		{Name: "web", Repo: "ext::sh -c id"},
		{Name: "web", Repo: "https://github.com/acme/web?x=1"},
		{Name: "web", Repo: "https://github.com/acme/web", Ref: "--upload-pack=id"},
		{Name: "web", Repo: "https://github.com/acme/web", Ref: "a..b"},
		{Name: "web", Repo: "https://github.com/acme/web", Path: "../x"},
		{Name: "web", Repo: "https://github.com/acme/web", Env: map[string]string{"A": "x\ny"}},
		{Name: "web", Repo: "https://github.com/acme/web", Env: map[string]string{"ZIRO_APP": "x"}},
		{Name: "../x", Repo: "https://github.com/acme/web"},
	} {
		if validateDeployment(&d) == nil {
			t.Errorf("accepted %+v", d)
		}
	}
	if nameFromRepo("https://github.com/Acme/My_Site.git") != "my-site" {
		t.Error(nameFromRepo("https://github.com/Acme/My_Site.git"))
	}
}

// The pipeline end to end with git, buildctl and the runtime stubbed: build, release, a failed
// release that puts the previous build back, a rollback, and retention.
func TestDeployPipeline(t *testing.T) {
	calls := stubApps(t)
	oldState, oldTok, oldExec, oldCheck, oldNerd, oldKeep := deployStateDir, deployTokenDir, deployExec, deployCheck, runNerdctl, deployKeep
	deployStateDir, deployTokenDir = t.TempDir(), t.TempDir()
	defer func() {
		deployStateDir, deployTokenDir, deployExec, deployCheck, runNerdctl, deployKeep = oldState, oldTok, oldExec, oldCheck, oldNerd, oldKeep
	}()
	digests := map[string]string{} // image name -> digest the stub built
	n := 0
	deployExec = func(ctx context.Context, log io.Writer, env []string, name string, args ...string) error {
		switch {
		case name == "git" && slices.Contains(args, "clone"): // the destination is the last argument
			dst := args[len(args)-1]
			os.MkdirAll(dst, 0755)
			return os.WriteFile(filepath.Join(dst, "index.html"), []byte("hi"), 0644)
		case name == "git" && slices.Contains(args, "rev-parse"):
			fmt.Fprint(log, "0123456789abcdef0123456789abcdef01234567\n")
		case name == "buildctl":
			n++
			var img, meta string
			for i, a := range args {
				if strings.HasPrefix(a, "type=image,name=") {
					img = strings.TrimSuffix(strings.TrimPrefix(a, "type=image,name="), ",unpack=true")
				}
				if a == "--metadata-file" {
					meta = args[i+1]
				}
			}
			dig := fmt.Sprintf("sha256:%064x", n)
			digests[img] = dig
			return os.WriteFile(meta, []byte(`{"containerimage.digest": "`+dig+`"}`), 0644)
		}
		return nil
	}
	var removed []string
	runNerdctl = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "images":
			var b strings.Builder
			for img, d := range digests {
				repo, tag, _ := strings.Cut(img, ":")
				fmt.Fprintf(&b, `{"Repository":%q,"Tag":%q,"Digest":%q}`+"\n", repo, tag, d)
			}
			return []byte(b.String()), nil
		case "rmi":
			removed = append(removed, args[1])
		}
		return nil, nil
	}
	healthy := true
	deployCheck = func(port int, path string, _ time.Duration) error {
		if !healthy {
			return errors.New("HTTP 502")
		}
		return nil
	}

	dd := &deployDaemon{queue: make(chan buildJob, 8)}
	run := func() *Build {
		j := <-dd.queue
		d, _ := loadDeployment(j.app)
		b, _ := loadBuild(j.app, j.build)
		_ = runBuild(context.Background(), d, b, j.secrets)
		b, _ = loadBuild(j.app, j.build)
		return b
	}
	if _, err := dd.create(DeployRequest{Deployment: Deployment{Name: "site", Repo: "https://github.com/acme/site"},
		SecretValues: map[string]string{"API_KEY": "k1"}}); err != nil {
		t.Fatal(err)
	}
	b1 := run()
	d, _ := loadDeployment("site")
	if b1.Status != "live" || d.Live != "b1" || b1.Kind != "static" || !localImageRe.MatchString(b1.Image) || d.Publish < 20000 {
		t.Fatalf("first build %+v, deployment %+v", b1, d)
	}
	in, err := loadAppInstance("site")
	if err != nil || in.Def.Components[0].Port != 8080 || in.Def.Components[0].Env["PORT"] != "8080" {
		t.Fatalf("app instance %+v %v", in, err)
	}
	secrets, _ := loadOrCreateSecrets(appSecretsPath("site"), nil, nil)
	if secrets["API_KEY"] != "k1" {
		t.Errorf("input secret not kept: %v", secrets)
	}
	var runRef string
	for _, c := range *calls {
		if c[0] == "run" {
			runRef = c[len(c)-1]
		}
		if c[0] == "pull" {
			t.Errorf("a local build was pulled: %v", c)
		}
	}
	if runRef != "ziro.local/site:b1" {
		t.Errorf("ran %q", runRef)
	}

	// A release that doesn't answer fails, and b1 serves again.
	healthy = false
	dd.enqueue(d, &Build{}, nil)
	b2 := run()
	healthy = true
	d, _ = loadDeployment("site")
	if b2.Status != "failed" || d.Live != "b1" {
		t.Fatalf("failed release: %+v live %s", b2, d.Live)
	}
	// Redeploy without secrets keeps them; then roll back to b1 from b3.
	dd.enqueue(d, &Build{}, nil)
	if b3 := run(); b3.Status != "live" {
		t.Fatalf("b3 %+v", b3)
	}
	rb, err := dd.rollback("site", "")
	if err != nil {
		t.Fatal(err)
	}
	b4 := run()
	d, _ = loadDeployment("site")
	if rb.ID != "b4" || b4.Status != "live" || !b4.Rollback || b4.Image != b1.Image || d.Live != "b4" {
		t.Fatalf("rollback %+v live %s", b4, d.Live)
	}

	// Retention: with keep=2, the oldest build records go, but b1's image stays (b4 uses it).
	deployKeep = 2
	pruneBuilds(d)
	var ids []string
	for _, b := range listBuilds("site") {
		ids = append(ids, b.ID)
	}
	if !slices.Equal(ids, []string{"b4", "b3"}) || slices.Contains(removed, "ziro.local/site:b1") {
		t.Errorf("kept %v, removed images %v", ids, removed)
	}

	// The socket API: a bad request is refused, the list shows the deployment.
	srv := httptest.NewServer(dd.routes())
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/v1/deployments", "application/json", strings.NewReader(`{"name":"x","repo":"file:///etc"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad repo: HTTP %d", resp.StatusCode)
	}
	resp, _ = http.Get(srv.URL + "/v1/deployments/site/builds/b4/log")
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "==> live") {
		t.Errorf("log: %s", body)
	}

	if err := removeDeployment("site", true); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeployment("site"); err == nil {
		t.Error("deployment still there")
	}
}

// The release check only talks to 127.0.0.1 and only sends a validated path.
func TestCheckHTTPLoopbackOnly(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RequestURI()
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	_, portStr, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://127.0.0.1"), ":")
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if err := checkHTTP(port, "/healthz?full=1", 3*time.Second); err != nil || got != "/healthz?full=1" {
		t.Fatalf("healthy app: %v (path %q)", err, got)
	}
	if err := checkHTTP(port, "", 3*time.Second); err != nil || got != "/" {
		t.Errorf("default path: %v %q", err, got)
	}
	if err := checkHTTP(port, "/boom", 100*time.Millisecond); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("server error accepted: %v", err)
	}
	for _, bad := range []string{"/a b", "/x\r\nHost: evil", "//evil.example/x", "http://evil.example/", "healthz"} {
		if err := checkHTTP(port, bad, time.Second); err == nil || !strings.Contains(err.Error(), "invalid health path") {
			t.Errorf("path %q accepted: %v", bad, err)
		}
	}
	if checkHTTP(0, "/", time.Second) == nil || checkHTTP(70000, "/", time.Second) == nil {
		t.Error("invalid port accepted")
	}
}

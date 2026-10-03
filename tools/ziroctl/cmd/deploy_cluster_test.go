package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const testLocalImage = "ziro.local/web:b2@sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

func clusterWithArchs() *ClusterState {
	now := time.Now()
	return &ClusterState{Nodes: []ClusterNode{
		{ID: "m", Role: "master", Arch: "amd64", MeshIP: "10.200.0.1", LastSeen: now, Caps: []string{capBuilder}},
		{ID: "a1", Role: "worker", Arch: "arm64", MeshIP: "10.200.0.2", LastSeen: now, Caps: []string{capBuilder}, Labels: map[string]string{"builder": "true"}},
		{ID: "a2", Role: "worker", Arch: "arm64", MeshIP: "10.200.0.3", LastSeen: now},
		{ID: "old", Role: "worker", MeshIP: "10.200.0.4", LastSeen: now}, // agent too old to report its arch
	}}
}

func TestSchedulerArchAndImageSource(t *testing.T) {
	st := clusterWithArchs()
	st.Apps = []ClusteredApp{{Name: "web", Image: testLocalImage, Replicas: 3, Arch: "arm64", ImageNode: "a1"},
		{Name: "any", Image: "docker.io/library/nginx:1@sha256:" + strings.Repeat("c", 64), Replicas: 4}}
	scheduleReplicas(st, time.Now())
	on := map[string]int{}
	for _, r := range st.Replicas {
		if r.App == "web" {
			on[r.Node]++
			if n := st.node(r.Node); n == nil || n.Arch != "arm64" {
				t.Errorf("arm64 replica placed on %q", r.Node)
			}
		}
	}
	if on["a1"]+on["a2"] != 3 {
		t.Errorf("web replicas %v", on)
	}
	if specHash(st.Apps[0]) == specHash(ClusteredApp{Name: "web", Image: testLocalImage, Replicas: 3, ImageNode: "a1"}) {
		t.Error("arch not in the spec hash")
	}
	// a2 fetches the image from a1's agent; a1 has it; a1 admits a2 through the policy.
	if got := imageSource(st, st.Apps[0], "a2"); got != "10.200.0.2:7444" {
		t.Errorf("image source for a2 = %q", got)
	}
	if imageSource(st, st.Apps[0], "a1") != "" || imageSource(st, st.Apps[1], "a2") != "" {
		t.Error("image source for the holder or a registry image")
	}
	r := imagePolicyRule(st, "a1")
	if on["a2"] > 0 && (r == nil || r.Port != imageServerPort || r.Sources[0] != "10.200.0.3") {
		t.Errorf("image rule %+v", r)
	}
	if imagePolicyRule(st, "a2") != nil {
		t.Error("a node holding no image opens its image server")
	}
	if !builtInCluster(st, testLocalImage) || builtInCluster(st, "ziro.local/x:b1@sha256:"+strings.Repeat("d", 64)) {
		t.Error("builtInCluster")
	}
}

func TestPickBuilderAndHeartbeat(t *testing.T) {
	st := clusterWithArchs()
	for i := range st.Nodes {
		st.Nodes[i].Status = "Ready"
	}
	if b := pickBuilder(st, ""); b == nil || b.ID != "a1" {
		t.Fatalf("builder %v (want the labelled one)", b)
	}
	if b := pickBuilder(st, "amd64"); b == nil || b.ID != "m" {
		t.Fatalf("amd64 builder %v", b)
	}
	st.Nodes[1].Labels["builder"] = "false"
	if b := pickBuilder(st, "arm64"); b != nil {
		t.Fatalf("builder=false or no builder plugin still picked: %v", b)
	}
	st.Nodes[1].Labels["builder"] = "true"

	st.Secrets = map[string]map[string]string{clusterBuildSecret("web"): {"GIT_TOKEN": "ghp_x"}}
	st.Builds = []ClusterBuild{{App: "web", Build: "b2", Node: "a1", Repo: "https://github.com/acme/web", Status: "pending"}}
	n := st.node("a1")
	tasks, tok := heartbeatBuilds(st, n, heartbeatRequest{Arch: "arm64"})
	if len(tasks) != 1 || tasks[0].GitToken != "ghp_x" || len(tok) != 64 {
		t.Fatalf("tasks %+v token %q", tasks, tok)
	}
	if st.Builds[0].GitToken != "" {
		t.Error("the git token was written into the build record")
	}
	if other, _ := heartbeatBuilds(st, st.node("a2"), heartbeatRequest{}); len(other) != 0 {
		t.Error("another node got a1's build")
	}
	// A result: a bad image fails the build; a good one completes it.
	_, tok2 := heartbeatBuilds(st, n, heartbeatRequest{Builds: []BuildResult{{App: "web", Build: "b2", Image: "docker.io/evil:1"}}})
	if st.Builds[0].Status != "failed" || tok2 != tok {
		t.Errorf("bad image accepted: %+v (token stable %v)", st.Builds[0], tok2 == tok)
	}
	st.Builds[0].Status = "pending"
	heartbeatBuilds(st, n, heartbeatRequest{Builds: []BuildResult{{App: "web", Build: "b2", Image: testLocalImage, Arch: "arm64"}}})
	if st.Builds[0].Status != "done" || st.Builds[0].Result.Image != testLocalImage || !builtInCluster(st, testLocalImage) {
		t.Errorf("result %+v", st.Builds[0])
	}
	if heartbeatBuilds(st, n, heartbeatRequest{Arch: "s390x"}); n.Arch != "arm64" {
		t.Error("an unknown arch was accepted")
	}
}

func TestAgentBuilds(t *testing.T) {
	old := requestBuildTask
	defer func() { requestBuildTask = old }()
	release := make(chan struct{})
	requestBuildTask = func(task ClusterBuild) BuildResult {
		<-release
		return BuildResult{App: task.App, Build: task.Build, Image: testLocalImage}
	}
	var ab agentBuilds
	task := ClusterBuild{App: "web", Build: "b2"}
	ab.start([]ClusterBuild{task})
	ab.start([]ClusterBuild{task}) // still running: not started twice
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for len(ab.report()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r := ab.report(); len(r) != 1 || r[0].Image != testLocalImage {
		t.Fatalf("report %+v", r)
	}
	ab.start(nil) // the master has it
	if len(ab.report()) != 0 {
		t.Error("result kept after the master dropped the task")
	}
}

// A node fetches a ziro.local image from its holder and runs it only if the digest matches.
func TestImageFetchAndServe(t *testing.T) {
	oldN, oldLoad := runNerdctl, loadImage
	defer func() { runNerdctl, loadImage = oldN, oldLoad }()
	_, digest, _ := strings.Cut(testLocalImage, "@")
	loaded := ""
	runNerdctl = func(args ...string) ([]byte, error) {
		if args[0] == "images" && loaded != "" {
			return []byte(`{"Repository":"ziro.local/web","Tag":"b2","Digest":"` + loaded + `"}` + "\n"), nil
		}
		return nil, nil
	}
	loadImage = func(ctx context.Context, r io.Reader) error {
		b, _ := io.ReadAll(r)
		loaded = map[bool]string{true: digest, false: "sha256:" + strings.Repeat("0", 64)}[string(b) == "good-tar"]
		return nil
	}
	tar := "good-tar"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/v1/images/"+digest {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, tar)
	}))
	l, err := net.Listen("tcp", "127.0.0.1:7444")
	if err != nil {
		t.Skip("port 7444 busy")
	}
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	a := Assignment{Image: testLocalImage, ImageFrom: "127.0.0.1:7444"}
	if name, err := fetchClusterImage(context.Background(), a, "tok"); err != nil || name != "ziro.local/web:b2" {
		t.Fatalf("fetch %q %v", name, err)
	}
	loaded, tar = "", "tampered"
	if _, err := fetchClusterImage(context.Background(), a, "tok"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("tampered image accepted: %v", err)
	}
	loaded = ""
	if _, err := fetchClusterImage(context.Background(), a, "wrong"); err == nil {
		t.Error("fetched with a wrong token")
	}
	if _, err := fetchClusterImage(context.Background(), Assignment{Image: testLocalImage, ImageFrom: "evil.example:80"}, "tok"); err == nil {
		t.Error("fetched from a non-mesh source")
	}

	// The serving side refuses a wrong token and unknown digests.
	s := &imageServer{token: "tok"}
	for _, c := range []struct {
		auth, digest string
		code         int
	}{{"Bearer bad", digest, 401}, {"", digest, 401}, {"Bearer tok", "sha256:" + strings.Repeat("9", 64), 404}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/v1/images/"+c.digest, nil)
		r.SetPathValue("digest", c.digest)
		r.Header.Set("Authorization", c.auth)
		s.serveImage(w, r)
		if w.Code != c.code {
			t.Errorf("serve %+v: HTTP %d", c, w.Code)
		}
	}
}

func TestDeployWebhook(t *testing.T) {
	stubApps(t)
	oldState, oldTok := deployStateDir, deployTokenDir
	deployStateDir, deployTokenDir = t.TempDir(), t.TempDir()
	defer func() { deployStateDir, deployTokenDir = oldState, oldTok }()
	d := &Deployment{Name: "web", Repo: "https://github.com/acme/web", Ref: "main"}
	if err := saveDeployment(d); err != nil {
		t.Fatal(err)
	}
	secret, _ := hookSecret("web", false)
	if again, _ := hookSecret("web", false); again != secret || len(secret) != 64 {
		t.Fatal("hook secret not stable")
	}
	dd := &deployDaemon{queue: make(chan buildJob, 8)}
	srv := httptest.NewServer(dd.routes())
	defer srv.Close()
	push := func(body string, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/hooks/deploy/web", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	sign := func(body string) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(body))
		return "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	main, dev := `{"ref":"refs/heads/main","repository":{"default_branch":"main"}}`, `{"ref":"refs/heads/dev"}`
	if c, _ := push(main, nil); c != 401 {
		t.Errorf("unsigned: %d", c)
	}
	if c, _ := push(main, map[string]string{"X-Hub-Signature-256": sign(dev)}); c != 401 {
		t.Errorf("signature of another body: %d", c)
	}
	if c, b := push(dev, map[string]string{"X-Hub-Signature-256": sign(dev)}); c != 202 || !strings.Contains(b, "ignored") {
		t.Errorf("other branch: %d %s", c, b)
	}
	if c, b := push(main, map[string]string{"X-Hub-Signature-256": sign(main), "X-GitHub-Delivery": "d1"}); c != 202 || !strings.Contains(b, "queued b1") {
		t.Errorf("push: %d %s", c, b)
	}
	if c, b := push(main, map[string]string{"X-Hub-Signature-256": sign(main), "X-GitHub-Delivery": "d1"}); !strings.Contains(b, "already seen") {
		t.Errorf("replay: %d %s", c, b)
	}
	if c, b := push(main, map[string]string{"X-Gitlab-Token": secret}); c != 202 || !strings.Contains(b, "already queued") {
		t.Errorf("gitlab push while queued: %d %s", c, b)
	}
	if c, _ := push(main, map[string]string{"X-Gitlab-Token": "wrong"}); c != 401 {
		t.Errorf("gitlab bad token: %d", c)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v1/hooks/deploy/nope", strings.NewReader(main))
	req.Header.Set("X-Gitlab-Token", secret)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("unknown app: %d (must look like a bad secret)", resp.StatusCode)
	}
	if _, err := os.Stat(hookSecretPath("web")); err != nil {
		t.Error(err)
	}
}

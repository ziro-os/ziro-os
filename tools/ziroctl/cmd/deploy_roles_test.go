package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNodeRoles(t *testing.T) {
	st := clusterWithArchs()
	for i := range st.Nodes {
		st.Nodes[i].Status = "Ready"
	}
	a1 := st.node("a1")
	if err := setNodeRole(a1, "runner", false); err != nil || a1.Labels["runner"] != "false" {
		t.Fatalf("runner off: %v %v", err, a1.Labels)
	}
	if err := setNodeRole(a1, "runner", true); err != nil || a1.Labels["runner"] != "" {
		t.Fatalf("runner on: %v %v", err, a1.Labels)
	}
	if err := setNodeRole(a1, "gateway", true); err != nil || !a1.Gateway {
		t.Fatal("gateway on")
	}
	if setNodeRole(a1, "nope", true) == nil {
		t.Error("an unknown role was accepted")
	}

	// A node with the runner role off gets no new replicas; the rest of the cluster does.
	st.Apps = []ClusteredApp{{Name: "any", Image: "docker.io/library/nginx:1@sha256:" + strings.Repeat("c", 64), Replicas: 6}}
	setNodeRole(st.node("a2"), "runner", false)
	scheduleReplicas(st, time.Now())
	for _, r := range st.Replicas {
		if r.Node == "a2" {
			t.Errorf("replica %d placed on a node with runner off", r.Index)
		}
	}

	// A builder that already lost the build is skipped.
	st.node("a1").Labels["builder"] = "true"
	if b := pickBuilder(st, "", map[string]bool{"a1": true}); b == nil || b.ID != "m" {
		t.Errorf("builder after losing a1: %v", b)
	}
	if b := pickBuilder(st, "", map[string]bool{"a1": true, "m": true}); b != nil {
		t.Errorf("a builder left: %v", b)
	}
}

// A build whose builder goes NotReady moves to the next builder and finishes there.
func TestBuilderFailover(t *testing.T) {
	oldDir, oldTok, oldState, oldPoll := clusterDir, deployTokenDir, deployStateDir, deployPollEvery
	clusterDir, deployTokenDir, deployStateDir, deployPollEvery = t.TempDir(), t.TempDir(), t.TempDir(), 10*time.Millisecond
	defer func() {
		clusterDir, deployTokenDir, deployStateDir, deployPollEvery = oldDir, oldTok, oldState, oldPoll
	}()
	if err := os.WriteFile(clusterConfigPath(), []byte(`{"role":"master","node_id":"m"}`), 0600); err != nil {
		t.Fatal(err)
	}
	st := &ClusterState{Nodes: []ClusterNode{
		{ID: "m", Role: "master", Arch: "amd64", MeshIP: "10.200.0.1", Status: "Ready", LastSeen: time.Now()},
		{ID: "b1", Role: "worker", Arch: "amd64", MeshIP: "10.200.0.2", Status: "Ready", Caps: []string{capBuilder}, Labels: map[string]string{"builder": "true"}},
		{ID: "b2", Role: "worker", Arch: "amd64", MeshIP: "10.200.0.3", Status: "Ready", Caps: []string{capBuilder}},
	}}
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	// The "master" of this test: b1 dies right away; b2 answers the task when it appears.
	stop, stopped := make(chan struct{}), make(chan struct{})
	defer func() { close(stop); <-stopped }() // before the globals are put back
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			_ = withState(func(st *ClusterState) error {
				for k := range st.Builds {
					cb := &st.Builds[k]
					switch {
					case cb.Node == "b1" && cb.Status == "pending":
						st.node("b1").Status = "NotReady"
					case cb.Node == "b2" && cb.Status == "pending":
						cb.Status, cb.Result = "done", &BuildResult{App: cb.App, Build: cb.Build, Image: testLocalImage, Kind: "static", Port: 8080}
					}
				}
				return nil
			})
		}
	}()
	d := &Deployment{Name: "web", Repo: "https://github.com/acme/web"}
	b := &Build{ID: "b2", App: "web"}
	var log bytes.Buffer
	plan, err := buildOnCluster(context.Background(), d, b, &log, func(f string, a ...any) {})
	if err != nil || plan.Kind != "static" || b.Node != "b2" || b.Image != testLocalImage {
		t.Fatalf("plan %+v err %v build %+v", plan, err, b)
	}
}

// An uploaded archive travels from the master to the builder over the mesh, checked by digest.
func TestClusterSourceTransfer(t *testing.T) {
	oldState, oldMax := deployStateDir, deployUploadMax
	deployStateDir = t.TempDir()
	defer func() { deployStateDir, deployUploadMax = oldState, oldMax }()
	data := []byte("archive-bytes")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	tok := strings.Repeat("ab", 32)
	if err := storeUpload("web", bytes.NewReader(data), sha); err != nil {
		t.Fatal(err)
	}

	s := &imageServer{token: tok}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/source/{app}/{sha}", s.serveSource)
	l, err := net.Listen("tcp", "127.0.0.1:7444")
	if err != nil {
		t.Skip("port 7444 busy")
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	mesh := netip.MustParsePrefix("127.0.0.0/8")
	task := ClusterBuild{App: "web", Source: deploySourceUpload, SourceSHA: sha, SourceFrom: "127.0.0.1:7444"}
	if err := fetchTaskArchive(context.Background(), task, tok, mesh); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(uploadArchive("web")); !bytes.Equal(got, data) { // here master and builder share a disk
		t.Errorf("fetched %q", got)
	}
	// Wrong token, a replaced archive, a source outside the mesh, a bad digest: all refused.
	if fetchTaskArchive(context.Background(), task, strings.Repeat("cd", 32), mesh) == nil {
		t.Error("fetched with a wrong token")
	}
	stale := task
	stale.SourceSHA = strings.Repeat("0", 64)
	if fetchTaskArchive(context.Background(), stale, tok, mesh) == nil {
		t.Error("fetched an archive that was replaced")
	}
	out := task
	out.SourceFrom = "192.0.2.1:7444"
	if err := fetchTaskArchive(context.Background(), out, tok, mesh); err == nil || !strings.Contains(err.Error(), "not a node of the mesh") {
		t.Errorf("fetched from outside the mesh: %v", err)
	}
	bad := task
	bad.App = "../etc"
	if fetchTaskArchive(context.Background(), bad, tok, mesh) == nil {
		t.Error("a bad app name was accepted")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/source/web/"+sha, nil)
	r.SetPathValue("app", "web")
	r.SetPathValue("sha", sha)
	s.serveSource(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}
}

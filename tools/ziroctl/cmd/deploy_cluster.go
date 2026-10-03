package cmd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// Deploys on a cluster. The master's ziroctld keeps the deployment; the build runs on a builder
// node (a node with the builder plugin, preferably labelled builder=true) and the replicas run
// on nodes of the builder's architecture. It all goes through the control plane:
//
//   - the master records a ClusterBuild for the builder; the builder's agent sees it in its
//     heartbeat reply, has its local ziroctld build it, and reports the image digest back;
//   - the app is deployed with that ziro.local image (pinned by digest, Arch, ImageNode);
//   - a node that lacks the image fetches it from ImageNode's agent over the WireGuard mesh
//     (port 7444, bearer token handed out by the master) and loads it only if the digest matches.

const imageServerPort = 7444

// Seams for tests: loading an image into the runtime, and asking the local ziroctld to build.
var (
	loadImage = func(ctx context.Context, tar io.Reader) error {
		// deepcode ignore CommandInjection: fixed argv; the tar arrives on stdin
		c := exec.CommandContext(ctx, "nerdctl", "load")
		c.Stdin = tar
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, lastLines(string(out), 2))
		}
		return nil
	}
	requestBuildTask = func(t ClusterBuild) BuildResult {
		var r BuildResult
		if err := deployCallTimeout("POST", "/v1/build-task", t, &r, deployFetchLimit+deployBuildLimit); err != nil {
			r = BuildResult{App: t.App, Build: t.Build, Error: err.Error()}
		}
		return r
	}
)

// ClusterBuild is a build the master asked a builder node to run.
type ClusterBuild struct {
	App      string       `json:"app"`
	Build    string       `json:"build"`
	Node     string       `json:"node"`
	Repo     string       `json:"repo"`
	Ref      string       `json:"ref,omitempty"`
	Path     string       `json:"path,omitempty"`
	GitToken string       `json:"git_token,omitempty"` // only in the builder's heartbeat reply (from sealed secrets)
	Status   string       `json:"status"`              // pending, done, failed
	Result   *BuildResult `json:"result,omitempty"`
	Created  time.Time    `json:"created"`
}

// BuildResult is what a builder reports.
type BuildResult struct {
	App     string `json:"app"`
	Build   string `json:"build"`
	Image   string `json:"image,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Port    int    `json:"port,omitempty"`
	Health  string `json:"health,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Error   string `json:"error,omitempty"`
	LogTail string `json:"log_tail,omitempty"` // the end of the builder's log, for the master's
}

var archRe = regexp.MustCompile(`^(amd64|arm64)$`)

func clusterBuildSecret(app string) string { return "deploy-" + app }

const imageTokenSecret = "ziro-images"

// builtInCluster: a ziro.local image a builder of this cluster reported (it can't come from a
// registry, so registry policies don't apply; its digest pin is what's checked on every node).
func builtInCluster(st *ClusterState, image string) bool {
	if !localImageRe.MatchString(image) {
		return false
	}
	for _, b := range st.Builds {
		if b.Result != nil && b.Result.Image == image {
			return true
		}
	}
	for _, a := range st.Apps {
		if a.Image == image && a.ImageNode != "" { // the build record may be gone; the app keeps it
			return true
		}
	}
	return false
}

// fits reports whether replica r's spec may run on node: same architecture as a pinned image,
// and every label the app selects.
func (st *ClusterState) fits(r Replica, node string) bool {
	spec, _ := st.specFor(r)
	if spec.Arch == "" {
		return true
	}
	n := st.node(node)
	return n != nil && n.Arch == spec.Arch
}

// imageSource is where nodeID fetches spec's image from ("" = it doesn't need to).
func imageSource(st *ClusterState, spec ClusteredApp, nodeID string) string {
	if spec.ImageNode == "" || spec.ImageNode == nodeID || !localImageRe.MatchString(spec.Image) {
		return ""
	}
	if n := st.node(spec.ImageNode); n != nil && n.MeshIP != "" {
		return net.JoinHostPort(n.MeshIP, strconv.Itoa(imageServerPort))
	}
	return ""
}

// imagePolicyRule opens this node's image server (deny-mode policy) to the nodes that run
// replicas of an app whose image it holds; nil when it holds none.
func imagePolicyRule(st *ClusterState, nodeID string) *MeshRule {
	holds := map[string]bool{}
	for _, a := range st.Apps {
		if a.ImageNode == nodeID {
			holds[a.Name] = true
		}
	}
	seen := map[string]bool{}
	var src []string
	for _, r := range st.Replicas {
		if !holds[r.App] || r.Node == nodeID || seen[r.Node] {
			continue
		}
		seen[r.Node] = true
		if n := st.node(r.Node); n != nil && n.MeshIP != "" {
			src = append(src, n.MeshIP)
		}
	}
	if len(src) == 0 {
		return nil
	}
	sort.Strings(src)
	return &MeshRule{App: "images", Port: imageServerPort, Proto: "tcp", Sources: src}
}

// ---- master: heartbeat ----

// heartbeatBuilds records a node's arch and build results and returns its pending builds and
// the image token (created on first use, kept with the sealed secrets).
func heartbeatBuilds(st *ClusterState, n *ClusterNode, req heartbeatRequest) ([]ClusterBuild, string) {
	if archRe.MatchString(req.Arch) {
		n.Arch = req.Arch
	}
	for _, r := range req.Builds {
		for i := range st.Builds {
			b := &st.Builds[i]
			if b.Node == n.ID && b.App == r.App && b.Build == r.Build && b.Status == "pending" {
				r := r
				r.Error, r.LogTail = sanitizeLabel(r.Error, 500), lastN(r.LogTail, 32<<10)
				if r.Error == "" && !localImageRe.MatchString(r.Image) {
					r.Error = "the builder reported no valid image"
				}
				b.Result, b.Status = &r, map[bool]string{true: "failed", false: "done"}[r.Error != ""]
			}
		}
	}
	var mine []ClusterBuild
	for _, b := range st.Builds {
		if b.Node == n.ID && b.Status == "pending" {
			b.GitToken = st.Secrets[clusterBuildSecret(b.App)]["GIT_TOKEN"]
			mine = append(mine, b)
		}
	}
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]string{}
	}
	if st.Secrets[imageTokenSecret]["TOKEN"] == "" {
		st.Secrets[imageTokenSecret] = map[string]string{"TOKEN": randomHex(32)}
	}
	return mine, st.Secrets[imageTokenSecret]["TOKEN"]
}

func lastN(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// ---- master: ziroctld side ----

// clusterNodeID is this host's node ID when it is a cluster master ("" otherwise).
func clusterNodeID() string {
	if cfg, err := loadClusterConfig(); err == nil && cfg.Role == "master" {
		return cfg.NodeID
	}
	return ""
}

// pickBuilder chooses the node that builds: Ready, with the builder plugin; nodes labelled
// builder=true first, then the least busy; arch narrows it when the deployment pins one.
func pickBuilder(st *ClusterState, arch string) *ClusterNode {
	busy := map[string]int{}
	for _, b := range st.Builds {
		if b.Status == "pending" {
			busy[b.Node]++
		}
	}
	var best *ClusterNode
	score := func(n *ClusterNode) int {
		s := busy[n.ID] * 2
		if n.Labels["builder"] != "true" {
			s++
		}
		return s
	}
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if n.Status != "Ready" || n.Cordoned || !hasCap(n, capBuilder) || (arch != "" && n.Arch != arch) || n.Labels["builder"] == "false" {
			continue
		}
		if best == nil || score(n) < score(best) {
			best = n
		}
	}
	return best
}

// buildOnCluster runs b on a builder node and waits for its result.
func buildOnCluster(ctx context.Context, d *Deployment, b *Build, log io.Writer, logf func(string, ...any)) (BuildPlan, error) {
	self := clusterNodeID()
	var node *ClusterNode
	token, _ := os.ReadFile(filepath.Join(deployTokenDir, d.Name+".token"))
	err := withState(func(st *ClusterState) error {
		if node = pickBuilder(st, d.Arch); node == nil {
			return errors.New("no builder node: enable the builder plugin on a node (ziroctl module enable builder)")
		}
		if node.ID == self {
			return nil
		}
		if t := strings.TrimSpace(string(token)); t != "" {
			if st.Secrets == nil {
				st.Secrets = map[string]map[string]string{}
			}
			st.Secrets[clusterBuildSecret(d.Name)] = map[string]string{"GIT_TOKEN": t}
		}
		st.Builds = append(st.Builds, ClusterBuild{App: d.Name, Build: b.ID, Node: node.ID, Repo: d.Repo, Ref: b.Ref,
			Path: d.Path, Status: "pending", Created: time.Now().UTC()})
		return nil
	})
	if err != nil {
		return BuildPlan{}, err
	}
	b.Node, b.Arch = node.ID, node.Arch
	if node.ID == self {
		b.Arch = runtime.GOARCH
		logf("building on this node (%s)", b.Arch)
		return fetchAndBuild(ctx, d, b, log, logf)
	}
	logf("building on %s (%s)", node.ID, node.Arch)
	deadline := time.Now().Add(deployFetchLimit + deployBuildLimit)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return BuildPlan{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		st, err := readState()
		if err != nil {
			continue
		}
		for _, cb := range st.Builds {
			if cb.App != d.Name || cb.Build != b.ID || cb.Status == "pending" || cb.Result == nil {
				continue
			}
			r := cb.Result
			fmt.Fprintf(log, "--- log from %s ---\n%s\n------\n", node.ID, r.LogTail)
			_ = withState(func(st *ClusterState) error { // done with the task
				st.Builds = slices.DeleteFunc(st.Builds, func(x ClusterBuild) bool { return x.App == d.Name && x.Build == b.ID })
				return nil
			})
			if cb.Status == "failed" {
				return BuildPlan{}, fmt.Errorf("on %s: %s", node.ID, r.Error)
			}
			b.Image, b.Commit, b.Kind = r.Image, r.Commit, r.Kind
			return BuildPlan{Kind: r.Kind, Port: r.Port, Health: r.Health}, nil
		}
	}
	return BuildPlan{}, fmt.Errorf("%s did not finish the build in time", node.ID)
}

// waitRollout waits until every replica of app runs its current spec.
func waitRollout(app string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	last := "not scheduled"
	for time.Now().Before(deadline) {
		if st, err := readState(); err == nil {
			if a := st.app(app); a != nil {
				want, ok, n := specHash(*a), 0, 0
				for _, r := range st.Replicas {
					if r.App != app {
						continue
					}
					n++
					switch {
					case r.Hash == want && st.replicaRunning(r):
						ok++
					case r.Error != "":
						last = r.Error
					}
				}
				if n > 0 && ok == n && n >= a.Replicas {
					return nil
				}
				if last == "not scheduled" && n > 0 {
					last = fmt.Sprintf("%d/%d replicas running", ok, n)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s did not roll out in %s: %s", app, limit, last)
}

// ---- builder node: ziroctld side ----

// buildTask builds a ClusterBuild locally (no release) for this node's agent.
func buildTask(ctx context.Context, t ClusterBuild) BuildResult {
	res := BuildResult{App: t.App, Build: t.Build, Arch: runtime.GOARCH}
	d := &Deployment{Name: t.App, Repo: t.Repo, Ref: t.Ref, Path: t.Path}
	if err := validateDeployment(d); err != nil || !buildIDRe.MatchString(t.Build) {
		res.Error = fmt.Sprintf("invalid build task: %v", err)
		return res
	}
	if t.GitToken != "" {
		_ = os.MkdirAll(deployTokenDir, 0700)
		_ = writeFileAtomic(filepath.Join(deployTokenDir, t.App+".token"), []byte(t.GitToken), 0600)
	}
	logPath := buildLog(t.App, t.Build)
	_ = os.MkdirAll(filepath.Dir(logPath), 0700)
	var buf bytes.Buffer
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	w := io.MultiWriter(logF, &buf)
	b := &Build{ID: t.Build, App: t.App, Ref: t.Ref}
	plan, err := fetchAndBuild(ctx, d, b, w, func(f string, a ...any) { fmt.Fprintf(w, "==> "+f+"\n", a...) })
	logF.Close()
	res.Image, res.Commit, res.Kind, res.Port, res.Health = b.Image, b.Commit, plan.Kind, plan.Port, plan.Health
	if err != nil {
		res.Error = err.Error()
	}
	res.LogTail = lastN(buf.String(), 32<<10)
	return res
}

// ---- agent side ----

// agentBuilds runs the builds the master assigned to this node, one at a time, through the
// local ziroctld, and keeps the results until the master has them.
type agentBuilds struct {
	mu      sync.Mutex
	running map[string]bool
	results map[string]BuildResult
}

func (ab *agentBuilds) start(tasks []ClusterBuild) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	if ab.running == nil {
		ab.running, ab.results = map[string]bool{}, map[string]BuildResult{}
	}
	want := map[string]bool{}
	for _, t := range tasks {
		key := t.App + "/" + t.Build
		want[key] = true
		if ab.running[key] {
			continue
		}
		if _, done := ab.results[key]; done {
			continue
		}
		ab.running[key] = true
		go func(t ClusterBuild) {
			r := requestBuildTask(t)
			ab.mu.Lock()
			delete(ab.running, key)
			ab.results[key] = r
			ab.mu.Unlock()
		}(t)
	}
	for k := range ab.results { // the master no longer lists it: it has the result
		if !want[k] {
			delete(ab.results, k)
		}
	}
}

func (ab *agentBuilds) report() []BuildResult {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	out := make([]BuildResult, 0, len(ab.results))
	for _, r := range ab.results {
		out = append(out, r)
	}
	return out
}

// builderCaps adds "builder" when this node runs ziroctld.
func builderCaps(caps []string) []string {
	if _, err := os.Stat(deploySocket); err == nil {
		return append(append([]string{}, caps...), capBuilder)
	}
	return caps
}

const capBuilder = "builder"

// imageServer serves this node's ziro.local images to other nodes over the mesh.
type imageServer struct {
	mu    sync.Mutex
	token string
	addr  string
	srv   *http.Server
}

// ensure (re)starts the server on meshIP with token; a no-op when nothing changed.
func (s *imageServer) ensure(meshIP, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if meshIP == "" || token == "" {
		return
	}
	s.token = token
	addr := net.JoinHostPort(meshIP, strconv.Itoa(imageServerPort))
	if s.addr == addr && s.srv != nil {
		return
	}
	if s.srv != nil {
		_ = s.srv.Close()
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("[agent] image server: %v\n", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/images/{digest}", s.serveImage)
	s.addr, s.srv = addr, &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func(srv *http.Server) { _ = srv.Serve(l) }(s.srv)
}

func (s *imageServer) serveImage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	tok := s.token
	s.mu.Unlock()
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := localImageByDigest(r.PathValue("digest"))
	if name == "" {
		http.Error(w, "no such image", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	// deepcode ignore CommandInjection: name is a ziro.local image name read from the runtime and matched against localImageRe
	c := exec.CommandContext(r.Context(), "nerdctl", "save", name)
	c.Stdout = w
	if err := c.Run(); err != nil {
		fmt.Printf("[agent] image server: save %s: %v\n", name, err)
	}
}

// localImageByDigest finds the ziro.local image with this digest ("" if none).
func localImageByDigest(digest string) string {
	if !digestRe.MatchString(digest) {
		return ""
	}
	out, err := runNerdctl("images", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var img struct{ Repository, Tag, Digest string }
		if json.Unmarshal([]byte(line), &img) == nil && img.Digest == digest && strings.HasPrefix(img.Repository, "ziro.local/") {
			ref := img.Repository + ":" + img.Tag
			if localImageRe.MatchString(ref + "@" + digest) {
				return ref
			}
		}
	}
	return ""
}

// fetchClusterImage makes a.Image runnable here: present locally with the pinned digest, or
// fetched from a.ImageFrom and loaded, then checked against the pin. It returns the local name.
func fetchClusterImage(ctx context.Context, a Assignment, token string) (string, error) {
	if name, err := localBuildImage(a.Image); err == nil {
		return name, nil
	}
	if a.ImageFrom == "" || token == "" {
		return "", fmt.Errorf("%s is not on this node and no node serves it", a.Image)
	}
	host, port, err := net.SplitHostPort(a.ImageFrom)
	if ip := net.ParseIP(host); err != nil || ip == nil || port != strconv.Itoa(imageServerPort) {
		return "", fmt.Errorf("invalid image source %q", a.ImageFrom)
	}
	_, digest, _ := strings.Cut(a.Image, "@")
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+a.ImageFrom+"/v1/images/"+digest, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req) // plain HTTP inside the WireGuard mesh; the digest is checked after loading
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", a.Image, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", a.Image, resp.StatusCode)
	}
	if err := loadImage(ctx, io.LimitReader(resp.Body, 20<<30)); err != nil {
		return "", fmt.Errorf("load %s: %w", a.Image, err)
	}
	name, err := localBuildImage(a.Image)
	if err != nil { // what arrived is not what was built: never run it
		ref, _, _ := strings.Cut(a.Image, "@")
		_, _ = runNerdctl("rmi", ref)
		return "", fmt.Errorf("fetched image rejected: %w", err)
	}
	return name, nil
}

// ---- ziroctl cluster node label ----

var nodeLabelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

var clusterNodeLabelCmd = &cobra.Command{
	Use:   "label <node> key=value... | key-",
	Short: "Set or remove node labels",
	Long: `Set labels on a node (key=value) or remove them (key-). builder=true makes a node with the
builder plugin the first choice for builds; builder=false keeps builds off it.`,
	Example: `  ziroctl cluster node label worker-1 builder=true
  ziroctl cluster node label worker-1 builder-`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		set, del := map[string]string{}, []string{}
		for _, l := range args[1:] {
			if k, ok := strings.CutSuffix(l, "-"); ok && nodeLabelRe.MatchString(k) {
				del = append(del, k)
				continue
			}
			k, v, ok := strings.Cut(l, "=")
			if !ok || !nodeLabelRe.MatchString(k) || (v != "" && !nodeLabelRe.MatchString(v)) {
				return fmt.Errorf("label %q: want key=value or key- (a-z 0-9 . _ -)", l)
			}
			set[k] = v
		}
		return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error {
			if n.Labels == nil {
				n.Labels = map[string]string{}
			}
			for k, v := range set {
				n.Labels[k] = v
			}
			for _, k := range del {
				delete(n.Labels, k)
			}
			if len(n.Labels) > 32 {
				return errors.New("at most 32 labels per node")
			}
			fmt.Printf("%s: %v\n", n.ID, n.Labels)
			return nil
		})
	},
}

func init() {
	clusterNodeCmd.AddCommand(clusterNodeLabelCmd)
}

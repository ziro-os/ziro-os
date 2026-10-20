package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"golang.org/x/crypto/ssh"
)

func TestSandboxPlacement(t *testing.T) {
	st := &ClusterState{Nodes: []ClusterNode{
		{ID: "a", Status: "Ready", MeshIP: "10.200.0.1", Caps: []string{capSandbox}, MemTotal: 8000},
		{ID: "b", Status: "Ready", MeshIP: "10.200.0.2", Caps: []string{capSandbox}, MemTotal: 16000},
		{ID: "c", Status: "Ready", MeshIP: "10.200.0.3", Caps: []string{capSandbox}, Cordoned: true},
		{ID: "d", Status: "NotReady", MeshIP: "10.200.0.4", Caps: []string{capSandbox}},
		{ID: "e", Status: "Ready", MeshIP: "10.200.0.5"}, // no sandbox module
		{ID: "f", Status: "Ready", MeshIP: "10.200.0.6", Caps: []string{capSandbox}, Labels: map[string]string{"runner": "false"}},
	}}
	if n := pickSandboxNode(st, nil); n == nil || n.ID != "b" {
		t.Fatalf("empty cluster: %v", n)
	}
	st.Sandboxes = map[string]SandboxPlacement{"x1": {Node: "b"}}
	if n := pickSandboxNode(st, nil); n.ID != "a" {
		t.Errorf("fewest sandboxes: %s", n.ID)
	}
	if n := pickSandboxNode(st, map[string]bool{"b": true}); n.ID != "b" {
		t.Errorf("snapshot node: %s", n.ID)
	}
	if n := pickSandboxNode(st, map[string]bool{"c": true}); n != nil {
		t.Errorf("cordoned node picked")
	}
	// Prune: the node no longer has x1 (kept while young), the mesh config lists where things run.
	now := time.Now()
	st.Sandboxes = map[string]SandboxPlacement{"aaaaaaaaaaaa": {Node: "b", Since: now}, "bbbbbbbbbbbb": {Node: "b", Since: now.Add(-time.Hour)}, "cccccccccccc": {Node: "a", Since: now.Add(-time.Hour)}}
	if gone := pruneSandboxes(st, "b", []string{}, now); len(gone) != 1 || gone[0] != "bbbbbbbbbbbb" {
		t.Errorf("pruned %v", gone)
	}
	st.GatewayDomain.Name = "apps.example.com"
	c := sandboxMeshFor(st, &st.Nodes[1])
	if c == nil || c.Listen != "10.200.0.2:7446" || len(c.Token) != 64 || c.Domain != "apps.example.com" || c.Where["cccccccccccc"] != "10.200.0.1" ||
		!strings.Contains(c.HostKey, "OPENSSH PRIVATE KEY") {
		t.Errorf("mesh config %+v", c)
	}
	if c2 := sandboxMeshFor(st, &st.Nodes[0]); c2.HostKey != c.HostKey || c2.Token != c.Token {
		t.Error("nodes got different gateway keys or tokens")
	}
	if sandboxMeshFor(st, &st.Nodes[4]) != nil {
		t.Error("a node without the module got the token")
	}
	rules := sandboxPolicyRules(st, "b")
	if len(rules) != 3 || rules[0].Port != 7446 || len(rules[0].Sources) != 5 || slices.Contains(rules[0].Sources, "10.200.0.2") {
		t.Errorf("mesh rules %+v", rules)
	}
	if sandboxPolicyRules(st, "e") != nil {
		t.Error("a node without the module opened ports")
	}
}

// meshNode is one cluster node in-process: a sandbox manager behind its mesh API.
type meshNode struct {
	m   *sandboxManager
	srv *httptest.Server
}

// TestSandboxClusterForwarding runs the master's API against two nodes' real mesh handlers.
func TestSandboxClusterForwarding(t *testing.T) {
	m1, _, _ := stubSandboxes(t)
	m2 := &sandboxManager{st: &sandboxStore{all: map[string]*sdkapi.Sandbox{}}, net: m1.net, access: loadAccessStore(nil), now: m1.now}
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nodes := map[string]*meshNode{}
	for id, m := range map[string]*sandboxManager{"n1": m1, "n2": m2} {
		m.mesh = &meshState{}
		m.mesh.cfg.Store(&sandboxMeshConfig{Listen: id, Token: tok})
		nodes[id] = &meshNode{m: m, srv: httptest.NewServer(m.meshHandler())}
		defer nodes[id].srv.Close()
	}
	st := &ClusterState{Nodes: []ClusterNode{
		{ID: "n1", Status: "Ready", MeshIP: "10.200.0.1", Caps: []string{capSandbox}, MemTotal: 4000},
		{ID: "n2", Status: "Ready", MeshIP: "10.200.0.2", Caps: []string{capSandbox}, MemTotal: 8000}},
		Sandboxes: map[string]SandboxPlacement{}}
	routes := map[string]GatewayRoute{}
	old1, old2, old3 := sandboxClusterState, sandboxClusterMutate, sandboxMeshAddr
	sandboxClusterState = func() (*sandboxClusterView, bool) {
		return &sandboxClusterView{token: tok, nodes: st.Nodes, st: st}, true
	}
	sandboxClusterMutate = func(fn func(*ClusterState) error) error { return fn(st) }
	sandboxMeshAddr = func(n *ClusterNode) string { return strings.TrimPrefix(nodes[n.ID].srv.URL, "http://") }
	defer func() { sandboxClusterState, sandboxClusterMutate, sandboxMeshAddr = old1, old2, old3 }()

	api := newAPIHarness(t, registerSandboxRoutes)
	agent, _, _ := createAPIToken("agent", "deployer", 0, "sandboxes")
	other, _, _ := createAPIToken("other", "deployer", 0)
	do := func(token, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		api.h.ServeHTTP(w, r)
		return w
	}
	// Create: placed on the node with the most memory, recorded in the directory.
	w := do(agent, "POST", "/api/v1/sandboxes", `{"image":"alpine"}`)
	var sb sdkapi.Sandbox
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &sb) != nil || sb.Owner != "agent" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if p := st.Sandboxes[sb.ID]; p.Node != "n2" || p.Owner != "agent" {
		t.Fatalf("placement %+v", p)
	}
	if _, err := m2.st.get(sb.ID, sandboxCaller{Role: "admin"}); err != nil {
		t.Fatal("not on n2")
	}
	// The next one goes to the emptier node.
	w = do(agent, "POST", "/api/v1/sandboxes", `{"image":"alpine"}`)
	var sb2 sdkapi.Sandbox
	json.Unmarshal(w.Body.Bytes(), &sb2)
	if st.Sandboxes[sb2.ID].Node != "n1" {
		t.Errorf("second placement %+v", st.Sandboxes[sb2.ID])
	}
	// List merges both nodes; another owner sees nothing.
	var list []sdkapi.Sandbox
	if w := do(agent, "GET", "/api/v1/sandboxes", ""); json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 2 {
		t.Errorf("list: %s", w.Body)
	}
	if w := do(other, "GET", "/api/v1/sandboxes", ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("other's list: %s", w.Body)
	}
	// Per-sandbox requests reach the owner node; others get 404 at the master.
	if w := do(agent, "GET", "/api/v1/sandboxes/"+sb.ID, ""); w.Code != 200 || !strings.Contains(w.Body.String(), sb.ID) {
		t.Errorf("get: %d %s", w.Code, w.Body)
	}
	if w := do(other, "GET", "/api/v1/sandboxes/"+sb.ID, ""); w.Code != 404 {
		t.Errorf("other's get: %d", w.Code)
	}
	if w := do(agent, "GET", "/api/v1/sandboxes/zzzzzzzzzzzz", ""); w.Code != 404 {
		t.Errorf("unknown: %d", w.Code)
	}
	// The mesh API refuses callers without the cluster token.
	if resp, err := http.Get(nodes["n2"].srv.URL + "/v1/sandboxes"); err != nil || resp.StatusCode != 401 {
		t.Errorf("mesh without token: %v %v", resp, err)
	}
	// Delete: forwarded, and the directory entry goes.
	if w := do(agent, "DELETE", "/api/v1/sandboxes/"+sb.ID, ""); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if _, ok := st.Sandboxes[sb.ID]; ok {
		t.Error("directory entry kept")
	}
	_ = routes
}

// The SSH edge: a token for a sandbox on another node is checked by that node, and the session
// is relayed to its gateway.
func TestSandboxSSHRelay(t *testing.T) {
	owner, _, _ := stubSandboxes(t)
	owner.now = time.Now
	sb, _ := owner.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	old := sandboxExecCommand
	sandboxExecCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "echo relayed; exit 4")
	}
	defer func() { sandboxExecCommand = old }()

	ownerKey, _ := testKey(t)
	owner.ssh = newSSHGateway(owner, ownerKey)
	_ = ownerKey
	oln, _ := net.Listen("tcp", "127.0.0.1:0")
	owner.ssh.port = oln.Addr().(*net.TCPAddr).Port
	owner.mesh = &meshState{}
	owner.mesh.cfg.Store(&sandboxMeshConfig{Listen: "owner", Token: tok})
	mesh := httptest.NewServer(owner.meshHandler())
	defer mesh.Close()
	_, mport, _ := net.SplitHostPort(strings.TrimPrefix(mesh.URL, "http://"))
	oldPort := sandboxMeshPort
	sandboxMeshPort, _ = strconv.Atoi(mport)
	defer func() { sandboxMeshPort = oldPort }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go owner.ssh.accept(ctx, oln)

	edge := &sandboxManager{st: &sandboxStore{all: map[string]*sdkapi.Sandbox{}}, access: loadAccessStore(nil), now: time.Now, mesh: &meshState{}}
	// The edge doesn't know the sandbox yet (no Where entry): it asks every sandbox node.
	edge.mesh.cfg.Store(&sandboxMeshConfig{Listen: "edge", Token: tok, Nodes: []string{"127.0.0.1"}})
	edge.ssh = newSSHGateway(edge, func() ssh.Signer { k, _ := testKey(t); return k }())
	clusterKey, _ := testKey(t) // both gateways present the cluster's key
	owner.ssh.shared.Store(&clusterKey)
	edge.ssh.shared.Store(&clusterKey)
	edgeKey := clusterKey
	eln, _ := net.Listen("tcp", "127.0.0.1:0")
	go edge.ssh.accept(ctx, eln)

	token, _, err := owner.access.create(sb.ID, sdkapi.SandboxAccessRequest{SingleUse: true}, time.Now(), sb.Expires)
	if err != nil || tokenSandbox(token) != sb.ID {
		t.Fatalf("token %q %v", token, err)
	}
	c, err := ssh.Dial("tcp", eln.Addr().String(), &ssh.ClientConfig{User: token, HostKeyCallback: ssh.FixedHostKey(edgeKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("edge login: %v", err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	var out bytes.Buffer
	s.Stdout = &out
	err = s.Run("anything")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 4 || out.String() != "relayed\n" {
		t.Fatalf("relayed session: %v %q", err, out.String())
	}
	// Single use, spent on the owner: a second login through the edge fails.
	if _, err := ssh.Dial("tcp", eln.Addr().String(), &ssh.ClientConfig{User: token, HostKeyCallback: ssh.FixedHostKey(edgeKey.PublicKey()), Timeout: 5 * time.Second}); err == nil {
		t.Error("a single-use token worked twice through the edge")
	}
	// The relay login itself needs the cluster key; nobody is offered a password.
	stranger, _ := testKey(t)
	for _, auth := range []ssh.AuthMethod{ssh.PublicKeys(stranger), ssh.Password(tok)} {
		if _, err := ssh.Dial("tcp", oln.Addr().String(), &ssh.ClientConfig{User: "zrelay_" + sb.ID, Auth: []ssh.AuthMethod{auth},
			HostKeyCallback: ssh.FixedHostKey(clusterKey.PublicKey()), Timeout: 5 * time.Second}); err == nil {
			t.Error("relay login without the cluster key")
		}
	}
}

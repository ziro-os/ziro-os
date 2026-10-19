package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// fakeNerdctl records nerdctl calls and answers ps from a container table.
type fakeNerdctl struct {
	mu     sync.Mutex
	calls  [][]string
	ps     map[string]string // container -> status
	fail   string            // a verb that fails
	sticky map[string]int    // container -> how many rm calls leave it in place
}

func (f *fakeNerdctl) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	if args[0] == f.fail {
		return []byte("time=x level=fatal msg=\"boom\"\nboom"), errors.New("exit status 1")
	}
	switch args[0] {
	case "run":
		f.ps[args[slices.Index(args, "--name")+1]] = "Up"
	case "rm":
		if f.sticky[args[len(args)-1]] > 0 { // nerdctl rm -f of a gVisor container that stays
			f.sticky[args[len(args)-1]]--
			f.ps[args[len(args)-1]] = "Exited (137)"
			return nil, nil
		}
		delete(f.ps, args[len(args)-1])
	case "ps":
		var b strings.Builder
		for name, st := range f.ps {
			if slices.Contains(args, "{{.Names}}") && slices.Contains(args, "-a") {
				b.WriteString(name + "\n")
			} else if slices.Contains(args, "-a") {
				b.WriteString(name + "\t" + st + "\n")
			} else if !strings.HasPrefix(st, "Exited") {
				b.WriteString(name + "\n")
			}
		}
		return []byte(b.String()), nil
	}
	return nil, nil
}

func stubSandboxes(t *testing.T) (*sandboxManager, *fakeNerdctl, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	oldRoot, oldCfg, oldN, oldAudit, oldNft := sandboxRoot, sandboxConfigFile, sandboxNerdctl, auditPath, sandboxNft
	sandboxRoot, sandboxConfigFile, auditPath = filepath.Join(dir, "sbx"), filepath.Join(dir, "sandbox.json"), filepath.Join(dir, "audit.log")
	f := &fakeNerdctl{ps: map[string]string{}, sticky: map[string]int{}}
	sandboxNerdctl = f.run
	sandboxNft = func(script string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, []string{"nft", script})
		if f.fail == "nft" {
			return errors.New("nft: boom")
		}
		return nil
	}
	t.Cleanup(func() {
		sandboxRoot, sandboxConfigFile, sandboxNerdctl, auditPath, sandboxNft = oldRoot, oldCfg, oldN, oldAudit, oldNft
	})
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	net := newSandboxNet(sandboxDefSubnet)
	net.ready = true
	return &sandboxManager{st: loadSandboxStore(), net: net, access: loadAccessStore(nil), now: func() time.Time { return now }}, f, &now
}

var (
	alice = sandboxCaller{Owner: "alice", Role: "deployer"}
	bob   = sandboxCaller{Owner: "bob", Role: "deployer"}
	ops   = sandboxCaller{Owner: "ops", Role: "operator"}
)

func TestSandboxRunArgsAreLockedDown(t *testing.T) {
	sb := &sdkapi.Sandbox{ID: "abcdefghijkl", Spec: schema.SandboxSpec{Image: "python:3", Runtime: "gvisor", Workdir: "/workspace",
		Resources: &schema.Resources{Memory: "1Gi", CPUs: 1, PIDs: 512}, Env: map[string]string{"B": "2", "A": "1"}, User: "1000"}}
	args := sandboxRunArgs(sb, "python:3", "10.250.0.1", nil)
	joined := strings.Join(args, " ")
	for _, want := range []string{"--runtime " + sandboxRunsc, "--cap-drop ALL", "--security-opt no-new-privileges", "--network none",
		"--memory 1073741824", "--pids-limit 512", "--restart no", "-u 1000", "-e A=1 -e B=2",
		"--entrypoint sleep -- python:3 infinity", "--label ziro.sandbox=abcdefghijkl"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	for _, bad := range []string{"--privileged", "--device", "--cap-add SYS_ADMIN", "--cap-add NET_RAW", "--net host", "--pid ", "--ipc ", "-p "} {
		if strings.Contains(joined, bad) {
			t.Errorf("%q in %s", bad, joined)
		}
	}
	vols := 0
	for i, a := range args {
		if a == "-v" {
			vols++
			if args[i+1] != filepath.Join(sandboxDir(sb.ID), "workspace")+":/workspace" {
				t.Errorf("unexpected mount %s", args[i+1])
			}
		}
	}
	if vols != 1 {
		t.Errorf("%d mounts", vols)
	}
	// A command is passed after the image, never as flags; runc drops the gVisor runtime.
	sb.Spec.Command, sb.Spec.Runtime = []string{"--privileged", "x"}, "runc"
	args = sandboxRunArgs(sb, "python:3", "10.250.0.1", nil)
	if i := slices.Index(args, "--"); i < 0 || !slices.Equal(args[i+1:], []string{"python:3", "--privileged", "x"}) || slices.Contains(args, sandboxRunsc) {
		t.Errorf("command args: %v", args)
	}
}

func TestResolveSandboxSpec(t *testing.T) {
	cfg := defaultSandboxConfig()
	s := schema.SandboxSpec{Image: "alpine"}
	ttl, err := resolveSandboxSpec(&s, cfg, alice)
	if err != nil || ttl != time.Hour || s.Runtime != "gvisor" || s.Workdir != "/workspace" || s.Resources.Memory != "1Gi" || s.Resources.PIDs != 512 {
		t.Fatalf("defaults: %v %v %+v %+v", ttl, err, s, s.Resources)
	}
	for name, c := range map[string]struct {
		spec   schema.SandboxSpec
		caller sandboxCaller
		allow  bool
	}{
		"memory over limit": {schema.SandboxSpec{Image: "a", Resources: &schema.Resources{Memory: "16Gi"}}, alice, false},
		"cpus over limit":   {schema.SandboxSpec{Image: "a", Resources: &schema.Resources{CPUs: 8}}, alice, false},
		"timeout over max":  {schema.SandboxSpec{Image: "a", Timeout: "48h"}, alice, false},
		"runc disabled":     {schema.SandboxSpec{Image: "a", Runtime: "runc"}, ops, false},
		"runc deployer":     {schema.SandboxSpec{Image: "a", Runtime: "runc"}, alice, true},
	} {
		cfg := defaultSandboxConfig()
		cfg.AllowRunc = c.allow
		if _, err := resolveSandboxSpec(&c.spec, cfg, c.caller); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg.AllowRunc = true
	if _, err := resolveSandboxSpec(&schema.SandboxSpec{Image: "a", Runtime: "runc"}, cfg, ops); err != nil {
		t.Errorf("runc for an operator on an opted-in host: %v", err)
	}
	// gvisor-kvm needs /dev/kvm; a host can make it the default.
	old := kvmReady
	defer func() { kvmReady = old }()
	kvmReady = func() bool { return false }
	if _, err := resolveSandboxSpec(&schema.SandboxSpec{Image: "a", Runtime: "gvisor-kvm"}, cfg, alice); err == nil || !strings.Contains(err.Error(), "/dev/kvm") {
		t.Errorf("gvisor-kvm without KVM: %v", err)
	}
	kvmReady = func() bool { return true }
	cfg.DefaultRuntime = "gvisor-kvm"
	s2 := schema.SandboxSpec{Image: "a"}
	if _, err := resolveSandboxSpec(&s2, cfg, alice); err != nil || s2.Runtime != "gvisor-kvm" {
		t.Errorf("default runtime: %v %s", err, s2.Runtime)
	}
	sb := &sdkapi.Sandbox{ID: "abcdefghijkl", Spec: s2}
	if args := sandboxRunArgs(sb, "a", "", nil); !slices.Contains(args, sandboxRunscKVM) {
		t.Errorf("kvm runtime args: %v", args)
	}
}

func TestSandboxConfigFile(t *testing.T) {
	stubSandboxes(t)
	os.WriteFile(sandboxConfigFile, []byte(`{"max_sandboxes":2,"limits":{"memory":"2Gi"}}`), 0600)
	c, err := loadSandboxConfig()
	if err != nil || c.MaxSandboxes != 2 || c.Limits.Memory != "2Gi" || c.MaxPerOwner != 8 || c.DefaultTimeout != "1h" {
		t.Fatalf("%+v %v", c, err)
	}
	os.WriteFile(sandboxConfigFile, []byte(`{"max_sandbox":2}`), 0600)
	if _, err := loadSandboxConfig(); err == nil {
		t.Fatal("unknown field accepted")
	}
	os.WriteFile(sandboxConfigFile, []byte(`{"default_runtime":"runc"}`), 0600)
	if _, err := loadSandboxConfig(); err == nil {
		t.Fatal("runc accepted as the default runtime")
	}
}

// The daemon's HTTP API end to end with nerdctl stubbed: ownership, the state machine, quotas.
func TestSandboxDaemonLifecycle(t *testing.T) {
	m, f, now := stubSandboxes(t)
	os.WriteFile(sandboxConfigFile, []byte(`{"max_per_owner":2}`), 0600)
	h := m.routes()
	call := func(c *sandboxCaller, method, path, body string) (int, []byte) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if c != nil {
			r.Header.Set(hdrOwner, c.Owner)
			r.Header.Set(hdrRole, c.Role)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	code, body := call(&alice, "POST", "/v1/sandboxes", `{"image":"python:3","timeout":"30m","metadata":{"task":"t1"}}`)
	var sb sdkapi.Sandbox
	if code != 200 || json.Unmarshal(body, &sb) != nil || sb.State != "running" || sb.Owner != "alice" || !sb.Expires.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("create: %d %s", code, body)
	}
	if fi, err := os.Stat(filepath.Join(sandboxDir(sb.ID), "sandbox.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("record: %v", err)
	}
	id := "/v1/sandboxes/" + sb.ID

	// Another deployer can't see, touch or probe it; an operator can.
	for _, c := range [][2]string{{"GET", id}, {"DELETE", id}, {"POST", id + "/pause"}, {"POST", id + "/exec"}} {
		if code, _ := call(&bob, c[0], c[1], `{"command":["id"]}`); code != 404 {
			t.Errorf("bob %s %s: %d", c[0], c[1], code)
		}
	}
	if _, body := call(&bob, "GET", "/v1/sandboxes", ""); string(bytes.TrimSpace(body)) != "[]" {
		t.Errorf("bob's list: %s", body)
	}
	if code, _ := call(&ops, "GET", id, ""); code != 200 {
		t.Errorf("operator get: %d", code)
	}
	if code, _ := call(nil, "GET", id, ""); code != 200 { // the host CLI is root
		t.Errorf("root get: %d", code)
	}

	// pause -> resume; pausing twice is refused.
	if code, body := call(&alice, "POST", id+"/pause", ""); code != 200 || !strings.Contains(string(body), `"paused"`) {
		t.Fatalf("pause: %d %s", code, body)
	}
	if code, _ := call(&alice, "POST", id+"/pause", ""); code != 400 {
		t.Errorf("double pause: %d", code)
	}
	if code, _ := call(&alice, "POST", id+"/exec", `{"command":["id"]}`); code != 400 {
		t.Errorf("exec in a paused sandbox: %d", code)
	}
	if code, _ := call(&alice, "POST", id+"/resume", ""); code != 200 {
		t.Errorf("resume: %d", code)
	}

	*now = now.Add(10 * time.Minute)
	if code, body := call(&alice, "POST", id+"/renew", `{"timeout":"2h"}`); code != 200 || !strings.Contains(string(body), now.Add(2*time.Hour).Format(time.RFC3339)) {
		t.Errorf("renew: %d %s", code, body)
	}
	if code, _ := call(&alice, "POST", id+"/renew", `{"timeout":"100h"}`); code != 400 {
		t.Errorf("renew over max: %d", code)
	}
	if code, body := call(&alice, "PUT", id+"/metadata", `{"task":"t2"}`); code != 200 || !strings.Contains(string(body), `"t2"`) {
		t.Errorf("metadata: %d %s", code, body)
	}

	// Quota: alice may have two.
	call(&alice, "POST", "/v1/sandboxes", `{"image":"alpine"}`)
	if code, body := call(&alice, "POST", "/v1/sandboxes", `{"image":"alpine"}`); code != 400 || !strings.Contains(string(body), "maximum of 2") {
		t.Errorf("quota: %d %s", code, body)
	}
	// A failed start is reported and kept for inspection (the reaper deletes it at expiry).
	f.fail = "run"
	if code, body := call(&bob, "POST", "/v1/sandboxes", `{"image":"alpine"}`); code != 400 || !strings.Contains(string(body), "boom") {
		t.Errorf("failed start: %d %s", code, body)
	}
	f.fail = ""

	f.sticky[sandboxContainer(sb.ID)] = 1
	if code, _ := call(&alice, "DELETE", id, ""); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if _, left := f.ps[sandboxContainer(sb.ID)]; left {
		t.Error("a container nerdctl rm -f left behind is still there")
	}
	if _, err := os.Stat(sandboxDir(sb.ID)); !os.IsNotExist(err) {
		t.Errorf("workspace left behind: %v", err)
	}
	if code, _ := call(&alice, "GET", "/v1/sandboxes/NOTANID", ""); code != 404 {
		t.Errorf("bad id: %d", code)
	}

	// A restarted daemon reloads the records.
	if n := len(loadSandboxStore().all); n != 2 {
		t.Errorf("reloaded %d sandboxes", n)
	}
}

func TestSandboxReaper(t *testing.T) {
	m, f, now := stubSandboxes(t)
	mk := func(spec string) sdkapi.Sandbox {
		var s schema.SandboxSpec
		json.Unmarshal([]byte(spec), &s)
		sb, err := m.create(context.Background(), s, alice)
		if err != nil {
			t.Fatal(err)
		}
		return sb
	}
	short, idle, live, dies := mk(`{"image":"a","timeout":"10m"}`), mk(`{"image":"a","idle_timeout":"5m"}`), mk(`{"image":"a"}`), mk(`{"image":"a"}`)
	f.ps["ziro-sbx-orphan00000"] = "Up"
	f.ps[sandboxContainer(dies.ID)] = "Exited (0) 1 second ago"
	*now = now.Add(11 * time.Minute)
	m.markExited(context.Background())
	m.reap(context.Background())
	for _, gone := range []string{short.ID, idle.ID} {
		if _, ok := m.st.all[gone]; ok {
			t.Errorf("%s not reaped", gone)
		}
		if _, err := os.Stat(sandboxDir(gone)); !os.IsNotExist(err) {
			t.Errorf("%s: files left", gone)
		}
	}
	if sb := m.st.all[live.ID]; sb == nil || sb.State != "running" {
		t.Errorf("live sandbox: %+v", sb)
	}
	if sb := m.st.all[dies.ID]; sb == nil || sb.State != "failed" {
		t.Errorf("exited sandbox: %+v", sb)
	}
	if _, ok := f.ps["ziro-sbx-orphan00000"]; ok {
		t.Error("orphan container kept")
	}
	if b, _ := os.ReadFile(auditPath); strings.Count(string(b), "sandbox expire") != 2 {
		t.Errorf("audit: %s", b)
	}
}

func TestSandboxExecArgs(t *testing.T) {
	args, timeout, err := sandboxExecArgs("abcdefghijkl", sdkapi.SandboxExecRequest{Command: []string{"sh", "-c", "--rm x"},
		Env: map[string]string{"Z": "1", "A": "2"}, Workdir: "/tmp", User: "1000:1000", Stdin: "x", Timeout: "10s"})
	want := []string{"exec", "-i", "-w", "/tmp", "-u", "1000:1000", "-e", "A=2", "-e", "Z=1", "ziro-sbx-abcdefghijkl", "--", "sh", "-c", "--rm x"}
	if err != nil || timeout != 10*time.Second || !slices.Equal(args, want) {
		t.Fatalf("%v %v %v", args, timeout, err)
	}
	for name, req := range map[string]sdkapi.SandboxExecRequest{
		"empty":   {},
		"env":     {Command: []string{"x"}, Env: map[string]string{"ZIRO_X": "1"}},
		"user":    {Command: []string{"x"}, User: "root"},
		"workdir": {Command: []string{"x"}, Workdir: "tmp"},
		"timeout": {Command: []string{"x"}, Timeout: "2h"},
		"stdin":   {Command: []string{"x"}, Stdin: strings.Repeat("a", sandboxExecMaxStdin+1)},
	} {
		if _, _, err := sandboxExecArgs("abcdefghijkl", req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPrintExecStream(t *testing.T) {
	var out, errb bytes.Buffer
	in := `{"stream":"stdout","data":"hi\n"}` + "\n" + `{"stream":"stderr","data":"oops\n"}` + "\n" + `{"exit_code":3}` + "\n"
	err := printExecStream(strings.NewReader(in), &out, &errb)
	var code exitCodeError
	if !errors.As(err, &code) || code != 3 || out.String() != "hi\n" || errb.String() != "oops\n" {
		t.Fatalf("%v %q %q", err, out.String(), errb.String())
	}
	if err := printExecStream(strings.NewReader(`{"exit_code":0}`+"\n"), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := printExecStream(strings.NewReader(`{"error":"timed out after 1s"}`+"\n"), io.Discard, io.Discard); err == nil || err.Error() != "timed out after 1s" {
		t.Fatal(err)
	}
	if err := printExecStream(strings.NewReader(`{"stream":"stdout","data":"x"}`+"\n"), io.Discard, io.Discard); err == nil {
		t.Fatal("a cut stream passed")
	}
}

// The REST API forwards to the daemon with the caller's identity (never the client's headers),
// and a token scoped to sandboxes can reach nothing else.
func TestSandboxAPIIdentityAndScope(t *testing.T) {
	dir, err := os.MkdirTemp("", "z")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	oldSock := sandboxSocket
	sandboxSocket = filepath.Join(dir, "s.sock")
	defer func() { sandboxSocket = oldSock }()
	seen := make(chan [3]string, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen <- [3]string{r.URL.Path, r.Header.Get(hdrOwner), r.Header.Get(hdrRole) + "|" + r.Header.Get("Authorization")}
		io.WriteString(w, "[]")
	})
	l, err := net.Listen("unix", sandboxSocket)
	if err != nil {
		t.Fatal(err)
	}
	daemon := &http.Server{Handler: mux}
	go daemon.Serve(l)
	defer daemon.Close()

	api := newAPIHarness(t, registerSandboxRoutes, registerAppRoutes)
	agent, _, err := createAPIToken("agent", "deployer", 0, "sandboxes")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/sandboxes", nil)
	r.Header.Set("Authorization", "Bearer "+agent)
	r.Header.Set(hdrOwner, "root") // a client trying to pass as the host CLI
	w := httptest.NewRecorder()
	api.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("scoped token on sandboxes: %d %s", w.Code, w.Body)
	}
	if got := <-seen; got != [3]string{"/v1/sandboxes", "agent", "deployer|"} {
		t.Fatalf("forwarded %v", got)
	}
	r = httptest.NewRequest("GET", "/api/v1/apps", nil)
	r.Header.Set("Authorization", "Bearer "+agent)
	w = httptest.NewRecorder()
	api.h.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "limited to: sandboxes") {
		t.Fatalf("scoped token on apps: %d %s", w.Code, w.Body)
	}
	if code := api.code("viewer", "GET", "/api/v1/sandboxes", ""); code != 403 {
		t.Errorf("viewer: %d", code)
	}
	if _, _, err := createAPIToken("x", "deployer", 0, "everything"); err == nil {
		t.Error("unknown scope accepted")
	}
}

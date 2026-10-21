package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

type fakeMCP struct {
	mu      sync.Mutex
	spec    schema.SandboxSpec
	exec    sdkapi.SandboxExecRequest
	execID  string
	files   map[string]string
	calls   []string
	blockCh chan struct{} // ExecSandbox waits on it (or its ctx) when set
}

func (f *fakeMCP) call(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fakeMCP) Sandboxes(context.Context) ([]sdkapi.Sandbox, error) {
	t := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return []sdkapi.Sandbox{{ID: "aaaaaaaaaaaa", State: "running", Created: t},
		{ID: "abcdefghijkl", State: "running", Created: t.Add(time.Hour)},
		{ID: "zzzzzzzzzzzz", State: "failed", Created: t.Add(2 * time.Hour)}}, nil
}
func (f *fakeMCP) Sandbox(_ context.Context, id string) (sdkapi.Sandbox, error) {
	return sdkapi.Sandbox{ID: id, State: "running"}, nil
}
func (f *fakeMCP) CreateSandbox(_ context.Context, s schema.SandboxSpec) (sdkapi.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spec = s
	return sdkapi.Sandbox{ID: "abcdefghijkl", State: "running", Spec: s}, nil
}
func (f *fakeMCP) DeleteSandbox(_ context.Context, id string) error {
	if id != "abcdefghijkl" {
		return errors.New("no sandbox " + id)
	}
	return nil
}
func (f *fakeMCP) PauseSandbox(_ context.Context, id string) (sdkapi.Sandbox, error) {
	f.call("pause " + id)
	return sdkapi.Sandbox{ID: id, State: "paused"}, nil
}
func (f *fakeMCP) ResumeSandbox(_ context.Context, id string) (sdkapi.Sandbox, error) {
	return sdkapi.Sandbox{ID: id, State: "running"}, nil
}
func (f *fakeMCP) RenewSandbox(_ context.Context, id, timeout string) (sdkapi.Sandbox, error) {
	f.call("renew " + id + " " + timeout)
	return sdkapi.Sandbox{ID: id}, nil
}
func (f *fakeMCP) ExecSandbox(ctx context.Context, id string, r sdkapi.SandboxExecRequest) (client.ExecResult, error) {
	if f.blockCh != nil {
		select {
		case <-f.blockCh:
		case <-ctx.Done():
			f.call("exec cancelled")
			return client.ExecResult{}, ctx.Err()
		}
	}
	f.mu.Lock()
	f.exec, f.execID = r, id
	f.mu.Unlock()
	return client.ExecResult{ExitCode: 3, Stdout: "out", Stderr: "err"}, nil
}
func (f *fakeMCP) ReadSandboxFile(_ context.Context, id, p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []byte(f.files[p]), nil
}
func (f *fakeMCP) WriteSandboxFile(_ context.Context, id, p string, r io.Reader, mode string) error {
	b, _ := io.ReadAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = string(b)
	return nil
}
func (f *fakeMCP) ListSandboxFiles(_ context.Context, id, p string) ([]sdkapi.SandboxFile, error) {
	f.call("ls " + p)
	return []sdkapi.SandboxFile{{Name: "a.py", Size: 8}}, nil
}
func (f *fakeMCP) DeleteSandboxFile(_ context.Context, id, p string, recursive bool) error {
	f.call("rm " + p)
	return nil
}
func (f *fakeMCP) ExposeSandboxPort(_ context.Context, id string, r sdkapi.SandboxPreviewRequest) (sdkapi.SandboxPreview, error) {
	return sdkapi.SandboxPreview{Port: r.Port, URL: "https://3000-x.example.com/", Token: "t", TokenURL: "https://3000-x.example.com/?ziro_token=t"}, nil
}
func (f *fakeMCP) UnexposeSandboxPort(_ context.Context, id string, port int) error { return nil }
func (f *fakeMCP) SandboxTemplates(context.Context) (map[string]schema.SandboxSpec, error) {
	return map[string]schema.SandboxSpec{"py": {Image: "python:3"}}, nil
}
func (f *fakeMCP) SnapshotSandbox(_ context.Context, id, name string) (sdkapi.SandboxSnapshot, error) {
	return sdkapi.SandboxSnapshot{Image: "ziro.local/sandbox/agent/" + name + ":1", Sandbox: id}, nil
}
func (f *fakeMCP) SandboxSnapshots(context.Context) ([]sdkapi.SandboxSnapshot, error) {
	return []sdkapi.SandboxSnapshot{{Image: "ziro.local/sandbox/agent/deps:1"}}, nil
}
func (f *fakeMCP) RemoveSandboxSnapshot(_ context.Context, image string) error {
	f.call("rmi " + image)
	return nil
}

// runMCP sends lines to a stdio server and returns its answers by id.
func runMCP(t *testing.T, f *fakeMCP, lines ...string) map[float64]map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := serveMCP(context.Background(), f, strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatal(err)
	}
	byID := map[float64]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		id, _ := m["id"].(float64)
		byID[id] = m
	}
	return byID
}

func mcpText(m map[string]any) string {
	return m["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
}

func callLine(id int, tool, args string) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": json.RawMessage(args)}})
	return string(b)
}

func TestMCPServer(t *testing.T) {
	f := &fakeMCP{files: map[string]string{"/workspace/b.py": "print(1)"}}
	r := runMCP(t, f,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		callLine(3, "sandbox_create", `{"image":"python:3.13-slim","allow":["pypi.org"],"memory":"2Gi","idle_timeout":"5m","env":{"A":"1"},"metadata":{"task":"7"}}`),
		callLine(4, "sandbox_exec", `{"id":"abcdefghijkl","command":"python3 -V"}`),
		callLine(5, "sandbox_write_file", `{"id":"abcdefghijkl","path":"/workspace/a.py","content":"print(1)"}`),
		callLine(6, "sandbox_read_file", `{"id":"abcdefghijkl","path":"/workspace/b.py"}`),
		callLine(7, "sandbox_delete", `{"id":"nope"}`),
		callLine(8, "rm_rf", `{}`),
		`{"jsonrpc":"2.0","id":9,"method":"nope"}`,
		`not json`,
		callLine(10, "sandbox_expose", `{"id":"abcdefghijkl","port":3000}`),
		callLine(11, "sandbox_create", `{"image":"a","bogus":1}`),
	)
	if len(r) != 12 { // the notification gets no answer; "not json" answers with id null
		t.Fatalf("%d answers: %v", len(r), r)
	}
	if v := r[1]["result"].(map[string]any)["protocolVersion"]; v != mcpProtocol {
		t.Errorf("initialize: %v", r[1])
	}
	tools := r[2]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != len(mcpTools) || len(tools) < 18 {
		t.Errorf("tools/list: %d", len(tools))
	}
	for _, tl := range tools {
		m := tl.(map[string]any)
		if m["annotations"] == nil || m["inputSchema"].(map[string]any)["required"] == nil {
			t.Errorf("tool %v: annotations and required must be set", m["name"])
		}
	}
	if f.spec.Image != "python:3.13-slim" || f.spec.Network.Mode != "allowlist" || f.spec.Network.Allow[0] != "pypi.org" ||
		f.spec.Resources.Memory != "2Gi" || f.spec.IdleTimeout != "5m" || f.spec.Env["A"] != "1" || f.spec.Metadata["task"] != "7" {
		t.Errorf("create spec %+v", f.spec)
	}
	if sc := r[3]["result"].(map[string]any)["structuredContent"]; sc == nil || sc.(map[string]any)["id"] != "abcdefghijkl" {
		t.Errorf("create structuredContent: %v", r[3])
	}
	if strings.Join(f.exec.Command, " ") != "/bin/sh -c python3 -V" || !strings.Contains(mcpText(r[4]), "exit_code: 3") || !strings.Contains(mcpText(r[4]), "out") {
		t.Errorf("exec: %v %q", f.exec.Command, mcpText(r[4]))
	}
	if sc := r[4]["result"].(map[string]any)["structuredContent"].(map[string]any); sc["exit_code"] != 3.0 || sc["stderr"] != "err" {
		t.Errorf("exec structuredContent: %v", sc)
	}
	if f.files["/workspace/a.py"] != "print(1)" || mcpText(r[6]) != "print(1)" {
		t.Errorf("files: %v %q", f.files, mcpText(r[6]))
	}
	if res := r[7]["result"].(map[string]any); res["isError"] != true || !strings.Contains(mcpText(r[7]), "no sandbox nope") {
		t.Errorf("tool error: %v", res)
	}
	if r[8]["error"] == nil || r[9]["error"] == nil || r[0]["error"] == nil {
		t.Errorf("protocol errors: %v %v %v", r[8], r[9], r[0])
	}
	if !strings.Contains(mcpText(r[10]), "?ziro_token=t") {
		t.Errorf("expose: %q", mcpText(r[10]))
	}
	if res := r[11]["result"].(map[string]any); res["isError"] != true {
		t.Errorf("unknown argument accepted: %v", res)
	}
}

// Calls that take an id default to the caller's newest live sandbox; run_code passes the code on
// stdin; binary files travel as base64; the rest of the tool table reaches the backend.
func TestMCPTools(t *testing.T) {
	f := &fakeMCP{files: map[string]string{"/workspace/bin": "\xff\x00\x01"}}
	bin := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255})
	r := runMCP(t, f,
		callLine(1, "sandbox_run_code", `{"language":"python","code":"print(2)"}`),
		callLine(2, "sandbox_run_code", `{"language":"cobol","code":"x"}`),
		callLine(3, "sandbox_read_file", `{"path":"/workspace/bin"}`),
		callLine(4, "sandbox_write_file", `{"path":"/workspace/b","content":"`+bin+`","encoding":"base64"}`),
		callLine(5, "sandbox_list_files", `{}`),
		callLine(6, "sandbox_delete_file", `{"path":"/workspace/b"}`),
		callLine(7, "sandbox_pause", `{}`),
		callLine(8, "sandbox_renew", `{"timeout":"2h"}`),
		callLine(9, "sandbox_snapshot_create", `{"name":"deps"}`),
		callLine(10, "sandbox_create", `{"snapshot":"ziro.local/sandbox/agent/deps:1"}`),
		callLine(11, "sandbox_create", `{"snapshot":"x","image":"y"}`),
		callLine(12, "sandbox_snapshot_delete", `{"snapshot":"ziro.local/sandbox/agent/deps:1"}`),
		callLine(13, "sandbox_templates", `{}`),
	)
	if f.execID != "abcdefghijkl" || strings.Join(f.exec.Command, " ") != "python3 -" || f.exec.Stdin != "print(2)" {
		t.Errorf("run_code: %s %v %q", f.execID, f.exec.Command, f.exec.Stdin)
	}
	if r[2]["result"].(map[string]any)["isError"] != true {
		t.Error("an unknown language ran")
	}
	if sc := r[3]["result"].(map[string]any)["structuredContent"].(map[string]any); sc["encoding"] != "base64" || sc["content"] != base64.StdEncoding.EncodeToString([]byte("\xff\x00\x01")) {
		t.Errorf("binary read: %v", sc)
	}
	if f.files["/workspace/b"] != "\x00\x01\x02\xff" {
		t.Errorf("binary write: %q", f.files["/workspace/b"])
	}
	want := []string{"ls /workspace", "rm /workspace/b", "pause abcdefghijkl", "renew abcdefghijkl 2h", "rmi ziro.local/sandbox/agent/deps:1"}
	slices.Sort(want)
	if slices.Sort(f.calls); !slices.Equal(f.calls, want) { // tool calls run concurrently
		t.Errorf("calls %v, want %v", f.calls, want)
	}
	if f.spec.Image != "ziro.local/sandbox/agent/deps:1" || r[11]["result"].(map[string]any)["isError"] != true {
		t.Errorf("create from snapshot: %+v %v", f.spec, r[11])
	}
	if !strings.Contains(mcpText(r[13]), "python:3") {
		t.Errorf("templates: %s", mcpText(r[13]))
	}
}

// A long tool call doesn't hold up the session, and notifications/cancelled stops it.
func TestMCPConcurrentAndCancel(t *testing.T) {
	f := &fakeMCP{files: map[string]string{}, blockCh: make(chan struct{})}
	pr, pw := io.Pipe()
	var out syncBuffer
	done := make(chan error, 1)
	go func() { done <- serveMCP(context.Background(), f, pr, &out) }()
	io.WriteString(pw, callLine(1, "sandbox_exec", `{"id":"abcdefghijkl","command":"sleep 3600"}`)+"\n")
	io.WriteString(pw, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
	waitFor(t, "the ping answer", func() bool { return strings.Contains(out.String(), `"id":2`) })
	io.WriteString(pw, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user"}}`+"\n")
	waitFor(t, "the cancel", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) == 1 })
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"id":1`) {
		t.Errorf("a cancelled call was answered: %s", out.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// POST /api/v1/sandboxes/mcp: the tools reach the sandbox API in process, as the caller's token.
func TestMCPOverHTTP(t *testing.T) {
	dir, err := os.MkdirTemp("", "z")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	oldSock := sandboxSocket
	sandboxSocket = filepath.Join(dir, "s.sock")
	defer func() { sandboxSocket = oldSock }()
	owners := make(chan string, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		owners <- r.Header.Get(hdrOwner)
		io.WriteString(w, `[{"id":"abcdefghijkl","owner":"agent","state":"running"}]`)
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
	post := func(tok, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/sandboxes/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		api.h.ServeHTTP(w, r)
		return w
	}
	w := post(agent, callLine(1, "sandbox_list", `{}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "abcdefghijkl") {
		t.Fatalf("tools/call: %d %s", w.Code, w.Body)
	}
	if o := <-owners; o != "agent" {
		t.Errorf("the daemon saw owner %q", o)
	}
	if w := post(agent, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); w.Code != 202 {
		t.Errorf("notification: %d", w.Code)
	}
	if w := post(agent, `nope`); w.Code != 400 {
		t.Errorf("parse error: %d", w.Code)
	}
	if w := post("bogus", callLine(1, "sandbox_list", `{}`)); w.Code != 401 {
		t.Errorf("bad token: %d", w.Code)
	}
	if code := api.code("viewer", "POST", "/api/v1/sandboxes/mcp", callLine(1, "sandbox_list", `{}`)); code != 403 {
		t.Errorf("viewer: %d", code)
	}
}

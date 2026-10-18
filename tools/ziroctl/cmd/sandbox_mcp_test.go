package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

type fakeMCP struct {
	spec  schema.SandboxSpec
	exec  sdkapi.SandboxExecRequest
	files map[string]string
}

func (f *fakeMCP) Sandboxes(context.Context) ([]sdkapi.Sandbox, error) {
	return []sdkapi.Sandbox{{ID: "abcdefghijkl", State: "running"}}, nil
}
func (f *fakeMCP) CreateSandbox(_ context.Context, s schema.SandboxSpec) (sdkapi.Sandbox, error) {
	f.spec = s
	return sdkapi.Sandbox{ID: "abcdefghijkl", State: "running", Spec: s}, nil
}
func (f *fakeMCP) DeleteSandbox(_ context.Context, id string) error {
	if id != "abcdefghijkl" {
		return errors.New("no sandbox " + id)
	}
	return nil
}
func (f *fakeMCP) ExecSandbox(_ context.Context, id string, r sdkapi.SandboxExecRequest) (client.ExecResult, error) {
	f.exec = r
	return client.ExecResult{ExitCode: 3, Stdout: "out", Stderr: "err"}, nil
}
func (f *fakeMCP) ReadSandboxFile(_ context.Context, id, p string) ([]byte, error) {
	return []byte(f.files[p]), nil
}
func (f *fakeMCP) WriteSandboxFile(_ context.Context, id, p string, r io.Reader, mode string) error {
	b, _ := io.ReadAll(r)
	f.files[p] = string(b)
	return nil
}
func (f *fakeMCP) ExposeSandboxPort(_ context.Context, id string, r sdkapi.SandboxPreviewRequest) (sdkapi.SandboxPreview, error) {
	return sdkapi.SandboxPreview{Port: r.Port, URL: "https://3000-x.example.com/", Token: "t", TokenURL: "https://3000-x.example.com/?ziro_token=t"}, nil
}

func TestMCPServer(t *testing.T) {
	f := &fakeMCP{files: map[string]string{}}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sandbox_create","arguments":{"image":"python:3.13-slim","allow":["pypi.org"],"memory":"2Gi"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sandbox_exec","arguments":{"id":"abcdefghijkl","command":"python3 -V"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sandbox_write_file","arguments":{"id":"abcdefghijkl","path":"/workspace/a.py","content":"print(1)"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sandbox_read_file","arguments":{"id":"abcdefghijkl","path":"/workspace/a.py"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sandbox_delete","arguments":{"id":"nope"}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"rm_rf","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"nope"}`,
		`not json`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"sandbox_expose","arguments":{"id":"abcdefghijkl","port":3000}}}`,
	}, "\n")
	var out bytes.Buffer
	if err := serveMCP(context.Background(), f, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		resps = append(resps, m)
	}
	if len(resps) != 11 { // the notification gets no answer
		t.Fatalf("%d answers:\n%s", len(resps), out.String())
	}
	text := func(i int) string {
		c := resps[i]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
		return c["text"].(string)
	}
	if v := resps[0]["result"].(map[string]any)["protocolVersion"]; v != mcpProtocol {
		t.Errorf("initialize: %v", resps[0])
	}
	if tools := resps[1]["result"].(map[string]any)["tools"].([]any); len(tools) != len(mcpTools) {
		t.Errorf("tools/list: %d", len(tools))
	}
	if f.spec.Image != "python:3.13-slim" || f.spec.Network.Mode != "allowlist" || f.spec.Network.Allow[0] != "pypi.org" || f.spec.Resources.Memory != "2Gi" {
		t.Errorf("create spec %+v", f.spec)
	}
	if strings.Join(f.exec.Command, " ") != "/bin/sh -c python3 -V" || !strings.Contains(text(3), "exit_code: 3") || !strings.Contains(text(3), "out") {
		t.Errorf("exec: %v %q", f.exec.Command, text(3))
	}
	if f.files["/workspace/a.py"] != "print(1)" || text(5) != "print(1)" {
		t.Errorf("files: %v %q", f.files, text(5))
	}
	if r := resps[6]["result"].(map[string]any); r["isError"] != true || !strings.Contains(text(6), "no sandbox nope") {
		t.Errorf("tool error: %v", r)
	}
	if resps[7]["error"] == nil || resps[8]["error"] == nil || resps[9]["error"] == nil {
		t.Errorf("protocol errors: %v %v %v", resps[7], resps[8], resps[9])
	}
	if !strings.Contains(text(10), "?ziro_token=t") {
		t.Errorf("expose: %q", text(10))
	}
}

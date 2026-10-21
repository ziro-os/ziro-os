package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"unicode/utf8"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Sandboxes as Model Context Protocol tools, so an AI agent (Claude and any MCP client) can
// create sandboxes, run code, move files, snapshot and publish ports. Two transports, one tool
// table:
//   - `ziroctl sandbox mcp`: stdio (newline-delimited JSON-RPC 2.0), anywhere ziroctl runs; it
//     calls the REST API with the agent's own token (ZIRO_API_TOKEN).
//   - POST /api/v1/sandboxes/mcp: Streamable HTTP (JSON answers, no SSE) on the API itself, with
//     the bearer token of the request. Each tool call goes through the API's own handler in
//     process, so auth, token scopes, the audit trail and cluster forwarding are the REST API's.
//
// Either way, everything an agent does is owned by its token, limited and audited like any other
// API client; ideally the token is --role deployer --scope sandboxes.

const mcpProtocol = "2025-06-18"

// mcpBackend is the part of the SDK client the tools use (a fake in tests).
type mcpBackend interface {
	Sandboxes(ctx context.Context) ([]sdkapi.Sandbox, error)
	Sandbox(ctx context.Context, id string) (sdkapi.Sandbox, error)
	CreateSandbox(ctx context.Context, spec schema.SandboxSpec) (sdkapi.Sandbox, error)
	DeleteSandbox(ctx context.Context, id string) error
	PauseSandbox(ctx context.Context, id string) (sdkapi.Sandbox, error)
	ResumeSandbox(ctx context.Context, id string) (sdkapi.Sandbox, error)
	RenewSandbox(ctx context.Context, id, timeout string) (sdkapi.Sandbox, error)
	ExecSandbox(ctx context.Context, id string, req sdkapi.SandboxExecRequest) (client.ExecResult, error)
	ReadSandboxFile(ctx context.Context, id, path string) ([]byte, error)
	WriteSandboxFile(ctx context.Context, id, path string, r io.Reader, mode string) error
	ListSandboxFiles(ctx context.Context, id, path string) ([]sdkapi.SandboxFile, error)
	DeleteSandboxFile(ctx context.Context, id, path string, recursive bool) error
	ExposeSandboxPort(ctx context.Context, id string, req sdkapi.SandboxPreviewRequest) (sdkapi.SandboxPreview, error)
	UnexposeSandboxPort(ctx context.Context, id string, port int) error
	SandboxTemplates(ctx context.Context) (map[string]schema.SandboxSpec, error)
	SnapshotSandbox(ctx context.Context, id, name string) (sdkapi.SandboxSnapshot, error)
	SandboxSnapshots(ctx context.Context) ([]sdkapi.SandboxSnapshot, error)
	RemoveSandboxSnapshot(ctx context.Context, image string) error
}

// mcpArgs is every tool's arguments (each tool's input schema says which it takes).
type mcpArgs struct {
	ID, Image, Template, Snapshot, Timeout, Memory         string
	IdleTimeout                                            string `json:"idle_timeout"`
	Command, Workdir, Stdin, Path, Content, Encoding, Name string
	Language, Code                                         string
	Env, Metadata                                          map[string]string
	Allow                                                  []string
	NetworkOpen                                            bool `json:"network_open"`
	CPUs                                                   float64
	Port                                                   int
	Public, Recursive                                      bool
}

// mcpToolDef is a tool: what clients see, and what it does. A result is shown to the model as
// text (a string as is, anything else as JSON) and, unless it is a string, as structuredContent.
type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
	run         func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error)
}

func obj(required []string, props map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func desc(typ, d string) map[string]any { return map[string]any{"type": typ, "description": d} }

var (
	mcpStr   = map[string]any{"type": "string"}
	mcpStrMp = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}
	mcpID    = desc("string", "the sandbox id (default: your newest running or paused sandbox)")
	mcpPath  = desc("string", "a path in /workspace, e.g. /workspace/main.py")

	// Annotations: hints for the client's confirmation UI (MCP 2025-06-18).
	readOnly    = map[string]any{"readOnlyHint": true}
	additive    = map[string]any{"readOnlyHint": false, "destructiveHint": false}
	idempotent  = map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}
	destructive = map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true}
	runsCode    = map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}
)

// mcpRunners: how sandbox_run_code runs a program read from stdin.
var mcpRunners = map[string][]string{
	"python": {"python3", "-"},
	"node":   {"node", "-"},
	"bash":   {"bash", "-s"},
	"sh":     {"sh", "-s"},
}

var mcpTools []mcpToolDef

func init() {
	mcpTools = []mcpToolDef{
		{Name: "sandbox_create", Annotations: additive,
			Description: "Create an isolated Linux sandbox (gVisor) and wait until it runs. No network unless allow (domains, e.g. pypi.org) or network_open is given. Start from an image, a host template or one of your snapshots. Returns the sandbox; later calls may leave out its id.",
			InputSchema: obj(nil, map[string]any{
				"image":        desc("string", "container image, e.g. python:3.13-slim"),
				"template":     desc("string", "a host template name (see sandbox_templates)"),
				"snapshot":     desc("string", "a snapshot image to start from (see sandbox_snapshot_list): its rootfs and /workspace"),
				"allow":        map[string]any{"type": "array", "items": mcpStr, "description": "domains or IPv4 CIDRs the sandbox may reach"},
				"network_open": desc("boolean", "allow the public internet"),
				"timeout":      desc("string", "lifetime, e.g. 30m (default 1h)"),
				"idle_timeout": desc("string", "delete after this long without an exec, e.g. 15m"),
				"memory":       desc("string", "e.g. 2Gi"), "cpus": map[string]any{"type": "number"},
				"env":      map[string]any{"type": "object", "additionalProperties": mcpStr, "description": "plain environment variables (not for secrets)"},
				"metadata": map[string]any{"type": "object", "additionalProperties": mcpStr, "description": "your labels, e.g. task id"}}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				spec := schema.SandboxSpec{Image: a.Image, Template: a.Template, Timeout: a.Timeout, IdleTimeout: a.IdleTimeout, Env: a.Env, Metadata: a.Metadata}
				if a.Snapshot != "" {
					if a.Image != "" {
						return nil, errors.New("give image or snapshot, not both")
					}
					spec.Image = a.Snapshot
				}
				if a.Memory != "" || a.CPUs > 0 {
					spec.Resources = &schema.Resources{Memory: a.Memory, CPUs: a.CPUs}
				}
				switch {
				case a.NetworkOpen:
					spec.Network = &schema.SandboxNetwork{Mode: schema.SandboxNetOpen}
				case len(a.Allow) > 0:
					spec.Network = &schema.SandboxNetwork{Mode: schema.SandboxNetAllowlist, Allow: a.Allow}
				}
				return b.CreateSandbox(ctx, spec)
			}},
		{Name: "sandbox_exec", Annotations: runsCode,
			Description: "Run a shell command in a sandbox (sh -c) and return its exit code, stdout and stderr.",
			InputSchema: obj([]string{"command"}, map[string]any{"id": mcpID, "command": mcpStr, "workdir": mcpStr,
				"stdin": desc("string", "text sent to the command's stdin (at most 1 MiB)"), "env": mcpStrMp,
				"timeout": desc("string", "default 5m, at most 1h")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				return mcpExec(ctx, b, a.ID, sdkapi.SandboxExecRequest{Command: []string{"/bin/sh", "-c", a.Command},
					Workdir: a.Workdir, Stdin: a.Stdin, Env: a.Env, Timeout: a.Timeout})
			}},
		{Name: "sandbox_run_code", Annotations: runsCode,
			Description: "Run a program in a sandbox: the code is passed on stdin to python3, node, bash or sh (the image must have it). Returns the exit code, stdout and stderr.",
			InputSchema: obj([]string{"language", "code"}, map[string]any{"id": mcpID,
				"language": map[string]any{"type": "string", "enum": []string{"python", "node", "bash", "sh"}},
				"code":     desc("string", "the program (at most 1 MiB)"), "workdir": mcpStr, "env": mcpStrMp,
				"timeout": desc("string", "default 5m, at most 1h")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				argv, ok := mcpRunners[a.Language]
				if !ok {
					return nil, errors.New("language: python, node, bash or sh")
				}
				return mcpExec(ctx, b, a.ID, sdkapi.SandboxExecRequest{Command: argv, Stdin: a.Code, Workdir: a.Workdir, Env: a.Env, Timeout: a.Timeout})
			}},
		{Name: "sandbox_write_file", Annotations: idempotent,
			Description: "Write a file in the sandbox's /workspace (directories are created). Text by default; encoding base64 for binary content.",
			InputSchema: obj([]string{"path", "content"}, map[string]any{"id": mcpID, "path": mcpPath, "content": mcpStr,
				"encoding": map[string]any{"type": "string", "enum": []string{"text", "base64"}}}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				data := []byte(a.Content)
				if a.Encoding == "base64" {
					var err error
					if data, err = base64.StdEncoding.DecodeString(a.Content); err != nil {
						return nil, fmt.Errorf("content: %w", err)
					}
				}
				if err := b.WriteSandboxFile(ctx, a.ID, a.Path, bytes.NewReader(data), ""); err != nil {
					return nil, err
				}
				return fmt.Sprintf("wrote %d bytes to %s", len(data), a.Path), nil
			}},
		{Name: "sandbox_read_file", Annotations: readOnly,
			Description: "Read a file from the sandbox's /workspace. Text comes back as is; anything that isn't UTF-8 comes back base64-encoded.",
			InputSchema: obj([]string{"path"}, map[string]any{"id": mcpID, "path": mcpPath}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				data, err := b.ReadSandboxFile(ctx, a.ID, a.Path)
				if err != nil {
					return nil, err
				}
				if len(data) > mcpMaxText {
					return nil, fmt.Errorf("%s is %d bytes, over the %d KiB a tool answer may carry; read a part with sandbox_exec (head, tail, sed -n)", a.Path, len(data), mcpMaxText>>10)
				}
				if utf8.Valid(data) {
					return string(data), nil
				}
				return map[string]any{"path": a.Path, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(data)}, nil
			}},
		{Name: "sandbox_list_files", Annotations: readOnly,
			Description: "List a directory of the sandbox's /workspace (default /workspace).",
			InputSchema: obj(nil, map[string]any{"id": mcpID, "path": mcpPath}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				if a.Path == "" {
					a.Path = "/workspace"
				}
				return b.ListSandboxFiles(ctx, a.ID, a.Path)
			}},
		{Name: "sandbox_delete_file", Annotations: destructive,
			Description: "Delete a file of the sandbox's /workspace (recursive for a directory).",
			InputSchema: obj([]string{"path"}, map[string]any{"id": mcpID, "path": mcpPath, "recursive": map[string]any{"type": "boolean"}}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				if err := b.DeleteSandboxFile(ctx, a.ID, a.Path, a.Recursive); err != nil {
					return nil, err
				}
				return "deleted " + a.Path, nil
			}},
		{Name: "sandbox_expose", Annotations: additive,
			Description: "Publish a port of the sandbox at an HTTPS URL (the sandbox needs a network; the server must listen on 0.0.0.0). Private by default: the URL carries a token.",
			InputSchema: obj([]string{"port"}, map[string]any{"id": mcpID, "port": map[string]any{"type": "integer"}, "public": desc("boolean", "no token needed")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				return b.ExposeSandboxPort(ctx, a.ID, sdkapi.SandboxPreviewRequest{Port: a.Port, Public: a.Public})
			}},
		{Name: "sandbox_unexpose", Annotations: destructive,
			Description: "Stop publishing a port (its URL and tokens stop working).",
			InputSchema: obj([]string{"port"}, map[string]any{"id": mcpID, "port": map[string]any{"type": "integer"}}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				if err := b.UnexposeSandboxPort(ctx, a.ID, a.Port); err != nil {
					return nil, err
				}
				return fmt.Sprintf("port %d unpublished", a.Port), nil
			}},
		{Name: "sandbox_get", Annotations: readOnly,
			Description: "Show a sandbox: state, expiry, network, resources, metadata.",
			InputSchema: obj(nil, map[string]any{"id": mcpID}),
			run:         func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.Sandbox(ctx, a.ID) }},
		{Name: "sandbox_list", Annotations: readOnly, Description: "List your sandboxes.", InputSchema: obj(nil, map[string]any{}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.Sandboxes(ctx) }},
		{Name: "sandbox_pause", Annotations: idempotent,
			Description: "Freeze a sandbox's processes (memory and files are kept; it uses no CPU). Resume it to go on.",
			InputSchema: obj(nil, map[string]any{"id": mcpID}),
			run:         func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.PauseSandbox(ctx, a.ID) }},
		{Name: "sandbox_resume", Annotations: idempotent, Description: "Thaw a paused sandbox.",
			InputSchema: obj(nil, map[string]any{"id": mcpID}),
			run:         func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.ResumeSandbox(ctx, a.ID) }},
		{Name: "sandbox_renew", Annotations: idempotent,
			Description: "Extend a sandbox's lifetime: it now expires timeout from now (default: its own timeout).",
			InputSchema: obj(nil, map[string]any{"id": mcpID, "timeout": desc("string", "e.g. 2h")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				return b.RenewSandbox(ctx, a.ID, a.Timeout)
			}},
		{Name: "sandbox_delete", Annotations: destructive, Description: "Delete a sandbox and its files.",
			InputSchema: obj([]string{"id"}, map[string]any{"id": desc("string", "the sandbox id")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				if err := b.DeleteSandbox(ctx, a.ID); err != nil {
					return nil, err
				}
				return "deleted " + a.ID, nil
			}},
		{Name: "sandbox_templates", Annotations: readOnly, Description: "List the host's sandbox templates (create with template).",
			InputSchema: obj(nil, map[string]any{}),
			run:         func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.SandboxTemplates(ctx) }},
		{Name: "sandbox_snapshot_create", Annotations: additive,
			Description: "Save a sandbox's filesystem (rootfs and /workspace) as a snapshot; sandbox_create with snapshot starts new sandboxes from it. Install once, fork many.",
			InputSchema: obj([]string{"name"}, map[string]any{"id": mcpID, "name": desc("string", "lowercase letters, digits, . _ -")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				return b.SnapshotSandbox(ctx, a.ID, a.Name)
			}},
		{Name: "sandbox_snapshot_list", Annotations: readOnly, Description: "List your snapshots.", InputSchema: obj(nil, map[string]any{}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) { return b.SandboxSnapshots(ctx) }},
		{Name: "sandbox_snapshot_delete", Annotations: destructive, Description: "Delete a snapshot.",
			InputSchema: obj([]string{"snapshot"}, map[string]any{"snapshot": desc("string", "its image, from sandbox_snapshot_list")}),
			run: func(ctx context.Context, b mcpBackend, a mcpArgs) (any, error) {
				if err := b.RemoveSandboxSnapshot(ctx, a.Snapshot); err != nil {
					return nil, err
				}
				return "deleted " + a.Snapshot, nil
			}},
	}
}

const mcpInstructions = `Isolated Linux sandboxes (gVisor) on a Ziro OS host, for running untrusted code.
Workflow: sandbox_create (an image such as python:3.13-slim, a template, or a snapshot) -> sandbox_exec / sandbox_run_code
and the file tools on /workspace -> sandbox_delete when done. Calls that take an id default to your newest sandbox.
Network: none unless you ask; allow lists domains (e.g. pypi.org, files.pythonhosted.org), network_open is the public
internet. A sandbox never reaches the host, other sandboxes or private networks. Sandboxes expire (default 1h;
sandbox_renew extends). To reuse a prepared environment, sandbox_snapshot_create once, then sandbox_create with
snapshot. Pause a sandbox you will come back to; it keeps its memory and files.`

// mcpExec runs a command and shapes its result for the model.
func mcpExec(ctx context.Context, b mcpBackend, id string, req sdkapi.SandboxExecRequest) (any, error) {
	res, err := b.ExecSandbox(ctx, id, req)
	if err != nil {
		return nil, err
	}
	return mcpExecResult{ExitCode: res.ExitCode, Stdout: mcpClip(res.Stdout), Stderr: mcpClip(res.Stderr)}, nil
}

type mcpExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func (r mcpExecResult) text() string {
	return fmt.Sprintf("exit_code: %d\n--- stdout\n%s\n--- stderr\n%s", r.ExitCode, r.Stdout, r.Stderr)
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mcpAnswer(id json.RawMessage, result any, rerr *mcpError) map[string]any {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		resp["error"] = rerr
	} else {
		resp["result"] = result
	}
	return resp
}

// mcpMaxCalls bounds the tool calls of one stdio session that run at once.
const mcpMaxCalls = 8

// serveMCP reads requests from in and writes answers to out until in ends. Tool calls run
// concurrently (a long exec doesn't hold up ping or other calls), and notifications/cancelled
// cancels the call it names.
func serveMCP(ctx context.Context, b mcpBackend, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var (
		mu       sync.Mutex // the encoder and inflight
		enc      = json.NewEncoder(out)
		werr     error
		inflight = map[string]context.CancelFunc{}
		wg       sync.WaitGroup
		slots    = make(chan struct{}, mcpMaxCalls)
	)
	send := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(v); err != nil && werr == nil {
			werr = err
		}
	}
	for sc.Scan() {
		var req mcpRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			send(map[string]any{"jsonrpc": "2.0", "id": nil, "error": mcpError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 { // a notification: no answer
			if req.Method == "notifications/cancelled" {
				var p struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(req.Params, &p) == nil {
					mu.Lock()
					if cancel := inflight[string(p.RequestID)]; cancel != nil {
						cancel()
					}
					mu.Unlock()
				}
			}
			continue
		}
		if req.Method != "tools/call" {
			result, rerr := mcpHandle(ctx, b, req)
			send(mcpAnswer(req.ID, result, rerr))
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		key := string(req.ID)
		mu.Lock()
		inflight[key] = cancel
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			slots <- struct{}{}
			defer func() { <-slots }()
			result, rerr := mcpHandle(cctx, b, req)
			mu.Lock()
			delete(inflight, key)
			mu.Unlock()
			if cctx.Err() != nil && ctx.Err() == nil { // cancelled by the client: no answer is expected
				return
			}
			send(mcpAnswer(req.ID, result, rerr))
		}()
	}
	wg.Wait()
	if werr != nil {
		return werr
	}
	return sc.Err()
}

func mcpHandle(ctx context.Context, b mcpBackend, req mcpRequest) (any, *mcpError) {
	switch req.Method {
	case "initialize":
		return map[string]any{"protocolVersion": mcpProtocol, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "ziro-sandbox", "version": "2.0"}, "instructions": mcpInstructions}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &mcpError{-32602, "invalid params"}
		}
		res, err := mcpCall(ctx, b, p.Name, p.Arguments)
		if errors.Is(err, errUnknownTool) {
			return nil, &mcpError{-32602, err.Error()}
		}
		if err != nil { // tool errors go to the model, not the protocol
			return map[string]any{"content": []map[string]string{{"type": "text", "text": err.Error()}}, "isError": true}, nil
		}
		return res, nil
	}
	return nil, &mcpError{-32601, "method not found: " + req.Method}
}

var errUnknownTool = errors.New("unknown tool")

const mcpMaxText = 256 << 10

func mcpClip(s string) string {
	if len(s) > mcpMaxText {
		return s[:mcpMaxText] + fmt.Sprintf("\n[... %d more bytes]", len(s)-mcpMaxText)
	}
	return s
}

// mcpCall runs a tool and returns its CallToolResult.
func mcpCall(ctx context.Context, b mcpBackend, name string, raw json.RawMessage) (map[string]any, error) {
	var tool *mcpToolDef
	for i := range mcpTools {
		if mcpTools[i].Name == name {
			tool = &mcpTools[i]
		}
	}
	if tool == nil {
		return nil, fmt.Errorf("%w %q", errUnknownTool, name)
	}
	var a mcpArgs
	if len(raw) > 0 && string(raw) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields() // a misspelt argument is an error, not silently dropped
		if err := dec.Decode(&a); err != nil {
			return nil, fmt.Errorf("bad arguments: %w", err)
		}
	}
	if _, takesID := tool.InputSchema["properties"].(map[string]any)["id"]; takesID && a.ID == "" {
		id, err := mcpDefaultID(ctx, b)
		if err != nil {
			return nil, err
		}
		a.ID = id
	}
	v, err := tool.run(ctx, b, a)
	if err != nil {
		return nil, err
	}
	var text string
	switch r := v.(type) {
	case string:
		return map[string]any{"content": []map[string]string{{"type": "text", "text": r}}}, nil
	case mcpExecResult:
		text = r.text()
	default:
		js, _ := json.MarshalIndent(v, "", "  ")
		text = string(js)
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "structuredContent": v}, nil
}

// mcpDefaultID is the caller's newest running or paused sandbox: agents lose track of ids, and
// asking the server keeps both transports stateless.
func mcpDefaultID(ctx context.Context, b mcpBackend) (string, error) {
	list, err := b.Sandboxes(ctx)
	if err != nil {
		return "", err
	}
	var best *sdkapi.Sandbox
	for i, sb := range list {
		if (sb.State == "running" || sb.State == "paused") && (best == nil || sb.Created.After(best.Created)) {
			best = &list[i]
		}
	}
	if best == nil {
		return "", errors.New("no running sandbox: create one with sandbox_create, or pass id")
	}
	return best.ID, nil
}

// ---- Streamable HTTP: POST /api/v1/sandboxes/mcp ----

// serveMCPHTTP answers one JSON-RPC message per POST (MCP Streamable HTTP, JSON answers only:
// GET has no event stream, so the route table answers it 405). The tools reach the API through
// self, in process, with the request's own bearer token.
func serveMCPHTTP(self http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req mcpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, sandboxExecMaxStdin+(1<<20))).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": mcpError{-32700, "parse error"}})
			return
		}
		if len(req.ID) == 0 { // a notification or a response: accepted, nothing to answer
			w.WriteHeader(http.StatusAccepted)
			return
		}
		c, err := client.New("http://127.0.0.1", trimBearer(r.Header.Get("Authorization")),
			client.WithUserAgent("ziro-sandbox-mcp-http"),
			client.WithHTTPClient(&http.Client{Transport: inProcess{h: self, remote: r.RemoteAddr}}))
		if err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		result, rerr := mcpHandle(r.Context(), c, req)
		_ = json.NewEncoder(w).Encode(mcpAnswer(req.ID, result, rerr))
	}
}

// ---- stdio: ziroctl sandbox mcp ----

var sandboxMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Serve sandboxes to AI agents as MCP tools on stdio",
	Long: `Runs a Model Context Protocol server on stdin/stdout. Its tools create sandboxes, run commands
and code, read and write files, snapshot, pause and publish ports through the REST API, with the
agent's own token:

  ZIRO_API_TOKEN  a token, ideally: ziroctl api token create agent --role deployer --scope sandboxes
  ZIRO_API_URL    default https://127.0.0.1:8443
  ZIRO_API_CA     the API's certificate (PEM), when it is self-signed (on the host itself,
                  /etc/ziro/tls/server.crt is used)

Clients that speak Streamable HTTP can skip ziroctl: the API serves the same tools at
POST /api/v1/sandboxes/mcp (with the token as a bearer token).`,
	Example: `  ZIRO_API_URL=https://sbx.example.com:8443 ZIRO_API_TOKEN=ziro_... ziroctl sandbox mcp
  claude mcp add ziro-sandbox -e ZIRO_API_TOKEN=ziro_... -- ziroctl sandbox mcp
  claude mcp add --transport http ziro-sandbox https://sbx.example.com:8443/api/v1/sandboxes/mcp \
    --header "Authorization: Bearer ziro_..."`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		tok := os.Getenv("ZIRO_API_TOKEN")
		if tok == "" {
			return errors.New("set ZIRO_API_TOKEN (ziroctl api token create agent --role deployer --scope sandboxes)")
		}
		url := os.Getenv("ZIRO_API_URL")
		if url == "" {
			url = "https://127.0.0.1:8443"
		}
		opts := []client.Option{client.WithUserAgent("ziro-sandbox-mcp")}
		ca := os.Getenv("ZIRO_API_CA")
		if ca == "" && url == "https://127.0.0.1:8443" && fileExists(apiTLSCert) {
			ca = apiTLSCert // on the host itself: its own API's certificate
		}
		if ca != "" {
			opts = append(opts, client.WithCAFile(ca))
		}
		c, err := client.New(url, tok, opts...)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return serveMCP(ctx, c, os.Stdin, os.Stdout)
	},
}

func init() { sandboxCmd.AddCommand(sandboxMCPCmd) }

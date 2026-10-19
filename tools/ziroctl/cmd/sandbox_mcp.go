package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// `ziroctl sandbox mcp`: a Model Context Protocol server on stdio, so an AI agent (Claude and any
// MCP client) can create sandboxes, run code, move files and publish ports as tools. It speaks
// to the REST API with the agent's own token (ZIRO_API_TOKEN, ideally --role deployer --scope
// sandboxes), so everything it does is owned, limited and audited like any other API client.
//
// Transport: newline-delimited JSON-RPC 2.0 (the MCP stdio transport). Only tools are served.

const mcpProtocol = "2025-06-18"

// mcpBackend is the part of the SDK client the tools use (a fake in tests).
type mcpBackend interface {
	Sandboxes(ctx context.Context) ([]sdkapi.Sandbox, error)
	CreateSandbox(ctx context.Context, spec schema.SandboxSpec) (sdkapi.Sandbox, error)
	DeleteSandbox(ctx context.Context, id string) error
	ExecSandbox(ctx context.Context, id string, req sdkapi.SandboxExecRequest) (client.ExecResult, error)
	ReadSandboxFile(ctx context.Context, id, path string) ([]byte, error)
	WriteSandboxFile(ctx context.Context, id, path string, r io.Reader, mode string) error
	ExposeSandboxPort(ctx context.Context, id string, req sdkapi.SandboxPreviewRequest) (sdkapi.SandboxPreview, error)
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

var (
	mcpStr = map[string]any{"type": "string"}
	mcpNum = map[string]any{"type": "number"}
)

var mcpTools = []mcpTool{
	{"sandbox_create", "Create an isolated Linux sandbox (gVisor) and wait until it runs. No network unless allow (domains, e.g. pypi.org) or network_open is given. Returns the sandbox (use its id with the other tools).",
		obj(nil, map[string]any{"image": map[string]any{"type": "string", "description": "container image, e.g. python:3.13-slim (or use template)"},
			"template":     map[string]any{"type": "string", "description": "a host template name"},
			"allow":        map[string]any{"type": "array", "items": mcpStr, "description": "domains or IPv4 CIDRs the sandbox may reach"},
			"network_open": map[string]any{"type": "boolean", "description": "allow the public internet"},
			"timeout":      map[string]any{"type": "string", "description": "lifetime, e.g. 30m (default 1h)"},
			"memory":       map[string]any{"type": "string", "description": "e.g. 2Gi"}, "cpus": mcpNum})},
	{"sandbox_exec", "Run a shell command in a sandbox (sh -c) and return its exit code, stdout and stderr.",
		obj([]string{"id", "command"}, map[string]any{"id": mcpStr, "command": mcpStr, "workdir": mcpStr, "stdin": mcpStr,
			"timeout": map[string]any{"type": "string", "description": "default 5m, at most 1h"}})},
	{"sandbox_write_file", "Write a text file in the sandbox's /workspace (directories are created).",
		obj([]string{"id", "path", "content"}, map[string]any{"id": mcpStr, "path": map[string]any{"type": "string", "description": "e.g. /workspace/main.py"}, "content": mcpStr})},
	{"sandbox_read_file", "Read a text file from the sandbox's /workspace.",
		obj([]string{"id", "path"}, map[string]any{"id": mcpStr, "path": mcpStr})},
	{"sandbox_expose", "Publish a port of the sandbox at an HTTPS URL (the sandbox needs a network; the server must listen on 0.0.0.0).",
		obj([]string{"id", "port"}, map[string]any{"id": mcpStr, "port": mcpNum, "public": map[string]any{"type": "boolean"}})},
	{"sandbox_list", "List your sandboxes.", obj(nil, map[string]any{})},
	{"sandbox_delete", "Delete a sandbox and its files.", obj([]string{"id"}, map[string]any{"id": mcpStr})},
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

// serveMCP reads requests from in and writes answers to out until in ends.
func serveMCP(ctx context.Context, b mcpBackend, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var req mcpRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": mcpError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 { // a notification (initialized, cancelled): no answer
			continue
		}
		result, rerr := mcpHandle(ctx, b, req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rerr != nil {
			resp["error"] = rerr
		} else {
			resp["result"] = result
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func mcpHandle(ctx context.Context, b mcpBackend, req mcpRequest) (any, *mcpError) {
	switch req.Method {
	case "initialize":
		return map[string]any{"protocolVersion": mcpProtocol, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo":   map[string]any{"name": "ziro-sandbox", "version": "1.0"},
			"instructions": "Isolated Linux sandboxes on a Ziro OS host. Create one, run commands and read/write files in /workspace, delete it when done."}, nil
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
		text, err := mcpCall(ctx, b, p.Name, p.Arguments)
		if errors.Is(err, errUnknownTool) {
			return nil, &mcpError{-32602, err.Error()}
		}
		res := map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}
		if err != nil { // tool errors go to the model, not the protocol
			res["content"] = []map[string]string{{"type": "text", "text": err.Error()}}
			res["isError"] = true
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

func mcpCall(ctx context.Context, b mcpBackend, name string, raw json.RawMessage) (string, error) {
	var a struct {
		ID, Image, Template, Timeout, Memory, Command, Workdir, Stdin, Path, Content string
		Allow                                                                        []string
		NetworkOpen                                                                  bool `json:"network_open"`
		CPUs                                                                         float64
		Port                                                                         int
		Public                                                                       bool
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "", fmt.Errorf("bad arguments: %w", err)
		}
	}
	js := func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
	switch name {
	case "sandbox_create":
		spec := schema.SandboxSpec{Image: a.Image, Template: a.Template, Timeout: a.Timeout}
		if a.Memory != "" || a.CPUs > 0 {
			spec.Resources = &schema.Resources{Memory: a.Memory, CPUs: a.CPUs}
		}
		switch {
		case a.NetworkOpen:
			spec.Network = &schema.SandboxNetwork{Mode: schema.SandboxNetOpen}
		case len(a.Allow) > 0:
			spec.Network = &schema.SandboxNetwork{Mode: schema.SandboxNetAllowlist, Allow: a.Allow}
		}
		sb, err := b.CreateSandbox(ctx, spec)
		return js(sb), err
	case "sandbox_exec":
		res, err := b.ExecSandbox(ctx, a.ID, sdkapi.SandboxExecRequest{Command: []string{"/bin/sh", "-c", a.Command},
			Workdir: a.Workdir, Stdin: a.Stdin, Timeout: a.Timeout})
		if err != nil {
			return "", err
		}
		return mcpClip(fmt.Sprintf("exit_code: %d\n--- stdout\n%s\n--- stderr\n%s", res.ExitCode, res.Stdout, res.Stderr)), nil
	case "sandbox_write_file":
		if err := b.WriteSandboxFile(ctx, a.ID, a.Path, strings.NewReader(a.Content), ""); err != nil {
			return "", err
		}
		return fmt.Sprintf("wrote %d bytes to %s", len(a.Content), a.Path), nil
	case "sandbox_read_file":
		data, err := b.ReadSandboxFile(ctx, a.ID, a.Path)
		return mcpClip(string(data)), err
	case "sandbox_expose":
		pv, err := b.ExposeSandboxPort(ctx, a.ID, sdkapi.SandboxPreviewRequest{Port: a.Port, Public: a.Public})
		if err != nil {
			return "", err
		}
		if pv.TokenURL != "" {
			return "private preview (open once to set a cookie, or send header X-Ziro-Preview-Token: " + pv.Token + "):\n" + pv.TokenURL, nil
		}
		return pv.URL, nil
	case "sandbox_list":
		list, err := b.Sandboxes(ctx)
		return js(list), err
	case "sandbox_delete":
		if err := b.DeleteSandbox(ctx, a.ID); err != nil {
			return "", err
		}
		return "deleted " + a.ID, nil
	}
	return "", fmt.Errorf("%w %q", errUnknownTool, name)
}

var sandboxMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Serve sandboxes to AI agents as MCP tools on stdio",
	Long: `Runs a Model Context Protocol server on stdin/stdout. Its tools create sandboxes, run commands,
read and write files and publish ports through the REST API, with the agent's own token:

  ZIRO_API_TOKEN  a token, ideally: ziroctl api token create agent --role deployer --scope sandboxes
  ZIRO_API_URL    default https://127.0.0.1:8443
  ZIRO_API_CA     the API's certificate (PEM), when it is self-signed (on the host itself,
                  /etc/ziro/tls/server.crt is used)`,
	Example: `  ZIRO_API_URL=https://sbx.example.com:8443 ZIRO_API_TOKEN=ziro_... ziroctl sandbox mcp
  claude mcp add ziro-sandbox -e ZIRO_API_TOKEN=ziro_... -- ziroctl sandbox mcp`,
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

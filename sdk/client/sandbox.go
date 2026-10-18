package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// ---- sandboxes (/api/v1/sandboxes; an agent's token: --role deployer --scope sandboxes) ----

// Sandboxes lists the caller's sandboxes (operators and admins see all).
func (c *Client) Sandboxes(ctx context.Context) ([]api.Sandbox, error) {
	var out []api.Sandbox
	return out, c.Get(ctx, "/api/v1/sandboxes", &out)
}

// Sandbox returns one sandbox.
func (c *Client) Sandbox(ctx context.Context, id string) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Get(ctx, "/api/v1/sandboxes/"+esc(id), &out)
}

// CreateSandbox creates a sandbox and returns once it runs. The first use of an image pulls it,
// so ctx (not the client's default timeout) bounds the call.
func (c *Client) CreateSandbox(ctx context.Context, spec schema.SandboxSpec) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.postLong(ctx, "/api/v1/sandboxes", spec, &out)
}

// DeleteSandbox deletes a sandbox and its workspace.
func (c *Client) DeleteSandbox(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/sandboxes/"+esc(id), nil, nil)
}

// PauseSandbox freezes a sandbox's processes; ResumeSandbox thaws them.
func (c *Client) PauseSandbox(ctx context.Context, id string) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Do(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/pause", nil, &out)
}

func (c *Client) ResumeSandbox(ctx context.Context, id string) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Do(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/resume", nil, &out)
}

// RenewSandbox moves a sandbox's expiry to now + timeout ("" = its own timeout).
func (c *Client) RenewSandbox(ctx context.Context, id, timeout string) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Do(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/renew", map[string]string{"timeout": timeout}, &out)
}

// SetSandboxMetadata replaces a sandbox's metadata.
func (c *Client) SetSandboxMetadata(ctx context.Context, id string, md map[string]string) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Do(ctx, http.MethodPut, "/api/v1/sandboxes/"+esc(id)+"/metadata", md, &out)
}

// ExecResult is a finished command: its exit code and output.
type ExecResult struct {
	ExitCode       int
	Stdout, Stderr string
}

// ExecSandbox runs a command and collects its output (use ExecSandboxStream for long output).
func (c *Client) ExecSandbox(ctx context.Context, id string, req api.SandboxExecRequest) (ExecResult, error) {
	var res ExecResult
	var out, errb bytes.Buffer
	code, err := c.ExecSandboxStream(ctx, id, req, &out, &errb)
	res.ExitCode, res.Stdout, res.Stderr = code, out.String(), errb.String()
	return res, err
}

// ExecSandboxStream runs a command, copying its output to stdout and stderr as it comes, and
// returns its exit code.
func (c *Client) ExecSandboxStream(ctx context.Context, id string, req api.SandboxExecRequest, stdout, stderr io.Writer) (int, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	hr, err := c.newRequest(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/exec", bytes.NewReader(b), "application/json")
	if err != nil {
		return 0, err
	}
	resp, err := c.longHTTP().Do(hr)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, decodeReply(resp, nil)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		var ev api.SandboxExecEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return 0, err
		}
		switch {
		case ev.Error != "":
			return 0, errors.New(ev.Error)
		case ev.ExitCode != nil:
			return *ev.ExitCode, nil
		case ev.Stream == "stderr":
			_, _ = io.WriteString(stderr, ev.Data)
		default:
			_, _ = io.WriteString(stdout, ev.Data)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("the exec stream ended without an exit code")
}

// postLong is Do for a POST bounded by ctx only.
func (c *Client) postLong(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json")
	if err != nil {
		return err
	}
	resp, err := c.longHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeReply(resp, out)
}

package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// ---- sandboxes (/api/v1/sandboxes; an agent's token: --role deployer --scope sandboxes) ----

// Sandboxes lists the caller's sandboxes (operators and admins see all).
func (c *Client) Sandboxes(ctx context.Context) ([]api.Sandbox, error) {
	var out []api.Sandbox
	return out, c.Get(ctx, "/api/v1/sandboxes", &out)
}

// ListSandboxes lists the caller's sandboxes that match f.
func (c *Client) ListSandboxes(ctx context.Context, f api.SandboxFilter) ([]api.Sandbox, error) {
	q := url.Values{}
	if f.State != "" {
		q.Set("state", f.State)
	}
	keys := make([]string, 0, len(f.Labels))
	for k := range f.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := f.Labels[k]; v != "" {
			q.Add("label", k+"="+v)
		} else {
			q.Add("label", k)
		}
	}
	path := "/api/v1/sandboxes"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out []api.Sandbox
	return out, c.Get(ctx, path, &out)
}

// SandboxStats returns a sandbox's resource use (CPU over a short sample).
func (c *Client) SandboxStats(ctx context.Context, id string) (api.SandboxStats, error) {
	var out api.SandboxStats
	return out, c.Get(ctx, "/api/v1/sandboxes/"+esc(id)+"/stats", &out)
}

// SandboxLogs returns the last tail lines (0: 200) of the sandbox's main command's output.
func (c *Client) SandboxLogs(ctx context.Context, id string, tail int) (string, error) {
	path := "/api/v1/sandboxes/" + esc(id) + "/logs"
	if tail > 0 {
		path += "?tail=" + strconv.Itoa(tail)
	}
	var out api.SandboxLogs
	return out.Logs, c.Get(ctx, path, &out)
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

// SetSandboxNetwork replaces a sandbox's egress policy; it applies at once.
func (c *Client) SetSandboxNetwork(ctx context.Context, id string, n schema.SandboxNetwork) (api.Sandbox, error) {
	var out api.Sandbox
	return out, c.Do(ctx, http.MethodPut, "/api/v1/sandboxes/"+esc(id)+"/network", n, &out)
}

// CreateSandboxAccess issues an SSH session token; the answer carries the ssh command and the
// gateway's known_hosts line (the token is shown only here).
func (c *Client) CreateSandboxAccess(ctx context.Context, id string, req api.SandboxAccessRequest) (api.SandboxAccess, error) {
	var out api.SandboxAccess
	return out, c.Do(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/access", req, &out)
}

// SandboxAccesses lists a sandbox's SSH session tokens (without secrets).
func (c *Client) SandboxAccesses(ctx context.Context, id string) ([]api.SandboxAccess, error) {
	var out []api.SandboxAccess
	return out, c.Get(ctx, "/api/v1/sandboxes/"+esc(id)+"/access", &out)
}

// RevokeSandboxAccess revokes an SSH session token.
func (c *Client) RevokeSandboxAccess(ctx context.Context, id, accessID string) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/sandboxes/"+esc(id)+"/access/"+esc(accessID), nil, nil)
}

// ReadSandboxFile returns a file of the sandbox's /workspace.
func (c *Client) ReadSandboxFile(ctx context.Context, id, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/sandboxes/"+esc(id)+"/files?path="+url.QueryEscape(path), nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.longHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, errors.New(path + " is a directory")
	}
	var b []byte
	return b, decodeReply(resp, &b)
}

// WriteSandboxFile writes r to a file of the sandbox's /workspace (mode "" = 0644), creating
// its directories.
func (c *Client) WriteSandboxFile(ctx context.Context, id, path string, r io.Reader, mode string) error {
	q := "path=" + url.QueryEscape(path)
	if mode != "" {
		q += "&mode=" + url.QueryEscape(mode)
	}
	req, err := c.newRequest(ctx, http.MethodPut, "/api/v1/sandboxes/"+esc(id)+"/files?"+q, r, "application/octet-stream")
	if err != nil {
		return err
	}
	resp, err := c.longHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeReply(resp, nil)
}

// ListSandboxFiles lists a directory of the sandbox's /workspace.
func (c *Client) ListSandboxFiles(ctx context.Context, id, path string) ([]api.SandboxFile, error) {
	var out []api.SandboxFile
	return out, c.Get(ctx, "/api/v1/sandboxes/"+esc(id)+"/files?path="+url.QueryEscape(path), &out)
}

// DeleteSandboxFile removes a file (or, recursive, a directory) of the sandbox's /workspace.
func (c *Client) DeleteSandboxFile(ctx context.Context, id, path string, recursive bool) error {
	q := "path=" + url.QueryEscape(path)
	if recursive {
		q += "&recursive=true"
	}
	return c.Do(ctx, http.MethodDelete, "/api/v1/sandboxes/"+esc(id)+"/files?"+q, nil, nil)
}

// ExposeSandboxPort publishes a port at https://<port>-<id>.<domain>; a private preview's
// answer carries a token (and a link with it).
func (c *Client) ExposeSandboxPort(ctx context.Context, id string, req api.SandboxPreviewRequest) (api.SandboxPreview, error) {
	var out api.SandboxPreview
	return out, c.Do(ctx, http.MethodPost, "/api/v1/sandboxes/"+esc(id)+"/previews", req, &out)
}

// UnexposeSandboxPort removes a preview and revokes its tokens.
func (c *Client) UnexposeSandboxPort(ctx context.Context, id string, port int) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/sandboxes/"+esc(id)+"/previews/"+strconv.Itoa(port), nil, nil)
}

// SandboxTemplates lists the host's sandbox templates (create with Template set).
func (c *Client) SandboxTemplates(ctx context.Context) (map[string]schema.SandboxSpec, error) {
	var out map[string]schema.SandboxSpec
	return out, c.Get(ctx, "/api/v1/sandboxes/templates", &out)
}

// SnapshotSandbox commits a sandbox's filesystem to an image new sandboxes can start from.
func (c *Client) SnapshotSandbox(ctx context.Context, id, name string) (api.SandboxSnapshot, error) {
	var out api.SandboxSnapshot
	return out, c.postLong(ctx, "/api/v1/sandboxes/"+esc(id)+"/snapshot", map[string]string{"name": name}, &out)
}

// SandboxSnapshots lists the caller's snapshots.
func (c *Client) SandboxSnapshots(ctx context.Context) ([]api.SandboxSnapshot, error) {
	var out []api.SandboxSnapshot
	return out, c.Get(ctx, "/api/v1/sandboxes/snapshots", &out)
}

// RemoveSandboxSnapshot deletes a snapshot image.
func (c *Client) RemoveSandboxSnapshot(ctx context.Context, image string) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/sandboxes/snapshots?image="+url.QueryEscape(image), nil, nil)
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

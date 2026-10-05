package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Methods for every other /api/v1 route. Results without a dedicated type in sdk/api decode
// into map[string]any (the shapes are documented in sdk/openapi.yaml). Every call returns a
// *Error with the server's status, code and message on failure.

func (c *Client) post(ctx context.Context, path string, in any) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodPost, path, in, &m)
}

func (c *Client) del(ctx context.Context, path string) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodDelete, path, nil, &m)
}

func lines(n int) string {
	if n <= 0 {
		return ""
	}
	return "?lines=" + strconv.Itoa(n)
}

// ---- host and services ----

// Metrics returns the Prometheus exposition text.
func (c *Client) Metrics(ctx context.Context) (string, error) {
	var b []byte
	err := c.Get(ctx, "/api/v1/metrics", &b)
	return string(b), err
}

func (c *Client) Services(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/services", &out)
}

func (c *Client) Service(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/services/"+esc(name), &out)
}

// ServiceLogs returns the last n lines (0 = server default) of a service's log.
func (c *Client) ServiceLogs(ctx context.Context, name string, n int) ([]string, error) {
	var out struct {
		Lines []string `json:"lines"`
	}
	return out.Lines, c.Get(ctx, "/api/v1/services/"+esc(name)+"/logs"+lines(n), &out)
}

// Top samples container and process resource use over one second.
func (c *Client) Top(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/system/top", &out)
}

func (c *Client) DiskUsage(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/system/df", &out)
}

// Prune plans (confirm=false) or removes unused containers, images, logs, temp files and caches.
func (c *Client) Prune(ctx context.Context, categories []string, all, confirm bool) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"categories": categories, "all": all, "confirm": confirm}
	return out, c.Do(ctx, http.MethodPost, "/api/v1/system/prune", body, &out)
}

// Power reboots or powers off the host ("reboot" or "poweroff").
func (c *Client) Power(ctx context.Context, action string) (api.Message, error) {
	return c.post(ctx, "/api/v1/system/"+esc(action), nil)
}

// ToolsUpdate reports the last ziroctl update check; refresh checks now.
func (c *Client) ToolsUpdate(ctx context.Context, refresh bool) (map[string]any, error) {
	var out map[string]any
	q := ""
	if refresh {
		q = "?refresh=true"
	}
	return out, c.Get(ctx, "/api/v1/system/update"+q, &out)
}

func (c *Client) InstallToolsUpdate(ctx context.Context) (api.Message, error) {
	return c.post(ctx, "/api/v1/system/update", nil)
}

func (c *Client) OSUpgrade(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/upgrade", &out)
}

// StartOSUpgrade upgrades the OS in the background (version "" = latest).
func (c *Client) StartOSUpgrade(ctx context.Context, version string, reboot bool) (api.Message, error) {
	return c.post(ctx, "/api/v1/upgrade", map[string]any{"version": version, "reboot": reboot})
}

func (c *Client) RollbackOSUpgrade(ctx context.Context) (api.Message, error) {
	return c.post(ctx, "/api/v1/upgrade/rollback", nil)
}

// ---- containers ----

func (c *Client) Containers(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/containers", &out)
}

func (c *Client) Container(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/containers/"+esc(id), &out)
}

func (c *Client) ContainerLogs(ctx context.Context, id string, n int) ([]string, error) {
	var out struct {
		Lines []string `json:"lines"`
	}
	return out.Lines, c.Get(ctx, "/api/v1/containers/"+esc(id)+"/logs"+lines(n), &out)
}

// ContainerAction starts, stops or restarts a container.
func (c *Client) ContainerAction(ctx context.Context, id, action string) (api.Message, error) {
	return c.post(ctx, "/api/v1/containers/"+esc(id)+"/"+esc(action), nil)
}

func (c *Client) RemoveContainer(ctx context.Context, id string) (api.Message, error) {
	return c.del(ctx, "/api/v1/containers/"+esc(id))
}

func (c *Client) Images(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/images", &out)
}

func (c *Client) PullImage(ctx context.Context, image string) (api.Message, error) {
	return c.post(ctx, "/api/v1/images/pull", map[string]string{"image": image})
}

// ---- firewall, network, security ----

func (c *Client) Firewall(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/firewall", &out)
}

// FirewallPort allows ("allow") or removes ("deny") an inbound port such as "443/tcp".
func (c *Client) FirewallPort(ctx context.Context, action, port, comment string) (api.Message, error) {
	return c.post(ctx, "/api/v1/firewall/"+esc(action), map[string]string{"port": port, "comment": comment})
}

// FirewallBlock blocks (block=true) or unblocks an IP or CIDR.
func (c *Client) FirewallBlock(ctx context.Context, target string, block bool) (api.Message, error) {
	action := "unblock"
	if block {
		action = "block"
	}
	return c.post(ctx, "/api/v1/firewall/"+action, map[string]string{"target": target})
}

func (c *Client) SetFirewall(ctx context.Context, enabled bool) (api.Message, error) {
	if enabled {
		return c.post(ctx, "/api/v1/firewall/enable", nil)
	}
	return c.post(ctx, "/api/v1/firewall/disable", nil)
}

func (c *Client) WireGuard(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/wireguard", &out)
}

func (c *Client) Security(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/security", &out)
}

func (c *Client) Bans(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/security/bans", &out)
}

// Ban blocks ip for duration (Go duration, "" = 1h).
func (c *Client) Ban(ctx context.Context, ip, duration string) (api.Message, error) {
	return c.post(ctx, "/api/v1/security/bans", map[string]string{"ip": ip, "duration": duration})
}

func (c *Client) Unban(ctx context.Context, ip string) (api.Message, error) {
	return c.del(ctx, "/api/v1/security/bans/"+esc(ip))
}

func (c *Client) Network(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/network", &out)
}

func (c *Client) SetHostname(ctx context.Context, hostname string) (api.Message, error) {
	return c.post(ctx, "/api/v1/network/hostname", map[string]string{"hostname": hostname})
}

func (c *Client) DNS(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/dns", &out)
}

// ---- cluster (on a master) ----

func (c *Client) Cluster(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/cluster", &out)
}

// ApplyClusterApp creates or replaces a cluster app from its full spec (as `cluster apply`).
func (c *Client) ApplyClusterApp(ctx context.Context, app map[string]any) (api.Message, error) {
	return c.post(ctx, "/api/v1/cluster/apps", app)
}

func (c *Client) ScaleClusterApp(ctx context.Context, name string, replicas int) (api.Message, error) {
	return c.post(ctx, "/api/v1/cluster/apps/"+esc(name)+"/scale", map[string]int{"replicas": replicas})
}

func (c *Client) RollbackClusterApp(ctx context.Context, name string) (api.Message, error) {
	return c.post(ctx, "/api/v1/cluster/apps/"+esc(name)+"/rollback", nil)
}

func (c *Client) RemoveClusterApp(ctx context.Context, name string) (api.Message, error) {
	return c.del(ctx, "/api/v1/cluster/apps/"+esc(name))
}

// NodeAction cordons, uncordons or drains a node.
func (c *Client) NodeAction(ctx context.Context, id, action string) (api.Message, error) {
	return c.post(ctx, "/api/v1/cluster/nodes/"+esc(id)+"/"+esc(action), nil)
}

func (c *Client) RemoveNode(ctx context.Context, id string) (api.Message, error) {
	return c.del(ctx, "/api/v1/cluster/nodes/"+esc(id))
}

// SetClusterSecret creates or replaces a secret (values are write-only).
func (c *Client) SetClusterSecret(ctx context.Context, name string, kv map[string]string) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodPut, "/api/v1/cluster/secrets/"+esc(name), kv, &m)
}

func (c *Client) RemoveClusterSecret(ctx context.Context, name string) (api.Message, error) {
	return c.del(ctx, "/api/v1/cluster/secrets/"+esc(name))
}

// ---- operations ----

func (c *Client) Backups(ctx context.Context) ([]api.Backup, error) {
	var out []api.Backup
	return out, c.Get(ctx, "/api/v1/backups", &out)
}

func (c *Client) CreateBackup(ctx context.Context) (api.Message, error) {
	return c.post(ctx, "/api/v1/backups", nil)
}

func (c *Client) RestoreBackup(ctx context.Context, name string) (api.Message, error) {
	return c.post(ctx, "/api/v1/backups/"+esc(name)+"/restore", nil)
}

// Audit returns the latest records (limit 0 = server default), at or after since (RFC 3339).
func (c *Client) Audit(ctx context.Context, limit int, since string) ([]api.AuditRecord, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if since != "" {
		q.Set("since", since)
	}
	var out []api.AuditRecord
	p := "/api/v1/audit"
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return out, c.Get(ctx, p, &out)
}

func (c *Client) Tokens(ctx context.Context) ([]api.Token, error) {
	var out []api.Token
	return out, c.Get(ctx, "/api/v1/tokens", &out)
}

// CreateToken issues a token; its Secret is returned only here. ttl is a Go duration ("" = 90 days, "0" = never).
func (c *Client) CreateToken(ctx context.Context, name, role, ttl string) (api.Token, error) {
	var out api.Token
	return out, c.Do(ctx, http.MethodPost, "/api/v1/tokens", map[string]string{"name": name, "role": role, "ttl": ttl}, &out)
}

func (c *Client) RevokeToken(ctx context.Context, name string) (api.Message, error) {
	return c.del(ctx, "/api/v1/tokens/"+esc(name))
}

func (c *Client) ModuleCatalog(ctx context.Context, query string) ([]api.ModuleInfo, error) {
	var out []api.ModuleInfo
	return out, c.Get(ctx, "/api/v1/modules/catalog?q="+url.QueryEscape(query), &out)
}

func (c *Client) AppCatalog(ctx context.Context, query string) ([]api.AppCatalogEntry, error) {
	var out []api.AppCatalogEntry
	return out, c.Get(ctx, "/api/v1/apps/catalog?q="+url.QueryEscape(query), &out)
}

// Events streams every audited change as it happens, calling fn for each until ctx ends, fn
// returns an error, or the server closes the stream (reconnect to continue).
func (c *Client) Events(ctx context.Context, fn func(api.AuditRecord) error) error {
	u := *c.base
	u.Path = c.base.Path + "/api/v1/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", c.ua)
	hc := *c.http
	hc.Timeout = 0 // a stream outlives the client's request timeout
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var m api.Message
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return &Error{Status: resp.StatusCode, Code: m.Code, Message: m.Message}
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		data, ok := bytes.CutPrefix(sc.Bytes(), []byte("data: "))
		if !ok {
			continue
		}
		var rec api.AuditRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("bad event: %w", err)
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		return err
	}
	return ctx.Err()
}

// ---- stacks and host provisioning ----

func (c *Client) Stacks(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/stacks", &out)
}

// CatalogStacks lists the stacks published in the host's signed app catalogs.
func (c *Client) CatalogStacks(ctx context.Context) ([]schema.Stack, error) {
	var out []schema.Stack
	return out, c.Get(ctx, "/api/v1/stacks?source=catalog", &out)
}

// Stack returns a stack and the status of each of its apps.
func (c *Client) Stack(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/stacks/"+esc(name), &out)
}

// PlanStack reports what applying s would create, update, keep or remove. s is validated
// locally first with the server's rules.
func (c *Client) PlanStack(ctx context.Context, s schema.Stack) (map[string]any, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/api/v1/stacks/"+esc(s.Stack)+"/plan", s, &out)
}

// ApplyStack applies s in the background (catalog apps only); poll Stack for progress.
func (c *Client) ApplyStack(ctx context.Context, s schema.Stack) (api.Message, error) {
	if err := s.Validate(); err != nil {
		return api.Message{}, err
	}
	var m api.Message
	return m, c.Do(ctx, http.MethodPut, "/api/v1/stacks/"+esc(s.Stack), s, &m)
}

// RemoveStack removes a stack's apps; purge also deletes their data and credentials.
func (c *Client) RemoveStack(ctx context.Context, name string, purge bool) (api.Message, error) {
	q := ""
	if purge {
		q = "?purge=true"
	}
	return c.del(ctx, "/api/v1/stacks/"+esc(name)+q)
}

// ApplyHost makes the host match cfg: with dryRun it returns the plan, otherwise it applies in
// the background.
func (c *Client) ApplyHost(ctx context.Context, cfg schema.HostConfig, dryRun bool) (map[string]any, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	q := ""
	if dryRun {
		q = "?dry_run=true"
	}
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/api/v1/apply"+q, cfg, &out)
}

// ---- deployments (ziroctl deploy) ----

// Deployments lists the apps deployed from git with their URL and latest build.
func (c *Client) Deployments(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Get(ctx, "/api/v1/deployments", &out)
}

// Deployment returns a deployment and its builds, newest first.
func (c *Client) Deployment(ctx context.Context, app string) (map[string]any, error) {
	var out map[string]any
	return out, c.Get(ctx, "/api/v1/deployments/"+esc(app), &out)
}

// Deploy creates or updates a deployment and queues its build; it returns the queued build.
func (c *Client) Deploy(ctx context.Context, req api.DeployRequest) (map[string]any, error) {
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/api/v1/deployments", req, &out)
}

// Redeploy builds the latest commit again (ref switches the branch when set).
func (c *Client) Redeploy(ctx context.Context, app, ref string) (map[string]any, error) {
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/api/v1/deployments/"+esc(app)+"/redeploy", map[string]string{"ref": ref}, &out)
}

// RollbackDeployment releases an earlier build again (build "" = the previous one).
func (c *Client) RollbackDeployment(ctx context.Context, app, build string) (map[string]any, error) {
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/api/v1/deployments/"+esc(app)+"/rollback", map[string]string{"build": build}, &out)
}

// PushSource deploys a .tar.gz of source files as app and returns the queued build. It needs a
// deployer token. The archive is read twice (a digest first, then the upload), hence the Seeker.
func (c *Client) PushSource(ctx context.Context, app string, spec api.SourceSpec, archive io.ReadSeeker) (map[string]any, error) {
	h := sha256.New()
	if _, err := io.Copy(h, archive); err != nil {
		return nil, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	spec.SourceSHA256 = hex.EncodeToString(h.Sum(nil))
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			w, err := mw.CreateFormField("spec")
			if err != nil {
				return err
			}
			if err := json.NewEncoder(w).Encode(spec); err != nil {
				return err
			}
			if w, err = mw.CreateFormFile("source", "source.tar.gz"); err != nil {
				return err
			}
			if _, err := io.Copy(w, archive); err != nil {
				return err
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	req, err := c.newRequest(ctx, http.MethodPost, "/api/v1/deployments/"+esc(app)+"/source", pr, mw.FormDataContentType())
	if err != nil {
		pr.CloseWithError(err)
		return nil, err
	}
	resp, err := c.longHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	return out, decodeReply(resp, &out)
}

// StreamBuildLog copies a build's log to w until the build finishes.
func (c *Client) StreamBuildLog(ctx context.Context, app, build string, w io.Writer) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/v1/deployments/"+esc(app)+"/builds/"+esc(build)+"/log?follow=true", nil, "")
	if err != nil {
		return err
	}
	resp, err := c.longHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeReply(resp, nil)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// BuildLog returns a build's log.
func (c *Client) BuildLog(ctx context.Context, app, build string) (string, error) {
	var b []byte
	err := c.Get(ctx, "/api/v1/deployments/"+esc(app)+"/builds/"+esc(build)+"/log", &b)
	return string(b), err
}

// RemoveDeployment removes a deployment, its builds and its app; purge deletes its data too.
func (c *Client) RemoveDeployment(ctx context.Context, app string, purge bool) error {
	q := ""
	if purge {
		q = "?purge=true"
	}
	return c.Do(ctx, http.MethodDelete, "/api/v1/deployments/"+esc(app)+q, nil, nil)
}

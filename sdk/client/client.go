// Package client is a typed Go client for the Ziro OS API (`ziroctl api`). It covers the
// documented routes in sdk/openapi.yaml; Do and Get reach any other route.
//
//	c, err := client.New("https://10.0.0.5:8443", os.Getenv("ZIRO_TOKEN"), client.WithCAFile("ziro-api.crt"))
//	routes, err := c.GatewayRoutes(ctx)
//	_, err = c.PutGatewayRoute(ctx, schema.GatewayRoute{Name: "web", Hosts: []string{"www.example.com"},
//		To: []schema.GatewayUpstream{{App: "web"}}})
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Client talks to one Ziro API server. It is safe for concurrent use.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
	ua    string
}

// Option configures a Client.
type Option func(*Client) error

// WithHTTPClient uses your own *http.Client (timeouts, proxies, tracing).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error { c.http = h; return nil }
}

// WithCAFile trusts the API server's certificate (or its CA) from a PEM file.
func WithCAFile(path string) Option {
	return func(c *Client) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := WithCAPEM(b)(c); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
}

// WithCAPEM trusts the PEM certificates given (the server's own self-signed certificate, or its
// CA). The server's name or address must still match the certificate.
func WithCAPEM(pemData []byte) Option {
	return func(c *Client) error {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return errors.New("no PEM certificates")
		}
		c.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
		return nil
	}
}

// WithUserAgent sets the User-Agent (useful in the server's audit log).
func WithUserAgent(ua string) Option {
	return func(c *Client) error { c.ua = ua; return nil }
}

// New returns a client for baseURL (https:// required unless the host is loopback).
func New(baseURL, token string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid base URL %q", baseURL)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("refusing to send a token over plain HTTP to a non-loopback host")
	}
	c := &Client{base: u, token: token, http: &http.Client{Timeout: 60 * time.Second}, ua: "ziro-sdk-go/1"}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// Error is a non-2xx answer from the server.
type Error struct {
	Status  int
	Code    string // invalid, unauthorized, forbidden, not_found, conflict, rate_limited, ...
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("ziro api: %d %s", e.Status, e.Message) }

// IsForbidden reports whether err is a 403: the token's role is too low for the operation.
func IsForbidden(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusForbidden
}

// IsNotFound reports whether err is a 404 from the server.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// Do sends method path with in (JSON, may be nil) and decodes a JSON answer into out (may be nil).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ctype = bytes.NewReader(b), "application/json"
	}
	req, err := c.newRequest(ctx, method, path, body, ctype)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeReply(resp, out)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader, ctype string) (*http.Request, error) {
	u := *c.base
	p, q, _ := strings.Cut(path, "?")
	u.Path, u.RawQuery = c.base.Path+p, q
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	return req, nil
}

// longHTTP is the client for transfers that outlast the default timeout (uploads, log streams):
// the caller's context bounds them instead.
func (c *Client) longHTTP() *http.Client {
	h := *c.http
	h.Timeout = 0
	return &h
}

// decodeReply maps a non-2xx answer to an *Error and decodes a 2xx body into out.
func decodeReply(resp *http.Response, out any) error {
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var m api.Message
		if json.Unmarshal(data, &m) == nil && m.Message != "" {
			return &Error{Status: resp.StatusCode, Code: m.Code, Message: m.Message}
		}
		return &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(data))}
	}
	switch o := out.(type) {
	case nil:
		return nil
	case *[]byte:
		*o = data
		return nil
	default:
		return json.Unmarshal(data, out)
	}
}

// Get decodes GET path into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

func esc(s string) string { return url.PathEscape(s) }

// ---- host ----

// Health is the liveness check (no token needed).
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var m map[string]any
	return m, c.Get(ctx, "/api/v1/health", &m)
}

// System returns host metrics and cloud metadata.
func (c *Client) System(ctx context.Context) (map[string]any, error) {
	var m map[string]any
	return m, c.Get(ctx, "/api/v1/system", &m)
}

// ServiceAction starts, stops, restarts, enables or disables a service.
func (c *Client) ServiceAction(ctx context.Context, name, action string) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodPost, "/api/v1/services/"+esc(name)+"/"+esc(action), nil, &m)
}

// ---- modules (plugins) ----

func (c *Client) Modules(ctx context.Context) ([]api.ModuleInfo, error) {
	var out []api.ModuleInfo
	return out, c.Get(ctx, "/api/v1/modules", &out)
}

// ModuleAction runs enable, upgrade, disable or purge in the background (poll Modules).
func (c *Client) ModuleAction(ctx context.Context, name, action string) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodPost, "/api/v1/modules/"+esc(name)+"/"+esc(action), nil, &m)
}

// ---- apps ----

func (c *Client) Apps(ctx context.Context) ([]api.AppStatus, error) {
	var out []api.AppStatus
	return out, c.Get(ctx, "/api/v1/apps", &out)
}

// DeployApp starts a deploy in the background (poll Apps).
func (c *Client) DeployApp(ctx context.Context, req api.AppDeployRequest) (api.Message, error) {
	var m api.Message
	return m, c.Do(ctx, http.MethodPost, "/api/v1/apps/deploy", req, &m)
}

// RemoveApp removes an app; purge also deletes its data and credentials.
func (c *Client) RemoveApp(ctx context.Context, name string, purge bool) (api.Message, error) {
	var m api.Message
	q := ""
	if purge {
		q = "?purge=true"
	}
	return m, c.Do(ctx, http.MethodDelete, "/api/v1/apps/"+esc(name)+q, nil, &m)
}

// ---- storage ----

func (c *Client) NFS(ctx context.Context) (api.NFSConfig, error) {
	var out api.NFSConfig
	return out, c.Get(ctx, "/api/v1/nfs", &out)
}

func (c *Client) NFSClients(ctx context.Context) ([]api.NFSClient, error) {
	var out []api.NFSClient
	return out, c.Get(ctx, "/api/v1/nfs/clients", &out)
}

// ---- gateway ----

func (c *Client) GatewayRoutes(ctx context.Context) ([]schema.GatewayRouteState, error) {
	var out []schema.GatewayRouteState
	return out, c.Get(ctx, "/api/v1/gateway/routes", &out)
}

func (c *Client) GatewayRoute(ctx context.Context, name string) (schema.GatewayRouteState, error) {
	var out schema.GatewayRouteState
	return out, c.Get(ctx, "/api/v1/gateway/routes/"+esc(name), &out)
}

// PutGatewayRoute creates or replaces a route. It is validated locally first with the same rules
// as the server, so mistakes fail fast with a precise error.
func (c *Client) PutGatewayRoute(ctx context.Context, r schema.GatewayRoute) (schema.GatewayRoute, error) {
	check := r
	check.Normalize()
	if err := check.Validate(); err != nil {
		return r, err
	}
	var out schema.GatewayRoute
	return out, c.Do(ctx, http.MethodPut, "/api/v1/gateway/routes/"+esc(r.Name), r, &out)
}

func (c *Client) DeleteGatewayRoute(ctx context.Context, name string) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/gateway/routes/"+esc(name), nil, nil)
}

func (c *Client) GatewayStatus(ctx context.Context) (api.GatewayStatus, error) {
	var out api.GatewayStatus
	return out, c.Get(ctx, "/api/v1/gateway/status", &out)
}

// GatewayCA returns the internal CA certificate (PEM) for `tls internal` routes.
func (c *Client) GatewayCA(ctx context.Context) ([]byte, error) {
	var out []byte
	return out, c.Get(ctx, "/api/v1/gateway/ca", &out)
}

// UploadGatewayCert stores a certificate chain and key for `tls cert:<name>` routes.
func (c *Client) UploadGatewayCert(ctx context.Context, name string, cert schema.GatewayCert) error {
	body := struct {
		Name string `json:"name"`
		schema.GatewayCert
	}{name, cert}
	return c.Do(ctx, http.MethodPost, "/api/v1/gateway/certs", body, nil)
}

func (c *Client) DeleteGatewayCert(ctx context.Context, name string) error {
	return c.Do(ctx, http.MethodDelete, "/api/v1/gateway/certs/"+esc(name), nil, nil)
}

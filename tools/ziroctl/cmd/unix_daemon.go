package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// Local daemons behind a root-only unix socket (ziroctld, ziro-sandboxd). The CLI talks to the
// socket directly (as root it is the host's admin); the REST API authenticates the caller and
// forwards, passing who it is in X-Ziro-Owner / X-Ziro-Role (a client can't set those: the proxy
// replaces them, and only root can reach the socket).

const (
	hdrOwner = "X-Ziro-Owner"
	hdrRole  = "X-Ziro-Role"
)

func unixClient(sock *string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *sock)
		},
	}}
}

// daemonRaw sends one request to a daemon. If the daemon doesn't answer (crashed, or not up yet
// after a boot), start runs once (starting its service) and the request is retried.
func daemonRaw(ctx context.Context, c *http.Client, name, sock string, start func(context.Context) error, method, path string, body any) (*http.Response, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	do := func() (*http.Response, error) {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, "http://"+name+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return c.Do(req)
	}
	resp, err := do()
	if err == nil {
		return resp, nil
	}
	if serr := start(ctx); serr != nil {
		return nil, serr
	}
	if resp, err = do(); err != nil {
		return nil, fmt.Errorf("%s isn't answering on %s (log: /var/log/%s.log): %w", name, sock, name, err)
	}
	return resp, nil
}

// daemonDecode reads a daemon's JSON answer into out (nil: ignore the body), or its error.
func daemonDecode(name string, resp *http.Response, out any) error {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error+e.Message != "" {
			return errors.New(e.Error + e.Message)
		}
		return fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// startSocketService starts a module's supervised daemon and waits (up to 10s) for its socket.
func startSocketService(ctx context.Context, name, sock, module string) error {
	if _, err := loadServiceDef(name); err != nil {
		return fmt.Errorf("%s isn't running (enable it with: ziroctl module enable %s)", name, module)
	}
	if err := startModuleService(name); err != nil && !strings.Contains(err.Error(), "already running") {
		return fmt.Errorf("%s isn't running and could not be started: %w (log: /var/log/%s.log)", name, err, name)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil // let the retry report why the socket doesn't answer
}

// daemonProxy forwards /api/v1/... to a daemon's /v1/..., replacing the API token with the
// caller's identity, and streams the answer (logs, exec output) as it comes.
func daemonProxy(c *http.Client, name, down string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: c.Transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", name, name
			r.Out.URL.Path = "/v1" + strings.TrimPrefix(r.In.URL.Path, "/api/v1")
			r.Out.Header.Del("Authorization") // the API token stays with the API
			r.Out.Header.Set(hdrOwner, apiTokenName(r.In))
			r.Out.Header.Set(hdrRole, apiRole(r.In))
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			apiError(w, http.StatusServiceUnavailable, down)
		},
	}
}

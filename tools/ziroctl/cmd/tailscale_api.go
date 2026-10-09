package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// API for the tailscale module (the same operations as `ziroctl tailscale`): status for a viewer,
// join, disconnect and leave for an admin. Ports are opened to the tailnet with the firewall
// routes (`iface`: "tailscale0"). An auth key travels in the request body only: it is checked,
// handed to Tailscale as a 0600 file and never stored, logged or returned. The API cannot do the
// browser login (it would block on a link nobody sees): use the CLI for that.

// TailscaleView is GET /api/v1/tailscale.
type TailscaleView struct {
	Enabled bool `json:"enabled"` // the module is enabled
	TailscaleStatus
}

func tsEnabled() bool {
	st := enabledModules()[tsModule]
	return st != nil && st.Status == "enabled"
}

// tsErr turns a CLI failure into an error that says why: the last line it printed (never a key:
// the CLI never prints one).
func tsErr(err error, stderr *bytes.Buffer) error {
	if err == nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" && !strings.Contains(err.Error(), last) {
		return errors.New(err.Error() + ": " + last)
	}
	return err
}

func registerTailscaleRoutes(a *apiRouter) {
	done := func(msg string) APIMessage { return APIMessage{Status: "ok", Message: msg} }
	a.get("/api/v1/tailscale", "viewer", func(w http.ResponseWriter, r *http.Request) {
		if !tsEnabled() {
			apiReply(w, nil, TailscaleView{})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		st, err := tsStatus(ctx)
		apiReply(w, err, TailscaleView{Enabled: true, TailscaleStatus: st})
	})
	a.post("/api/v1/tailscale/up", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req TailscaleUp
		if !decodeBody(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.AuthKey) == "" {
			apiReply(w, errors.New("auth_key: an auth key or OAuth client secret is required through the API (use `ziroctl tailscale up` for the browser login)"), nil)
			return
		}
		if req.TimeoutSeconds <= 0 || req.TimeoutSeconds > 300 {
			req.TimeoutSeconds = 120
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.TimeoutSeconds+30)*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		st, err := tsUp(ctx, req, nil, &stderr)
		apiReply(w, tsErr(err, &stderr), TailscaleView{Enabled: true, TailscaleStatus: st})
	})
	a.post("/api/v1/tailscale/down", "admin", func(w http.ResponseWriter, r *http.Request) {
		if !tsEnabled() {
			apiReply(w, errors.New("tailscale is not enabled"), nil)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		apiReply(w, tsErr(tsDown(ctx, nil, &stderr), &stderr), done("disconnected"))
	})
	a.post("/api/v1/tailscale/logout", "admin", func(w http.ResponseWriter, r *http.Request) {
		if !tsEnabled() {
			apiReply(w, errors.New("tailscale is not enabled"), nil)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		apiReply(w, tsErr(tsLogout(ctx, nil, &stderr), &stderr), done("logged out"))
	})
}

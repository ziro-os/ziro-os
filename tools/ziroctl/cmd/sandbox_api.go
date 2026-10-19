package cmd

import (
	"net/http"
	"time"
)

// /api/v1/sandboxes: the REST API authenticates, audits and forwards to ziro-sandboxd, passing
// the caller's token name and role (the daemon scopes every sandbox to its owner). Deployers
// manage their own sandboxes, so an agent's token can be a deployer limited to --scope sandboxes.
func registerSandboxRoutes(a *apiRouter) {
	proxy := daemonProxy(sandboxHTTP, "ziro-sandboxd", "ziro-sandboxd isn't running (ziroctl module enable sandbox)")
	fwd := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		proxy.ServeHTTP(w, r)
	}
	a.get("/api/v1/sandboxes", "deployer", fwd)
	// Creating pulls the image on first use: allow minutes instead of the server's 15 s.
	a.post("/api/v1/sandboxes", "deployer", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(11 * time.Minute))
		fwd(w, r)
	})
	a.get("/api/v1/sandboxes/{id}", "deployer", fwd)
	a.delete("/api/v1/sandboxes/{id}", "deployer", fwd)
	a.post("/api/v1/sandboxes/{id}/pause", "deployer", fwd)
	a.post("/api/v1/sandboxes/{id}/resume", "deployer", fwd)
	a.post("/api/v1/sandboxes/{id}/renew", "deployer", fwd)
	a.put("/api/v1/sandboxes/{id}/metadata", "deployer", fwd)
	a.put("/api/v1/sandboxes/{id}/network", "deployer", fwd)
	// An exec streams its output for as long as it runs (up to 1 h); each write gets its own deadline.
	a.post("/api/v1/sandboxes/{id}/exec", "deployer", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})
		r.Body = http.MaxBytesReader(w, r.Body, sandboxExecMaxStdin+(64<<10))
		proxy.ServeHTTP(&deadlineWriter{w, rc}, r)
	})
}

package cmd

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

var (
	deployUploadTimeout = 30 * time.Minute // a source upload, start to answer
	deployStreamTimeout = time.Minute      // one write of a streamed build log to a client
)

// deadlineWriter gives every write of a streamed answer its own deadline, so a log that stays
// open for an hour is cut only when a client stops reading, not after the server's 15 s.
type deadlineWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (d *deadlineWriter) Write(b []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(deployStreamTimeout))
	return d.ResponseWriter.Write(b)
}

func (d *deadlineWriter) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// /api/v1/deployments: the REST API forwards to ziroctld's socket. Creating a deployment runs
// code from a repository, so it needs admin (like apps deploy); rebuilding or rolling back an
// existing one, or pushing source to a deployment that is already set up, is a deployer's job (a CI token).
func registerDeployRoutes(a *apiRouter) {
	proxy := &httputil.ReverseProxy{
		Transport: deployHTTP.Transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "ziroctld", "ziroctld"
			r.Out.URL.Path = "/v1" + strings.TrimPrefix(r.In.URL.Path, "/api/v1")
			r.Out.Header.Del("Authorization") // the API token stays with the API
		},
		FlushInterval: -1, // stream build logs
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			apiError(w, http.StatusServiceUnavailable, "ziroctld isn't running (ziroctl module enable builder)")
		},
	}
	fwd := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		proxy.ServeHTTP(w, r)
	}
	a.get("/api/v1/deployments", "viewer", fwd)
	a.post("/api/v1/deployments", "admin", fwd)
	// A client pushes its source here: the one route with a large body (ziroctld streams it to disk).
	a.post("/api/v1/deployments/{app}/source", "deployer", func(w http.ResponseWriter, r *http.Request) {
		// The default 10 s to read a request would cut any upload that takes longer, and the
		// default 15 s write deadline would already be over when the answer is written.
		rc := http.NewResponseController(w)
		end := time.Now().Add(deployUploadTimeout)
		_ = rc.SetReadDeadline(end)
		_ = rc.SetWriteDeadline(end.Add(time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, deployUploadMax+(64<<10))
		proxy.ServeHTTP(w, r)
	})
	a.get("/api/v1/deployments/{app}", "viewer", fwd)
	a.delete("/api/v1/deployments/{app}", "admin", fwd)
	a.post("/api/v1/deployments/{app}/redeploy", "deployer", fwd)
	a.post("/api/v1/deployments/{app}/rollback", "deployer", fwd)
	a.get("/api/v1/deployments/{app}/builds/{id}/log", "viewer", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{}) // a queued build writes nothing for a while; each write sets its own
		proxy.ServeHTTP(&deadlineWriter{w, rc}, r)
	})
	// Git push webhooks: public, authenticated by the deployment's hook secret (in ziroctld).
	a.post("/api/v1/hooks/deploy/{app}", "public", fwd)
}

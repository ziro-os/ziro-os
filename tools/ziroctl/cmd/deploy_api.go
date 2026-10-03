package cmd

import (
	"net/http"
	"net/http/httputil"
	"strings"
)

// /api/v1/deployments: the REST API forwards to ziroctld's socket. Creating a deployment runs
// code from a repository, so it needs admin (like apps deploy); rebuilding or rolling back an
// existing one is an operator's job.
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
	a.get("/api/v1/deployments/{app}", "viewer", fwd)
	a.delete("/api/v1/deployments/{app}", "admin", fwd)
	a.post("/api/v1/deployments/{app}/redeploy", "operator", fwd)
	a.post("/api/v1/deployments/{app}/rollback", "operator", fwd)
	a.get("/api/v1/deployments/{app}/builds/{id}/log", "viewer", fwd)
}

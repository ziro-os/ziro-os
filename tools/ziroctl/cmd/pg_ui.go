package cmd

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

// The Postgres dashboard: a static page served by the API server at /ui/ (docs/postgres.md,
// "Dashboard"). It is plain HTML, CSS and JavaScript embedded in ziroctl: no build step, nothing loaded
// from elsewhere, and a Content-Security-Policy that allows only its own files. The page holds no data:
// it asks for an API token, keeps it in the browser tab's sessionStorage, and calls the same API with
// it, so it can never do more than the token's role allows. The files are the only public route besides
// health (TestRoutePolicy names it).

//go:embed ui/index.html ui/app.js ui/app.css
var pgUIFiles embed.FS

var pgUITypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
}

// pgUICSP: only this origin's files and API; no inline script or style, no framing, no forms posting
// elsewhere.
const pgUICSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func servePGUI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" {
		name = "index.html"
	}
	if strings.Contains(name, "/") || strings.HasPrefix(name, ".") {
		apiError(w, http.StatusNotFound, "no such file")
		return
	}
	typ, ok := pgUITypes[path.Ext(name)]
	if !ok {
		apiError(w, http.StatusNotFound, "no such file")
		return
	}
	b, err := pgUIFiles.ReadFile("ui/" + name)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such file")
		return
	}
	h := w.Header()
	h.Set("Content-Type", typ)
	h.Set("Content-Security-Policy", pgUICSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	_, _ = w.Write(b)
}

func registerPGUIRoutes(a *apiRouter) {
	a.get("/ui/{file...}", "public", servePGUI)
	a.get("/api/v1/pg/{name}/roles", "viewer", func(w http.ResponseWriter, r *http.Request) {
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		c, err := pgCluster(st, r.PathValue("name"))
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, pgRoleRows(st, c))
	})
}

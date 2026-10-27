package cmd

import (
	"fmt"
	"net/http"
)

// registerDockerAPIRoutes: the opt-in Docker Engine API socket (RFC 0006). Anyone who can use the socket
// is root on the host, so turning it on or off needs admin; reading whether it is on needs a token.
func registerDockerAPIRoutes(a *apiRouter) {
	a.get("/api/v1/docker-api", "viewer", func(w http.ResponseWriter, r *http.Request) {
		enabled, running := dockerAPIState()
		apiReply(w, nil, map[string]any{"socket": dockerSock, "enabled": enabled, "running": running})
	})
	a.post("/api/v1/docker-api/{action}", "admin", func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch action := r.PathValue("action"); action {
		case "enable":
			err = dockerAPIEnable()
		case "disable":
			err = dockerAPIDisable()
		default:
			err = errNotFound(fmt.Sprintf("unknown action %q (enable or disable)", action))
		}
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		enabled, running := dockerAPIState()
		apiReply(w, nil, map[string]any{"socket": dockerSock, "enabled": enabled, "running": running})
	})
}

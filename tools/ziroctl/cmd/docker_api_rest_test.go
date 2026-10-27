package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The socket is root on the host: reading its state needs a token, changing it needs admin.
func TestDockerAPIRoutesRBAC(t *testing.T) {
	var role string
	api := newAPIHarness(t, registerDockerAPIRoutes)
	do := func(method, path string) int { return api.code(role, method, path, "") }
	for _, r := range []string{"viewer", "operator"} {
		role = r
		if code := do("GET", "/api/v1/docker-api"); code != http.StatusOK {
			t.Errorf("%s GET: %d", r, code)
		}
		for _, a := range []string{"enable", "disable"} {
			if code := do("POST", "/api/v1/docker-api/"+a); code != http.StatusForbidden {
				t.Errorf("%s %s: %d, want 403", r, a, code)
			}
		}
	}
	role = "admin"
	if code := do("POST", "/api/v1/docker-api/restart"); code != http.StatusNotFound {
		t.Errorf("an unknown action: %d, want 404", code)
	}
	if code := do("GET", "/api/v1/docker-api"); code != http.StatusOK {
		t.Errorf("admin GET: %d", code)
	}
	if code := newAPIHarness(t, registerDockerAPIRoutes).code("", "GET", "/api/v1/docker-api", ""); code == http.StatusOK {
		t.Error("an unauthenticated read was served")
	}
}

func TestDockerAPIEnabledReadsTheServiceSwitch(t *testing.T) {
	dir := t.TempDir()
	if dockerAPIEnabled(dir) {
		t.Fatal("enabled without a state file")
	}
	for state, want := range map[string]bool{"enabled\n": true, "enabled": true, "disabled\n": false, "": false, "garbage": false} {
		os.WriteFile(filepath.Join(dir, dockerService), []byte(state), 0o644)
		if got := dockerAPIEnabled(dir); got != want {
			t.Errorf("%q: %v, want %v", state, got, want)
		}
	}
}

// The audit entry names who opened the connection; without a peer it says the socket, never "root".
func TestDockerAPIAuditNamesThePeer(t *testing.T) {
	f := &fakeDocker{}
	h := f.api().handler()
	r := post(h, "POST", "/containers/web/start", "")
	if r.Code != 204 || len(f.actors) != 1 || f.actors[0] != "docker-socket" {
		t.Fatalf("no peer: %d %q", r.Code, f.actors)
	}
	req := httptest.NewRequest("POST", "/containers/web/stop", nil)
	req = req.WithContext(context.WithValue(req.Context(), dockerPeerKey{}, "uid:1000 pid:4242"))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(f.actors) != 2 || f.actors[1] != "uid:1000 pid:4242" {
		t.Fatalf("with a peer: %q", f.actors)
	}
}

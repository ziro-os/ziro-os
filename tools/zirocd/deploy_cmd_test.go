package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziro-os/ziro-os/sdk/api"
)

func TestDefaultName(t *testing.T) {
	for in, want := range map[string]string{"/w/My_Next.App": "my-next-app", "/w/site": "site"} {
		if got := defaultName(in); got != want {
			t.Errorf("defaultName(%q) = %q, want %q", in, got, want)
		}
	}
	f := filepath.Join(t.TempDir(), "index.html")
	os.WriteFile(f, nil, 0644)
	if got := defaultName(f); got == "index-html" || got == "" {
		t.Errorf("a file is named after its folder, got %q", got)
	}
}

// zirocd deploy packs the directory, pushes it with the token, follows the log and checks the
// build went live.
func TestDeployCommand(t *testing.T) {
	status := "live"
	var spec api.SourceSpec
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v1/deployments/site/source":
			mr, _ := r.MultipartReader()
			p, _ := mr.NextPart()
			json.NewDecoder(p).Decode(&spec)
			json.NewEncoder(w).Encode(map[string]string{"id": "b1"})
		case "/api/v1/deployments/site/builds/b1/log":
			io.WriteString(w, "building\n")
		case "/api/v1/deployments/site":
			json.NewEncoder(w).Encode(map[string]any{"url": "http://site.example", "builds": []map[string]string{{"id": "b1", "status": status}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "site")
	os.Mkdir(dir, 0755)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0644)
	tok := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tok, []byte("dep-token\n"), 0600)

	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"deploy"}, args...))
		return root.Execute()
	}
	if err := run(dir, "--host", srv.URL, "--token-file", tok, "--port", "8080", "--env", "A=b"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer dep-token" || spec.Port != 8080 || spec.Env["A"] != "b" || len(spec.SourceSHA256) != 64 {
		t.Errorf("auth %q spec %+v", auth, spec)
	}
	status = "failed"
	if err := run(dir, "--host", srv.URL, "--token-file", tok); err == nil {
		t.Error("a failed build exited 0")
	}
	if err := run(dir, "--host", srv.URL); err == nil {
		t.Error("deployed without a token")
	}
	if err := run(dir, "--host", srv.URL, "--token-file", tok, "--env", "BAD"); err == nil {
		t.Error("accepted --env without =")
	}
}

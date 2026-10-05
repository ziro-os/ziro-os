package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uploadBody(t *testing.T, spec string, archive []byte, parts ...string) (*bytes.Buffer, string) {
	t.Helper()
	if len(parts) == 0 {
		parts = []string{"spec", "source"}
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		w, _ := mw.CreateFormField(p)
		if p == "spec" {
			io.WriteString(w, spec)
		} else {
			w.Write(archive)
		}
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestDeployUpload(t *testing.T) {
	stubApps(t)
	oldState, oldTok, oldMax := deployStateDir, deployTokenDir, deployUploadMax
	deployStateDir, deployTokenDir = t.TempDir(), t.TempDir()
	defer func() { deployStateDir, deployTokenDir, deployUploadMax = oldState, oldTok, oldMax }()

	var raw bytes.Buffer
	if _, err := io.Copy(&raw, mkTarGz(t, tarEnt{name: "index.html", body: "hi"})); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw.Bytes())
	sha := hex.EncodeToString(sum[:])

	dd := &deployDaemon{queue: make(chan buildJob, 4)}
	post := func(app, spec string, archive []byte, parts ...string) *httptest.ResponseRecorder {
		body, ct := uploadBody(t, spec, archive, parts...)
		r := httptest.NewRequest("POST", "/v1/deployments/"+app+"/source", body)
		r.Header.Set("Content-Type", ct)
		r.SetPathValue("app", app)
		w := httptest.NewRecorder()
		dd.handleUpload(w, r)
		return w
	}

	// A valid push queues a build and stores the archive 0600.
	if w := post("site", `{"source_sha256":"`+sha+`","port":8080}`, raw.Bytes()); w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	if fi, err := os.Stat(uploadArchive("site")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("archive: %v %v", fi, err)
	}
	d, _ := loadDeployment("site")
	if d.Source != deploySourceUpload || d.Repo != "" || len(dd.queue) != 1 {
		t.Fatalf("deployment %+v, queued %d", d, len(dd.queue))
	}

	// The build unpacks it.
	src := filepath.Join(t.TempDir(), "src")
	b := &Build{}
	if err := fetchSource(context.Background(), d, b, "", src, io.Discard, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(src, "index.html")); string(got) != "hi" || !strings.HasPrefix(b.Commit, "sha256:"+sha[:12]) {
		t.Errorf("unpacked %q, commit %q", got, b.Commit)
	}

	// A deployer can't move traffic.
	if w := post("site", `{"source_sha256":"`+sha+`","expose":"evil.example.com"}`, raw.Bytes()); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "admin") {
		t.Errorf("expose by a deployer: %d %s", w.Code, w.Body)
	}
	bad := map[string]struct {
		spec     string
		archive  []byte
		parts    []string
		wantCode int
	}{
		"wrong digest":  {`{"source_sha256":"` + strings.Repeat("0", 64) + `"}`, raw.Bytes(), nil, 400},
		"no digest":     {`{}`, raw.Bytes(), nil, 400},
		"unknown field": {`{"source_sha256":"` + sha + `","repo":"https://github.com/a/b","x":1}`, raw.Bytes(), nil, 400},
		"source first":  {`{"source_sha256":"` + sha + `"}`, raw.Bytes(), []string{"source", "spec"}, 400},
		"bad env":       {`{"source_sha256":"` + sha + `","env":{"ZIRO_X":"1"}}`, raw.Bytes(), nil, 400},
	}
	for name, c := range bad {
		if w := post("other", c.spec, c.archive, c.parts...); w.Code != c.wantCode {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body, c.wantCode)
		}
	}
	if _, err := os.Stat(uploadArchive("other")); err == nil {
		t.Error("a refused upload left an archive")
	}

	// Too large is refused while streaming.
	deployUploadMax = 10
	if w := post("big", `{"source_sha256":"`+sha+`"}`, raw.Bytes()); w.Code < 400 {
		t.Errorf("oversize upload: %d", w.Code)
	}
}

// A deployer pushes and rolls back; creating from a repo, removing and day-to-day changes stay
// with admin and operator. (No ziroctld runs here, so an allowed call answers 503, not 403.)
func TestDeployerRole(t *testing.T) {
	api := newAPIHarness(t, registerDeployRoutes)
	tok, _, err := createAPIToken("t-deployer", "deployer", 0)
	if err != nil {
		t.Fatal(err)
	}
	api.tok["deployer"] = tok
	for _, c := range []struct {
		role, m, p string
		allowed    bool
	}{
		{"viewer", "POST", "/api/v1/deployments/a/source", false},
		{"viewer", "POST", "/api/v1/deployments/a/rollback", false},
		{"deployer", "POST", "/api/v1/deployments/a/source", true},
		{"deployer", "POST", "/api/v1/deployments/a/redeploy", true},
		{"deployer", "POST", "/api/v1/deployments/a/rollback", true},
		{"deployer", "GET", "/api/v1/deployments", true},
		{"deployer", "POST", "/api/v1/deployments", false},
		{"deployer", "DELETE", "/api/v1/deployments/a", false},
		{"operator", "POST", "/api/v1/deployments/a/source", true},
	} {
		code := api.code(c.role, c.m, c.p, `{}`)
		if c.allowed != (code != http.StatusForbidden) {
			t.Errorf("%s %s %s: %d, allowed=%v", c.role, c.m, c.p, code, c.allowed)
		}
	}
}

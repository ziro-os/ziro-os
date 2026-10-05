package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// ziroctld: the deploy daemon (ziroctl run as /usr/bin/ziroctld, or `ziroctl deploy serve`).
// It owns the build queue and the deployment records, and answers on a root-only unix socket;
// `ziroctl deploy` and the REST API (/api/v1/deployments) are its clients. Builds run one at a
// time (a build may use the whole machine), in the order they were asked for.

var deploySocket = "/run/ziro/ziroctld.sock"

// DeployRequest creates or updates a deployment and builds it.
type DeployRequest struct {
	Deployment
	SecretValues map[string]string `json:"secret_values,omitempty"` // input secret values (kept by the app)
	GitToken     string            `json:"git_token,omitempty"`     // stored 0600, used through GIT_ASKPASS
	SourceSHA256 string            `json:"source_sha256,omitempty"` // upload: hex SHA-256 of the archive
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

type buildJob struct {
	app, build string
	secrets    map[string]string
}

type deployDaemon struct {
	queue chan buildJob
	hooks hookDeliveries
}

func runDeployDaemon(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(deploySocket), 0755); err != nil {
		return err
	}
	_ = os.Remove(deploySocket)
	l, err := net.Listen("unix", deploySocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(deploySocket, 0600); err != nil { // root only: a deploy runs code
		l.Close()
		return err
	}
	dd := &deployDaemon{queue: make(chan buildJob, 64)}
	dd.recover()
	go dd.worker(ctx)
	srv := &http.Server{Handler: dd.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	fmt.Printf("ziroctld listening on %s\n", deploySocket)
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// recover marks builds a restart interrupted as failed (their work dirs are gone with them).
func (dd *deployDaemon) recover() {
	for _, d := range listDeployments() {
		for _, b := range listBuilds(d.Name) {
			if !b.done() {
				b.Status, b.Error, b.Finished = "failed", "interrupted: ziroctld restarted", time.Now().UTC()
				_ = saveBuild(b)
			}
		}
		_ = os.RemoveAll(filepath.Join(deployDir(d.Name), "work"))
	}
}

func (dd *deployDaemon) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-dd.queue:
			d, err1 := loadDeployment(j.app)
			b, err2 := loadBuild(j.app, j.build)
			if err1 != nil || err2 != nil {
				continue
			}
			if err := runBuild(ctx, d, b, j.secrets); err != nil {
				fmt.Printf("[%s] %s %s failed: %v\n", time.Now().Format("15:04:05"), j.app, j.build, err)
			}
		}
	}
}

// enqueue records a new build of d and queues it.
func (dd *deployDaemon) enqueue(d *Deployment, b *Build, secrets map[string]string) (*Build, error) {
	deployMu.Lock()
	d.Next++
	b.ID, b.App, b.Status, b.Queued = "b"+strconv.Itoa(d.Next), d.Name, "queued", time.Now().UTC()
	if b.Ref == "" {
		b.Ref = d.Ref
	}
	err := saveDeployment(d)
	if err == nil {
		err = saveBuild(b)
	}
	deployMu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case dd.queue <- buildJob{d.Name, b.ID, secrets}:
		return b, nil
	default:
		b.Status, b.Error = "failed", "the build queue is full; try again later"
		_ = saveBuild(b)
		return nil, errors.New(b.Error)
	}
}

func (dd *deployDaemon) routes() *http.ServeMux {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, err error, v any) { apiReply(w, err, v) }
	mux.HandleFunc("GET /v1/deployments", func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		for _, d := range listDeployments() {
			row := map[string]any{"deployment": d, "url": deploymentURL(d)}
			if bs := listBuilds(d.Name); len(bs) > 0 {
				row["latest"] = bs[0]
			}
			out = append(out, row)
		}
		reply(w, nil, out)
	})
	mux.HandleFunc("POST /v1/deployments", func(w http.ResponseWriter, r *http.Request) {
		var req DeployRequest
		if err := decodeStrict(w, r, &req, 1<<20); err != nil {
			reply(w, err, nil)
			return
		}
		b, err := dd.create(req)
		reply(w, err, b)
	})
	mux.HandleFunc("POST /v1/deployments/{app}/source", dd.handleUpload)
	mux.HandleFunc("GET /v1/deployments/{app}", func(w http.ResponseWriter, r *http.Request) {
		d, err := loadDeployment(r.PathValue("app"))
		if err != nil {
			reply(w, err, nil)
			return
		}
		reply(w, nil, map[string]any{"deployment": d, "url": deploymentURL(d), "builds": listBuilds(d.Name)})
	})
	mux.HandleFunc("POST /v1/deployments/{app}/redeploy", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ref string `json:"ref,omitempty"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil && !errors.Is(err, io.EOF) {
			reply(w, err, nil)
			return
		}
		d, err := loadDeployment(r.PathValue("app"))
		if err == nil && req.Ref != "" && d.Source == deploySourceUpload {
			err = errors.New("an uploaded deployment has no branch (upload again to change it)")
		}
		if err == nil && req.Ref != "" && (!gitRefRe.MatchString(req.Ref) || strings.Contains(req.Ref, "..")) {
			err = fmt.Errorf("invalid branch or tag %q", req.Ref)
		}
		if err != nil {
			reply(w, err, nil)
			return
		}
		b, err := dd.enqueue(d, &Build{Ref: req.Ref}, nil)
		reply(w, err, b)
	})
	mux.HandleFunc("POST /v1/deployments/{app}/rollback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Build string `json:"build,omitempty"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil && !errors.Is(err, io.EOF) {
			reply(w, err, nil)
			return
		}
		b, err := dd.rollback(r.PathValue("app"), req.Build)
		reply(w, err, b)
	})
	mux.HandleFunc("GET /v1/deployments/{app}/builds/{id}/log", func(w http.ResponseWriter, r *http.Request) {
		streamBuildLog(w, r, r.PathValue("app"), r.PathValue("id"), r.URL.Query().Get("follow") == "true")
	})
	mux.HandleFunc("POST /v1/hooks/deploy/{app}", dd.handleHook)
	mux.HandleFunc("GET /v1/deployments/{app}/hook", func(w http.ResponseWriter, r *http.Request) {
		if _, err := loadDeployment(r.PathValue("app")); err != nil {
			reply(w, err, nil)
			return
		}
		s, err := hookSecret(r.PathValue("app"), r.URL.Query().Get("rotate") == "true")
		reply(w, err, map[string]string{"path": "/api/v1/hooks/deploy/" + r.PathValue("app"), "secret": s})
	})
	// A builder node's agent asks for the build the master assigned to it (no release here).
	mux.HandleFunc("POST /v1/build-task", func(w http.ResponseWriter, r *http.Request) {
		var t ClusterBuild
		if err := decodeStrict(w, r, &t, 64<<10); err != nil {
			reply(w, err, nil)
			return
		}
		reply(w, nil, buildTask(r.Context(), t))
	})
	mux.HandleFunc("DELETE /v1/deployments/{app}", func(w http.ResponseWriter, r *http.Request) {
		reply(w, removeDeployment(r.PathValue("app"), r.URL.Query().Get("purge") == "true"), map[string]string{"removed": r.PathValue("app")})
	})
	return mux
}

// handleUpload is POST /v1/deployments/{app}/source: a multipart body with the deployment spec
// (a DeployRequest as JSON, part "spec") followed by the source (a .tar.gz, part "source"). The
// spec comes first so a bad one is refused before the archive is read; the archive is streamed to
// disk (never held in memory), checked against the spec's source_sha256 and then replaces the
// app's current source. It is unpacked, safely, when the build runs.
func (dd *deployDaemon) handleUpload(w http.ResponseWriter, r *http.Request) {
	app := r.PathValue("app")
	r.Body = http.MaxBytesReader(w, r.Body, deployUploadMax+(64<<10))
	mr, err := r.MultipartReader()
	if err != nil {
		apiReply(w, fmt.Errorf("multipart body expected: %w", err), nil)
		return
	}
	var req DeployRequest
	if err := nextPart(mr, "spec", func(p io.Reader) error {
		dec := json.NewDecoder(io.LimitReader(p, 64<<10))
		dec.DisallowUnknownFields()
		return dec.Decode(&req)
	}); err != nil {
		apiReply(w, err, nil)
		return
	}
	req.Name, req.Source, req.Repo, req.Ref, req.GitToken = app, deploySourceUpload, "", "", ""
	// Pushing source is a deployer's job (a CI token); where traffic goes stays an admin's, so
	// the gateway name, TLS mode and host port are the deployment's current ones.
	var cur Deployment
	if c, err := loadDeployment(app); err == nil {
		cur = *c
	}
	if (req.Expose != "" && req.Expose != cur.Expose) || (req.ExposeTLS != "" && req.ExposeTLS != cur.ExposeTLS) ||
		(req.Publish != 0 && req.Publish != cur.Publish) {
		apiReply(w, errors.New("expose, expose_tls and publish need an admin token (ziroctl deploy / POST /api/v1/deployments)"), nil)
		return
	}
	req.Expose, req.ExposeTLS, req.Publish = cur.Expose, cur.ExposeTLS, cur.Publish
	if err := validateDeployment(&req.Deployment); err != nil {
		apiReply(w, err, nil)
		return
	}
	if !sha256Re.MatchString(req.SourceSHA256) {
		apiReply(w, errors.New("source_sha256: the archive's hex SHA-256 is required"), nil)
		return
	}
	if err := nextPart(mr, "source", func(p io.Reader) error { return storeUpload(app, p, req.SourceSHA256) }); err != nil {
		apiReply(w, err, nil)
		return
	}
	b, err := dd.create(req)
	apiReply(w, err, b)
}

// nextPart reads the next multipart part, which must be called name.
func nextPart(mr *multipart.Reader, name string, read func(io.Reader) error) error {
	p, err := mr.NextPart()
	if err != nil || p.FormName() != name {
		return fmt.Errorf("multipart part %q expected", name)
	}
	defer p.Close()
	return read(p)
}

// storeUpload streams the archive to <app>/source.tar.gz (0600) if it has the given SHA-256.
func storeUpload(app string, r io.Reader, want string) error {
	if err := os.MkdirAll(deployDir(app), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(deployDir(app), "upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // a no-op once renamed
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(r, deployUploadMax+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if fi, _ := os.Stat(f.Name()); fi != nil && fi.Size() > deployUploadMax {
		return fmt.Errorf("the archive is larger than %d MiB", deployUploadMax>>20)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("the archive doesn't match source_sha256 (upload corrupted)")
	}
	deployMu.Lock()
	defer deployMu.Unlock()
	return os.Rename(f.Name(), uploadArchive(app))
}

// create stores (or updates) a deployment from a request and queues its first build.
func (dd *deployDaemon) create(req DeployRequest) (*Build, error) {
	spec := req.Deployment
	if err := validateDeployment(&spec); err != nil {
		return nil, err
	}
	if spec.Source == deploySourceUpload {
		if _, err := os.Stat(uploadArchive(spec.Name)); err != nil {
			return nil, errors.New("no uploaded source (POST /v1/deployments/{app}/source)")
		}
	}
	for k, v := range req.SecretValues {
		if !slices.Contains(spec.Secrets, k) {
			spec.Secrets = append(spec.Secrets, k)
		}
		if err := schema.ValidSecretValue(v); err != nil {
			return nil, fmt.Errorf("secret %s: %w", k, err)
		}
	}
	if err := schema.ValidSecretValue(req.GitToken); err != nil {
		return nil, fmt.Errorf("git token: %w", err)
	}
	d, err := loadDeployment(spec.Name)
	if err != nil {
		var nf errNotFound
		if !errors.As(err, &nf) {
			return nil, err
		}
		if in, err := loadAppInstance(spec.Name); err == nil { // a catalog app has this name
			return nil, fmt.Errorf("%s is already a deployed %s app (pick another --name)", spec.Name, in.App)
		}
		d = &Deployment{Name: spec.Name, Created: time.Now().UTC()}
	}
	live, next, publish, created := d.Live, d.Next, d.Publish, d.Created
	*d = spec
	d.Live, d.Next, d.Created = live, next, created
	if d.Publish == 0 {
		d.Publish = publish // keep the host port an app already has
	}
	if req.GitToken != "" {
		if err := os.MkdirAll(deployTokenDir, 0700); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(filepath.Join(deployTokenDir, d.Name+".token"), []byte(req.GitToken), 0600); err != nil {
			return nil, err
		}
	}
	return dd.enqueue(d, &Build{}, req.SecretValues)
}

// rollback releases an earlier build's image again (no rebuild): the given one, or the newest
// finished build before the live one that has an image.
func (dd *deployDaemon) rollback(app, id string) (*Build, error) {
	d, err := loadDeployment(app)
	if err != nil {
		return nil, err
	}
	var target *Build
	if id != "" {
		if target, err = loadBuild(app, id); err != nil {
			return nil, err
		}
	} else {
		for _, b := range listBuilds(app) {
			if b.ID != d.Live && b.Image != "" && (b.Status == "superseded" || b.Status == "live") && buildNum(b.ID) < buildNum(d.Live) {
				target = b
				break
			}
		}
	}
	if target == nil || target.Image == "" {
		return nil, errors.New("no earlier build to roll back to")
	}
	return dd.enqueue(d, &Build{Ref: target.Ref, Commit: target.Commit, Kind: target.Kind, Image: target.Image, Rollback: true}, nil)
}

// removeDeployment removes the app and the deployment's records; purge also deletes the app's
// data and secrets.
func removeDeployment(app string, purge bool) error {
	d, err := loadDeployment(app)
	if err != nil {
		return err
	}
	if _, err := loadAppInstance(app); err == nil {
		if err := removeAppInstance(app, purge); err != nil {
			return err
		}
	}
	deployMu.Lock()
	defer deployMu.Unlock()
	for _, b := range listBuilds(app) {
		if ref, _, ok := strings.Cut(b.Image, "@"); ok {
			_, _ = runNerdctl("rmi", ref)
		}
	}
	_ = os.Remove(filepath.Join(deployTokenDir, d.Name+".token"))
	return os.RemoveAll(deployDir(d.Name))
}

// streamBuildLog writes a build's log; follow keeps streaming until the build finishes.
func streamBuildLog(w http.ResponseWriter, r *http.Request, app, id string, follow bool) {
	b, err := loadBuild(app, id)
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	f, err := os.Open(buildLog(app, b.ID))
	for follow && os.IsNotExist(err) && !b.done() { // queued: the log starts with the build
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		f, err = os.Open(buildLog(app, b.ID))
		if cur, lerr := loadBuild(app, id); lerr == nil {
			b = cur
		}
	}
	if err != nil {
		apiReply(w, errNotFound("no log yet"), nil)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if rerr == nil {
			continue
		}
		if !follow {
			return
		}
		if cur, err := loadBuild(app, id); err != nil || cur.done() {
			_, _ = io.Copy(w, f) // the last lines written before it finished
			fmt.Fprintf(w, "==> %s\n", cur.Status)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ---- client (ziroctl deploy, the REST API) ----

var deployHTTP = &http.Client{Transport: &http.Transport{
	DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", deploySocket)
	},
}}

// deployCall sends a request to ziroctld and decodes the JSON reply into out.
func deployCall(method, path string, body, out any) error {
	return deployCallTimeout(method, path, body, out, 0)
}

// deployCallTimeout is deployCall bounded by timeout (0 = none).
func deployCallTimeout(method, path string, body, out any, timeout time.Duration) error {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	resp, err := deployRawCtx(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("ziroctld: HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func deployRaw(method, path string, body any) (*http.Response, error) {
	return deployRawCtx(context.Background(), method, path, body)
}

func deployRawCtx(ctx context.Context, method, path string, body any) (*http.Response, error) {
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
		req, err := http.NewRequestWithContext(ctx, method, "http://ziroctld"+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return deployHTTP.Do(req)
	}
	resp, err := do()
	if err == nil {
		return resp, nil
	}
	// ziroctld is a supervised service of the builder module: if it is down (crashed, or not up
	// yet after a boot), start it once and retry instead of sending the operator away.
	if serr := startDeployDaemon(ctx); serr != nil {
		return nil, serr
	}
	if resp, err = do(); err != nil {
		return nil, fmt.Errorf("ziroctld isn't answering on %s (log: /var/log/ziroctld.log): %w", deploySocket, err)
	}
	return resp, nil
}

// startDeployDaemon starts the ziroctld service and waits (up to 10s) for its socket.
func startDeployDaemon(ctx context.Context) error {
	if _, err := loadServiceDef("ziroctld"); err != nil {
		return errors.New("ziroctld isn't running (enable it with: ziroctl module enable builder)")
	}
	if err := startModuleService("ziroctld"); err != nil && !strings.Contains(err.Error(), "already running") {
		return fmt.Errorf("ziroctld isn't running and could not be started: %w (log: /var/log/ziroctld.log)", err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if c, err := net.DialTimeout("unix", deploySocket, time.Second); err == nil {
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

// serveDeployDaemon runs ziroctld until SIGTERM.
func serveDeployDaemon() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return runDeployDaemon(ctx)
}

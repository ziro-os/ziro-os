package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The build pipeline: fetch the repository (shallow, https only), detect how to build it, build
// the image with BuildKit (buildkitd's containerd worker, so the image is in the host's image
// store at once), then release it as an app (apps.go: the same hardened containers, secrets and
// gateway routes as catalog apps) and check it answers before it goes live. A release that
// fails its check puts the previous build back.

var (
	buildkitAddr     = "unix:///run/buildkit/buildkitd.sock"
	deployFetchLimit = 30 * time.Minute
	deployBuildLimit = 60 * time.Minute
	deployCheckLimit = 2 * time.Minute
	// deployExec runs git and buildctl (a variable so tests can stub them).
	deployExec = func(ctx context.Context, log io.Writer, env []string, name string, args ...string) error {
		// deepcode ignore CommandInjection: fixed binaries; every argument is validated (URL, ref, paths) and passed as argv, no shell
		c := exec.CommandContext(ctx, name, args...)
		c.Env, c.Stdout, c.Stderr = env, log, log
		return c.Run()
	}
	deployCheck  = checkHTTP
	digestLineRe = regexp.MustCompile(`"containerimage\.digest":\s*"(sha256:[0-9a-f]{64})"`)
)

// runBuild takes a queued build to live or failed. secrets are input secret values given with
// this deploy (kept by the app afterwards).
func runBuild(ctx context.Context, d *Deployment, b *Build, secrets map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(buildLog(d.Name, b.ID)), 0700); err != nil {
		return err
	}
	logF, err := os.OpenFile(buildLog(d.Name, b.ID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logF.Close()
	logf := func(format string, a ...any) { fmt.Fprintf(logF, "==> "+format+"\n", a...) }
	set := func(status, msg string) {
		deployMu.Lock()
		defer deployMu.Unlock()
		b.Status, b.Error = status, msg
		if status == "building" && b.Started.IsZero() {
			b.Started = time.Now().UTC()
		}
		if b.done() {
			b.Finished = time.Now().UTC()
		}
		_ = saveBuild(b)
	}
	fail := func(err error) error {
		logf("failed: %v", err)
		set("failed", err.Error())
		return err
	}

	set("building", "")
	var plan BuildPlan
	if !b.Rollback {
		build := fetchAndBuild
		if clusterNodeID() != "" { // a master: build on a builder node, run on the cluster
			build = buildOnCluster
		}
		if plan, err = build(ctx, d, b, logF, logf); err != nil {
			return fail(err)
		}
	}
	set("releasing", "")
	prev, _ := loadBuild(d.Name, d.Live)
	logf("releasing %s", b.Image)
	if err := releaseBuild(d, b, plan, secrets); err != nil {
		if prev != nil && prev.ID != b.ID {
			logf("putting %s back", prev.ID)
			if rerr := releaseBuild(d, prev, BuildPlan{}, nil); rerr != nil {
				logf("restoring %s failed too: %v", prev.ID, rerr)
			}
		}
		return fail(err)
	}

	deployMu.Lock()
	if prev != nil && prev.ID != b.ID && prev.Status == "live" {
		prev.Status = "superseded"
		_ = saveBuild(prev)
	}
	d.Live = b.ID
	err = updateDeployment(d.Name, func(cur *Deployment) { cur.Live = b.ID })
	deployMu.Unlock()
	if err != nil {
		return fail(err)
	}
	set("live", "")
	logf("live: %s", deploymentURL(d))
	pruneBuilds(d)
	return nil
}

// fetchAndBuild clones the commit, detects the build and builds the image.
func fetchAndBuild(ctx context.Context, d *Deployment, b *Build, log io.Writer, logf func(string, ...any)) (BuildPlan, error) {
	work := filepath.Join(deployDir(d.Name), "work", b.ID)
	defer os.RemoveAll(work)
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(work, 0700); err != nil {
		return BuildPlan{}, err
	}
	env, err := gitEnv(d.Name, work)
	if err != nil {
		return BuildPlan{}, err
	}
	logf("fetching %s %s", d.Repo, b.Ref)
	args := []string{"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "clone", "--depth", "1",
		"--single-branch", "--no-tags", "--recurse-submodules=no"}
	if b.Ref != "" {
		args = append(args, "--branch", b.Ref)
	}
	fctx, cancel := context.WithTimeout(ctx, deployFetchLimit)
	defer cancel()
	if err := deployExec(fctx, log, env, "git", append(args, "--", d.Repo, src)...); err != nil {
		return BuildPlan{}, fmt.Errorf("git clone: %w", err)
	}
	var head strings.Builder
	if err := deployExec(fctx, &head, env, "git", "-C", src, "rev-parse", "HEAD"); err == nil {
		b.Commit = strings.TrimSpace(head.String())
	}
	ctxDir := filepath.Join(src, filepath.FromSlash(d.Path))
	root, err := os.OpenRoot(ctxDir)
	if err != nil {
		return BuildPlan{}, fmt.Errorf("path %q: %w", d.Path, err)
	}
	plan, err := detectBuild(root)
	root.Close()
	if err != nil {
		return plan, err
	}
	b.Kind = plan.Kind
	logf("commit %s, build: %s, port %d", b.Commit, plan.Kind, plan.Port)

	dfDir, dfName := ctxDir, plan.File
	if plan.Dockerfile != "" {
		dfDir, dfName = filepath.Join(work, "dockerfile"), "Dockerfile"
		if err := os.MkdirAll(dfDir, 0700); err != nil {
			return plan, err
		}
		if err := os.WriteFile(filepath.Join(dfDir, dfName), []byte(plan.Dockerfile), 0600); err != nil {
			return plan, err
		}
		fmt.Fprintf(log, "--- generated Dockerfile ---\n%s----------------------------\n", plan.Dockerfile)
	}
	name := "ziro.local/" + d.Name + ":" + b.ID
	meta := filepath.Join(work, "metadata.json")
	logf("building %s", name)
	bctx, bcancel := context.WithTimeout(ctx, deployBuildLimit)
	defer bcancel()
	if err := deployExec(bctx, log, os.Environ(), "buildctl", "--addr", buildkitAddr, "build", "--progress", "plain",
		"--frontend", "dockerfile.v0", "--local", "context="+ctxDir, "--local", "dockerfile="+dfDir, "--opt", "filename="+dfName,
		"--output", "type=image,name="+name+",unpack=true", "--metadata-file", meta); err != nil {
		return plan, fmt.Errorf("build: %w (is the builder plugin enabled? ziroctl module enable builder)", err)
	}
	raw, err := os.ReadFile(meta)
	m := digestLineRe.FindSubmatch(raw)
	if err != nil || m == nil {
		return plan, errors.New("build: no image digest in buildctl's metadata")
	}
	b.Image = name + "@" + string(m[1])
	return plan, nil
}

// gitEnv is git's environment: no prompts, no system or user config, and the deployment's token
// (if any) through GIT_ASKPASS, never in the URL or argv.
func gitEnv(app, work string) ([]string, error) {
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + work, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	tok, err := os.ReadFile(filepath.Join(deployTokenDir, app+".token"))
	if os.IsNotExist(err) {
		return env, nil
	}
	if err != nil {
		return nil, err
	}
	askpass := filepath.Join(work, "askpass")
	script := "#!/bin/sh\ncase \"$1\" in Username*) echo x-access-token ;; *) printf '%s\\n' \"$ZIRO_GIT_TOKEN\" ;; esac\n"
	if err := os.WriteFile(askpass, []byte(script), 0700); err != nil {
		return nil, err
	}
	return append(env, "GIT_ASKPASS="+askpass, "ZIRO_GIT_TOKEN="+strings.TrimSpace(string(tok))), nil
}

// releaseBuild runs b's image as the app d.Name (replacing the running build) and checks it.
func releaseBuild(d *Deployment, b *Build, plan BuildPlan, secrets map[string]string) error {
	if !localImageRe.MatchString(b.Image) {
		return fmt.Errorf("build %s has no image", b.ID)
	}
	port := d.Port
	if port == 0 {
		port = plan.Port
	}
	if port == 0 { // a rollback: the port the live app uses
		if in, err := loadAppInstance(d.Name); err == nil && len(in.Def.Components) > 0 {
			port = in.Def.Components[0].Port
		}
	}
	if port == 0 {
		port = 8080
	}
	env := map[string]string{"PORT": strconv.Itoa(port)}
	maps.Copy(env, plan.Env) // ziro.yaml
	maps.Copy(env, d.Env)    // the deploy's --env wins
	if plan.Kind == "" {     // a rollback keeps the env it had
		if in, err := loadAppInstance(d.Name); err == nil && len(in.Def.Components) > 0 {
			env = in.Def.Components[0].Env
		}
	}
	def := AppDef{Schema: 1, Name: d.Name, Description: "deployed from " + d.Repo, Default: b.ID,
		Versions:   map[string]schema.AppVersion{b.ID: {Images: map[string]string{"web": b.Image}}},
		Components: []AppComponent{{Name: "web", Port: port, Env: env, Secrets: d.Secrets, Resources: d.Resources}},
		Outputs:    map[string]string{"url": "http://{{host}}:{{port}}/", "host": "{{host}}", "port": "{{port}}"},
		Secrets:    map[string]string{}}
	for _, s := range d.Secrets {
		def.Secrets[s] = "input"
	}
	if err := def.Validate(); err != nil {
		return err
	}
	if clusterNodeID() != "" { // cluster: replicas on nodes of the image's arch, checked by the rollout
		if err := deployAppDef(def, b.ID, appDeployOpts{Name: d.Name, NewVersion: true, Replicas: d.Replicas, Publish: d.Publish,
			Expose: d.Expose, ExposeTLS: d.ExposeTLS, Secrets: secrets, Arch: b.Arch, ImageNode: b.Node}); err != nil {
			return err
		}
		return waitRollout(d.Name, 2*deployCheckLimit)
	}
	if d.Publish == 0 {
		p, err := freeLocalPort()
		if err != nil {
			return err
		}
		d.Publish = p // kept for every later build, even if this release fails
		deployMu.Lock()
		err = updateDeployment(d.Name, func(cur *Deployment) { cur.Publish = p })
		deployMu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := deployAppDef(def, b.ID, appDeployOpts{Name: d.Name, Local: true, NewVersion: true, Publish: d.Publish,
		Bind: "127.0.0.1", Expose: d.Expose, ExposeTLS: d.ExposeTLS, Secrets: secrets}); err != nil {
		return err
	}
	health := plan.Health
	if health == "" {
		health = "/"
	}
	return deployCheck(fmt.Sprintf("http://127.0.0.1:%d%s", d.Publish, health), deployCheckLimit)
}

// updateDeployment changes one field of the stored deployment (the spec may have been updated
// while a build ran: never write back a stale copy). The caller holds deployMu.
func updateDeployment(app string, change func(*Deployment)) error {
	cur, err := loadDeployment(app)
	if err != nil {
		return err
	}
	change(cur)
	return saveDeployment(cur)
}

// checkHTTP waits until url answers with anything but a server error.
func checkHTTP(url string, limit time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(limit)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("not answering on %s after %s: %v", url, limit, last)
}

// freeLocalPort picks a free port in 20000-29999 for an app's 127.0.0.1 publish.
func freeLocalPort() (int, error) {
	used := map[int]bool{}
	for _, d := range listDeployments() {
		used[d.Publish] = true
	}
	for p := 20000; p < 30000; p++ {
		if used[p] {
			continue
		}
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			l.Close()
			return p, nil
		}
	}
	return 0, errors.New("no free port in 20000-29999")
}

func deploymentURL(d *Deployment) string {
	if d.Expose != "" {
		if d.ExposeTLS == "off" {
			return "http://" + d.Expose
		}
		return "https://" + d.Expose
	}
	return fmt.Sprintf("http://127.0.0.1:%d", d.Publish)
}

// localBuildImage resolves a ziro.local/<app>:<build>@sha256 reference to the local image name,
// after checking that the image under that name still has the pinned digest (nothing replaced
// it since the build).
func localBuildImage(ref string) (string, error) {
	if !localImageRe.MatchString(ref) {
		return "", fmt.Errorf("invalid local image %q", ref)
	}
	name, digest, _ := strings.Cut(ref, "@")
	out, err := runNerdctl("images", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return "", fmt.Errorf("list images: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var img struct{ Repository, Tag, Digest string }
		if json.Unmarshal([]byte(line), &img) == nil && img.Repository+":"+img.Tag == name {
			if img.Digest != digest {
				return "", fmt.Errorf("%s is %s, not the built %s", name, img.Digest, digest)
			}
			return name, nil
		}
	}
	return "", fmt.Errorf("%s is not on this host (pruned? redeploy it)", name)
}

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// What ziroctld keeps per deployment, under /var/lib/ziro/deploy/<app>/ (root-only):
//   deploy.json        the spec and the live build
//   builds/<id>.json   one record per build (commit, image digest, status)
//   logs/<id>.log      the build and release log
// The git token, when one is given, is in /etc/ziro/deploy/<app>.token (0600). Values of input
// secrets live with the app's other secrets (apps.go), never here.

var (
	deployStateDir = "/var/lib/ziro/deploy"
	deployTokenDir = "/etc/ziro/deploy"
	deployKeep     = 5 // builds (and their images) kept per app, for rollback
)

// Deployment is an app deployed from a git repository.
type Deployment struct {
	Name      string            `json:"name"`
	Repo      string            `json:"repo"`              // https URL
	Ref       string            `json:"ref,omitempty"`     // branch or tag (default: the repository's default branch)
	Path      string            `json:"path,omitempty"`    // subdirectory to build (monorepos)
	Port      int               `json:"port,omitempty"`    // container port (default: detected)
	Publish   int               `json:"publish,omitempty"` // host port on 127.0.0.1 (allocated on the first deploy)
	Env       map[string]string `json:"env,omitempty"`
	Secrets   []string          `json:"secrets,omitempty"` // names of input secrets the app receives
	Expose    string            `json:"expose,omitempty"`  // gateway hostname
	ExposeTLS string            `json:"expose_tls,omitempty"`
	Resources *Resources        `json:"resources,omitempty"`
	Replicas  int               `json:"replicas,omitempty"` // cluster: replicas (default 1)
	Arch      string            `json:"arch,omitempty"`     // cluster: build for this architecture (amd64, arm64)
	Live      string            `json:"live,omitempty"`     // build serving traffic
	Next      int               `json:"next"`               // next build number
	Created   time.Time         `json:"created"`
	Updated   time.Time         `json:"updated"`
}

// Build is one build of a deployment.
type Build struct {
	ID       string    `json:"id"` // b1, b2, ...
	App      string    `json:"app"`
	Ref      string    `json:"ref,omitempty"`
	Commit   string    `json:"commit,omitempty"`
	Kind     string    `json:"kind,omitempty"`  // dockerfile, node, next, static, go, python
	Image    string    `json:"image,omitempty"` // ziro.local/<app>:<id>@sha256:...
	Status   string    `json:"status"`          // queued, building, releasing, live, failed, superseded
	Error    string    `json:"error,omitempty"`
	Rollback bool      `json:"rollback,omitempty"` // a release of an earlier build's image
	Node     string    `json:"node,omitempty"`     // cluster: the node that built it
	Arch     string    `json:"arch,omitempty"`     // cluster: the image's architecture
	Queued   time.Time `json:"queued"`
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
}

func (b Build) done() bool {
	return b.Status == "live" || b.Status == "failed" || b.Status == "superseded"
}

var (
	deployMu     sync.Mutex // one writer for every deployment's files
	buildIDRe    = regexp.MustCompile(`^b[0-9]{1,9}$`)
	repoPathRe   = regexp.MustCompile(`^[A-Za-z0-9._~/-]{1,512}$`)
	gitRefRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
	subPathRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	localImageRe = regexp.MustCompile(`^ziro\.local/[a-z0-9][a-z0-9_.-]{0,62}:b[0-9]{1,9}@sha256:[0-9a-f]{64}$`)
)

func deployDir(app string) string { return filepath.Join(deployStateDir, app) }

// validateDeployment checks a spec from the CLI or the API (the trust boundary of ziroctld).
func validateDeployment(d *Deployment) error {
	if err := validName(d.Name); err != nil {
		return err
	}
	u, err := url.Parse(d.Repo)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!repoPathRe.MatchString(strings.TrimPrefix(u.Path, "/")) || strings.Contains(u.Path, "..") {
		return errors.New("repo: an https URL without credentials (private repos: --git-token-file)")
	}
	if d.Ref != "" && (!gitRefRe.MatchString(d.Ref) || strings.Contains(d.Ref, "..")) {
		return fmt.Errorf("invalid branch or tag %q", d.Ref)
	}
	if d.Path != "" && (!subPathRe.MatchString(d.Path) || strings.Contains(d.Path, "..")) {
		return fmt.Errorf("invalid path %q (a subdirectory of the repository)", d.Path)
	}
	if d.Port < 0 || d.Port > 65535 || d.Publish < 0 || d.Publish > 65535 {
		return errors.New("invalid port")
	}
	for k, v := range d.Env {
		if !envKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") || strings.ContainsAny(v, "\x00\r\n") || strings.Contains(v, "{{") {
			return fmt.Errorf("env %q: bad name or value", k)
		}
	}
	for _, k := range d.Secrets {
		if !envKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
			return fmt.Errorf("secret %q: bad name", k)
		}
	}
	if d.Replicas < 0 || d.Replicas > 64 || (d.Arch != "" && !archRe.MatchString(d.Arch)) {
		return errors.New("replicas 0..64, arch amd64 or arm64")
	}
	if d.Expose != "" && (!validHost(d.Expose) || strings.HasPrefix(d.Expose, "*.")) {
		return fmt.Errorf("invalid expose host %q", d.Expose)
	}
	return d.Resources.Validate()
}

func loadDeployment(app string) (*Deployment, error) {
	if err := validName(app); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(deployDir(app), "deploy.json"))
	if os.IsNotExist(err) {
		return nil, errNotFound("no deployment " + app + " (see: ziroctl deploy ls)")
	}
	if err != nil {
		return nil, err
	}
	var d Deployment
	return &d, json.Unmarshal(b, &d)
}

func saveDeployment(d *Deployment) error {
	d.Updated = time.Now().UTC()
	return writeJSON0600(filepath.Join(deployDir(d.Name), "deploy.json"), d)
}

func listDeployments() []*Deployment {
	var out []*Deployment
	ents, _ := os.ReadDir(deployStateDir)
	for _, e := range ents {
		if d, err := loadDeployment(e.Name()); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func buildPath(app, id string) string { return filepath.Join(deployDir(app), "builds", id+".json") }
func buildLog(app, id string) string  { return filepath.Join(deployDir(app), "logs", id+".log") }

func saveBuild(b *Build) error { return writeJSON0600(buildPath(b.App, b.ID), b) }

func loadBuild(app, id string) (*Build, error) {
	if err := validName(app); err != nil || !buildIDRe.MatchString(id) {
		return nil, errors.New("invalid app or build")
	}
	raw, err := os.ReadFile(buildPath(app, id))
	if os.IsNotExist(err) {
		return nil, errNotFound("no build " + id + " of " + app)
	}
	if err != nil {
		return nil, err
	}
	var b Build
	return &b, json.Unmarshal(raw, &b)
}

// listBuilds returns an app's builds, newest first.
func listBuilds(app string) []*Build {
	files, _ := filepath.Glob(filepath.Join(deployDir(app), "builds", "b*.json"))
	var out []*Build
	for _, f := range files {
		if b, err := loadBuild(app, strings.TrimSuffix(filepath.Base(f), ".json")); err == nil {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return buildNum(out[i].ID) > buildNum(out[j].ID) })
	return out
}

func buildNum(id string) int { n, _ := strconv.Atoi(strings.TrimPrefix(id, "b")); return n }

func writeJSON0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0600)
}

// pruneBuilds keeps the newest deployKeep finished builds (and the live one) with their logs
// and images; older ones are removed. An image a kept build still uses (a rollback releases an
// earlier build's image) stays.
func pruneBuilds(d *Deployment) {
	var keep, drop []*Build
	for _, b := range listBuilds(d.Name) {
		switch {
		case !b.done():
		case b.ID == d.Live || len(keep) < deployKeep:
			keep = append(keep, b)
		default:
			drop = append(drop, b)
		}
	}
	inUse := map[string]bool{}
	for _, b := range keep {
		inUse[b.Image] = true
	}
	for _, b := range drop {
		if b.Image != "" && !inUse[b.Image] {
			ref, _, _ := strings.Cut(b.Image, "@")
			_, _ = runNerdctl("rmi", ref)
		}
		_ = os.Remove(buildPath(d.Name, b.ID))
		_ = os.Remove(buildLog(d.Name, b.ID))
	}
}

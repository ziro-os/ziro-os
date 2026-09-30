package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Apps: one-command deployments of pinned app definitions from signed catalogs
// (github.com/ziro-os/apps, or a repo the admin added). `ziroctl apps deploy postgres:17`
// generates credentials, runs hardened containers with persistent data and prints how to connect.
//
// Two backends, chosen automatically:
//   - cluster master: each component becomes a ClusteredApp through deployApp (image policy,
//     scheduling, rolling updates); generated secrets become a cluster secret
//   - any other host (or --local): containers on this host with the same hardening as cluster
//     replicas (containerArgs), data in /var/lib/ziro/apps, secrets in a 0600 file

type AppDef struct {
	Schema      int                   `json:"schema"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Default     string                `json:"default"` // version used when none is given
	Versions    map[string]AppVersion `json:"versions"`
	Settings    []Setting             `json:"settings,omitempty"`
	Secrets     map[string]string     `json:"secrets,omitempty"` // env name -> hex:N|base64:N|alnum:N
	Cluster     bool                  `json:"cluster,omitempty"` // needs a cluster with the pod network
	Components  []AppComponent        `json:"components"`
	Outputs     map[string]string     `json:"outputs,omitempty"` // shown by `apps credentials`
	Notes       string                `json:"notes,omitempty"`
}

// AppVersion pins each component's image by digest.
type AppVersion struct {
	Images map[string]string `json:"images"`
}

type AppComponent struct {
	Name        string            `json:"name"`
	Replicas    int               `json:"replicas,omitempty"`     // default 1
	MaxReplicas int               `json:"max_replicas,omitempty"` // --replicas allowed up to this
	Port        int               `json:"port,omitempty"`         // container port clients use
	Env         map[string]string `json:"env,omitempty"`          // placeholders: settings, app, peers, replicas
	Secrets     []string          `json:"secrets,omitempty"`      // app secrets passed as env (env file, never argv)
	Data        []string          `json:"data,omitempty"`         // container paths kept on the host
	Args        []string          `json:"args,omitempty"`
	Health      []string          `json:"health,omitempty"` // run in the container; exit 0 = ready
}

var (
	digestImageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$`)
	appVersionRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	appStateDir   = "/etc/ziro/apps"
)

func parseAppDef(b []byte) (AppDef, error) {
	var d AppDef
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, d.validate()
}

func (d AppDef) validate() error {
	if d.Schema != 1 {
		return fmt.Errorf("unsupported app schema %d", d.Schema)
	}
	if err := validName(d.Name); err != nil {
		return err
	}
	if len(d.Components) == 0 || len(d.Components) > 8 {
		return errors.New("an app needs 1..8 components")
	}
	if _, ok := d.Versions[d.Default]; !ok {
		return fmt.Errorf("default version %q is not in versions", d.Default)
	}
	if err := validateSettings(d.Settings); err != nil {
		return err
	}
	for k, spec := range d.Secrets {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("secret %q: must be an env name", k)
		}
		if err := validSecretSpec(spec); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for _, c := range d.Components {
		if err := validName(c.Name); err != nil || names[c.Name] {
			return fmt.Errorf("component %q: bad or duplicate name", c.Name)
		}
		names[c.Name] = true
		if c.Replicas < 0 || c.Replicas > 16 || c.MaxReplicas < 0 || c.MaxReplicas > 64 || (c.MaxReplicas > 0 && c.MaxReplicas < max(c.Replicas, 1)) {
			return fmt.Errorf("component %s: bad replica counts", c.Name)
		}
		if max(c.Replicas, 1) > 1 && !d.Cluster {
			return fmt.Errorf("component %s: several replicas need \"cluster\": true", c.Name)
		}
		if c.Port < 0 || c.Port > 65535 {
			return fmt.Errorf("component %s: bad port", c.Name)
		}
		if err := validateDataPaths(c.Data); err != nil {
			return fmt.Errorf("component %s: %w", c.Name, err)
		}
		for _, s := range c.Secrets {
			if _, ok := d.Secrets[s]; !ok {
				return fmt.Errorf("component %s: unknown secret %s", c.Name, s)
			}
		}
		// Secrets reach containers only through env files: placeholders in env or args may not
		// name them (argv and plain env are visible in `nerdctl inspect` and the cluster spec).
		vars := d.placeholderNames(false)
		for k, v := range c.Env {
			if !envKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
				return fmt.Errorf("component %s: bad env name %q", c.Name, k)
			}
			if _, err := expand(v, vars); err != nil {
				return fmt.Errorf("component %s: env %s: %w", c.Name, k, err)
			}
		}
		for _, a := range append(append([]string(nil), c.Args...), c.Health...) {
			if _, err := expand(a, vars); err != nil {
				return fmt.Errorf("component %s: %w", c.Name, err)
			}
		}
	}
	for tag, v := range d.Versions {
		if !appVersionRe.MatchString(tag) {
			return fmt.Errorf("bad version tag %q", tag)
		}
		for _, c := range d.Components {
			if !digestImageRe.MatchString(v.Images[c.Name]) {
				return fmt.Errorf("version %s: component %s needs an image pinned by digest (name@sha256:...)", tag, c.Name)
			}
		}
		for c := range v.Images {
			if !names[c] {
				return fmt.Errorf("version %s: image for unknown component %s", tag, c)
			}
		}
	}
	all := d.placeholderNames(true)
	for k, v := range d.Outputs {
		if !settingNameRe.MatchString(k) {
			return fmt.Errorf("output %q: bad name", k)
		}
		if _, err := expand(v, all); err != nil {
			return fmt.Errorf("output %s: %w", k, err)
		}
	}
	return nil
}

// placeholderNames lists the placeholders an app may use (values only matter for validation).
func (d AppDef) placeholderNames(withSecrets bool) map[string]string {
	v := map[string]string{"app": "x", "peers": "x", "replicas": "1", "host": "x", "port": "1"}
	for _, s := range d.Settings {
		v["setting."+s.Name] = s.Default
	}
	if withSecrets {
		for k := range d.Secrets {
			v["secret."+k] = "x"
		}
	}
	return v
}

func init() {
	catalogCheckers["app"] = func(b []byte) (CatalogEntry, error) {
		d, err := parseAppDef(b)
		return CatalogEntry{Name: d.Name, Version: d.Default, Description: d.Description}, err
	}
}

var loadAppDefsFn = loadAppDefs // tests stub the catalog

// loadAppDefs returns verified catalog apps (official repos first; no shadowing).
func loadAppDefs() map[string]AppDef {
	items, errs := catalogItems("app")
	out := map[string]AppDef{}
	src := map[string]string{}
	for _, it := range items {
		d, err := parseAppDef(it.Data)
		if err == nil && d.Name != it.Name {
			err = fmt.Errorf("app name %q differs from its index entry", d.Name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s: %s: %w", it.Repo, it.Name, err))
			continue
		}
		if prev, taken := src[d.Name]; taken {
			errs = append(errs, fmt.Errorf("repo %s: app %s is already provided by %s; ignored", it.Repo, d.Name, prev))
			continue
		}
		src[d.Name] = it.Repo
		out[d.Name] = d
	}
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	return out
}

// ---- deployed state ----

// AppInstance is what `apps deploy` created (secrets are stored apart, never here).
type AppInstance struct {
	Name       string            `json:"name"`
	App        string            `json:"app"`
	Version    string            `json:"version"`
	Mode       string            `json:"mode"` // local or cluster
	Settings   map[string]string `json:"settings,omitempty"`
	Components []string          `json:"components"` // container (local) or cluster app names
	Publish    string            `json:"publish,omitempty"`
	CreatedAt  string            `json:"created_at"`
	Def        AppDef            `json:"def"` // the definition deployed, for credentials and rm
}

func appInstancePath(name string) string  { return filepath.Join(appStateDir, name+".json") }
func appSecretsPath(name string) string   { return filepath.Join(appStateDir, name+".secrets") }
func appClusterSecret(name string) string { return "app-" + name }

func loadAppInstance(name string) (*AppInstance, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(appInstancePath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no app %q (see: ziroctl apps list)", name)
		}
		return nil, err
	}
	var in AppInstance
	return &in, json.Unmarshal(b, &in)
}

func saveAppInstance(in *AppInstance) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(appStateDir, 0700); err != nil {
		return err
	}
	return writeFileAtomic(appInstancePath(in.Name), b, 0600)
}

func listAppInstances() []*AppInstance {
	var out []*AppInstance
	ents, _ := os.ReadDir(appStateDir)
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if in, err := loadAppInstance(n); err == nil {
				out = append(out, in)
			}
		}
	}
	return out
}

// componentApp names a component's containers (local) or cluster app: the instance name, or
// <instance>-<component> for multi-component apps.
func componentApp(inst string, d AppDef, c AppComponent) string {
	if len(d.Components) == 1 {
		return inst
	}
	return inst + "-" + c.Name
}

// ---- deploy ----

type appDeployOpts struct {
	Name      string
	Set       map[string]string
	Replicas  int      // 0 = the definition's
	Publish   int      // host port for the first component with a port (0 = none on clusters)
	Bind      string   // local publish address
	AllowFrom []string // cluster: apps allowed to reach it
	Local     bool
	// NewVersion allows moving an instance to another version line; data written by one major
	// version is often unreadable by another (postgres 16 -> 17 needs a dump and restore).
	NewVersion bool
}

// parseAppRef splits "name[:version]".
func parseAppRef(ref string) (name, version string) {
	name, version, _ = strings.Cut(ref, ":")
	return name, version
}

func deployAppRef(ref string, o appDeployOpts) error {
	name, version := parseAppRef(ref)
	d, ok := loadAppDefsFn()[name]
	if !ok {
		refreshStaleCatalogs("app")
		if d, ok = loadAppDefsFn()[name]; !ok {
			return fmt.Errorf("unknown app %q (see: ziroctl apps search)", name)
		}
	}
	if version == "" {
		version = d.Default
	}
	if _, ok := d.Versions[version]; !ok {
		var tags []string
		for t := range d.Versions {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		return fmt.Errorf("%s has no version %q (available: %s)", name, version, strings.Join(tags, ", "))
	}
	if o.Name == "" {
		o.Name = d.Name
	}
	if err := validName(o.Name); err != nil {
		return err
	}
	var prevSettings map[string]string
	if prev, err := loadAppInstance(o.Name); err == nil {
		if prev.App != d.Name {
			return fmt.Errorf("%s is already a deployed %s app (pick another --name)", o.Name, prev.App)
		}
		if prev.Version != version && !o.NewVersion {
			return fmt.Errorf("%s runs %s %s; its data may not work with %s. Deploy a new instance (--name) and migrate, or pass --new-version if the app supports in-place upgrades", o.Name, d.Name, prev.Version, version)
		}
		prevSettings = prev.Settings
	}
	settings, err := resolveSettings(d.Settings, prevSettings, o.Set)
	if err != nil {
		return err
	}
	cluster := false
	if !o.Local {
		if cfg, err := loadClusterConfig(); err == nil {
			if cfg.Role != "master" {
				return fmt.Errorf("this host is a cluster worker: deploy on the master (%s), or use --local", cfg.MasterAddr)
			}
			cluster = true
		}
	}
	if d.Cluster && !cluster {
		return fmt.Errorf("%s runs several replicas that find each other over the cluster pod network: deploy it on a cluster master (a one-node cluster works: ziroctl cluster init)", d.Name)
	}
	in := &AppInstance{Name: o.Name, App: d.Name, Version: version, Settings: settings, Def: d,
		CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if o.Publish > 0 {
		in.Publish = strconv.Itoa(o.Publish)
	}
	fmt.Printf("==> Deploying %s %s as %s\n", d.Name, version, o.Name)
	if cluster {
		in.Mode = "cluster"
		err = deployAppCluster(in, o)
	} else {
		in.Mode = "local"
		err = deployAppLocal(in, o)
	}
	if err != nil {
		if len(in.Components) > 0 { // keep what was created, so `apps list` shows it and `apps rm` cleans it up
			_ = saveAppInstance(in)
		}
		return err
	}
	if err := saveAppInstance(in); err != nil {
		return err
	}
	fmt.Printf("✓ %s deployed. Connection details: ziroctl apps credentials %s\n", o.Name, o.Name)
	if d.Notes != "" {
		fmt.Println("  " + d.Notes)
	}
	return nil
}

// componentSpec renders one component: env and args with placeholders expanded.
func componentSpec(in *AppInstance, c AppComponent, replicas int) (env map[string]string, args, health []string, err error) {
	app := componentApp(in.Name, in.Def, c)
	var peers []string
	for i := 1; i <= replicas; i++ { // replica indexes start at 1, like the cluster scheduler's
		peers = append(peers, strconv.Itoa(i)+"."+app+"."+meshDomain)
	}
	vars := map[string]string{"app": app, "peers": strings.Join(peers, ","), "replicas": strconv.Itoa(replicas), "host": app}
	for k, v := range in.Settings {
		vars["setting."+k] = v
	}
	env = map[string]string{}
	for k, v := range c.Env {
		if env[k], err = expand(v, vars); err != nil {
			return nil, nil, nil, err
		}
	}
	env["ZIRO_APP"] = app
	if in.Def.Cluster {
		env["ZIRO_PEERS"] = vars["peers"]
	}
	for _, a := range c.Args {
		x, err := expand(a, vars)
		if err != nil {
			return nil, nil, nil, err
		}
		args = append(args, x)
	}
	for _, a := range c.Health {
		x, err := expand(a, vars)
		if err != nil {
			return nil, nil, nil, err
		}
		health = append(health, x)
	}
	return env, args, health, nil
}

func componentReplicas(c AppComponent, want int) (int, error) {
	n := max(c.Replicas, 1)
	if want > 0 && want != n {
		if c.MaxReplicas == 0 || want > c.MaxReplicas {
			return 0, fmt.Errorf("component %s: replicas can be set up to %d", c.Name, max(c.MaxReplicas, n))
		}
		n = want
	}
	return n, nil
}

func deployAppCluster(in *AppInstance, o appDeployOpts) error {
	d := in.Def
	// Generated secrets live in the cluster's (sealed, replicated) secret store, kept across
	// redeploys so a database never loses its password.
	secret := appClusterSecret(in.Name)
	if len(d.Secrets) > 0 {
		if err := withState(func(st *ClusterState) error {
			cur := st.Secrets[secret]
			next := map[string]string{}
			for k, spec := range d.Secrets {
				if v := cur[k]; v != "" {
					next[k] = v
					continue
				}
				v, err := genSecret(spec)
				if err != nil {
					return err
				}
				next[k] = v
			}
			if st.Secrets == nil {
				st.Secrets = map[string]map[string]string{}
			}
			st.Secrets[secret] = next
			return nil
		}); err != nil {
			return err
		}
	}
	published := false
	for _, c := range d.Components {
		n, err := componentReplicas(c, o.Replicas)
		if err != nil {
			return err
		}
		env, args, _, err := componentSpec(in, c, n)
		if err != nil {
			return err
		}
		name := componentApp(in.Name, d, c)
		app := ClusteredApp{Name: name, Image: d.Versions[in.Version].Images[c.Name], Replicas: n, Env: env, Args: args,
			Data: c.Data, AllowFrom: uniq(append([]string{name}, o.AllowFrom...))} // replicas reach each other
		for _, other := range d.Components { // components of one app reach each other
			app.AllowFrom = uniq(append(app.AllowFrom, componentApp(in.Name, d, other)))
		}
		if len(c.Secrets) > 0 {
			app.Secrets = []string{secret}
		}
		if o.Publish > 0 && c.Port > 0 && !published {
			app.Port, published = fmt.Sprintf("%d:%d", o.Publish, c.Port), true
		}
		if err := deployApp(func(st *ClusterState) (*ClusteredApp, error) {
			if cur := st.app(name); cur != nil && !slices.Contains(in.Components, name) {
				if prev, err := loadAppInstance(in.Name); err != nil || !slices.Contains(prev.Components, name) {
					return nil, fmt.Errorf("cluster app %q exists and isn't part of %s", name, in.Name)
				}
			}
			return &app, nil
		}); err != nil {
			return err
		}
		in.Components = append(in.Components, name)
	}
	return nil
}

// Local backend (package vars so tests can stub nerdctl).
var (
	appNerdctl = func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), imagePullTimeout)
		defer cancel()
		return nerdctl(ctx, args...)
	}
	appReadyTimeout = 3 * time.Minute
)

func deployAppLocal(in *AppInstance, o appDeployOpts) error {
	d := in.Def
	secrets, err := loadOrCreateSecrets(appSecretsPath(in.Name), d.Secrets)
	if err != nil {
		return err
	}
	bind := o.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	published := false
	for _, c := range d.Components {
		if _, err := componentReplicas(c, o.Replicas); err != nil {
			return err
		}
		env, args, health, err := componentSpec(in, c, 1)
		if err != nil {
			return err
		}
		name := componentApp(in.Name, d, c)
		a := Assignment{Name: "ziro-app-" + name, App: name, Image: d.Versions[in.Version].Images[c.Name], Args: args, Env: env,
			Data: c.Data, Replica: 1}
		for _, s := range c.Secrets {
			if a.SecretEnv == nil {
				a.SecretEnv = map[string]string{}
			}
			a.SecretEnv[s] = secrets[s]
		}
		if c.Port > 0 && !published { // the app's entry point is reachable from this host by default
			host := o.Publish
			if host == 0 {
				host = c.Port
			}
			a.Port, published = fmt.Sprintf("%s:%d:%d", bind, host, c.Port), true
			in.Publish = bind + ":" + strconv.Itoa(host)
		}
		fmt.Printf("  pulling %s\n", a.Image)
		if err := appNerdctl("pull", "-q", a.Image); err != nil {
			return err
		}
		if err := ensureDataDirs(a); err != nil {
			return err
		}
		_ = appNerdctl("rm", "-f", a.Name) // redeploy: replace the container, keep the data
		if err := writeSecretEnv(a); err != nil {
			return err
		}
		err = appNerdctl(containerArgs(a, "ziro.apps="+in.Name)...)
		_ = os.Remove(secretEnvFile(a.Name)) // nerdctl copied it into the container spec
		if err != nil {
			_ = appNerdctl("rm", "-f", a.Name)
			return err
		}
		in.Components = append(in.Components, a.Name)
		if len(health) > 0 {
			fmt.Printf("  waiting for %s to be ready\n", name)
			if err := waitAppReady(a.Name, health); err != nil {
				return err
			}
		}
	}
	return nil
}

func waitAppReady(container string, health []string) error {
	deadline := time.Now().Add(appReadyTimeout)
	var err error
	for time.Now().Before(deadline) {
		if err = appNerdctl(append([]string{"exec", container}, health...)...); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s not ready after %s: %v (see: nerdctl logs %s)", container, appReadyTimeout, err, container)
}

// ---- credentials, status, removal ----

// appOutputs renders an instance's outputs (they may hold secrets: root-only CLI).
func appOutputs(in *AppInstance) (map[string]string, error) {
	vars := map[string]string{"app": in.Name, "peers": "", "replicas": ""}
	for k, v := range in.Settings {
		vars["setting."+k] = v
	}
	host := in.Name + "." + meshDomain
	if in.Mode == "local" {
		host = "127.0.0.1"
		if h, _, ok := strings.Cut(in.Publish, ":"); ok && h != "0.0.0.0" {
			host = h
		}
	}
	vars["host"] = host
	vars["port"] = ""
	for _, c := range in.Def.Components {
		if c.Port > 0 {
			vars["port"] = strconv.Itoa(c.Port)
			break
		}
	}
	if in.Mode == "local" && in.Publish != "" {
		_, vars["port"], _ = strings.Cut(in.Publish, ":")
	}
	secrets := map[string]string{}
	if in.Mode == "local" {
		var err error
		if secrets, err = loadOrCreateSecrets(appSecretsPath(in.Name), nil); err != nil {
			return nil, err
		}
	} else if st, err := readState(); err == nil {
		secrets = st.Secrets[appClusterSecret(in.Name)]
	}
	for k, v := range secrets {
		vars["secret."+k] = v
	}
	out := map[string]string{}
	for k, v := range in.Def.Outputs {
		x, err := expand(v, vars)
		if err != nil {
			return nil, err
		}
		out[k] = x
	}
	return out, nil
}

func removeAppInstance(name string, purge bool) error {
	in, err := loadAppInstance(name)
	if err != nil {
		return err
	}
	if in.Mode == "cluster" {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := withState(func(st *ClusterState) error {
			var kept []ClusteredApp
			for _, a := range st.Apps {
				if !slices.Contains(in.Components, a.Name) {
					kept = append(kept, a)
				}
			}
			st.Apps = kept
			for _, c := range in.Components {
				delete(st.History, c)
			}
			if purge {
				delete(st.Secrets, appClusterSecret(name))
			}
			scheduleReplicas(st, time.Now())
			return nil
		}); err != nil {
			return err
		}
		if purge {
			fmt.Printf("  note: data on each node stays in %s/<component>/ until you delete it there\n", appDataRoot)
		}
	} else {
		for _, c := range in.Components {
			if err := appNerdctl("rm", "-f", c); err != nil {
				fmt.Printf("  ! %s: %v\n", c, err)
			}
		}
		if purge {
			for _, c := range in.Def.Components {
				_ = os.RemoveAll(filepath.Join(appDataRoot, componentApp(name, in.Def, c)))
			}
			_ = os.Remove(appSecretsPath(name))
		}
	}
	if err := os.Remove(appInstancePath(name)); err != nil {
		return err
	}
	if purge {
		fmt.Printf("✓ %s removed with its data and credentials\n", name)
	} else {
		fmt.Printf("✓ %s removed; data and credentials kept (redeploy with --name %s to reuse them, or rm --purge)\n", name, name)
	}
	return nil
}

// ---- CLI ----

var (
	appsName       string
	appsSets       []string
	appsReplicas   int
	appsPublish    int
	appsBind       string
	appsAllowFrom  []string
	appsLocal      bool
	appsPurge      bool
	appsNewVersion bool
)

var appsCmd = &cobra.Command{
	Use:     "apps",
	Aliases: []string{"app"},
	Short:   "One-command app deployments from signed catalogs (postgres, mysql, mysql-cluster, ...)",
}

type appCatalogInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Versions    []string `json:"versions"`
	Cluster     bool     `json:"cluster,omitempty"`
}

func appCatalogList(q string) []appCatalogInfo {
	var out []appCatalogInfo
	for _, d := range loadAppDefs() {
		if q != "" && !strings.Contains(d.Name, q) && !strings.Contains(strings.ToLower(d.Description), q) {
			continue
		}
		ai := appCatalogInfo{Name: d.Name, Description: d.Description, Default: d.Default, Cluster: d.Cluster}
		for v := range d.Versions {
			ai.Versions = append(ai.Versions, v)
		}
		sort.Strings(ai.Versions)
		out = append(out, ai)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var appsSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search the app catalogs",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		refreshStaleCatalogs("app")
		q := ""
		if len(args) == 1 {
			q = strings.ToLower(args[0])
		}
		apps := appCatalogList(q)
		return printResult(apps, func() {
			fmt.Printf("%-16s %-18s %s\n", "APP", "VERSIONS", "DESCRIPTION")
			for _, a := range apps {
				desc := a.Description
				if a.Cluster {
					desc += " [cluster]"
				}
				fmt.Printf("%-16s %-18s %s\n", a.Name, strings.Join(a.Versions, ","), desc)
			}
			fmt.Println("\nDeploy: ziroctl apps deploy <app>[:<version>]")
		})
	},
}

var appsInfoCmd = &cobra.Command{
	Use:   "info <app>",
	Short: "Show an app definition: versions, images, settings, what it keeps",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d, ok := loadAppDefs()[args[0]]
		if !ok {
			return fmt.Errorf("unknown app %q (see: ziroctl apps search)", args[0])
		}
		return printResult(d, func() {
			fmt.Printf("%s: %s\n", d.Name, d.Description)
			var tags []string
			for t := range d.Versions {
				tags = append(tags, t)
			}
			sort.Strings(tags)
			for _, t := range tags {
				mark := ""
				if t == d.Default {
					mark = " (default)"
				}
				fmt.Printf("  version %s%s\n", t, mark)
				for c, img := range d.Versions[t].Images {
					fmt.Printf("    %s: %s\n", c, img)
				}
			}
			for _, c := range d.Components {
				fmt.Printf("  component %s: %d replica(s), port %d, data %s\n", c.Name, max(c.Replicas, 1), c.Port, strings.Join(c.Data, " "))
			}
			for _, s := range d.Settings {
				fmt.Printf("  setting %s=%s  %s\n", s.Name, s.Default, s.Description)
			}
		})
	},
}

var appsDeployCmd = &cobra.Command{
	Use:   "deploy <app>[:<version>]",
	Short: "Deploy an app with generated credentials and persistent data (redeploy updates it)",
	Example: `  ziroctl apps deploy postgres                 # latest pinned version, on 127.0.0.1:5432
  ziroctl apps deploy postgres:16 --name db2 --publish 5433
  ziroctl apps deploy mysql:8.4
  ziroctl apps deploy mysql-cluster             # on a cluster master: 3-node Group Replication
  ziroctl apps credentials postgres`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		set, err := parseSetFlags(appsSets)
		if err != nil {
			return err
		}
		if appsBind != "" && appsBind != "127.0.0.1" && appsBind != "0.0.0.0" && !ipv4Re.MatchString(appsBind) {
			return fmt.Errorf("--bind must be an IPv4 address")
		}
		if appsPublish < 0 || appsPublish > 65535 {
			return fmt.Errorf("--publish must be a port")
		}
		for _, a := range appsAllowFrom {
			if a != "*" {
				if err := validName(a); err != nil {
					return err
				}
			}
		}
		return deployAppRef(args[0], appDeployOpts{Name: appsName, Set: set, Replicas: appsReplicas, Publish: appsPublish,
			Bind: appsBind, AllowFrom: appsAllowFrom, Local: appsLocal, NewVersion: appsNewVersion})
	},
}

var ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

type appStatus struct {
	Name       string   `json:"name"`
	App        string   `json:"app"`
	Version    string   `json:"version"`
	Mode       string   `json:"mode"`
	Publish    string   `json:"publish,omitempty"`
	Components []string `json:"components"`
	Running    string   `json:"running"`
}

func appsStatus() []appStatus {
	var out []appStatus
	running := map[string]bool{}
	if b, err := exec.Command("nerdctl", "ps", "--filter", "label=ziro.apps", "--format", "{{.Names}}").Output(); err == nil {
		for _, n := range strings.Fields(string(b)) {
			running[n] = true
		}
	}
	st, _ := readState()
	for _, in := range listAppInstances() {
		s := appStatus{Name: in.Name, App: in.App, Version: in.Version, Mode: in.Mode, Publish: in.Publish, Components: in.Components}
		up, want := 0, 0
		for _, c := range in.Components {
			if in.Mode == "local" {
				want++
				if running[c] {
					up++
				}
				continue
			}
			if st == nil {
				continue
			}
			for _, r := range st.Replicas {
				if r.App == c {
					want++
					if st.replicaRunning(r) {
						up++
					}
				}
			}
		}
		s.Running = fmt.Sprintf("%d/%d", up, want)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var appsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "status"},
	Short:   "List deployed apps and whether they run",
	RunE: func(cmd *cobra.Command, args []string) error {
		apps := appsStatus()
		return printResult(apps, func() {
			fmt.Printf("%-16s %-14s %-8s %-8s %-8s %s\n", "NAME", "APP", "VERSION", "MODE", "RUNNING", "ENDPOINT")
			for _, a := range apps {
				ep := a.Publish
				if a.Mode == "cluster" && ep == "" {
					ep = a.Name + "." + meshDomain
				}
				fmt.Printf("%-16s %-14s %-8s %-8s %-8s %s\n", a.Name, a.App, a.Version, a.Mode, a.Running, ep)
			}
		})
	},
}

var appsCredentialsCmd = &cobra.Command{
	Use:   "credentials <name>",
	Short: "Show how to connect (includes generated passwords)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := loadAppInstance(args[0])
		if err != nil {
			return err
		}
		out, err := appOutputs(in)
		if err != nil {
			return err
		}
		return printResult(out, func() {
			keys := make([]string, 0, len(out))
			for k := range out {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("%-12s %s\n", k+":", out[k])
			}
		})
	},
}

var appsRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a deployed app (data and credentials are kept unless --purge)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return removeAppInstance(args[0], appsPurge)
	},
}

func init() {
	f := appsDeployCmd.Flags()
	f.StringVar(&appsName, "name", "", "Instance name (default: the app name)")
	f.StringArrayVar(&appsSets, "set", nil, "Set an app setting (name=value; see `apps info`)")
	f.IntVar(&appsReplicas, "replicas", 0, "Replicas, for apps that allow scaling")
	f.IntVar(&appsPublish, "publish", 0, "Host port (local default: the app's port on 127.0.0.1; cluster default: none)")
	f.StringVar(&appsBind, "bind", "", "Local publish address (default 127.0.0.1; 0.0.0.0 exposes it, the firewall still applies)")
	f.StringSliceVar(&appsAllowFrom, "allow-from", nil, "Cluster apps allowed to connect ('*' = any)")
	f.BoolVar(&appsLocal, "local", false, "Deploy on this host even if it is a cluster master")
	f.BoolVar(&appsNewVersion, "new-version", false, "Allow moving an existing instance to another version")
	appsRmCmd.Flags().BoolVar(&appsPurge, "purge", false, "Also delete the app's data and credentials")
	appsCmd.AddCommand(appsSearchCmd, appsInfoCmd, appsDeployCmd, appsListCmd, appsCredentialsCmd, appsRmCmd)
	rootCmd.AddCommand(appsCmd)
}

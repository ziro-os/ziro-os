package cmd

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Modules (also called plugins): opt-in feature packs (security scanners, audit, S3 storage, ...).
// Nothing is preinstalled; enabling a module installs its packages from the pinned Alpine
// repositories (apk verifies signatures) and its sha256-pinned artifacts, writes hardened
// configuration, registers supervised services and checks health.
//
// Manifests come from two places:
//   - built in: embedded in ziroctl (modules/*.json), reviewed and versioned with it
//   - catalogs: signed repositories (ziro-os/pkgs, or a repo the admin added with its key; see
//     catalog.go). A catalog can't shadow a built-in name, nor a third-party repo an official one.
//
// Enabling saves a copy of the manifest it used, so disable, upgrade and boot reconciliation keep
// working when a catalog later changes or drops the module. See docs/modules.md.

//go:embed modules/*.json
var moduleFS embed.FS

var moduleStateDir = "/etc/ziro/modules"

// ModuleState records exactly what enabling changed, so disable undoes only that.
type ModuleState struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Status    string            `json:"status"` // installing, enabled, failed, disabling
	Error     string            `json:"error,omitempty"`
	Auto      bool              `json:"auto,omitempty"` // enabled only as a dependency
	Packages  []string          `json:"packages,omitempty"`
	Files     map[string]string `json:"files,omitempty"` // path -> sha256 we wrote
	Services  []string          `json:"services,omitempty"`
	Artifacts []string          `json:"artifacts,omitempty"` // paths we downloaded
	// CreatedDirs are directories that didn't exist before this module: the only ones purge removes.
	CreatedDirs []string          `json:"created_dirs,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"` // resolved --set values, reused by upgrade and re-enable
	Source      string            `json:"source,omitempty"`
	UpdatedAt   string            `json:"updated_at"`
}

// moduleOpts are the operator's choices for an enable.
type moduleOpts struct {
	Auto  bool              // enabled only as a dependency
	Force bool              // ignore the memory gate
	Set   map[string]string // --set values
}

// loadManifests returns the built-in manifests, then verified catalog modules whose names are not
// taken yet (official repos come first). A broken catalog is reported, never fatal.
func loadManifests() (map[string]ModuleManifest, error) {
	ents, err := moduleFS.ReadDir("modules")
	if err != nil {
		return nil, err
	}
	out := map[string]ModuleManifest{}
	for _, e := range ents {
		b, err := moduleFS.ReadFile("modules/" + e.Name())
		if err != nil {
			return nil, err
		}
		m, err := parseManifest(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		m.Source = "builtin"
		out[m.Name] = m
	}
	items, errs := catalogItems("module")
	for _, it := range items {
		m, err := parseManifest(it.Data)
		if err == nil && m.Name != it.Name {
			err = fmt.Errorf("manifest name %q differs from its index entry", m.Name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s: %s: %w", it.Repo, it.Name, err))
			continue
		}
		if prev, taken := out[m.Name]; taken {
			if prev.Source != it.Repo {
				errs = append(errs, fmt.Errorf("repo %s: %s is already provided by %s; ignored", it.Repo, m.Name, prev.Source))
			}
			continue
		}
		m.Source = it.Repo
		out[m.Name] = m
	}
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	return out, nil
}

func manifestSnapshotPath(name string) string { return filepath.Join(moduleStateDir, name+".manifest") }
func moduleSecretsPath(name string) string    { return filepath.Join(moduleStateDir, name+".secrets") }

// installedManifest is the manifest an enabled module was installed with (falling back to the
// available one for modules enabled before snapshots existed).
func installedManifest(all map[string]ModuleManifest, name string) (ModuleManifest, bool) {
	if b, err := os.ReadFile(manifestSnapshotPath(name)); err == nil {
		var m ModuleManifest
		if json.Unmarshal(b, &m) == nil && m.Validate() == nil {
			return m, true
		}
	}
	m, ok := all[name]
	return m, ok
}

func moduleStatePath(name string) string { return filepath.Join(moduleStateDir, name+".json") }

func loadModuleState(name string) (*ModuleState, error) {
	b, err := os.ReadFile(moduleStatePath(name))
	if err != nil {
		return nil, err
	}
	var s ModuleState
	return &s, json.Unmarshal(b, &s)
}

func saveModuleState(s *ModuleState) error {
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(moduleStateDir, 0755); err != nil {
		return err
	}
	return writeFileAtomic(moduleStatePath(s.Name), b, 0644)
}

func enabledModules() map[string]*ModuleState {
	out := map[string]*ModuleState{}
	ents, _ := os.ReadDir(moduleStateDir)
	for _, e := range ents {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if s, err := loadModuleState(name); err == nil {
				out[name] = s
			}
		}
	}
	return out
}

// enableOrder returns name's dependencies first (depth-first), detecting cycles.
func enableOrder(all map[string]ModuleManifest, name string) ([]string, error) {
	var order []string
	seen, stack := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(n string) error {
		m, ok := all[n]
		if !ok {
			return fmt.Errorf("unknown module %q (see: ziroctl module list)", n)
		}
		if stack[n] {
			return fmt.Errorf("module dependency cycle at %q", n)
		}
		if seen[n] {
			return nil
		}
		stack[n] = true
		for _, r := range m.Requires {
			if err := visit(r); err != nil {
				return err
			}
		}
		stack[n], seen[n] = false, true
		order = append(order, n)
		return nil
	}
	return order, visit(name)
}

// ---- system operations (package-level vars so tests can stub them) ----

var (
	apkInstalled = func(pkg string) bool { return exec.Command("apk", "info", "-e", pkg).Run() == nil }
	apkAdd       = func(pkgs []string) error {
		return runLogged(10*time.Minute, "apk", append([]string{"add", "--no-cache"}, pkgs...)...)
	}
	apkDel             = func(pkgs []string) error { return runLogged(5*time.Minute, "apk", append([]string{"del"}, pkgs...)...) }
	memTotalMB         = func() int { return int(readMeminfo()["MemTotal"] >> 20) }
	memAvailableMB     = func() int { return int(readMeminfo()["MemAvailable"] >> 20) }
	artifactDownload   = func(rawURL, dst string, max int64) (string, error) { return catalogDownload(rawURL, dst, max) }
	startModuleService = startService
	stopModuleService  = stopService
	cronPath           = "/etc/crontabs/root"
)

func runLogged(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

var moduleExec = runModuleCmd

func runModuleCmd(c ModuleCmd) (string, error) {
	if c.Creates != "" {
		if m, _ := filepath.Glob(c.Creates); len(m) > 0 {
			return "", nil
		}
	}
	d := 2 * time.Minute
	if c.Timeout != "" {
		if v, err := time.ParseDuration(c.Timeout); err == nil {
			d = v
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.Exec, c.Args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%s: %w: %s", c.Exec, err, lastLines(s, 5))
	}
	if c.Expect != "" && !strings.Contains(s, c.Expect) {
		return s, fmt.Errorf("%s: output lacks %q: %s", c.Exec, c.Expect, lastLines(s, 5))
	}
	return s, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// moduleDirRoot prefixes every path a module writes (tests only; "" in production).
var moduleDirRoot = ""

func modPath(p string) string {
	if moduleDirRoot == "" {
		return p
	}
	return filepath.Join(moduleDirRoot, p)
}

var moduleChown = chownSpec

func chownSpec(path, owner string) error {
	if owner == "" {
		return nil
	}
	uname, gname, _ := strings.Cut(owner, ":")
	u, err := user.Lookup(uname)
	if err != nil {
		return fmt.Errorf("owner %s: %w", owner, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if gname != "" {
		g, err := user.LookupGroup(gname)
		if err != nil {
			return fmt.Errorf("group %s: %w", gname, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return os.Lchown(path, uid, gid)
}

// ensureDirs creates the module's directories; st (nil at boot) records the ones it created.
func ensureDirs(m ModuleManifest, st *ModuleState) error {
	for _, d := range m.Dirs {
		d.Path = modPath(d.Path)
		if _, err := os.Lstat(d.Path); os.IsNotExist(err) && st != nil {
			st.CreatedDirs = uniq(append(st.CreatedDirs, d.Path))
		}
		mode, _ := strconv.ParseUint(d.Mode, 8, 32)
		if mode == 0 {
			mode = 0755
		}
		if err := os.MkdirAll(d.Path, os.FileMode(mode)); err != nil {
			return err
		}
		if err := os.Chmod(d.Path, os.FileMode(mode)); err != nil {
			return err
		}
		if err := moduleChown(d.Path, d.Owner); err != nil {
			return err
		}
	}
	return nil
}

// writeModuleFiles writes each file unless the admin changed a copy we wrote earlier. A file the
// module didn't write (e.g. the package's default) is kept as <path>.ziro-orig.
func writeModuleFiles(m ModuleManifest, st *ModuleState) error {
	if st.Files == nil {
		st.Files = map[string]string{}
	}
	for _, f := range m.Files {
		f.Path = modPath(f.Path)
		want := sha256Hex([]byte(f.Content))
		cur, err := os.ReadFile(f.Path)
		switch {
		case err == nil && sha256Hex(cur) == want:
			st.Files[f.Path] = want
			continue
		case err == nil && st.Files[f.Path] != "" && sha256Hex(cur) != st.Files[f.Path]:
			fmt.Printf("  ! %s was modified locally; keeping your version\n", f.Path)
			continue
		case err == nil && st.Files[f.Path] == "":
			if err := os.WriteFile(f.Path+".ziro-orig", cur, 0600); err != nil {
				return err
			}
		}
		mode, _ := strconv.ParseUint(f.Mode, 8, 32)
		if err := os.MkdirAll(filepath.Dir(f.Path), 0755); err != nil {
			return err
		}
		if err := writeFileAtomic(f.Path, []byte(f.Content), os.FileMode(mode)); err != nil {
			return err
		}
		if err := moduleChown(f.Path, f.Owner); err != nil {
			return err
		}
		st.Files[f.Path] = want
	}
	return nil
}

const cronMarker = "# ziro-module:"

// setCron replaces this module's lines in root's crontab (tagged with a marker comment).
func setCron(name string, lines []string) error {
	cur, _ := os.ReadFile(cronPath)
	var kept []string
	skip := false
	for _, l := range strings.Split(strings.TrimRight(string(cur), "\n"), "\n") {
		if skip {
			skip = false
			continue
		}
		if l == cronMarker+name {
			skip = true
			continue
		}
		if l != "" || len(kept) > 0 {
			kept = append(kept, l)
		}
	}
	for _, l := range lines {
		kept = append(kept, cronMarker+name, l)
	}
	if err := os.MkdirAll(filepath.Dir(cronPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(cronPath, []byte(strings.Join(kept, "\n")+"\n"), 0600)
}

func serviceConf(s ModuleService) string { return supervisedConf(s) }

// fetchArtifacts downloads the artifacts for this host's architecture unless a file with the
// pinned sha256 is already in place.
func fetchArtifacts(m ModuleManifest, st *ModuleState) error {
	for _, a := range m.Artifacts {
		if a.Arch != "" && a.Arch != strings.Replace(hostArch(), "arm64", "aarch64", 1) {
			continue
		}
		p := modPath(a.Path)
		if b, err := os.ReadFile(p); err != nil || sha256Hex(b) != a.SHA256 {
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return err
			}
			fmt.Printf("  downloading %s\n", filepath.Base(a.Path))
			sum, err := artifactDownload(a.URL, p+".dl", 512<<20)
			if err == nil && sum != a.SHA256 {
				err = fmt.Errorf("%s: sha256 mismatch", a.URL)
			}
			if err != nil {
				_ = os.Remove(p + ".dl")
				return err
			}
			if err := os.Rename(p+".dl", p); err != nil {
				return err
			}
		}
		mode, _ := strconv.ParseUint(a.Mode, 8, 32)
		if err := os.Chmod(p, os.FileMode(mode)); err != nil {
			return err
		}
		st.Artifacts = uniq(append(st.Artifacts, p))
	}
	return nil
}

// ---- enable / disable ----

// enableModule enables name and its dependencies (opts.Auto marks it as dependency-only).
func enableModule(name string, opts moduleOpts) error {
	all, err := loadManifests()
	if err != nil {
		return err
	}
	return enableFrom(all, name, opts)
}

func enableFrom(all map[string]ModuleManifest, name string, opts moduleOpts) error {
	order, err := enableOrder(all, name)
	if err != nil {
		return err
	}
	enabled := enabledModules()
	for _, n := range order {
		if s := enabled[n]; s != nil && s.Status == "enabled" {
			if n == name && !opts.Auto && s.Auto { // explicitly enabled now: no longer dependency-only
				s.Auto = false
				_ = saveModuleState(s)
			}
			// Enabled once doesn't mean running now: a daemon that died, or never came up after a
			// reboot, is started again by enabling the module again.
			for _, svc := range s.Services {
				if err := startModuleService(svc); err == nil {
					fmt.Printf("  started service %s\n", svc)
				} else if !strings.Contains(err.Error(), "already running") {
					fmt.Printf("  ⚠ start %s: %v\n", svc, err)
				}
			}
			continue
		}
		o := moduleOpts{Auto: opts.Auto || n != name, Force: opts.Force}
		if n == name {
			o.Set = opts.Set // --set applies to the module named, not its dependencies
		}
		if err := installModule(all[n], o); err != nil {
			return fmt.Errorf("module %s: %w", n, err)
		}
	}
	return nil
}

func installModule(m ModuleManifest, opts moduleOpts) error {
	fmt.Printf("==> Enabling module %s %s: %s\n", m.Name, m.Version, m.Description)
	if m.MinMemoryMB > 0 && !opts.Force {
		if mem := memTotalMB(); mem > 0 && mem < m.MinMemoryMB {
			return fmt.Errorf("needs %d MB RAM, host has %d MB (--force to override)", m.MinMemoryMB, mem)
		}
		// A new module must also fit next to what already runs (an upgrade's own use is counted).
		if st, err := loadModuleState(m.Name); err != nil || st.Status != "enabled" {
			if avail := memAvailableMB(); avail > 0 && avail < m.MinMemoryMB {
				return fmt.Errorf("needs %d MB RAM, only %d MB of %d MB is available (--force to override)", m.MinMemoryMB, avail, memTotalMB())
			}
		}
	}
	st := &ModuleState{Name: m.Name, Version: m.Version, Status: "installing", Auto: opts.Auto, Source: m.Source}
	var prevSettings map[string]string
	if prev, err := loadModuleState(m.Name); err == nil {
		// Resume after a failed attempt, or upgrade: carry over only what this manifest still
		// owns; upgradeModule removes the rest.
		st.Files = map[string]string{}
		for _, f := range m.Files {
			if sum, ok := prev.Files[modPath(f.Path)]; ok {
				st.Files[modPath(f.Path)] = sum
			}
		}
		st.Packages = intersect(prev.Packages, m.Packages)
		st.CreatedDirs = prev.CreatedDirs
		prevSettings = prev.Settings
	}
	settings, err := resolveSettings(m.Settings, prevSettings, opts.Set)
	if err != nil {
		return err
	}
	st.Settings = settings
	if err := saveModuleState(st); err != nil {
		return err
	}
	fail := func(err error) error {
		st.Status, st.Error = "failed", err.Error()
		_ = saveModuleState(st)
		alertf("medium", "module", "Module "+m.Name+" failed to enable", map[string]any{"module": m.Name, "error": err.Error()})
		return err
	}

	var missing []string
	for _, p := range m.Packages {
		if !apkInstalled(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		fmt.Printf("  installing packages: %s\n", strings.Join(missing, " "))
		if err := apkAdd(missing); err != nil {
			return fail(err)
		}
		st.Packages = uniq(append(st.Packages, missing...)) // only what this module added
	}
	secrets, err := loadOrCreateSecrets(moduleSecretsPath(m.Name), m.Secrets, nil)
	if err != nil {
		return fail(err)
	}
	vars := map[string]string{}
	for k, v := range settings {
		vars["setting."+k] = v
	}
	for k, v := range secrets {
		vars["secret."+k] = v
	}
	src := m
	if m, err = m.Render(vars); err != nil {
		return fail(err)
	}
	if err := fetchArtifacts(m, st); err != nil {
		return fail(err)
	}
	if err := ensureDirs(m, st); err != nil {
		return fail(err)
	}
	if err := writeModuleFiles(m, st); err != nil {
		return fail(err)
	}
	if len(m.Cron) > 0 {
		if err := setCron(m.Name, m.Cron); err != nil {
			return fail(err)
		}
	}
	for _, c := range m.Prepare {
		fmt.Printf("  preparing: %s %s\n", c.Exec, strings.Join(c.Args, " "))
		if _, err := moduleExec(c); err != nil {
			return fail(err)
		}
	}
	for _, s := range m.Services {
		if err := writeFileAtomic(filepath.Join(servicesDir, s.Name+".conf"), []byte(serviceConf(s)), 0644); err != nil {
			return fail(err)
		}
		st.Services = uniq(append(st.Services, s.Name))
		if err := startModuleService(s.Name); err != nil && !strings.Contains(err.Error(), "already running") {
			return fail(fmt.Errorf("start %s: %w", s.Name, err))
		}
		fmt.Printf("  started service %s\n", s.Name)
	}
	for _, c := range m.PostStart {
		if _, err := moduleExec(c); err != nil {
			return fail(err)
		}
	}
	if m.Health != nil {
		if _, err := moduleExec(*m.Health); err != nil {
			return fail(fmt.Errorf("health check: %w", err))
		}
		fmt.Println("  health check passed")
	}
	// The snapshot keeps the unrendered manifest (no secrets); secrets stay in their 0600 file.
	snap, _ := json.Marshal(src)
	if err := writeFileAtomic(manifestSnapshotPath(m.Name), snap, 0644); err != nil {
		return fail(err)
	}
	st.Status, st.Error = "enabled", ""
	if err := saveModuleState(st); err != nil {
		return err
	}
	fmt.Printf("✓ Module %s enabled\n", m.Name)
	return nil
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// requiredBy lists enabled modules (other than name) that depend on name.
func requiredBy(all map[string]ModuleManifest, enabled map[string]*ModuleState, name string) []string {
	var out []string
	for n := range enabled {
		if n == name {
			continue
		}
		m, _ := installedManifest(all, n)
		if slices.Contains(m.Requires, name) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// disableModule stops and removes a module; purge also deletes its data (the directories it
// created, its service logs).
func disableModule(name string, purge bool) error {
	all, err := loadManifests()
	if err != nil {
		return err
	}
	enabled := enabledModules()
	st := enabled[name]
	if st == nil {
		return fmt.Errorf("module %s is not enabled", name)
	}
	if deps := requiredBy(all, enabled, name); len(deps) > 0 {
		return fmt.Errorf("module %s is required by %s; disable those first", name, strings.Join(deps, ", "))
	}
	m, _ := installedManifest(all, name)
	undoModule(m, st)
	if purge {
		purgeModuleData(m, st)
	}
	delete(enabled, name)
	// Dependencies that were only enabled for this module go too.
	for _, r := range m.Requires {
		if s := enabled[r]; s != nil && s.Auto && len(requiredBy(all, enabled, r)) == 0 {
			if err := disableModule(r, purge); err != nil {
				fmt.Printf("  ! %v\n", err)
			}
		}
	}
	return nil
}

// purgeModuleData deletes the module's data: directories it created (deepest first, never a
// system directory) and its services' log files.
func purgeModuleData(m ModuleManifest, st *ModuleState) {
	dirs := append([]string(nil), st.CreatedDirs...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		if slices.Contains(nfsForbidden, d) || strings.Count(d, "/") < 2 {
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			fmt.Printf("  ! %v\n", err)
			continue
		}
		fmt.Printf("  purged %s\n", d)
	}
	for _, s := range m.Services {
		_ = os.Remove(s.LogFile)
	}
}

// undoModule reverses exactly what installModule recorded in st.
func undoModule(m ModuleManifest, st *ModuleState) {
	fmt.Printf("==> Disabling module %s\n", m.Name)
	for _, c := range m.Stop {
		if _, err := moduleExec(c); err != nil {
			fmt.Printf("  ! %v\n", err)
		}
	}
	removeFootprint(m.Name, st, ModuleManifest{Name: m.Name})
	if len(m.Cron) > 0 {
		_ = setCron(m.Name, nil)
	}
	for _, p := range []string{moduleStatePath(m.Name), manifestSnapshotPath(m.Name), moduleSecretsPath(m.Name)} {
		_ = os.Remove(p)
	}
	fmt.Printf("✓ Module %s disabled\n", m.Name)
}

// removeFootprint removes what st recorded that keep (the manifest staying installed; empty on
// disable) no longer has: services, files (unless edited by the admin), artifacts, and packages
// no other enabled module lists. Shared by disable and upgrade.
func removeFootprint(name string, st *ModuleState, keep ModuleManifest) {
	all, _ := loadManifests()
	enabled := enabledModules()
	for _, s := range st.Services {
		if slices.ContainsFunc(keep.Services, func(k ModuleService) bool { return k.Name == s }) {
			continue
		}
		_ = stopModuleService(s)
		_ = os.Remove(filepath.Join(servicesDir, s+".conf"))
		_ = os.Remove(filepath.Join(stopMarkerDir, s))
	}
	for path, sum := range st.Files {
		if slices.ContainsFunc(keep.Files, func(k ModuleFile) bool { return modPath(k.Path) == path }) {
			continue
		}
		cur, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if sha256Hex(cur) != sum {
			fmt.Printf("  ! keeping %s (modified locally)\n", path)
			continue
		}
		if orig, err := os.ReadFile(path + ".ziro-orig"); err == nil {
			_ = writeFileAtomic(path, orig, 0644)
			_ = os.Remove(path + ".ziro-orig")
		} else {
			_ = os.Remove(path)
		}
	}
	for _, p := range st.Artifacts {
		if !slices.ContainsFunc(keep.Artifacts, func(k ModuleArtifact) bool { return modPath(k.Path) == p }) {
			_ = os.Remove(p)
		}
	}
	if len(keep.Artifacts) == 0 {
		_ = os.Remove(modPath(filepath.Join(pluginRoot, name))) // only if empty
	}
	// Remove only packages this module added that nothing enabled (keep included) still lists.
	var remove []string
	for _, p := range st.Packages {
		needed := slices.Contains(keep.Packages, p)
		for n := range enabled {
			if n == name {
				continue
			}
			m, _ := installedManifest(all, n)
			needed = needed || slices.Contains(m.Packages, p)
		}
		if !needed {
			remove = append(remove, p)
		}
	}
	if len(remove) > 0 {
		if err := apkDel(remove); err != nil {
			fmt.Printf("  ! %v\n", err)
		}
	}
}

// upgradeModule installs the available (newer) manifest over an enabled module, keeping its
// settings and secrets, then removes what the old version had and the new one dropped.
func upgradeModule(name string, force bool) error {
	all, err := loadManifests()
	if err != nil {
		return err
	}
	st := enabledModules()[name]
	if st == nil {
		return fmt.Errorf("module %s is not enabled", name)
	}
	next, ok := all[name]
	if !ok {
		return fmt.Errorf("module %s is no longer in any catalog", name)
	}
	cur, _ := installedManifest(all, name)
	if next.Version == cur.Version && st.Status == "enabled" && !force {
		fmt.Printf("= module %s is up to date (%s)\n", name, cur.Version)
		return nil
	}
	for _, r := range next.Requires {
		if s := enabledModules()[r]; s == nil || s.Status != "enabled" {
			if err := enableFrom(all, r, moduleOpts{Auto: true}); err != nil {
				return err
			}
		}
	}
	old := *st
	if err := installModule(next, moduleOpts{Auto: st.Auto, Force: force}); err != nil {
		return err
	}
	if len(next.Cron) == 0 {
		_ = setCron(name, nil)
	}
	removeFootprint(name, &old, next)
	fmt.Printf("✓ Module %s upgraded %s -> %s\n", name, cur.Version, next.Version)
	return nil
}

// reconcileModules re-applies enabled modules at boot: packages vanish after an OS upgrade and
// /run is empty on every boot. Idempotent and cheap when nothing is missing.
func reconcileModules() {
	reconcileExtraPackages()
	all, err := loadManifests()
	if err != nil {
		return
	}
	for name, st := range enabledModules() {
		m, ok := installedManifest(all, name)
		if !ok || st.Status != "enabled" {
			continue
		}
		if m, err = renderInstalled(m, st); err != nil {
			fmt.Printf("[modules] %s: %v\n", name, err)
			continue
		}
		var missing []string
		for _, p := range m.Packages {
			if !apkInstalled(p) {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			fmt.Printf("[modules] %s: reinstalling %s\n", name, strings.Join(missing, " "))
			if err := apkAdd(missing); err != nil {
				fmt.Printf("[modules] %s: %v\n", name, err)
				continue
			}
		}
		if err := fetchArtifacts(m, st); err != nil {
			fmt.Printf("[modules] %s: %v\n", name, err)
		}
		if err := ensureDirs(m, nil); err != nil {
			fmt.Printf("[modules] %s: %v\n", name, err)
		}
		// Prepare steps set up what services need before they start (kernel modules, special
		// mounts); they are guarded with "creates" or harmless to repeat.
		for _, c := range m.Prepare {
			if _, err := moduleExec(c); err != nil {
				fmt.Printf("[modules] %s: %v\n", name, err)
			}
		}
		for _, s := range m.Services {
			p := filepath.Join(servicesDir, s.Name+".conf")
			if !fileExists(p) {
				_ = writeFileAtomic(p, []byte(serviceConf(s)), 0644)
			}
		}
	}
}

// renderInstalled expands an installed manifest with the settings and secrets it was enabled with.
func renderInstalled(m ModuleManifest, st *ModuleState) (ModuleManifest, error) {
	vars := map[string]string{}
	settings, err := resolveSettings(m.Settings, st.Settings, nil)
	if err != nil {
		return m, err
	}
	for k, v := range settings {
		vars["setting."+k] = v
	}
	if len(m.Secrets) > 0 {
		secrets, err := loadOrCreateSecrets(moduleSecretsPath(m.Name), m.Secrets, nil)
		if err != nil {
			return m, err
		}
		for k, v := range secrets {
			vars["secret."+k] = v
		}
	}
	return m.Render(vars)
}

// moduleBootHooks re-runs post-start steps after boot (e.g. kernel audit rules are not persistent).
func moduleBootHooks() {
	all, err := loadManifests()
	if err != nil {
		return
	}
	for name, st := range enabledModules() {
		m, ok := installedManifest(all, name)
		if !ok || st.Status != "enabled" {
			continue
		}
		if m, err = renderInstalled(m, st); err != nil {
			fmt.Printf("[modules] %s: %v\n", name, err)
			continue
		}
		for _, c := range m.PostStart {
			if _, err := moduleExec(c); err != nil {
				fmt.Printf("[modules] %s: %v\n", name, err)
			}
		}
	}
}

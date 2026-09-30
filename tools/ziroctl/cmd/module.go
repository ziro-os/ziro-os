package cmd

import (
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Modules: opt-in feature packs (security scanners, audit, ...). Nothing is preinstalled; enabling
// a module installs its packages from the pinned Alpine repositories (apk verifies signatures),
// writes hardened configuration, registers supervised services and checks health. The manifests
// are embedded in ziroctl, so they are versioned and reviewed with it and cannot be altered on a
// host. Adding a module is one JSON file in modules/ (see docs/modules.md).

//go:embed modules/*.json
var moduleFS embed.FS

var moduleStateDir = "/etc/ziro/modules"

type ModuleCmd struct {
	Exec    string   `json:"exec"` // absolute path; run without a shell
	Args    []string `json:"args,omitempty"`
	Creates string   `json:"creates,omitempty"` // skip when a file matching this glob exists
	Timeout string   `json:"timeout,omitempty"` // default 2m
	Expect  string   `json:"expect,omitempty"`  // output must contain this (health checks)
}

type ModuleService struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Exec        string `json:"exec"`
	Args        string `json:"args,omitempty"`
	PIDFile     string `json:"pidfile"`
	LogFile     string `json:"logfile"`
}

type ModuleFile struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"` // octal, e.g. "0644"
	Content string `json:"content"`
}

type ModuleDir struct {
	Path  string `json:"path"`
	Mode  string `json:"mode"`
	Owner string `json:"owner,omitempty"` // user[:group]
}

type ModuleManifest struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Requires    []string        `json:"requires,omitempty"`
	Packages    []string        `json:"packages,omitempty"`
	MinMemoryMB int             `json:"min_memory_mb,omitempty"`
	Dirs        []ModuleDir     `json:"dirs,omitempty"`
	Files       []ModuleFile    `json:"files,omitempty"`
	Cron        []string        `json:"cron,omitempty"`
	Prepare     []ModuleCmd     `json:"prepare,omitempty"`    // after files, before services
	Services    []ModuleService `json:"services,omitempty"`   // restart=always under ziro-init
	PostStart   []ModuleCmd     `json:"post_start,omitempty"` // after services start
	Stop        []ModuleCmd     `json:"stop,omitempty"`       // on disable, before services stop
	Health      *ModuleCmd      `json:"health,omitempty"`
}

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
	UpdatedAt string            `json:"updated_at"`
}

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
		var m ModuleManifest
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[m.Name] = m
	}
	return out, nil
}

func (m ModuleManifest) validate() error {
	if err := validName(m.Name); err != nil {
		return err
	}
	abs := func(p string) error {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("path %q must be absolute and clean", p)
		}
		return nil
	}
	for _, f := range m.Files {
		if err := abs(f.Path); err != nil {
			return err
		}
		if _, err := strconv.ParseUint(f.Mode, 8, 32); err != nil {
			return fmt.Errorf("file %s: bad mode %q", f.Path, f.Mode)
		}
	}
	for _, d := range m.Dirs {
		if err := abs(d.Path); err != nil {
			return err
		}
	}
	for _, c := range append(append(append(append([]ModuleCmd{}, m.Prepare...), m.PostStart...), m.Stop...), func() []ModuleCmd {
		if m.Health != nil {
			return []ModuleCmd{*m.Health}
		}
		return nil
	}()...) {
		if err := abs(c.Exec); err != nil {
			return err
		}
	}
	for _, s := range m.Services {
		if err := validName(s.Name); err != nil {
			return err
		}
		if err := abs(s.Exec); err != nil {
			return err
		}
		if err := checkServicePaths(&ServiceDef{PIDFile: s.PIDFile, LogFile: s.LogFile}); err != nil {
			return err
		}
	}
	for _, c := range m.Cron {
		if strings.ContainsAny(c, "\n\r") || len(strings.Fields(c)) < 6 {
			return fmt.Errorf("bad cron line %q", c)
		}
	}
	return nil
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
	apkDel     = func(pkgs []string) error { return runLogged(5*time.Minute, "apk", append([]string{"del"}, pkgs...)...) }
	memTotalMB = func() int {
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return 0
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var kb int
			if n, _ := fmt.Sscanf(sc.Text(), "MemTotal: %d kB", &kb); n == 1 {
				return kb / 1024
			}
		}
		return 0
	}
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

func ensureDirs(m ModuleManifest) error {
	for _, d := range m.Dirs {
		d.Path = modPath(d.Path)
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

func serviceConf(s ModuleService) string {
	return fmt.Sprintf("name=%s\ndescription=%s\nexec=%s\nargs=%s\npidfile=%s\nlogfile=%s\nautostart=true\nrestart=always\n",
		s.Name, s.Description, s.Exec, s.Args, s.PIDFile, s.LogFile)
}

// ---- enable / disable ----

// enableModule enables name and its dependencies (auto marks it as dependency-only).
func enableModule(name string, auto, force bool) error {
	all, err := loadManifests()
	if err != nil {
		return err
	}
	order, err := enableOrder(all, name)
	if err != nil {
		return err
	}
	enabled := enabledModules()
	for _, n := range order {
		if s := enabled[n]; s != nil && s.Status == "enabled" {
			if n == name && !auto && s.Auto { // explicitly enabled now: no longer dependency-only
				s.Auto = false
				_ = saveModuleState(s)
			}
			continue
		}
		if err := installModule(all[n], auto || n != name, force); err != nil {
			return fmt.Errorf("module %s: %w", n, err)
		}
	}
	return nil
}

func installModule(m ModuleManifest, auto, force bool) error {
	fmt.Printf("==> Enabling module %s %s: %s\n", m.Name, m.Version, m.Description)
	if m.MinMemoryMB > 0 && !force {
		if mem := memTotalMB(); mem > 0 && mem < m.MinMemoryMB {
			return fmt.Errorf("needs %d MB RAM, host has %d MB (--force to override)", m.MinMemoryMB, mem)
		}
	}
	st := &ModuleState{Name: m.Name, Version: m.Version, Status: "installing", Auto: auto}
	if prev, err := loadModuleState(m.Name); err == nil { // resume after a failed attempt
		st.Files, st.Packages = prev.Files, prev.Packages
	}
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
	if err := ensureDirs(m); err != nil {
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
	st.Status, st.Error = "enabled", ""
	if err := saveModuleState(st); err != nil {
		return err
	}
	fmt.Printf("✓ Module %s enabled\n", m.Name)
	return nil
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
		for _, r := range all[n].Requires {
			if r == name {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func disableModule(name string) error {
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
	m := all[name]
	undoModule(m, st)
	delete(enabled, name)
	// Dependencies that were only enabled for this module go too.
	for _, r := range m.Requires {
		if s := enabled[r]; s != nil && s.Auto && len(requiredBy(all, enabled, r)) == 0 {
			if err := disableModule(r); err != nil {
				fmt.Printf("  ! %v\n", err)
			}
		}
	}
	return nil
}

// undoModule reverses exactly what installModule recorded in st.
func undoModule(m ModuleManifest, st *ModuleState) {
	name := m.Name
	all, _ := loadManifests()
	enabled := enabledModules()
	fmt.Printf("==> Disabling module %s\n", name)
	for _, c := range m.Stop {
		if _, err := moduleExec(c); err != nil {
			fmt.Printf("  ! %v\n", err)
		}
	}
	for _, s := range st.Services {
		_ = stopModuleService(s)
		_ = os.Remove(filepath.Join(servicesDir, s+".conf"))
		_ = os.Remove(filepath.Join(stopMarkerDir, s))
	}
	if len(m.Cron) > 0 {
		_ = setCron(name, nil)
	}
	for path, sum := range st.Files {
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
	delete(enabled, name)
	// Remove only packages this module added that no other enabled module still lists.
	var remove []string
	for _, p := range st.Packages {
		needed := false
		for n := range enabled {
			for _, q := range all[n].Packages {
				needed = needed || q == p
			}
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
	_ = os.Remove(moduleStatePath(name))
	fmt.Printf("✓ Module %s disabled\n", name)
}

// reconcileModules re-applies enabled modules at boot: packages vanish after an OS upgrade and
// /run is empty on every boot. Idempotent and cheap when nothing is missing.
func reconcileModules() {
	all, err := loadManifests()
	if err != nil {
		return
	}
	for name, st := range enabledModules() {
		m, ok := all[name]
		if !ok || st.Status != "enabled" {
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
		if err := ensureDirs(m); err != nil {
			fmt.Printf("[modules] %s: %v\n", name, err)
		}
		for _, s := range m.Services {
			p := filepath.Join(servicesDir, s.Name+".conf")
			if !fileExists(p) {
				_ = writeFileAtomic(p, []byte(serviceConf(s)), 0644)
			}
		}
	}
}

// moduleBootHooks re-runs post-start steps after boot (e.g. kernel audit rules are not persistent).
func moduleBootHooks() {
	all, err := loadManifests()
	if err != nil {
		return
	}
	for name, st := range enabledModules() {
		if st.Status != "enabled" {
			continue
		}
		for _, c := range all[name].PostStart {
			if _, err := moduleExec(c); err != nil {
				fmt.Printf("[modules] %s: %v\n", name, err)
			}
		}
	}
}

// ---- CLI ----

var (
	moduleForce bool
	moduleAsync bool
)

var moduleCmd = &cobra.Command{
	Use:   "module",
	Short: "Opt-in feature modules (security packs, audit, ...): list, enable, disable",
}

type moduleInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Requires    []string `json:"requires,omitempty"`
	Status      string   `json:"status"`
	Error       string   `json:"error,omitempty"`
	Auto        bool     `json:"auto,omitempty"`
}

func listModules() ([]moduleInfo, error) {
	all, err := loadManifests()
	if err != nil {
		return nil, err
	}
	enabled := enabledModules()
	var out []moduleInfo
	for _, m := range all {
		mi := moduleInfo{Name: m.Name, Version: m.Version, Description: m.Description, Requires: m.Requires, Status: "available"}
		if s := enabled[m.Name]; s != nil {
			mi.Status, mi.Error, mi.Auto = s.Status, s.Error, s.Auto
		}
		out = append(out, mi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var moduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available and enabled modules",
	RunE: func(cmd *cobra.Command, args []string) error {
		mods, err := listModules()
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(mods)
		}
		fmt.Printf("%-12s %-8s %-12s %s\n", "MODULE", "VERSION", "STATUS", "DESCRIPTION")
		for _, m := range mods {
			st := m.Status
			if m.Auto {
				st += "*"
			}
			fmt.Printf("%-12s %-8s %-12s %s\n", m.Name, m.Version, st, m.Description)
		}
		fmt.Println("\n* enabled as a dependency. Enable one: ziroctl module enable <name>")
		return nil
	},
}

var moduleInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show what a module installs and configures",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, err := loadManifests()
		if err != nil {
			return err
		}
		m, ok := all[args[0]]
		if !ok {
			return fmt.Errorf("unknown module %q", args[0])
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(m)
		}
		fmt.Printf("%s %s: %s\n", m.Name, m.Version, m.Description)
		if len(m.Requires) > 0 {
			fmt.Printf("  requires: %s\n", strings.Join(m.Requires, ", "))
		}
		if len(m.Packages) > 0 {
			fmt.Printf("  packages: %s\n", strings.Join(m.Packages, ", "))
		}
		for _, s := range m.Services {
			fmt.Printf("  service:  %s (%s)\n", s.Name, s.Description)
		}
		for _, f := range m.Files {
			fmt.Printf("  config:   %s\n", f.Path)
		}
		for _, c := range m.Cron {
			fmt.Printf("  schedule: %s\n", c)
		}
		if m.MinMemoryMB > 0 {
			fmt.Printf("  memory:   needs %d MB RAM\n", m.MinMemoryMB)
		}
		return nil
	},
}

var moduleEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Install and configure a module (and its dependencies)",
	Example: `  ziroctl module enable clamav     # antivirus: clamd + signature updates + daily scans
  ziroctl module enable security   # the full security pack`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if moduleAsync {
			return startModuleJob("enable", args[0])
		}
		return enableModule(args[0], false, moduleForce)
	},
}

var moduleDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Stop a module and remove exactly what enabling it added",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if moduleAsync {
			return startModuleJob("disable", args[0])
		}
		return disableModule(args[0])
	},
}

var moduleReconcileCmd = &cobra.Command{
	Use:    "reconcile",
	Hidden: true,
	Short:  "Re-apply enabled modules (run at boot)",
	Run:    func(cmd *cobra.Command, args []string) { reconcileModules() },
}

// startModuleJob runs `ziroctl module <action> <name>` detached (enable can download hundreds of
// MB); progress goes to /var/log/ziro-modules.log and the module status.
func startModuleJob(action, name string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	log, err := os.OpenFile("/var/log/ziro-modules.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer log.Close()
	c := exec.Command(self, "module", action, name)
	c.Stdout, c.Stderr = log, log
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return err
	}
	fmt.Printf("Started: module %s %s (PID %d); follow /var/log/ziro-modules.log or `ziroctl module list`\n", action, name, c.Process.Pid)
	return c.Process.Release()
}

func init() {
	moduleEnableCmd.Flags().BoolVar(&moduleForce, "force", false, "Enable even if the host has less memory than the module needs")
	for _, c := range []*cobra.Command{moduleEnableCmd, moduleDisableCmd} {
		c.Flags().BoolVar(&moduleAsync, "background", false, "Run in the background and return immediately")
	}
	moduleCmd.AddCommand(moduleListCmd, moduleInfoCmd, moduleEnableCmd, moduleDisableCmd, moduleReconcileCmd)
	rootCmd.AddCommand(moduleCmd)
}

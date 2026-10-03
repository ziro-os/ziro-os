package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ziro-os/ziro-os/sdk/catalog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// CLI for modules (`ziroctl module ...`, also `ziroctl plugin ...`) and catalogs.

var (
	moduleForce bool
	moduleAsync bool
	modulePurge bool
	moduleSets  []string
	moduleFile  string
	repoKeyFile string
	repoKind    string
)

var moduleCmd = &cobra.Command{
	Use:     "module",
	Aliases: []string{"plugin", "plugins", "modules"},
	Short:   "Enable and manage plugins",
	Example: `  ziroctl module search
  ziroctl module enable clamav
  ziroctl module list`,
}

func listModules() ([]moduleInfo, error) {
	all, err := loadManifests()
	if err != nil {
		return nil, err
	}
	enabled := enabledModules()
	var out []moduleInfo
	seen := map[string]bool{}
	add := func(m ModuleManifest) {
		seen[m.Name] = true
		mi := moduleInfo{Name: m.Name, Version: m.Version, Description: m.Description, Source: m.Source, Requires: m.Requires, Status: "available"}
		if s := enabled[m.Name]; s != nil {
			im, _ := installedManifest(all, m.Name)
			mi.Version, mi.Status, mi.Error, mi.Auto = im.Version, s.Status, s.Error, s.Auto
			if s.Source != "" {
				mi.Source = s.Source
			}
			if a, ok := all[m.Name]; ok && a.Version != im.Version {
				mi.Available = a.Version
			}
		}
		out = append(out, mi)
	}
	for _, m := range all {
		add(m)
	}
	for name := range enabled { // enabled, but gone from every catalog
		if !seen[name] {
			if m, ok := installedManifest(all, name); ok {
				add(m)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// refreshStaleCatalogs refreshes catalogs older than a day before a command that looks things up.
// Offline hosts keep working from their verified cache.
func refreshStaleCatalogs(kind string) {
	repos, err := catalogRepos(kind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		return
	}
	for _, r := range repos {
		if fi, err := os.Stat(filepath.Join(repoCache(r), "index.json")); err == nil && time.Since(fi.ModTime()) < 24*time.Hour {
			continue
		}
		if _, err := refreshRepo(r); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
}

func printModules(mods []moduleInfo) {
	fmt.Printf("%-16s %-10s %-12s %-10s %s\n", "MODULE", "VERSION", "STATUS", "SOURCE", "DESCRIPTION")
	for _, m := range mods {
		st, ver := m.Status, m.Version
		if m.Auto {
			st += "*"
		}
		if m.Available != "" {
			ver += "→" + m.Available
		}
		fmt.Printf("%-16s %-10s %-12s %-10s %s\n", m.Name, ver, st, m.Source, m.Description)
	}
}

var moduleListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List available and enabled plugins",
	Example: `  ziroctl module list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mods, err := listModules()
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(mods)
		}
		printModules(mods)
		fmt.Println("\n* enabled as a dependency. Enable one: ziroctl plugin enable <name>. More: ziroctl plugin search")
		return nil
	},
}

var moduleSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search plugins by name or description",
	Example: `  ziroctl module search
  ziroctl module search antivirus`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		refreshStaleCatalogs("module")
		q := ""
		if len(args) == 1 {
			q = args[0]
		}
		hits, err := searchModules(q)
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(hits)
		}
		printModules(hits)
		return nil
	},
}

// reinstallModule installs m over an enabled module (new settings or a new manifest), then
// removes what the old one installed and the new one doesn't.
func reinstallModule(m ModuleManifest, st *ModuleState, opts moduleOpts) error {
	old := *st
	if err := installModule(m, opts); err != nil {
		return err
	}
	removeFootprint(m.Name, &old, m)
	return nil
}

// searchModules lists built-in and catalog modules whose name or description contains q.
func searchModules(q string) ([]moduleInfo, error) {
	mods, err := listModules()
	if err != nil {
		return nil, err
	}
	q = strings.ToLower(q)
	hits := []moduleInfo{}
	for _, m := range mods {
		if strings.Contains(m.Name, q) || strings.Contains(strings.ToLower(m.Description), q) {
			hits = append(hits, m)
		}
	}
	return hits, nil
}

var moduleUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Refresh the signed catalogs",
	Example: `  ziroctl module update`,
	RunE: func(cmd *cobra.Command, args []string) error {
		repos, err := catalogRepos("")
		if err != nil {
			return err
		}
		var failed []string
		for _, r := range repos {
			idx, err := refreshRepo(r)
			if err != nil {
				fmt.Printf("✗ %s: %v\n", r.Name, err)
				failed = append(failed, r.Name)
				continue
			}
			fmt.Printf("✓ %s: %d %ss (serial %d, valid until %s)\n", r.Name, len(idx.Entries), r.Kind, idx.Serial, idx.Expires.Format("2006-01-02"))
		}
		if len(failed) > 0 {
			return fmt.Errorf("could not refresh: %s", strings.Join(failed, ", "))
		}
		return nil
	},
}

var moduleInfoCmd = &cobra.Command{
	Use:     "info <name>",
	Short:   "Show what a plugin installs and configures",
	Example: `  ziroctl module info clamav`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, err := loadManifests()
		if err != nil {
			return err
		}
		m, ok := installedManifest(all, args[0])
		if !ok {
			return fmt.Errorf("unknown module %q (try: ziroctl plugin search)", args[0])
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(m)
		}
		fmt.Printf("%s %s: %s\n  source:   %s\n", m.Name, m.Version, m.Description, m.Source)
		if len(m.Requires) > 0 {
			fmt.Printf("  requires: %s\n", strings.Join(m.Requires, ", "))
		}
		if len(m.Packages) > 0 {
			fmt.Printf("  packages: %s\n", strings.Join(m.Packages, ", "))
		}
		for _, a := range m.Artifacts {
			fmt.Printf("  artifact: %s (sha256 %s…)\n", a.Path, a.SHA256[:12])
		}
		for _, s := range m.Services {
			u := s.User
			if u == "" {
				u = "root"
			}
			fmt.Printf("  service:  %s as %s (%s)\n", s.Name, u, s.Description)
		}
		for _, f := range m.Files {
			fmt.Printf("  config:   %s\n", f.Path)
		}
		for _, c := range m.Cron {
			fmt.Printf("  schedule: %s\n", c)
		}
		for _, s := range m.Settings {
			fmt.Printf("  setting:  %s=%s  %s\n", s.Name, s.Default, s.Description)
		}
		if m.MinMemoryMB > 0 {
			fmt.Printf("  memory:   needs %d MB RAM\n", m.MinMemoryMB)
		}
		return nil
	},
}

var moduleEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Install and configure a plugin",
	Example: `  ziroctl plugin enable clamav                     # antivirus: clamd + signature updates + daily scans
  ziroctl plugin enable security                   # the full security pack
  ziroctl plugin enable s3-ziro --set capacity=50G # S3-compatible storage (from ziro-os/pkgs)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		set, err := parseSetFlags(moduleSets)
		if err != nil {
			return err
		}
		if moduleAsync {
			return startModuleJob(append([]string{"enable", args[0]}, setArgs(moduleSets)...)...)
		}
		all, err := loadManifests()
		if err != nil {
			return err
		}
		if _, ok := all[args[0]]; !ok {
			refreshStaleCatalogs("module")
		}
		return enableModule(args[0], moduleOpts{Force: moduleForce, Set: set})
	},
}

func setArgs(sets []string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, "--set", s)
	}
	return out
}

var moduleInstallCmd = &cobra.Command{
	Use:     "install -f <manifest.json>",
	Short:   "Enable an unsigned plugin from a local manifest",
	Example: `  ziroctl module install -f ./redis-exporter/manifest.json`,
	Long: `Enables a module from a manifest file on this host. It is validated like catalog modules but
not signed: use it to develop and test a plugin before publishing it to a catalog.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := os.ReadFile(moduleFile)
		if err != nil {
			return err
		}
		m, err := parseManifest(b)
		if err != nil {
			return fmt.Errorf("%s: %w", moduleFile, err)
		}
		all, err := loadManifests()
		if err != nil {
			return err
		}
		if prev, ok := all[m.Name]; ok && prev.Source != "local" {
			if st := enabledModules()[m.Name]; st == nil || st.Source != "local" {
				return fmt.Errorf("%s is provided by %s; rename the local plugin", m.Name, prev.Source)
			}
		}
		fmt.Fprintf(os.Stderr, "WARNING: %s is an unsigned local manifest; it runs as root. Only install plugins you reviewed.\n", moduleFile)
		set, err := parseSetFlags(moduleSets)
		if err != nil {
			return err
		}
		m.Source = "local"
		all[m.Name] = m
		if st := enabledModules()[m.Name]; st != nil && st.Status == "enabled" {
			return reinstallModule(m, st, moduleOpts{Auto: st.Auto, Force: moduleForce, Set: set})
		}
		return enableFrom(all, m.Name, moduleOpts{Force: moduleForce, Set: set})
	},
}

var moduleUpgradeCmd = &cobra.Command{
	Use:   "upgrade [name...]",
	Short: "Upgrade enabled plugins to the catalog version",
	Example: `  ziroctl module upgrade
  ziroctl module upgrade clamav`,
	RunE: func(cmd *cobra.Command, args []string) error {
		refreshStaleCatalogs("module")
		if len(args) == 0 {
			for n := range enabledModules() {
				args = append(args, n)
			}
			sort.Strings(args)
		}
		if moduleAsync {
			return startModuleJob(append([]string{"upgrade"}, args...)...)
		}
		var errs []error
		for _, n := range args {
			if err := upgradeModule(n, moduleForce); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", n, err))
			}
		}
		return errors.Join(errs...)
	},
}

var moduleDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable a plugin and undo what it added",
	Example: `  ziroctl module disable clamav
  ziroctl module disable clamav --purge`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDisable(args[0], modulePurge)
	},
}

var modulePurgeCmd = &cobra.Command{
	Use:     "purge <name>",
	Short:   "Disable a plugin and delete its data",
	Example: `  ziroctl module purge clamav`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDisable(args[0], true)
	},
}

func runDisable(name string, purge bool) error {
	if moduleAsync {
		args := []string{"disable", name}
		if purge {
			args = append(args, "--purge")
		}
		return startModuleJob(args...)
	}
	return disableModule(name, purge)
}

// moduleValidateCmd is `dev validate` (schema + lints) under its older name.
var moduleValidateCmd = &cobra.Command{
	Use:     "validate <manifest.json...>",
	Short:   "Check plugin manifests against the schema",
	Example: `  ziroctl module validate ./redis-exporter/manifest.json`,
	Args:    cobra.MinimumNArgs(1),
	RunE:    func(cmd *cobra.Command, args []string) error { return devValidateCmd.RunE(cmd, args) },
}

var moduleNewCmd = &cobra.Command{
	Use:     "new <name>",
	Short:   "Scaffold a plugin manifest",
	Example: `  ziroctl module new redis-exporter`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := validName(name); err != nil {
			return err
		}
		m := scaffoldPlugin(name)
		if err := m.Validate(); err != nil {
			return err
		}
		p := filepath.Join(name, "manifest.json")
		if fileExists(p) {
			return fmt.Errorf("%s exists", p)
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.MkdirAll(name, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(p, append(b, '\n'), 0644); err != nil {
			return err
		}
		fmt.Printf("Created %s. Try it: ziroctl plugin install -f %s; publish it: see docs/modules.md\n", p, p)
		return nil
	},
}

var moduleReconcileCmd = &cobra.Command{
	Use:    "reconcile",
	Hidden: true,
	Short:  "Re-apply enabled modules (run at boot)",
	Run:    func(cmd *cobra.Command, args []string) { reconcileModules() },
}

// ---- catalog repositories ----

var moduleRepoCmd = &cobra.Command{Use: "repo", Short: "Manage third-party catalogs", Example: "  ziroctl module repo add acme https://acme.github.io/ziro-catalog --key acme.pub\n  ziroctl module repo list"}

var moduleRepoListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List catalogs",
	Example: `  ziroctl module repo list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		repos, err := catalogRepos("")
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(repos)
		}
		for _, r := range repos {
			state := "not fetched (ziroctl plugin update)"
			if idx, err := readCachedIndex(r); err == nil {
				state = fmt.Sprintf("%d entries, valid until %s", len(idx.Entries), idx.Expires.Format("2006-01-02"))
			} else if !os.IsNotExist(err) {
				state = "error: " + err.Error()
			}
			tag := ""
			if r.Official {
				tag = " (official)"
			}
			fmt.Printf("%-14s %-6s %s%s\n    %s\n", r.Name, r.Kind, r.URL, tag, state)
		}
		return nil
	},
}

var moduleRepoAddCmd = &cobra.Command{
	Use:   "add <name> <https-url> --key <ed25519-public.pem>",
	Short: "Trust a third-party catalog signed with a key",
	Example: `  ziroctl module repo add acme https://acme.github.io/ziro-catalog --key acme.pub
  ziroctl module repo add acme-apps https://acme.github.io/ziro-apps --key acme.pub --kind app`,
	Long: `Adds a catalog repository. Its index must be signed with the ed25519 key given here. A module
from it runs as root when enabled, so add only publishers you trust. It can't replace built-in or
official modules and apps.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := os.ReadFile(repoKeyFile)
		if err != nil {
			return err
		}
		r := CatalogRepo{Name: args[0], URL: strings.TrimSuffix(args[1], "/"), Key: string(key), Kind: repoKind}
		if err := r.Validate(); err != nil {
			return err
		}
		repos, err := loadExtraRepos()
		if err != nil {
			return err
		}
		for _, o := range officialRepos {
			if o.Name == r.Name {
				return fmt.Errorf("%s is an official repository name", r.Name)
			}
		}
		for _, o := range repos {
			if o.Name == r.Name {
				return fmt.Errorf("repository %s exists (remove it first)", r.Name)
			}
		}
		if _, err := refreshRepo(r); err != nil {
			return err
		}
		if err := saveExtraRepos(append(repos, r)); err != nil {
			return err
		}
		fmt.Printf("✓ Added %s (%s)\n", r.Name, r.URL)
		return nil
	},
}

var moduleRepoRmCmd = &cobra.Command{
	Use:     "rm <name>",
	Short:   "Stop trusting a catalog",
	Example: `  ziroctl module repo rm acme`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repos, err := loadExtraRepos()
		if err != nil {
			return err
		}
		var kept []CatalogRepo
		for _, r := range repos {
			if r.Name != args[0] {
				kept = append(kept, r)
			}
		}
		if len(kept) == len(repos) {
			return fmt.Errorf("no third-party repository %q", args[0])
		}
		if err := saveExtraRepos(kept); err != nil {
			return err
		}
		_ = os.RemoveAll(filepath.Join(catalogDir, args[0]))
		fmt.Printf("✓ Removed %s\n", args[0])
		return nil
	},
}

// ---- building catalogs (repository CI) ----

var (
	catalogOut  string
	catalogRepo string
	catalogKind string
	catalogTTL  time.Duration
	catalogKey  string
)

// catalogCheckers validate one definition of a kind and describe it for the index.
var catalogCheckers = map[string]func([]byte) (CatalogEntry, error){
	"module": func(b []byte) (CatalogEntry, error) {
		m, err := parseManifest(b)
		return CatalogEntry{Name: m.Name, Version: m.Version, Description: m.Description}, err
	},
}

var catalogCmd = &cobra.Command{Use: "catalog", Short: "Build, sign and verify catalogs in CI", Example: "  ziroctl catalog build . --kind app --repo acme --out public\n  ziroctl catalog sign public"}

var catalogBuildCmd = &cobra.Command{
	Use:   "build <src-dir>",
	Short: "Validate definitions and write a catalog index",
	Example: `  ziroctl catalog build . --repo acme --out public
  ziroctl catalog build . --kind app --repo acme --out public`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		check := catalogCheckers[catalogKind]
		if check == nil {
			return fmt.Errorf("unknown kind %q", catalogKind)
		}
		idx, err := catalog.Build(args[0], catalogOut, catalogRepo, catalogKind, catalogTTL, catalogNow(), check)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %d %ss, serial %d, expires %s\n", len(idx.Entries), catalogKind, idx.Serial, idx.Expires.Format(time.RFC3339))
		return nil
	},
}

var catalogSignCmd = &cobra.Command{
	Use:     "sign <out-dir>",
	Short:   "Sign a built catalog with $ZIRO_CATALOG_KEY",
	Example: `  ZIRO_CATALOG_KEY="$(cat acme.key)" ziroctl catalog sign public`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := os.Getenv("ZIRO_CATALOG_KEY")
		if key == "" {
			return errors.New("ZIRO_CATALOG_KEY is not set")
		}
		return catalog.Sign(args[0], []byte(key))
	},
}

var catalogVerifyCmd = &cobra.Command{
	Use:     "verify <out-dir>",
	Short:   "Verify a built catalog against a public key",
	Example: `  ziroctl catalog verify public --key acme.pub --repo acme`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := os.ReadFile(catalogKey)
		if err != nil {
			return err
		}
		r := CatalogRepo{Name: catalogRepo, Kind: catalogKind, Key: string(key)}
		raw, err := os.ReadFile(filepath.Join(args[0], "index.json"))
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(filepath.Join(args[0], "index.json.sig"))
		if err != nil {
			return err
		}
		idx, err := verifyIndex(r, raw, sig)
		if err != nil {
			return err
		}
		for _, e := range idx.Entries {
			b, err := os.ReadFile(filepath.Join(args[0], e.Path))
			if err != nil || sha256Hex(b) != e.SHA256 {
				return fmt.Errorf("%s: missing or sha256 mismatch", e.Path)
			}
		}
		fmt.Printf("✓ %d entries verified\n", len(idx.Entries))
		return nil
	},
}

// startModuleJob runs `ziroctl module <args>` detached (enable can download hundreds of MB);
// progress goes to /var/log/ziro-modules.log and the module status.
func startModuleJob(args ...string) error {
	return startJob(append([]string{"module"}, args...), "/var/log/ziro-modules.log")
}

// startJob runs `ziroctl <args>` in its own session (it outlives an API request or a closed
// terminal), appending its output to logPath. args are argv, never a shell string.
func startJob(args []string, logPath string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer log.Close()
	c := exec.Command(self, args...)
	c.Stdout, c.Stderr = log, log
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return err
	}
	fmt.Printf("Started: %s (PID %d); follow %s\n", strings.Join(args, " "), c.Process.Pid, logPath)
	return c.Process.Release()
}

func init() {
	moduleEnableCmd.Flags().BoolVar(&moduleForce, "force", false, "Enable even if the host has less memory than the module needs")
	moduleUpgradeCmd.Flags().BoolVar(&moduleForce, "force", false, "Reinstall even when the version is unchanged")
	moduleInstallCmd.Flags().BoolVar(&moduleForce, "force", false, "Install even if the host has less memory than the module needs")
	for _, c := range []*cobra.Command{moduleEnableCmd, moduleInstallCmd} {
		c.Flags().StringArrayVar(&moduleSets, "set", nil, "Set a module setting (name=value; see `plugin info`)")
	}
	moduleDisableCmd.Flags().BoolVar(&modulePurge, "purge", false, "Also delete the module's data (directories it created, logs, secrets)")
	for _, c := range []*cobra.Command{moduleEnableCmd, moduleDisableCmd, modulePurgeCmd, moduleUpgradeCmd} {
		c.Flags().BoolVar(&moduleAsync, "background", false, "Run in the background and return immediately")
	}
	moduleInstallCmd.Flags().StringVarP(&moduleFile, "file", "f", "", "Manifest file")
	_ = moduleInstallCmd.MarkFlagRequired("file")
	moduleRepoAddCmd.Flags().StringVar(&repoKeyFile, "key", "", "ed25519 public key (PEM) the catalog is signed with")
	moduleRepoAddCmd.Flags().StringVar(&repoKind, "kind", "module", "Catalog kind: module or app")
	_ = moduleRepoAddCmd.MarkFlagRequired("key")
	moduleRepoCmd.AddCommand(moduleRepoListCmd, moduleRepoAddCmd, moduleRepoRmCmd)
	moduleCmd.AddCommand(moduleListCmd, moduleSearchCmd, moduleUpdateCmd, moduleInfoCmd, moduleEnableCmd, moduleInstallCmd,
		moduleUpgradeCmd, moduleDisableCmd, modulePurgeCmd, moduleValidateCmd, moduleNewCmd, moduleRepoCmd, moduleReconcileCmd)
	rootCmd.AddCommand(moduleCmd)

	for _, c := range []*cobra.Command{catalogBuildCmd, catalogVerifyCmd} {
		c.Flags().StringVar(&catalogRepo, "repo", "", "Repository name")
		c.Flags().StringVar(&catalogKind, "kind", "module", "module or app")
		_ = c.MarkFlagRequired("repo")
	}
	catalogBuildCmd.Flags().StringVar(&catalogOut, "out", "public", "Output directory")
	catalogBuildCmd.Flags().DurationVar(&catalogTTL, "ttl", 30*24*time.Hour, "How long hosts accept the index")
	catalogVerifyCmd.Flags().StringVar(&catalogKey, "key", "", "ed25519 public key (PEM)")
	_ = catalogVerifyCmd.MarkFlagRequired("key")
	catalogCmd.AddCommand(catalogBuildCmd, catalogSignCmd, catalogVerifyCmd)
	rootCmd.AddCommand(catalogCmd)
}

// scaffoldPlugin is a small, valid plugin to start from: a static web server as an unprivileged user.
func scaffoldPlugin(name string) ModuleManifest {
	return ModuleManifest{
		Name: name, Version: "0.1.0", Description: "What " + name + " does, in one line",
		Packages: []string{"busybox-extras"},
		Settings: []Setting{{Name: "port", Description: "listen port", Default: "8080", Pattern: `^[0-9]{2,5}$`}},
		Dirs:     []ModuleDir{{Path: "/var/lib/" + name, Mode: "0750", Owner: "nobody:nobody"}},
		Files:    []ModuleFile{{Path: "/var/lib/" + name + "/index.html", Mode: "0644", Content: "hello from " + name + "\n"}},
		Services: []ModuleService{{Name: name, Description: name + " daemon", Exec: "/usr/sbin/httpd",
			Args: "-f -p 127.0.0.1:{{setting.port}} -h /var/lib/" + name, User: "nobody",
			PIDFile: "/run/ziro-" + name + ".pid", LogFile: "/var/log/" + name + ".log"}},
		Health: &ModuleCmd{Exec: "/usr/bin/wget", Args: []string{"-qO-", "http://127.0.0.1:{{setting.port}}/"}, Expect: "hello", Timeout: "30s"},
	}
}

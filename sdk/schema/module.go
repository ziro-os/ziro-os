// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type ModuleCmd struct {
	Exec    string   `json:"exec"` // absolute path; run without a shell
	Args    []string `json:"args,omitempty"`
	Creates string   `json:"creates,omitempty"` // skip when a file matching this glob exists
	Timeout string   `json:"timeout,omitempty"` // default 2m
	Expect  string   `json:"expect,omitempty"`  // output must contain this (health checks)
}

// ModuleService is a supervised daemon (/etc/ziro/services/<name>.conf, restart=always). User runs
// it unprivileged; EnvFile (root-owned, not world-readable) passes it secrets outside argv.
type ModuleService = ServiceDef

type ModuleFile struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`            // octal, e.g. "0644"
	Owner   string `json:"owner,omitempty"` // user[:group]; e.g. root:garage with 0640 for a daemon's config
	Content string `json:"content"`
}

type ModuleDir struct {
	Path  string `json:"path"`
	Mode  string `json:"mode"`
	Owner string `json:"owner,omitempty"` // user[:group]
}

// ModuleArtifact is a file that isn't an Alpine package (a static binary, a helper script),
// downloaded over https and checked against its sha256. It lives under /var/lib/ziro/plugins/<name>/
// (kept across OS upgrades) and is removed on disable.
type ModuleArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Arch   string `json:"arch,omitempty"` // x86_64 or aarch64; empty for any
}

type ModuleManifest struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Source      string            `json:"source,omitempty"` // set when loaded: builtin, a repo name, or local
	Requires    []string          `json:"requires,omitempty"`
	Packages    []string          `json:"packages,omitempty"`
	MinMemoryMB int               `json:"min_memory_mb,omitempty"`
	Settings    []Setting         `json:"settings,omitempty"` // --set name=value; {{setting.name}}
	Secrets     map[string]string `json:"secrets,omitempty"`  // name -> hex:N|base64:N|alnum:N; {{secret.name}}
	Artifacts   []ModuleArtifact  `json:"artifacts,omitempty"`
	Dirs        []ModuleDir       `json:"dirs,omitempty"`
	Files       []ModuleFile      `json:"files,omitempty"`
	Cron        []string          `json:"cron,omitempty"`
	Prepare     []ModuleCmd       `json:"prepare,omitempty"`    // after files, before services
	Services    []ModuleService   `json:"services,omitempty"`   // restart=always under ziro-init
	PostStart   []ModuleCmd       `json:"post_start,omitempty"` // after services start
	Stop        []ModuleCmd       `json:"stop,omitempty"`       // on disable, before services stop
	Health      *ModuleCmd        `json:"health,omitempty"`
}

// ParseManifest decodes strictly (unknown fields are errors: a typo must not silently drop a
// hardening setting) and validates.
func ParseManifest(b []byte) (ModuleManifest, error) {
	var m ModuleManifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, err
	}
	return m, m.Validate()
}

func (m ModuleManifest) Validate() error {
	if err := ValidName(m.Name); err != nil {
		return err
	}
	abs := func(p string) error {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("path %q must be absolute and clean", p)
		}
		return nil
	}
	if err := ValidateSettings(m.Settings); err != nil {
		return err
	}
	for k, spec := range m.Secrets {
		if !SettingNameRe.MatchString(k) {
			return fmt.Errorf("secret %q: bad name", k)
		}
		if err := ValidSecretSpec(spec); err != nil {
			return err
		}
	}
	for _, p := range m.Packages {
		if !APKNameRe.MatchString(p) {
			return fmt.Errorf("bad package name %q", p)
		}
	}
	for _, r := range m.Requires {
		if err := ValidName(r); err != nil {
			return err
		}
	}
	pluginDir := filepath.Join(PluginRoot, m.Name) + "/"
	for _, a := range m.Artifacts {
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("artifact %s: URL must be https", a.Path)
		}
		if len(a.SHA256) != 64 || strings.Trim(a.SHA256, "0123456789abcdef") != "" {
			return fmt.Errorf("artifact %s: sha256 must be 64 lowercase hex digits", a.Path)
		}
		if err := abs(a.Path); err != nil || !strings.HasPrefix(a.Path, pluginDir) {
			return fmt.Errorf("artifact path %q must be under %s", a.Path, pluginDir)
		}
		if mode, err := strconv.ParseUint(a.Mode, 8, 32); err != nil || mode&0o022 != 0 {
			return fmt.Errorf("artifact %s: mode %q must be octal and not group/world-writable", a.Path, a.Mode)
		}
		if a.Arch != "" && a.Arch != "x86_64" && a.Arch != "aarch64" {
			return fmt.Errorf("artifact %s: arch must be x86_64 or aarch64", a.Path)
		}
	}
	vars := m.PlaceholderNames()
	for _, f := range m.Files {
		if err := abs(f.Path); err != nil {
			return err
		}
		mode, err := strconv.ParseUint(f.Mode, 8, 32)
		if err != nil {
			return fmt.Errorf("file %s: bad mode %q", f.Path, f.Mode)
		}
		if _, err := Expand(f.Content, vars); err != nil {
			return fmt.Errorf("file %s: %w", f.Path, err)
		}
		if UsesSecret(f.Content) && mode&0o007 != 0 {
			return fmt.Errorf("file %s holds secrets: mode %s must not give others access", f.Path, f.Mode)
		}
	}
	// Secrets go into files (0600/0640) or env files, never argv or crontabs (visible in ps).
	noSecret := func(what, s string) error {
		if UsesSecret(s) {
			return fmt.Errorf("%s: secrets can't be passed on a command line (use a file or env_file)", what)
		}
		if _, err := Expand(s, vars); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
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
		for _, a := range c.Args {
			if err := noSecret(c.Exec, a); err != nil {
				return err
			}
		}
	}
	for _, s := range m.Services {
		if err := noSecret("service "+s.Name, s.Args); err != nil {
			return err
		}
		if s.User != "" && !UserNameRe.MatchString(s.User) {
			return fmt.Errorf("service %s: bad user %q", s.Name, s.User)
		}
		if err := s.Resources.Validate(); err != nil {
			return fmt.Errorf("service %s: %w", s.Name, err)
		}
		if s.EnvFile != "" {
			if err := abs(s.EnvFile); err != nil {
				return err
			}
		}
		if err := ValidName(s.Name); err != nil {
			return err
		}
		if err := abs(s.Exec); err != nil {
			return err
		}
		if err := CheckServicePaths(&ServiceDef{PIDFile: s.PIDFile, LogFile: s.LogFile}); err != nil {
			return err
		}
	}
	for _, c := range m.Cron {
		if strings.ContainsAny(c, "\n\r") || len(strings.Fields(c)) < 6 {
			return fmt.Errorf("bad cron line %q", c)
		}
		if err := noSecret("cron", c); err != nil {
			return err
		}
	}
	return nil
}

var (
	APKNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)
	UserNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	PluginRoot = "/var/lib/ziro/plugins"
)

func UsesSecret(s string) bool {
	for _, m := range PlaceholderRe.FindAllStringSubmatch(s, -1) {
		if strings.HasPrefix(m[1], "secret.") {
			return true
		}
	}
	return false
}

// PlaceholderNames lists the placeholders a manifest may use (values empty: for validation).
func (m ModuleManifest) PlaceholderNames() map[string]string {
	v := map[string]string{}
	for _, s := range m.Settings {
		v["setting."+s.Name] = s.Default
	}
	for k := range m.Secrets {
		v["secret."+k] = "x"
	}
	return v
}

// Render expands placeholders in everything an install writes or runs.
func (m ModuleManifest) Render(vars map[string]string) (ModuleManifest, error) {
	var err error
	ex := func(s string) string {
		if err != nil {
			return s
		}
		var out string
		out, err = Expand(s, vars)
		return out
	}
	r := m
	r.Files = append([]ModuleFile(nil), m.Files...)
	for i := range r.Files {
		r.Files[i].Content = ex(r.Files[i].Content)
	}
	r.Cron = append([]string(nil), m.Cron...)
	for i := range r.Cron {
		r.Cron[i] = ex(r.Cron[i])
		if strings.ContainsAny(r.Cron[i], "\n\r") {
			return r, errors.New("cron line contains a newline after expansion")
		}
	}
	r.Services = append([]ModuleService(nil), m.Services...)
	for i := range r.Services {
		r.Services[i].Args = ex(r.Services[i].Args)
	}
	cmds := func(in []ModuleCmd) []ModuleCmd {
		out := append([]ModuleCmd(nil), in...)
		for i := range out {
			out[i].Args = append([]string(nil), out[i].Args...)
			for j := range out[i].Args {
				out[i].Args[j] = ex(out[i].Args[j])
			}
		}
		return out
	}
	r.Prepare, r.PostStart, r.Stop = cmds(m.Prepare), cmds(m.PostStart), cmds(m.Stop)
	if m.Health != nil {
		h := cmds([]ModuleCmd{*m.Health})[0]
		r.Health = &h
	}
	return r, err
}

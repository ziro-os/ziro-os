// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

// Package schema defines Ziro OS's declarative formats (plugin manifests, app definitions, gateway
// routes, supervised services) and validates them. ziroctl validates with exactly this code at every
// trust boundary (CLI, API, catalog CI, host).
package schema

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type ServiceDef struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Exec        string     `json:"exec"`
	Args        string     `json:"args"`
	PIDFile     string     `json:"pidfile"`
	LogFile     string     `json:"logfile"`
	Check       string     `json:"check,omitempty"`     // args that make exec Validate its config (sshd: -t)
	User        string     `json:"user,omitempty"`      // run as this user (and its primary group) instead of root
	Caps        []string   `json:"caps,omitempty"`      // Linux capabilities the unprivileged user keeps (see ServiceCaps); everything else is dropped
	EnvFile     string     `json:"env_file,omitempty"`  // KEY=VALUE lines added to the environment (root-owned, not world-readable)
	Resources   *Resources `json:"resources,omitempty"` // cgroup limits for the service
	Restart     string     `json:"restart,omitempty"`   // always, on-failure: ziro-init restarts it (with backoff)
	Autostart   bool       `json:"autostart"`
}

// ServiceCaps are the capabilities a service may keep (name -> Linux capability number). The
// list is deliberately short: each entry is a privilege a module can ask for, so adding one is
// a security review. Anything that allows loading code, ptrace, raw disk access, ownership or
// permission overrides, or becoming root (sys_admin, sys_module, sys_rawio, sys_ptrace,
// dac_override, setuid, setgid, ...) is not available to services.
var ServiceCaps = map[string]int{
	"net_bind_service": 10,
	"net_admin":        12,
	"net_raw":          13,
}

// ValidateCaps checks a service's capability list: known names, no duplicates, and only for a
// service that runs as an unprivileged user (a root service has every capability anyway).
func (s *ServiceDef) ValidateCaps() error {
	if len(s.Caps) == 0 {
		return nil
	}
	if s.User == "" || s.User == "root" {
		return fmt.Errorf("service %s: caps need an unprivileged \"user\"", s.Name)
	}
	seen := map[string]bool{}
	for _, c := range s.Caps {
		if _, ok := ServiceCaps[c]; !ok {
			return fmt.Errorf("service %s: capability %q is not available to services (allowed: net_admin, net_bind_service, net_raw)", s.Name, c)
		}
		if seen[c] {
			return fmt.Errorf("service %s: capability %q listed twice", s.Name, c)
		}
		seen[c] = true
	}
	return nil
}

// ValidName guards every user-supplied identifier that ends up in a file path.
var NameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func ValidName(name string) error {
	if !NameRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid name %q (allowed: a-z 0-9 _ . -)", name)
	}
	return nil
}

// CheckServicePaths keeps a definition's pid and log files where ziroctl and ziro-init expect
// them (both delete or truncate these paths as root).
func CheckServicePaths(def *ServiceDef) error {
	for _, c := range []struct{ path, dir string }{{def.PIDFile, "/run/"}, {def.LogFile, "/var/log/"}} {
		if c.path != "" && (!strings.HasPrefix(c.path, c.dir) || strings.Contains(c.path, "..")) {
			return fmt.Errorf("%q must be under %s", c.path, c.dir)
		}
	}
	return nil
}

// ValidateDataPaths: absolute, clean, not "/", and nothing nerdctl -v would misparse.
func ValidateDataPaths(paths []string) error {
	if len(paths) > 8 {
		return errors.New("too many data paths (max 8)")
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsAny(p, ":,\x00\n") || len(p) > 256 {
			return fmt.Errorf("invalid data path %q", p)
		}
	}
	return nil
}

// EnvKeyRe: a valid environment variable name.
var EnvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

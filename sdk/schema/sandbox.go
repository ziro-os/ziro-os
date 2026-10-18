package schema

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// SandboxSpec is a sandbox to create: an isolated, disposable machine for running untrusted code
// (an AI agent's tools, a code interpreter, a CI step). Everything about isolation that the caller
// can't loosen (capabilities, mounts, devices, the network default) is decided by the host, not
// here; the spec only picks what runs and how big it may get.
type SandboxSpec struct {
	Image       string            `json:"image"`
	Runtime     string            `json:"runtime,omitempty"`      // gvisor (default) or runc (operator + host opt-in)
	Command     []string          `json:"command,omitempty"`      // default: keep the sandbox up (sleep infinity)
	Env         map[string]string `json:"env,omitempty"`          // plain values: visible to anyone who can inspect the sandbox
	User        string            `json:"user,omitempty"`         // uid[:gid] inside the sandbox (default: the image's user)
	Workdir     string            `json:"workdir,omitempty"`      // default /workspace
	Resources   *Resources        `json:"resources,omitempty"`    // default and maximum come from the host config
	Timeout     string            `json:"timeout,omitempty"`      // lifetime, e.g. 30m (default and maximum from the host config)
	IdleTimeout string            `json:"idle_timeout,omitempty"` // delete after this long without an exec (default: off)
	Metadata    map[string]string `json:"metadata,omitempty"`     // caller's labels (agent, task id, ...)
}

// Sandbox runtimes.
const (
	SandboxGVisor = "gvisor"
	SandboxRunc   = "runc"
)

var (
	// SandboxImageRe: an image reference that can't be read as a flag (registry/name[:tag][@sha256:...]).
	SandboxImageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]{0,255}$`)
	sandboxUserRe  = regexp.MustCompile(`^[0-9]{1,10}(:[0-9]{1,10})?$`)
	metadataKeyRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,62}$`)
)

func (s *SandboxSpec) Validate() error {
	if !SandboxImageRe.MatchString(s.Image) {
		return fmt.Errorf("bad image %q", s.Image)
	}
	switch s.Runtime {
	case "", SandboxGVisor, SandboxRunc:
	default:
		return fmt.Errorf("runtime must be %s or %s", SandboxGVisor, SandboxRunc)
	}
	if len(s.Command) > 64 {
		return errors.New("command: at most 64 arguments")
	}
	for _, a := range s.Command {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return errors.New("command: arguments must be under 4 KiB, without NUL")
		}
	}
	if err := ValidateSandboxEnv(s.Env); err != nil {
		return err
	}
	if s.User != "" && !sandboxUserRe.MatchString(s.User) {
		return fmt.Errorf("user must be uid or uid:gid, not %q", s.User)
	}
	if s.Workdir != "" && (!path.IsAbs(s.Workdir) || path.Clean(s.Workdir) != s.Workdir || len(s.Workdir) > 256) {
		return fmt.Errorf("workdir must be a clean absolute path")
	}
	if err := s.Resources.Validate(); err != nil {
		return err
	}
	for _, d := range []string{s.Timeout, s.IdleTimeout} {
		if d == "" {
			continue
		}
		if v, err := time.ParseDuration(d); err != nil || v < time.Minute {
			return fmt.Errorf("bad duration %q (at least 1m)", d)
		}
	}
	return ValidateSandboxMetadata(s.Metadata)
}

// ValidateSandboxEnv checks env names and sizes (also used by exec requests).
func ValidateSandboxEnv(env map[string]string) error {
	if len(env) > 128 {
		return errors.New("env: at most 128 variables")
	}
	for k, v := range env {
		if !EnvKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
			return fmt.Errorf("bad env name %q", k)
		}
		if len(v) > 32<<10 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("env %s: value must be under 32 KiB, without NUL", k)
		}
	}
	return nil
}

func ValidateSandboxMetadata(m map[string]string) error {
	if len(m) > 32 {
		return errors.New("metadata: at most 32 keys")
	}
	for k, v := range m {
		if !metadataKeyRe.MatchString(k) {
			return fmt.Errorf("bad metadata key %q (lowercase, digits, . _ / -)", k)
		}
		if len(v) > 512 {
			return fmt.Errorf("metadata %s: value over 512 bytes", k)
		}
	}
	return nil
}

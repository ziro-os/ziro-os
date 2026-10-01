// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

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

func ParseAppDef(b []byte) (AppDef, error) {
	var d AppDef
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, d.Validate()
}

func (d AppDef) Validate() error {
	if d.Schema != 1 {
		return fmt.Errorf("unsupported app schema %d", d.Schema)
	}
	if err := ValidName(d.Name); err != nil {
		return err
	}
	if len(d.Components) == 0 || len(d.Components) > 8 {
		return errors.New("an app needs 1..8 components")
	}
	if _, ok := d.Versions[d.Default]; !ok {
		return fmt.Errorf("default version %q is not in versions", d.Default)
	}
	if err := ValidateSettings(d.Settings); err != nil {
		return err
	}
	for k, spec := range d.Secrets {
		if !EnvKeyRe.MatchString(k) {
			return fmt.Errorf("secret %q: must be an env name", k)
		}
		if err := ValidSecretSpec(spec); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for _, c := range d.Components {
		if err := ValidName(c.Name); err != nil || names[c.Name] {
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
		if err := ValidateDataPaths(c.Data); err != nil {
			return fmt.Errorf("component %s: %w", c.Name, err)
		}
		for _, s := range c.Secrets {
			if _, ok := d.Secrets[s]; !ok {
				return fmt.Errorf("component %s: unknown secret %s", c.Name, s)
			}
		}
		// Secrets reach containers only through env files: placeholders in env or args may not
		// name them (argv and plain env are visible in `nerdctl inspect` and the cluster spec).
		vars := d.PlaceholderNames(false)
		for k, v := range c.Env {
			if !EnvKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
				return fmt.Errorf("component %s: bad env name %q", c.Name, k)
			}
			if _, err := Expand(v, vars); err != nil {
				return fmt.Errorf("component %s: env %s: %w", c.Name, k, err)
			}
		}
		for _, a := range append(append([]string(nil), c.Args...), c.Health...) {
			if _, err := Expand(a, vars); err != nil {
				return fmt.Errorf("component %s: %w", c.Name, err)
			}
		}
	}
	for tag, v := range d.Versions {
		if !AppVersionRe.MatchString(tag) {
			return fmt.Errorf("bad version tag %q", tag)
		}
		for _, c := range d.Components {
			if !DigestImageRe.MatchString(v.Images[c.Name]) {
				return fmt.Errorf("version %s: component %s needs an image pinned by digest (name@sha256:...)", tag, c.Name)
			}
		}
		for c := range v.Images {
			if !names[c] {
				return fmt.Errorf("version %s: image for unknown component %s", tag, c)
			}
		}
	}
	all := d.PlaceholderNames(true)
	for k, v := range d.Outputs {
		if !SettingNameRe.MatchString(k) {
			return fmt.Errorf("output %q: bad name", k)
		}
		if _, err := Expand(v, all); err != nil {
			return fmt.Errorf("output %s: %w", k, err)
		}
	}
	return nil
}

// PlaceholderNames lists the placeholders an app may use (values only matter for validation).
func (d AppDef) PlaceholderNames(withSecrets bool) map[string]string {
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

var (
	// DigestImageRe: an image pinned by digest (name[:tag]@sha256:...).
	DigestImageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$`)
	AppVersionRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

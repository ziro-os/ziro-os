package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Templates and warm pools.
//
// A template is a named sandbox spec the host's admin keeps in /etc/ziro/sandbox/templates/
// (<name>.json): `create --template python` starts from it, and fields set in the request
// override it. A template has no secret values.
//
// A warm pool keeps N sandboxes of a template created and paused ("pools" in the host config),
// so a create that only names the template (plus timeout, idle timeout and metadata) is a
// resume: milliseconds instead of a container start. The reaper refills pools.
//
// ponytail: fixed pool sizes; size them from demand when there is a metric to drive it.

var sandboxTemplateDir = "/etc/ziro/sandbox/templates"

func templatePath(name string) string { return filepath.Join(sandboxTemplateDir, name+".json") }

func loadTemplate(name string) (schema.SandboxSpec, error) {
	var t schema.SandboxSpec
	if err := validName(name); err != nil {
		return t, err
	}
	b, err := os.ReadFile(templatePath(name))
	if os.IsNotExist(err) {
		return t, errNotFound("no sandbox template " + name)
	}
	if err != nil {
		return t, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return t, fmt.Errorf("template %s: %w", name, err)
	}
	return t, validateTemplate(name, &t)
}

func validateTemplate(name string, t *schema.SandboxSpec) error {
	if t.Template != "" || t.Image == "" {
		return fmt.Errorf("template %s: needs an image and can't name another template", name)
	}
	for _, s := range t.Secrets {
		if s.Value != "" {
			return fmt.Errorf("template %s: secret values don't belong in a template", name)
		}
	}
	if len(t.Secrets) > 0 {
		return fmt.Errorf("template %s: secrets are given at create, not in templates", name)
	}
	return t.Validate()
}

func saveTemplate(name string, t schema.SandboxSpec) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := validateTemplate(name, &t); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sandboxTemplateDir, 0755); err != nil {
		return err
	}
	return writeFileAtomic(templatePath(name), append(b, '\n'), 0644)
}

func listTemplates() map[string]schema.SandboxSpec {
	out := map[string]schema.SandboxSpec{}
	ents, _ := os.ReadDir(sandboxTemplateDir)
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		if t, err := loadTemplate(name); err == nil {
			out[name] = t
		}
	}
	return out
}

// applyTemplate starts from the named template and lays the request's fields over it.
func applyTemplate(req schema.SandboxSpec) (schema.SandboxSpec, error) {
	if req.Template == "" {
		return req, nil
	}
	s, err := loadTemplate(req.Template)
	if err != nil {
		return req, err
	}
	s.Template = req.Template
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&s.Image, req.Image)
	set(&s.Runtime, req.Runtime)
	set(&s.User, req.User)
	set(&s.Workdir, req.Workdir)
	set(&s.Timeout, req.Timeout)
	set(&s.IdleTimeout, req.IdleTimeout)
	if len(req.Command) > 0 {
		s.Command = req.Command
	}
	if req.Resources != nil {
		s.Resources = req.Resources
	}
	if req.Network != nil {
		s.Network = req.Network
	}
	s.Env = mergeMaps(s.Env, req.Env)
	s.Metadata = mergeMaps(s.Metadata, req.Metadata)
	s.Secrets = req.Secrets
	return s, nil
}

func mergeMaps(base, over map[string]string) map[string]string {
	if len(base)+len(over) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// ---- warm pools ----

const poolOwnerPrefix = "pool:"

// poolClaimable: a request a pooled sandbox can serve (nothing that is fixed at create).
func poolClaimable(req schema.SandboxSpec) bool {
	r := req
	r.Template, r.Timeout, r.IdleTimeout, r.Metadata = "", "", "", nil
	return req.Template != "" && fmt.Sprint(r) == fmt.Sprint(schema.SandboxSpec{})
}

// claim hands a paused pool sandbox of the template to the caller, or returns false.
func (m *sandboxManager) claim(ctx context.Context, req schema.SandboxSpec, c sandboxCaller, cfg sandboxConfig) (sdkapi.Sandbox, bool) {
	if !poolClaimable(req) || cfg.Pools[req.Template] == 0 {
		return sdkapi.Sandbox{}, false
	}
	ttl := time.Duration(0)
	m.st.mu.Lock()
	var picked *sdkapi.Sandbox
	for _, sb := range m.st.all {
		if sb.Owner == poolOwnerPrefix+req.Template && sb.State == "paused" {
			picked = sb
			break
		}
	}
	if picked == nil || checkSandboxQuota(m.st.all, cfg, c.Owner, 0) != nil {
		m.st.mu.Unlock()
		return sdkapi.Sandbox{}, false
	}
	spec := picked.Spec
	spec.Timeout, spec.IdleTimeout = req.Timeout, req.IdleTimeout
	if spec.Timeout == "" {
		spec.Timeout = cfg.DefaultTimeout
	}
	var err error
	if ttl, err = time.ParseDuration(spec.Timeout); err != nil || ttl > parseDur(cfg.MaxTimeout) {
		m.st.mu.Unlock()
		return sdkapi.Sandbox{}, false
	}
	spec.Metadata = mergeMaps(spec.Metadata, req.Metadata)
	now := m.now().UTC()
	picked.Owner, picked.Spec, picked.State = c.Owner, spec, "pending"
	picked.Created, picked.Expires, picked.LastActive = now, now.Add(ttl), now
	_ = m.st.save(picked)
	id := picked.ID
	m.st.mu.Unlock()
	if out, err := sandboxNerdctl(ctx, "unpause", sandboxContainer(id)); err != nil {
		fmt.Printf("[sandboxd] pool %s: resume %s: %s\n", req.Template, id, cmdError(out, err))
		m.st.mu.Lock()
		delete(m.st.all, id)
		m.st.mu.Unlock()
		_ = m.destroy(id)
		return sdkapi.Sandbox{}, false
	}
	var view sdkapi.Sandbox
	if m.st.update(id, func(x *sdkapi.Sandbox) { x.State = "running"; view = *x }) != nil {
		return sdkapi.Sandbox{}, false
	}
	return view, true
}

func parseDur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

var poolFilling atomic.Bool

// fillPools creates the missing sandboxes of every pool (in the background: a first image pull
// can take minutes).
func (m *sandboxManager) fillPools(cfg sandboxConfig) {
	if len(cfg.Pools) == 0 || !poolFilling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer poolFilling.Store(false)
		names := make([]string, 0, len(cfg.Pools))
		for t := range cfg.Pools {
			names = append(names, t)
		}
		sort.Strings(names)
		for _, t := range names {
			owner := poolOwnerPrefix + t
			have := 0
			for _, sb := range m.st.list(sandboxCaller{Role: "admin"}) {
				if sb.Owner == owner && (sb.State == "paused" || sb.State == "pending") {
					have++
				}
			}
			for ; have < cfg.Pools[t]; have++ {
				ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
				sb, err := m.create(ctx, schema.SandboxSpec{Template: t, Timeout: cfg.MaxTimeout}, sandboxCaller{Owner: owner, Role: "admin"})
				if err == nil {
					_, err = m.setPaused(ctx, sb.ID, sandboxCaller{Role: "admin"}, true)
				}
				cancel()
				if err != nil {
					fmt.Printf("[sandboxd] pool %s: %v\n", t, err)
					break
				}
			}
		}
	}()
}

func validatePools(pools map[string]int, maxPerOwner int) error {
	for t, n := range pools {
		if err := validName(t); err != nil {
			return fmt.Errorf("pools: %w", err)
		}
		if n < 0 || (maxPerOwner > 0 && n > maxPerOwner) {
			return fmt.Errorf("pools: %s: size must be 0..%d (max_per_owner)", t, maxPerOwner)
		}
	}
	return nil
}

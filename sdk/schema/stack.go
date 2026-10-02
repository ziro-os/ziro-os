package schema

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Stack deploys several apps together, in dependency order, as one unit:
//
//	stack: shop
//	version: 1
//	apps:
//	  db:
//	    app: postgres:18           # a catalog app[:version], or ./apps/api/app.yaml (next to the stack file)
//	    set: { database: shop }
//	    resources: { memory: 1Gi }
//	  web:
//	    app: ./apps/web/app.yaml
//	    expose: shop.example.com
//	    depends_on: [db]
//
// Each app becomes an instance named <stack>-<key> (shop-db, shop-web).
type Stack struct {
	Stack       string              `json:"stack"` // the stack's name
	Version     int                 `json:"version"`
	Description string              `json:"description,omitempty"`
	Apps        map[string]StackApp `json:"apps"`
}

type StackApp struct {
	App       string            `json:"app"`                  // catalog name[:version] or a relative path to an app definition
	Set       map[string]string `json:"set,omitempty"`        // app settings
	Replicas  int               `json:"replicas,omitempty"`   // apps that allow scaling
	Publish   int               `json:"publish,omitempty"`    // host port
	Expose    string            `json:"expose,omitempty"`     // gateway hostname (HTTPS)
	ExposeTLS string            `json:"expose_tls,omitempty"` // auto, internal, off, cert:<name>
	Resources *Resources        `json:"resources,omitempty"`  // limits for every component
	DependsOn []string          `json:"depends_on,omitempty"` // deployed (and healthy) first
}

// ParseStack decodes a stack (YAML or JSON) strictly and validates it.
func ParseStack(b []byte) (Stack, error) {
	var s Stack
	if err := DecodeStrict(b, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}

// IsLocalRef reports whether an app reference is a file path rather than a catalog app.
func IsLocalRef(ref string) bool {
	return strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../")
}

func (s Stack) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported stack version %d (want 1)", s.Version)
	}
	if err := ValidName(s.Stack); err != nil {
		return fmt.Errorf("stack name: %w", err)
	}
	if len(s.Apps) == 0 {
		return fmt.Errorf("stack %s has no apps", s.Stack)
	}
	for key, a := range s.Apps {
		if err := ValidName(key); err != nil {
			return fmt.Errorf("app key %q: %w", key, err)
		}
		if err := ValidName(s.Stack + "-" + key); err != nil {
			return fmt.Errorf("app %s: instance name %s-%s is too long", key, s.Stack, key)
		}
		if IsLocalRef(a.App) {
			if strings.Contains(path.Clean(a.App), "..") || !strings.HasSuffix(a.App, ".json") && !strings.HasSuffix(a.App, ".yaml") && !strings.HasSuffix(a.App, ".yml") {
				return fmt.Errorf("app %s: %q must be a .yaml or .json file inside the stack's directory", key, a.App)
			}
		} else {
			name, version, hasVersion := strings.Cut(a.App, ":")
			if ValidName(name) != nil || (hasVersion && !AppVersionRe.MatchString(version)) {
				return fmt.Errorf("app %s: %q is not a catalog app[:version] or ./path", key, a.App)
			}
		}
		for k, v := range a.Set {
			if !SettingNameRe.MatchString(k) || strings.ContainsAny(v, "\x00\r\n") {
				return fmt.Errorf("app %s: bad setting %q", key, k)
			}
		}
		if a.Replicas < 0 || a.Replicas > 64 || a.Publish < 0 || a.Publish > 65535 {
			return fmt.Errorf("app %s: bad replicas or publish port", key)
		}
		if a.Expose != "" && (!HostRe.MatchString(a.Expose) || strings.HasPrefix(a.Expose, "*.")) {
			return fmt.Errorf("app %s: bad expose host %q", key, a.Expose)
		}
		if err := a.Resources.Validate(); err != nil {
			return fmt.Errorf("app %s: %w", key, err)
		}
		for _, d := range a.DependsOn {
			if _, ok := s.Apps[d]; !ok || d == key {
				return fmt.Errorf("app %s: depends on unknown app %q", key, d)
			}
		}
	}
	_, err := s.Order()
	return err
}

// Order returns the app keys so that every app comes after what it depends on (alphabetical
// among equals, so plans are stable). A dependency cycle is an error.
func (s Stack) Order() ([]string, error) {
	keys := make([]string, 0, len(s.Apps))
	for k := range s.Apps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var out []string
	var visit func(k string, trail []string) error
	visit = func(k string, trail []string) error {
		switch state[k] {
		case 1:
			return fmt.Errorf("dependency cycle: %s", strings.Join(append(trail, k), " -> "))
		case 2:
			return nil
		}
		state[k] = 1
		deps := append([]string(nil), s.Apps[k].DependsOn...)
		sort.Strings(deps)
		for _, d := range deps {
			if err := visit(d, append(trail, k)); err != nil {
				return err
			}
		}
		state[k] = 2
		out = append(out, k)
		return nil
	}
	for _, k := range keys {
		if err := visit(k, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Instance is the deployed name of a stack app.
func (s Stack) Instance(key string) string { return s.Stack + "-" + key }

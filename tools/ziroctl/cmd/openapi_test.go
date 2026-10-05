package cmd

import (
	"os"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestOpenAPIMatchesRoutes keeps sdk/openapi.yaml and the route table identical: every served
// operation is documented with the role the server enforces (x-ziro-role), and nothing is
// documented that isn't served.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../../sdk/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Role string `yaml:"x-ziro-role"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	documented := map[string]string{} // "METHOD /path" -> role
	for path, ops := range spec.Paths {
		for method, op := range ops {
			if method == "parameters" {
				continue
			}
			documented[strings.ToUpper(method)+" "+path] = op.Role
		}
	}
	served := map[string]string{}
	for _, rt := range apiRoutes().routes {
		key := rt.Method + " " + rt.Path
		if _, dup := served[key]; dup {
			t.Errorf("%s is registered twice", key)
		}
		served[key] = rt.Role
	}
	var keys []string
	for k := range served {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		role, ok := documented[k]
		switch {
		case !ok:
			t.Errorf("%s is served but not documented in sdk/openapi.yaml", k)
		case role != served[k]:
			t.Errorf("%s: openapi says x-ziro-role %q, the server enforces %q", k, role, served[k])
		}
	}
	for k := range documented {
		if _, ok := served[k]; !ok {
			t.Errorf("sdk/openapi.yaml documents %s, which the server doesn't serve", k)
		}
	}
}

// Every route that changes state requires more than a viewer, and nothing but health is public.
// The one exception is the git webhook: public on purpose, and authenticated by the deployment's
// hook secret (HMAC or token, checked in constant time by ziroctld) instead of an API token.
func TestRoutePolicy(t *testing.T) {
	signedPublic := map[string]bool{"POST /api/v1/hooks/deploy/{app}": true}
	for _, rt := range apiRoutes().routes {
		if signedPublic[rt.Method+" "+rt.Path] {
			continue
		}
		if rt.Role == "public" && rt.Path != "/api/v1/health" {
			t.Errorf("%s %s is public", rt.Method, rt.Path)
		}
		if rt.Method != "GET" && apiRoleRank[rt.Role] < apiRoleRank["deployer"] {
			t.Errorf("%s %s changes state with role %s", rt.Method, rt.Path, rt.Role)
		}
	}
}

package cmd

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type recordingMux struct{ patterns []string }

func (m *recordingMux) HandleFunc(p string, _ func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, p)
}

// TestOpenAPICoversEveryRoute fails when a route is registered but not documented in
// sdk/openapi.yaml, or documented but not served (so clients generated from the spec work).
func TestOpenAPICoversEveryRoute(t *testing.T) {
	m := &recordingMux{}
	registerAPIRoutes(m, func(_ bool, h http.HandlerFunc) http.HandlerFunc { return h })
	spec, err := os.ReadFile("../../../sdk/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, mm := range regexp.MustCompile(`(?m)^  (/api/v1/\S*):\s*$`).FindAllStringSubmatch(string(spec), -1) {
		paths = append(paths, mm[1])
	}
	sort.Strings(paths)
	if len(paths) < 30 {
		t.Fatalf("only %d paths parsed from the spec", len(paths))
	}
	served := func(p string) bool {
		for _, pat := range m.patterns {
			if p == pat || strings.HasSuffix(pat, "/") && strings.HasPrefix(p, pat) {
				return true
			}
		}
		return false
	}
	for _, pat := range m.patterns {
		ok := false
		for _, p := range paths {
			ok = ok || p == pat || strings.HasSuffix(pat, "/") && strings.HasPrefix(p, pat) && len(p) > len(pat)
		}
		if !ok {
			t.Errorf("route %s is not documented in sdk/openapi.yaml", pat)
		}
	}
	for _, p := range paths {
		if !served(p) {
			t.Errorf("sdk/openapi.yaml documents %s, which the server doesn't serve", p)
		}
	}
}

package cmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// The filters parameter of the list calls. Docker clients send it as JSON in two shapes: the current
// {"label":{"a=b":true}} and the older {"label":["a=b"]}. An unknown filter name is refused: ignoring it
// would answer with everything, and a tool such as Compose then treats every container as its own.

type dockerFilters map[string][]string

func parseDockerFilters(raw string, allowed ...string) (dockerFilters, error) {
	f := dockerFilters{}
	if raw == "" || raw == "{}" {
		return f, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("invalid filters")
	}
	for k, v := range m {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return nil, fmt.Errorf("unsupported filter %q", sanitizeLabel(k, 40))
		}
		var arr []string
		var set map[string]bool
		switch {
		case json.Unmarshal(v, &arr) == nil:
			f[k] = arr
		case json.Unmarshal(v, &set) == nil:
			for s, on := range set {
				if on {
					f[k] = append(f[k], s)
				}
			}
		default:
			return nil, fmt.Errorf("invalid filters")
		}
	}
	return f, nil
}

// has reports whether the filter is set.
func (f dockerFilters) has(k string) bool { return len(f[k]) > 0 }

// labels: every listed label ("k" present, or "k=v" equal) must match.
func (f dockerFilters) labels(have map[string]string) bool {
	for _, want := range f["label"] {
		k, v, hasV := strings.Cut(want, "=")
		got, ok := have[k]
		if !ok || (hasV && got != v) {
			return false
		}
	}
	return true
}

// anyOf: no values set, or one of them matches. match decides for one value.
func (f dockerFilters) anyOf(k string, match func(v string) bool) bool {
	if !f.has(k) {
		return true
	}
	for _, v := range f[k] {
		if match(v) {
			return true
		}
	}
	return false
}

// nameMatch is Docker's name filter: a regular expression over the name, with or without a leading slash.
func nameMatch(name string) func(string) bool {
	return func(pat string) bool {
		if len(pat) > 256 {
			return false
		}
		re, err := regexp.Compile(pat) // RE2: no backtracking blow-up
		if err != nil {
			return false
		}
		return re.MatchString(name) || re.MatchString(strings.TrimPrefix(name, "/"))
	}
}

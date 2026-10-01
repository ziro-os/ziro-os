// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

package schema

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var PlaceholderRe = regexp.MustCompile(`\{\{\s*([a-z]+(?:\.[A-Za-z0-9_]+)?)\s*\}\}`)

// Expand substitutes {{secret.X}}, {{setting.X}}, {{replica}}, {{peers}}, {{host}} from vars. It
// only replaces values (no logic, no functions); an unknown or malformed placeholder is an error,
// so a definition can't contain a literal "{{".
func Expand(s string, vars map[string]string) (string, error) {
	var missing []string
	out := PlaceholderRe.ReplaceAllStringFunc(s, func(m string) string {
		k := PlaceholderRe.FindStringSubmatch(m)[1]
		v, ok := vars[k]
		if !ok {
			missing = append(missing, k)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unknown placeholder {{%s}}", missing[0])
	}
	// Values are substituted once and never re-scanned, so a value can't smuggle in a placeholder.
	if rest := PlaceholderRe.ReplaceAllString(s, ""); strings.Contains(rest, "{{") {
		return "", fmt.Errorf("malformed placeholder in %q", lastLine(s))
	}
	return out, nil
}

// Setting is a value an operator may set (--set name=value). Every value, the default included,
// must fully match Pattern, so settings can't inject lines or arguments into configs.
type Setting struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default"`
	Pattern     string `json:"pattern"`
}

var SettingNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func ValidateSettings(defs []Setting) error {
	for _, s := range defs {
		if !SettingNameRe.MatchString(s.Name) {
			return fmt.Errorf("setting %q: bad name", s.Name)
		}
		if !strings.HasPrefix(s.Pattern, "^") || !strings.HasSuffix(s.Pattern, "$") {
			return fmt.Errorf("setting %s: pattern must be anchored (^...$)", s.Name)
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("setting %s: %w", s.Name, err)
		}
		if !re.MatchString(s.Default) {
			return fmt.Errorf("setting %s: default %q doesn't match %s", s.Name, s.Default, s.Pattern)
		}
	}
	return nil
}

// ResolveSettings merges prev (earlier choices) and set (this run) over the defaults.
func ResolveSettings(defs []Setting, prev, set map[string]string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]bool{}
	for _, d := range defs {
		known[d.Name] = true
		v := d.Default
		if p, ok := prev[d.Name]; ok {
			v = p
		}
		if s, ok := set[d.Name]; ok {
			v = s
		}
		if !regexp.MustCompile(d.Pattern).MatchString(v) || strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("setting %s=%q must match %s", d.Name, v, d.Pattern)
		}
		out[d.Name] = v
	}
	for k := range set {
		if !known[k] {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	return out, nil
}

// ParseSetFlags turns --set k=v flags into a map.
func ParseSetFlags(sets []string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --set %q (want name=value)", s)
		}
		out[k] = v
	}
	return out, nil
}

var SecretSpecRe = regexp.MustCompile(`^(hex|base64|alnum):([0-9]{1,2})$`)

// ValidSecretSpec: "hex:N", "base64:N" (N random bytes) or "alnum:N" (N characters), 12 <= N <= 64.
func ValidSecretSpec(spec string) error {
	m := SecretSpecRe.FindStringSubmatch(spec)
	if m == nil {
		return fmt.Errorf("secret spec %q (want hex:N, base64:N or alnum:N)", spec)
	}
	if n, _ := strconv.Atoi(m[2]); n < 12 || n > 64 {
		return fmt.Errorf("secret spec %q: N must be 12..64", spec)
	}
	return nil
}

func GenSecret(spec string) (string, error) {
	if err := ValidSecretSpec(spec); err != nil {
		return "", err
	}
	m := SecretSpecRe.FindStringSubmatch(spec)
	n, _ := strconv.Atoi(m[2])
	if m[1] == "alnum" {
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, n)
		for i := range b {
			j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}
			b[i] = chars[j.Int64()]
		}
		return string(b), nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	if m[1] == "hex" {
		return hex.EncodeToString(b), nil
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func lastLine(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

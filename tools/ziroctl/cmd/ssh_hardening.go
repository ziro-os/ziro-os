package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

var sshPolicy = []struct{ key, value string }{
	{"PasswordAuthentication", "no"},
	{"KbdInteractiveAuthentication", "no"},
	{"PermitEmptyPasswords", "no"},
	{"PermitRootLogin", "prohibit-password"},
	{"X11Forwarding", "no"},
	{"MaxAuthTries", "3"},
}

func sshDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
	if len(fields) == 0 {
		return "", ""
	}
	key := strings.ToLower(strings.Trim(fields[0], "\""))
	if key == "challengeresponseauthentication" {
		key = "kbdinteractiveauthentication"
	}
	value := ""
	if len(fields) > 1 {
		value = strings.ToLower(strings.Trim(fields[1], "\""))
	}
	return key, value
}

func secureSSHValue(key, current, baseline string) string {
	switch key {
	case "permitrootlogin":
		if current == "no" || current == "forced-commands-only" {
			return current
		}
	case "maxauthtries":
		if n, err := strconv.Atoi(current); err == nil && n >= 0 && n < 3 {
			return current
		}
	}
	return baseline
}

// Rewrite controls in every scope. Includes are rejected before mutation: their
// conditional/glob expansion cannot be safely inferred from the main file.
func hardenedSSHConfig(data []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	global := map[string]string{}
	inMatch := false
	for i, line := range lines {
		key, value := sshDirective(line)
		if key == "include" {
			return nil, fmt.Errorf("SSH Include at line %d: consolidate included policy before hardening", i+1)
		}
		if key == "match" {
			inMatch = true
		}
		for _, policy := range sshPolicy {
			if key != strings.ToLower(policy.key) {
				continue
			}
			value = secureSSHValue(key, value, policy.value)
			if !inMatch {
				if _, exists := global[key]; !exists {
					global[key] = value
				}
			}
			lines[i] = policy.key + " " + value
		}
	}
	var out strings.Builder
	// First global values are explicit, before any Match. Preserve stronger
	// root-login and retry controls instead of broadening them to our baseline.
	for _, policy := range sshPolicy {
		value := policy.value
		if v, ok := global[strings.ToLower(policy.key)]; ok {
			value = v
		}
		out.WriteString(policy.key + " " + value + "\n")
	}
	inMatch = false
	for _, line := range lines {
		key, _ := sshDirective(line)
		// Drop global managed directives already emitted above, retaining Match ones.
		if key == "match" {
			inMatch = true
		}
		managed := false
		for _, policy := range sshPolicy {
			if key == strings.ToLower(policy.key) {
				managed = true
			}
		}
		if !inMatch && managed {
			continue
		}
		out.WriteString(line + "\n")
	}
	return []byte(out.String()), nil
}

func sshKeyOnlyConfig(data []byte) bool {
	seen := map[string]bool{}
	inMatch := false
	for _, line := range strings.Split(string(data), "\n") {
		key, value := sshDirective(line)
		if key == "include" {
			return false
		}
		if key == "match" {
			inMatch = true
		}
		if key == "passwordauthentication" || key == "kbdinteractiveauthentication" || key == "permitemptypasswords" {
			if value != "no" {
				return false
			}
			if !inMatch {
				seen[key] = true
			}
		}
	}
	return seen["passwordauthentication"] && seen["kbdinteractiveauthentication"] && seen["permitemptypasswords"]
}

func hardenSSHFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	candidate, err := hardenedSSHConfig(data)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ziro-sshd-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(candidate); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if out, err := exec.Command("sshd", "-t", "-f", f.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("SSH candidate validation: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return os.Rename(f.Name(), path)
}

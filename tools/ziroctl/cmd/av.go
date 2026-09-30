package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Antivirus scans through the clamav module's clamd. --fdpass hands clamd (which runs as the
// clamav user) open file descriptors, so root-only paths are scanned without giving clamd root.

var avDefaultPaths = []string{"/root", "/home", "/tmp", "/var/tmp", "/var/lib/ziro/volumes"}

type AVFinding struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
}

// parseClamdscan reads `clamdscan --infected --no-summary` output: "<path>: <signature> FOUND".
func parseClamdscan(out string) []AVFinding {
	var found []AVFinding
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutSuffix(line, " FOUND")
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, ": ")
		if i <= 0 {
			continue
		}
		found = append(found, AVFinding{Path: rest[:i], Signature: rest[i+2:]})
	}
	return found
}

// runAVScan scans paths (defaults when empty) and alerts on every detection.
func runAVScan(paths []string, quiet bool) ([]AVFinding, error) {
	if _, err := os.Stat("/usr/bin/clamdscan"); err != nil {
		return nil, fmt.Errorf("antivirus is not enabled: ziroctl module enable clamav")
	}
	if len(paths) == 0 {
		for _, p := range avDefaultPaths {
			if fileExists(p) {
				paths = append(paths, p)
			}
		}
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") {
			return nil, fmt.Errorf("scan path %q must be absolute", p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	args := append([]string{"--config-file=/etc/clamav/clamd.conf", "--multiscan", "--fdpass", "--infected", "--no-summary", "--"}, paths...)
	out, err := exec.CommandContext(ctx, "/usr/bin/clamdscan", args...).CombinedOutput()
	// clamdscan exits 1 when something was found, 2 on errors.
	if ee, ok := err.(*exec.ExitError); err != nil && (!ok || ee.ExitCode() != 1) {
		return nil, fmt.Errorf("clamdscan: %v: %s", err, lastLines(strings.TrimSpace(string(out)), 5))
	}
	found := parseClamdscan(string(out))
	for _, f := range found {
		if !quiet {
			fmt.Printf("🦠 %s: %s\n", f.Path, f.Signature)
		}
		alertf("critical", "av", "Malware detected: "+f.Signature+" in "+f.Path,
			map[string]any{"path": f.Path, "signature": f.Signature})
		_ = auditLog("clamav", "av-scan", "malware found", f.Path+" ("+f.Signature+")", nil)
	}
	flushAlerts() // a cron run exits right after: deliver now
	if !quiet {
		fmt.Printf("Scanned %s: %d detection(s)\n", strings.Join(paths, ", "), len(found))
	}
	return found, nil
}

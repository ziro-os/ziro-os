package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Host integrity (the `integrity` module): the kernel's IMA measures every executable, shared
// library and kernel module the host runs (container overlays excluded). `security integrity`
// checks each measured system file against what the OS image shipped
// (/etc/ziro/integrity.sha256, written at build time) or, for files a package added later
// (modules), against the signed apk database. Package files are verified by apk itself
// (`apk audit`, against its database); ziroctl only hashes with SHA-256. Anything else is a finding and raises a critical
// alert.

var (
	imaDir            = "/sys/kernel/security/ima"
	integrityBaseline = "/etc/ziro/integrity.sha256"
	apkInstalledDB    = "/lib/apk/db/installed"
	// System locations checked; executables elsewhere (data volumes, /tmp) are reported apart.
	integrityRoots = []string{"/bin/", "/sbin/", "/usr/", "/lib/", "/opt/cni/bin/"}
)

// imaPolicy measures what the host executes, maps executable and loads as modules or
// firmware. Pseudo filesystems and container overlays are skipped: a container's /usr/bin/sh is
// not the host's.
const imaPolicy = `dont_measure fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_measure fsmagic=0x1cd1
dont_measure fsmagic=0x73636673
dont_measure fsmagic=0x6e736673
dont_measure fsmagic=0x27e0eb
dont_measure fsmagic=0x63677270
dont_measure fsmagic=0x794c7630
measure func=BPRM_CHECK mask=MAY_EXEC
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK
measure func=FIRMWARE_CHECK
audit func=BPRM_CHECK mask=MAY_EXEC
`

// loadIMAPolicy installs imaPolicy unless a policy with our rules is already active (boot hooks
// run this on every boot; IMA policies only grow).
func loadIMAPolicy() error {
	if _, err := os.Stat(imaDir); err != nil {
		return errors.New("this kernel has no IMA (switch to the hardened kernel: ziroctl upgrade --flavor custom)")
	}
	if cur, err := os.ReadFile(path.Join(imaDir, "policy")); err == nil && strings.Contains(string(cur), "func=BPRM_CHECK") {
		return nil
	}
	f, err := os.OpenFile(path.Join(imaDir, "policy"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(imaPolicy); err != nil {
		f.Close()
		return fmt.Errorf("IMA rejected the policy: %w", err)
	}
	return f.Close()
}

// imaMeasurement is one ima-ng entry: "10 <template-hash> ima-ng sha256:<hex> <path>".
type imaMeasurement struct {
	Hash string // hex sha256 of the file when it was measured
	Path string
}

func parseIMAMeasurements(r io.Reader) []imaMeasurement {
	var out []imaMeasurement
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), " ", 5)
		if len(f) < 5 || f[2] != "ima-ng" {
			continue
		}
		algo, hash, ok := strings.Cut(f[3], ":")
		if !ok || algo != "sha256" {
			continue
		}
		out = append(out, imaMeasurement{Hash: hash, Path: f[4]})
	}
	return out
}

// readBaseline parses "sha256  /path" lines.
// readBaseline maps each path to its known-good hashes. A path can have several: `ziroctl
// update` adds the new binary's hash and keeps the old one, which IMA measured before the update
// and keeps in its (append-only) log until reboot.
func readBaseline(r io.Reader) map[string][]string {
	out := map[string][]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if hash, p, ok := strings.Cut(sc.Text(), "  "); ok && len(hash) == 64 {
			out[p] = append(out[p], hash)
		}
	}
	return out
}

// apkOwnedFiles lists the files installed packages own ("/path"), from the apk database.
func apkOwnedFiles(r io.Reader) map[string]bool {
	out := map[string]bool{}
	dir := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		switch l[0] {
		case 'F':
			dir = l[2:]
		case 'R':
			out["/"+path.Join(dir, l[2:])] = true
		}
	}
	return out
}

// apkModified asks apk which package files in dirs differ from its database
// (`apk audit --system`: "U path" for a changed file, "D" for a removed one).
var apkModified = func(dirs []string) (map[string]bool, error) {
	if len(dirs) == 0 {
		return map[string]bool{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "apk", append([]string{"audit", "--system", "--"}, dirs...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("apk audit: %w", err)
	}
	return parseAPKAudit(string(out)), nil
}

func parseAPKAudit(out string) map[string]bool {
	mod := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if code, p, ok := strings.Cut(l, " "); ok && (code == "U" || code == "D") {
			mod["/"+strings.TrimPrefix(p, "/")] = true
		}
	}
	return mod
}

type integrityFinding struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type integrityReport struct {
	Measured int                `json:"measured"`
	Image    int                `json:"from_image"`
	Package  int                `json:"from_packages"`
	Other    int                `json:"outside_system_paths"`
	Findings []integrityFinding `json:"findings"`
}

func isSystemPath(p string) bool {
	for _, r := range integrityRoots {
		if strings.HasPrefix(p, r) {
			return true
		}
	}
	return false
}

// fileSHA256 is a file's current SHA-256 (hex).
var fileSHA256 = computeFileSHA256

// checkIntegrity classifies every measured system file: shipped by the image (hash matches the
// baseline), installed by a signed package (apk reports it unchanged, and it still has the
// content that was measured), or a finding. modified is apk's verdict for owned files.
func checkIntegrity(ms []imaMeasurement, baseline map[string][]string, owned, modified map[string]bool) integrityReport {
	rep := integrityReport{Findings: []integrityFinding{}}
	seen := map[string]bool{}
	for _, m := range ms {
		key := m.Path + "\x00" + m.Hash
		if seen[key] || m.Path == "boot_aggregate" {
			continue
		}
		seen[key] = true
		rep.Measured++
		if !isSystemPath(m.Path) {
			rep.Other++
			continue
		}
		if want, ok := baseline[m.Path]; ok {
			if slices.Contains(want, m.Hash) {
				rep.Image++
			} else {
				rep.Findings = append(rep.Findings, integrityFinding{m.Path, "differs from the OS image"})
			}
			continue
		}
		if !owned[m.Path] {
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "not part of the OS image or any installed package"})
			continue
		}
		cur, err := fileSHA256(m.Path)
		switch {
		case err != nil:
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "package file can't be read: " + err.Error()})
		case modified[m.Path]:
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "differs from its package"})
		case cur != m.Hash:
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "ran with different content than its package"})
		default:
			rep.Package++
		}
	}
	sort.Slice(rep.Findings, func(i, j int) bool { return rep.Findings[i].Path < rep.Findings[j].Path })
	return rep
}

func runIntegrityCheck() (integrityReport, error) {
	mf, err := os.Open(path.Join(imaDir, "ascii_runtime_measurements"))
	if err != nil {
		return integrityReport{}, errors.New("no IMA measurements: enable the integrity module (ziroctl plugin enable integrity)")
	}
	defer mf.Close()
	ms := parseIMAMeasurements(mf)
	var baseline map[string][]string
	if bf, err := os.Open(integrityBaseline); err == nil {
		baseline = readBaseline(bf)
		bf.Close()
	} else {
		return integrityReport{}, fmt.Errorf("no integrity baseline at %s", integrityBaseline)
	}
	owned := map[string]bool{}
	if af, err := os.Open(apkInstalledDB); err == nil {
		owned = apkOwnedFiles(af)
		af.Close()
	}
	// apk audits only the directories holding measured package files (not in the image baseline).
	dirSet := map[string]bool{}
	for _, m := range ms {
		if _, inImage := baseline[m.Path]; !inImage && owned[m.Path] && isSystemPath(m.Path) {
			dirSet[path.Dir(m.Path)] = true
		}
	}
	dirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	modified, err := apkModified(dirs)
	if err != nil {
		return integrityReport{}, err
	}
	return checkIntegrity(ms, baseline, owned, modified), nil
}

var integrityQuiet bool

var securityIntegrityCmd = &cobra.Command{
	Use:     "integrity",
	Short:   "Check that everything run matches a signed hash",
	Example: `  ziroctl security integrity`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rep, err := runIntegrityCheck()
		if err != nil {
			return err
		}
		if len(rep.Findings) > 0 {
			details := map[string]any{"findings": len(rep.Findings), "first": rep.Findings[0].Path + ": " + rep.Findings[0].Reason}
			alertf("critical", "integrity", fmt.Sprintf("%d system file(s) failed the integrity check", len(rep.Findings)), details)
			_ = auditLog("system", "local", "security integrity", rep.Findings[0].Path, errors.New(rep.Findings[0].Reason))
		}
		err = printResult(rep, func() {
			if !integrityQuiet || len(rep.Findings) > 0 {
				fmt.Printf("Measured %d files: %d from the OS image, %d from signed packages, %d outside system paths\n",
					rep.Measured, rep.Image, rep.Package, rep.Other)
				for _, f := range rep.Findings {
					fmt.Printf("  ✗ %s: %s\n", f.Path, f.Reason)
				}
				if len(rep.Findings) == 0 {
					fmt.Println("✓ every measured system file is intact")
				}
			}
		})
		if err == nil && len(rep.Findings) > 0 {
			os.Exit(1)
		}
		return err
	},
}

var securityIntegrityLoadCmd = &cobra.Command{
	Use:    "load-policy",
	Hidden: true,
	Short:  "Install the IMA measurement policy (run by the integrity module at boot)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadIMAPolicy(); err != nil {
			return err
		}
		fmt.Println("IMA policy loaded")
		return nil
	},
}

func init() {
	securityIntegrityCmd.Flags().BoolVar(&integrityQuiet, "quiet", false, "Print only findings (for cron)")
	securityIntegrityCmd.AddCommand(securityIntegrityLoadCmd)
	securityCmd.AddCommand(securityIntegrityCmd)
}

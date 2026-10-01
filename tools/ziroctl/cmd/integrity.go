package cmd

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// Host integrity (the `integrity` module): the kernel's IMA measures every executable, shared
// library and kernel module the host runs (container overlays excluded). `security integrity`
// checks each measured system file against what the OS image shipped
// (/etc/ziro/integrity.sha256, written at build time) or, for files a package added later
// (modules), against the signed apk database. Anything else is a finding and raises a critical
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
func readBaseline(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if hash, p, ok := strings.Cut(sc.Text(), "  "); ok && len(hash) == 64 {
			out[p] = hash
		}
	}
	return out
}

// apkChecksums maps "/path" -> "Q1<base64 sha1>" from the apk database (signed packages).
func apkChecksums(r io.Reader) map[string]string {
	out := map[string]string{}
	dir, file := "", ""
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
			file = l[2:]
		case 'Z':
			if file != "" {
				out["/"+path.Join(dir, file)] = l[2:]
			}
		}
	}
	return out
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

// fileDigests returns the current sha256 (hex) and apk-style sha1 ("Q1"+base64) of a file.
var fileDigests = func(p string) (string, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h256, h1 := sha256.New(), sha1.New()
	if _, err := io.Copy(io.MultiWriter(h256, h1), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(h256.Sum(nil)), "Q1" + base64.StdEncoding.EncodeToString(h1.Sum(nil)), nil
}

// checkIntegrity classifies every measured system file: shipped by the image (hash matches the
// baseline), installed by a signed package (current file matches the apk database and what was
// measured), or a finding.
func checkIntegrity(ms []imaMeasurement, baseline, apk map[string]string) integrityReport {
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
			if want == m.Hash {
				rep.Image++
			} else {
				rep.Findings = append(rep.Findings, integrityFinding{m.Path, "differs from the OS image"})
			}
			continue
		}
		sum, ok := apk[m.Path]
		if !ok {
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "not part of the OS image or any installed package"})
			continue
		}
		cur256, cur1, err := fileDigests(m.Path)
		switch {
		case err != nil:
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "package file can't be read: " + err.Error()})
		case cur1 != sum:
			rep.Findings = append(rep.Findings, integrityFinding{m.Path, "differs from its package"})
		case cur256 != m.Hash:
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
	baseline := map[string]string{}
	if bf, err := os.Open(integrityBaseline); err == nil {
		baseline = readBaseline(bf)
		bf.Close()
	} else {
		return integrityReport{}, fmt.Errorf("no integrity baseline at %s", integrityBaseline)
	}
	apk := map[string]string{}
	if af, err := os.Open(apkInstalledDB); err == nil {
		apk = apkChecksums(af)
		af.Close()
	}
	return checkIntegrity(ms, baseline, apk), nil
}

var integrityQuiet bool

var securityIntegrityCmd = &cobra.Command{
	Use:   "integrity",
	Short: "Check that everything the host ran matches the OS image or a signed package (IMA)",
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

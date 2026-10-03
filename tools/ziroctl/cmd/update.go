package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// `ziroctl update`: ziroctl and ziropkg ship on their own release stream (tags tools/vX.Y.Z),
// independent of OS upgrades. Every release's SHA256SUMS is signed with the Ziro release key
// (ed25519; the public half is below), and nothing is installed unless the signature and every
// hash verify. The binaries are replaced atomically, the previous ones kept for --rollback.

// releasePublicKey verifies SHA256SUMS.sig of tools and OS releases (signed in CI with the
// secret ZIRO_RELEASE_KEY by scripts/release/sign-sums.sh, which checks against this file).
//
//go:embed release.pub
var releasePublicKey string

var (
	toolsTagRe      = regexp.MustCompile(`^tools/v([0-9]+\.[0-9]+\.[0-9]+)$`)
	toolsBinDir     = "/usr/bin"
	toolsLinkDir    = "/bin"
	toolsBinaries   = []string{"ziroctl", "ziropkg"}
	updateCheckFile = "/var/lib/ziro/update-check.json"
	updateConfFile  = "/etc/ziro/update.json"
	// Long-running ziroctl daemons restarted onto the new binary, one at a time.
	toolsDaemons = []string{"sentinel", "ziro-api", "gateway", "cluster-agent", "cluster-master"}
)

// verifyReleaseSums checks an ed25519 signature (base64) over SHA256SUMS.
func verifyReleaseSums(sums, sig []byte, pubPEM string) error {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return errors.New("bad release public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok {
		return errors.New("release public key is not ed25519")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, sums, raw) {
		return errors.New("SHA256SUMS signature does not verify: refusing the release")
	}
	return nil
}

// UpdateCheck is the cached result of the last check (shown in the login summary).
type UpdateCheck struct {
	Current string    `json:"current"`
	Latest  string    `json:"latest"`
	Tag     string    `json:"tag,omitempty"`
	Checked time.Time `json:"checked"`
	Error   string    `json:"error,omitempty"`
}

func (u UpdateCheck) Available() bool {
	return u.Latest != "" && compareSemver(u.Latest, strings.TrimPrefix(u.Current, "v")) > 0
}

func readUpdateCheck() UpdateCheck {
	var u UpdateCheck
	if b, err := os.ReadFile(updateCheckFile); err == nil {
		_ = json.Unmarshal(b, &u)
	}
	// A check made before an update would still offer the version now installed.
	u.Current = Version
	return u
}

// toolsRelease is the newest tools release this OS can run.
func latestToolsRelease(ctx context.Context) (*ghRelease, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/repos/"+upgradeRepo+"/releases?per_page=50", nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ziroctl/"+Version)
	resp, err := upgradeHTTP.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("query releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("query releases: HTTP %d", resp.StatusCode)
	}
	var rels []struct {
		ghRelease
		Draft      bool `json:"draft"`
		Prerelease bool `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rels); err != nil {
		return nil, "", fmt.Errorf("decode releases: %w", err)
	}
	var best *ghRelease
	bestV := ""
	for i := range rels {
		m := toolsTagRe.FindStringSubmatch(rels[i].TagName)
		if m == nil || rels[i].Draft || rels[i].Prerelease {
			continue
		}
		if bestV == "" || compareSemver(m[1], bestV) > 0 {
			best, bestV = &rels[i].ghRelease, m[1]
		}
	}
	if best == nil {
		return nil, "", errors.New("no tools release published yet")
	}
	return best, bestV, nil
}

// fetchToolsRelease returns the release's binaries for this host, downloaded and verified into
// dir: SHA256SUMS signed by the release key, each binary matching its signed hash, and the
// release's minimum OS version satisfied.
func fetchToolsRelease(rel *ghRelease, dir string) (map[string]string, error) {
	get := func(name string, max int64) ([]byte, error) {
		a := rel.asset(name)
		if a == nil {
			return nil, fmt.Errorf("release %s has no %s", rel.TagName, name)
		}
		p := filepath.Join(dir, name)
		if _, err := download(a.URL, p, max); err != nil {
			return nil, err
		}
		return os.ReadFile(p)
	}
	sums, err := get("SHA256SUMS", 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := get("SHA256SUMS.sig", 4<<10)
	if err != nil {
		return nil, err
	}
	if err := verifyReleaseSums(sums, sig, releasePublicKey); err != nil {
		return nil, err
	}
	want := parseSums(sums)
	meta, err := get("tools.json", 64<<10)
	if err != nil {
		return nil, err
	}
	if h := sha256Hex(meta); want["tools.json"] == "" || h != want["tools.json"] {
		return nil, errors.New("tools.json does not match the signed SHA256SUMS")
	}
	var tj struct {
		MinOS string `json:"min_os"`
	}
	if err := json.Unmarshal(meta, &tj); err != nil {
		return nil, fmt.Errorf("tools.json: %w", err)
	}
	if osv := strings.TrimPrefix(readRelease("/etc/ziro-release")["VERSION"], "v"); tj.MinOS != "" && osv != "" && compareSemver(osv, tj.MinOS) < 0 {
		return nil, fmt.Errorf("%s needs Ziro OS %s or newer (this host runs %s): run ziroctl upgrade first", rel.TagName, tj.MinOS, osv)
	}
	out := map[string]string{}
	for _, b := range toolsBinaries {
		name := b + "-" + hostArch()
		a := rel.asset(name)
		if a == nil || want[name] == "" {
			return nil, fmt.Errorf("release %s has no signed %s", rel.TagName, name)
		}
		p := filepath.Join(dir, name)
		got, err := download(a.URL, p, 256<<20)
		if err != nil {
			return nil, err
		}
		if got != want[name] {
			return nil, fmt.Errorf("%s: SHA-256 mismatch (got %s, want %s)", name, got, want[name])
		}
		out[b] = p
	}
	return out, nil
}

// installTool replaces /usr/bin/<name> atomically (same-filesystem rename), keeping the
// current binary as <name>.prev; /bin/<name> becomes a symlink to it.
func installTool(name, src string) error {
	dst := filepath.Join(toolsBinDir, name)
	tmp := dst + ".new"
	if err := copyFileSync(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	_ = os.Remove(dst + ".prev")
	if err := os.Link(dst, dst+".prev"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return linkBinCopy(name)
}

// linkBinCopy points /bin/<name> at /usr/bin/<name> (older images shipped two copies).
func linkBinCopy(name string) error {
	link := filepath.Join(toolsLinkDir, name)
	if t, err := os.Readlink(link); err == nil && t == filepath.Join(toolsBinDir, name) {
		return nil
	}
	tmp := link + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join(toolsBinDir, name), tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// trustToolHashes records the installed binaries' hashes as known good: added to the
// integrity baseline (the previous hash stays: IMA logged it before the update) and the FIM
// baseline.
func trustToolHashes(names []string) error {
	var lines []string
	fim := map[string]string{}
	if b, err := os.ReadFile(fimDBPath); err == nil {
		_ = json.Unmarshal(b, &fim)
	}
	for _, n := range names {
		p := filepath.Join(toolsBinDir, n)
		h, err := computeFileSHA256(p)
		if err != nil {
			return err
		}
		lines = append(lines, h+"  "+p)
		if _, ok := fim[p]; ok {
			fim[p] = h
		}
	}
	if fileExists(integrityBaseline) {
		f, err := os.OpenFile(integrityBaseline, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	if len(fim) > 0 {
		b, _ := json.MarshalIndent(fim, "", "  ")
		return writeFileAtomic(fimDBPath, b, 0600)
	}
	return nil
}

// writeCompletions installs bash and zsh completions for the (new) binaries. They take effect
// once bash or zsh is installed; BusyBox ash has no programmable completion.
func writeCompletions(root string) error {
	var errs []error
	for _, n := range toolsBinaries {
		for shell, dir := range map[string]string{"bash": "usr/share/bash-completion/completions", "zsh": "usr/share/zsh/site-functions"} {
			out, err := exec.Command(filepath.Join(toolsBinDir, n), "completion", shell).Output()
			if err != nil {
				continue // ziropkg may not offer completion
			}
			file := n
			if shell == "zsh" {
				file = "_" + n
			}
			d := filepath.Join(root, dir)
			if err := os.MkdirAll(d, 0755); err != nil {
				errs = append(errs, err)
				continue
			}
			errs = append(errs, writeFileAtomic(filepath.Join(d, file), out, 0644))
		}
	}
	return errors.Join(errs...)
}

// restartToolDaemons moves running ziroctl daemons onto the new binary, one at a time.
func restartToolDaemons() {
	for _, d := range toolsDaemons {
		if st, err := getServiceStatus(d); err == nil && st.Status == "RUNNING" {
			if err := restartService(d); err != nil {
				fmt.Fprintf(os.Stderr, "warning: restart %s: %v\n", d, err)
			} else {
				fmt.Printf("  restarted %s\n", d)
			}
		}
	}
}

func checkForUpdate() UpdateCheck {
	u := UpdateCheck{Current: Version, Checked: time.Now().UTC()}
	rel, v, err := latestToolsRelease(context.Background())
	if err != nil {
		u.Error = err.Error()
	} else {
		u.Latest, u.Tag = v, rel.TagName
	}
	if b, err := json.MarshalIndent(u, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(updateCheckFile), 0755)
		_ = writeFileAtomic(updateCheckFile, b, 0644)
	}
	return u
}

// runToolsUpdate installs the newest tools release (or tag), returning the version installed.
func runToolsUpdate(tag string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("ziroctl update must run as root")
	}
	var rel *ghRelease
	var ver string
	var err error
	if tag == "" {
		rel, ver, err = latestToolsRelease(context.Background())
	} else {
		if !strings.HasPrefix(tag, "tools/") {
			tag = "tools/" + tag
		}
		if m := toolsTagRe.FindStringSubmatch(tag); m == nil {
			return "", fmt.Errorf("invalid version %q (want vX.Y.Z)", tag)
		} else {
			ver = m[1]
			rel, err = getRelease(context.Background(), githubAPI+"/repos/"+upgradeRepo+"/releases/tags/"+tag)
			if err == nil && rel.TagName != tag {
				err = fmt.Errorf("release has tag %q, want %q", rel.TagName, tag)
			}
		}
	}
	if err != nil {
		return "", err
	}
	if tag == "" && compareSemver(ver, strings.TrimPrefix(Version, "v")) <= 0 {
		return "", nil // up to date
	}
	dir, err := os.MkdirTemp("/var/lib/ziro", ".update-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	bins, err := fetchToolsRelease(rel, dir)
	if err != nil {
		return "", err
	}
	for _, n := range toolsBinaries {
		if err := installTool(n, bins[n]); err != nil {
			return "", fmt.Errorf("install %s: %w", n, err)
		}
	}
	if err := trustToolHashes(toolsBinaries); err != nil {
		fmt.Fprintf(os.Stderr, "warning: integrity baselines: %v\n", err)
	}
	if err := writeCompletions("/"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: completions: %v\n", err)
	}
	_ = os.Remove(updateCheckFile)
	return ver, nil
}

func rollbackTools() error {
	if os.Geteuid() != 0 {
		return errors.New("ziroctl update must run as root")
	}
	for _, n := range toolsBinaries {
		dst := filepath.Join(toolsBinDir, n)
		if !fileExists(dst + ".prev") {
			return fmt.Errorf("no previous %s to roll back to", n)
		}
	}
	for _, n := range toolsBinaries {
		dst := filepath.Join(toolsBinDir, n)
		if err := os.Rename(dst+".prev", dst); err != nil {
			return err
		}
	}
	return trustToolHashes(toolsBinaries)
}

type updateConf struct {
	Auto bool `json:"auto"` // the daily check also installs
}

var (
	updateCheckOnly bool
	updateVersion   string
	updateRollback  bool
	updateCron      bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ziroctl and ziropkg",
	Example: `  ziroctl update --check
  ziroctl update
  ziroctl update --version v1.0.17
  ziroctl update --rollback`,
	Long: `Installs the newest ziroctl and ziropkg from the tools release stream (tags tools/vX.Y.Z),
independently of OS upgrades (ziroctl upgrade). The release's SHA256SUMS must carry a valid Ziro
release signature and every binary must match it. The binaries are swapped atomically, the
previous ones kept (--rollback), and running ziroctl daemons are restarted onto the new version.

A daily check runs from cron; the login summary shows when an update is available. Set
{"auto": true} in /etc/ziro/update.json to also install it automatically.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case updateRollback:
			if err := rollbackTools(); err != nil {
				return err
			}
			fmt.Println("✓ rolled back to the previous ziroctl and ziropkg")
			restartToolDaemons()
			return nil
		case updateCheckOnly || updateCron:
			if updateCron { // spread hosts' daily checks over half an hour
				time.Sleep(time.Duration(time.Now().UnixNano() % int64(30*time.Minute)))
			}
			u := checkForUpdate()
			if updateCron {
				var c updateConf
				if b, err := os.ReadFile(updateConfFile); err == nil {
					_ = json.Unmarshal(b, &c)
				}
				if !c.Auto || !u.Available() {
					return nil
				}
				break // auto-update
			}
			return printResult(u, func() {
				switch {
				case u.Error != "":
					fmt.Printf("ziroctl %s; update check failed: %s\n", Version, u.Error)
				case u.Available():
					fmt.Printf("ziroctl %s → %s available: run 'ziroctl update'\n", Version, u.Latest)
				default:
					fmt.Printf("ziroctl %s is up to date\n", Version)
				}
			})
		}
		ver, err := runToolsUpdate(updateVersion)
		if err != nil {
			return err
		}
		if ver == "" {
			fmt.Printf("ziroctl %s is up to date\n", Version)
			return nil
		}
		fmt.Printf("✓ ziroctl and ziropkg updated to %s (previous kept: ziroctl update --rollback)\n", ver)
		restartToolDaemons()
		return nil
	},
}

func init() {
	f := updateCmd.Flags()
	f.BoolVar(&updateCheckOnly, "check", false, "Only check whether an update is available")
	f.StringVar(&updateVersion, "version", "", "Install this tools version (vX.Y.Z) instead of the newest")
	f.BoolVar(&updateRollback, "rollback", false, "Restore the binaries replaced by the last update")
	f.BoolVar(&updateCron, "cron", false, "Daily check (cron); installs only when auto-update is enabled")
	_ = f.MarkHidden("cron")
	updateCmd.MarkFlagsMutuallyExclusive("check", "rollback", "version", "cron")
	rootCmd.AddCommand(updateCmd)
}

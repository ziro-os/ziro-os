package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/release"
)

// `ziroctl update`: ziroctl and ziropkg ship on their own release stream (tags tools/vX.Y.Z and
// tools/vX.Y.Z.N: the Nth tools-only build of OS version X.Y.Z), independent of OS upgrades. Every release's SHA256SUMS is signed with the Ziro release key
// (ed25519; the public half is below), and nothing is installed unless the signature and every
// hash verify. The binaries are replaced atomically, the previous ones kept for --rollback.

// releasePublicKey verifies SHA256SUMS.sig of tools and OS releases (sdk/release/release.pub,
// shared with zirocd; signed in CI with the secret ZIRO_RELEASE_KEY by scripts/release/sign-sums.sh).
var releasePublicKey = release.PublicKey

var (
	toolsBinDir   = "/usr/bin"
	toolsLinkDir  = "/bin"
	toolsBinaries = []string{"ziroctl", "ziropkg"}
	// Installed only where the image has them and the release carries them: zirocd ships in the
	// full image from its first tools release on, and updates through here on Ziro OS (its own
	// self-update stands down there, so the integrity baselines always know its hash).
	optionalTools   = []string{"zirocd"}
	updateCheckFile = "/var/lib/ziro/update-check.json"
	updateConfFile  = "/etc/ziro/update.json"
	// Long-running ziroctl daemons restarted onto the new binary, one at a time.
	toolsDaemons = []string{"sentinel", "ziro-api", "gateway", "cluster-agent", "cluster-master", "router-relay", "router-moon", "zirocd", "ziroctld"}
)

// verifyReleaseSums checks an ed25519 signature (base64) over SHA256SUMS.
func verifyReleaseSums(sums, sig []byte, pubPEM string) error {
	return release.Verify(sums, sig, pubPEM)
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
	return u.Latest != "" && release.Compare(u.Latest, strings.TrimPrefix(u.Current, "v")) > 0
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

// latestToolsRelease finds the newest tools/vX.Y.Z[.N] tag (from the tag refs, so OS releases never
// crowd it out of a page of releases) and fetches its release.
func latestToolsRelease(ctx context.Context) (*ghRelease, string, error) {
	var refs []struct {
		Ref string `json:"ref"`
	}
	if err := getGitHubJSON(ctx, githubAPI+"/repos/"+upgradeRepo+"/git/matching-refs/tags/tools/v", 4<<20, &refs); err != nil {
		return nil, "", err
	}
	tag, best := "", ""
	for _, r := range refs {
		t := strings.TrimPrefix(r.Ref, "refs/tags/")
		if m := release.ToolsTagRe.FindStringSubmatch(t); m != nil && (best == "" || release.Compare(m[1], best) > 0) {
			tag, best = t, m[1]
		}
	}
	if tag == "" {
		return nil, "", fmt.Errorf("no signed tools release found for %s; ziroctl upgrade brings newer tools with the OS", upgradeRepo)
	}
	rel, err := getRelease(ctx, githubAPI+"/repos/"+upgradeRepo+"/releases/tags/"+tag)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", tag, err)
	}
	if rel.TagName != tag || rel.Prerelease {
		return nil, "", fmt.Errorf("%s is not a published release", tag)
	}
	return rel, best, nil
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
	m := release.ToolsTagRe.FindStringSubmatch(rel.TagName)
	if m == nil {
		return nil, fmt.Errorf("%s is not a tools release", rel.TagName)
	}
	// The signed tools.json must name this very release: a signed older build re-published
	// under a newer tag (or the reverse) is refused instead of installing as the tag says.
	tj, err := release.CheckMeta(sums, meta, m[1])
	if err != nil {
		return nil, err
	}
	if osv := hostOSVersion(); tj.MinOS != "" && osv != "" && release.Compare(osv, tj.MinOS) < 0 {
		return nil, fmt.Errorf("%s needs Ziro OS %s or newer (this host runs %s): run ziroctl upgrade first", rel.TagName, tj.MinOS, osv)
	}
	out := map[string]string{}
	for _, b := range append(append([]string{}, toolsBinaries...), optionalTools...) {
		name := toolAsset(b)
		a := rel.asset(name)
		optional := slices.Contains(optionalTools, b)
		if optional && (a == nil || !fileExists(filepath.Join(toolsBinDir, b))) {
			continue
		}
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

// hostOSVersion is the Ziro OS version of this host ("" when unknown): the tools version
// (Version) is X.Y.Z.N and says nothing reliable about it.
func hostOSVersion() string {
	return strings.TrimPrefix(readRelease("/etc/ziro-release")["VERSION"], "v")
}

// toolAsset is a tool's file name in a tools release.
func toolAsset(b string) string {
	if b == "zirocd" { // the cross-platform client is named <os>-<goarch>
		return "zirocd-linux-" + runtime.GOARCH
	}
	return b + "-" + hostArch()
}

// installedTools lists the tools an update replaces on this host.
func installedTools(bins map[string]string) []string {
	out := append([]string{}, toolsBinaries...)
	for _, b := range optionalTools {
		if bins[b] != "" {
			out = append(out, b)
		}
	}
	return out
}

// stageTool copies src next to the installed binary (same filesystem, so the later rename is
// atomic) as <name>.new.
func stageTool(name, src string) (string, error) {
	tmp := filepath.Join(toolsBinDir, name) + ".new"
	if err := copyFileSync(src, tmp); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// reportedVersion extracts the version a tool's `version` output reports: "ziroctl version X (...)",
// "ziropkg version X" or zirocd's bare "X".
func reportedVersion(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	f := strings.Fields(line)
	switch {
	case len(f) == 1:
		return strings.TrimPrefix(f[0], "v")
	case len(f) >= 3 && f[1] == "version":
		return strings.TrimPrefix(f[2], "v")
	}
	return ""
}

// checkStaged runs a staged binary before it replaces the working one: it must start on this
// host and report exactly the release's version. A build whose version was not stamped (or a
// release published under the wrong tag) would otherwise look "available" forever and the
// daily update would reinstall it in a loop.
func checkStaged(staged, want string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, staged, "version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/"}
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the new %s does not run on this host: %w", filepath.Base(strings.TrimSuffix(staged, ".new")), err)
	}
	if got := reportedVersion(string(out)); got != want {
		return fmt.Errorf("the new %s reports version %q, not the release's %s: refusing to install it", filepath.Base(strings.TrimSuffix(staged, ".new")), got, want)
	}
	return nil
}

// commitTool swaps the staged binary in atomically, keeping the current one as <name>.prev;
// /bin/<name> becomes a symlink to it.
func commitTool(name, staged string) error {
	dst := filepath.Join(toolsBinDir, name)
	_ = os.Remove(dst + ".prev")
	if err := os.Link(dst, dst+".prev"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, dst); err != nil {
		return err
	}
	return linkBinCopy(name)
}

// installTool replaces /usr/bin/<name> atomically (same-filesystem rename), keeping the
// current binary as <name>.prev.
func installTool(name, src string) error {
	tmp, err := stageTool(name, src)
	if err != nil {
		return err
	}
	if err := commitTool(name, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
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

// resolveToolsTarget picks the release to install: the newest (tag "") when it is newer than
// the running ziroctl, else the given version. A nil release means nothing to do (already up to
// date, or the requested version is the running one). A requested version older than the
// running one is refused unless allowDowngrade: only the newest release is ever installed
// unprompted, so a typo or a stale script cannot walk a host backwards.
func resolveToolsTarget(ctx context.Context, tag string, allowDowngrade bool) (*ghRelease, string, error) {
	running := strings.TrimPrefix(Version, "v")
	if tag == "" {
		rel, ver, err := latestToolsRelease(ctx)
		if err != nil || release.Compare(ver, running) <= 0 {
			return nil, "", err
		}
		return rel, ver, nil
	}
	ver := strings.TrimPrefix(strings.TrimPrefix(tag, "tools/"), "v")
	if !release.ValidTools(ver) {
		return nil, "", fmt.Errorf("invalid version %q (want vX.Y.Z or vX.Y.Z.N)", tag)
	}
	switch c := release.Compare(ver, running); {
	case c == 0:
		return nil, "", nil
	case c < 0 && !allowDowngrade:
		return nil, "", fmt.Errorf("refusing to downgrade ziroctl %s to %s: pass --allow-downgrade to do it (or use --rollback to restore the previous binaries)", running, ver)
	}
	tag = "tools/v" + ver
	rel, err := getRelease(ctx, githubAPI+"/repos/"+upgradeRepo+"/releases/tags/"+tag)
	if err != nil {
		return nil, "", err
	}
	if rel.TagName != tag || rel.Prerelease {
		return nil, "", fmt.Errorf("%s is not a published tools release", tag)
	}
	return rel, ver, nil
}

// runToolsUpdate installs the newest tools release (or tag), returning the version installed
// ("" = nothing to do).
func runToolsUpdate(tag string, allowDowngrade bool) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("ziroctl update must run as root")
	}
	rel, ver, err := resolveToolsTarget(context.Background(), tag, allowDowngrade)
	if err != nil || rel == nil {
		return "", err
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
	// Stage and run every binary first, then swap: a bad build never replaces a working
	// one, and a failure on the second tool leaves no mix of old and new.
	names := installedTools(bins)
	staged := map[string]string{}
	defer func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}()
	for _, n := range names {
		p, err := stageTool(n, bins[n])
		if err != nil {
			return "", fmt.Errorf("stage %s: %w", n, err)
		}
		staged[n] = p
		if err := checkStaged(p, ver); err != nil {
			return "", err
		}
	}
	for _, n := range names {
		if err := commitTool(n, staged[n]); err != nil {
			return "", fmt.Errorf("install %s: %w", n, err)
		}
		delete(staged, n)
	}
	if err := trustToolHashes(names); err != nil {
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
	names := append([]string{}, toolsBinaries...)
	for _, n := range optionalTools {
		if fileExists(filepath.Join(toolsBinDir, n) + ".prev") {
			names = append(names, n)
		}
	}
	for _, n := range names {
		dst := filepath.Join(toolsBinDir, n)
		if err := os.Rename(dst+".prev", dst); err != nil {
			return err
		}
	}
	return trustToolHashes(names)
}

type updateConf struct {
	Auto bool `json:"auto"` // the daily check also installs
}

var (
	updateCheckOnly bool
	updateVersion   string
	updateDowngrade bool
	updateRollback  bool
	updateCron      bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ziroctl and ziropkg",
	Example: `  ziroctl update --check
  ziroctl update
  ziroctl update --version v1.0.21.3
  ziroctl update --version v1.0.17 --allow-downgrade
  ziroctl update --rollback`,
	Long: `Installs the newest ziroctl and ziropkg from the tools release stream (tags tools/vX.Y.Z and
tools/vX.Y.Z.N), independently of OS upgrades (ziroctl upgrade). A tools version is the Ziro OS
version it was built for plus a build number: 1.0.21.3 is the third tools-only build for Ziro OS
1.0.21, and the build that ships inside an OS image is just 1.0.21. The release's SHA256SUMS must carry a valid Ziro
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
		ver, err := runToolsUpdate(updateVersion, updateDowngrade)
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
	f.StringVar(&updateVersion, "version", "", "Install this tools version (vX.Y.Z or vX.Y.Z.N) instead of the newest")
	f.BoolVar(&updateDowngrade, "allow-downgrade", false, "With --version: allow installing a version older than the running one")
	f.BoolVar(&updateRollback, "rollback", false, "Restore the binaries replaced by the last update")
	f.BoolVar(&updateCron, "cron", false, "Daily check (cron); installs only when auto-update is enabled")
	_ = f.MarkHidden("cron")
	updateCmd.MarkFlagsMutuallyExclusive("check", "rollback", "version", "cron")
	updateCmd.MarkFlagsMutuallyExclusive("allow-downgrade", "check", "rollback", "cron")
	updateCmd.MarkFlagsRequiredTogether("allow-downgrade", "version")
	rootCmd.AddCommand(updateCmd)
}

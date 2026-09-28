package cmd

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Host upgrade: the release initramfs is the complete OS image (kernel, modules,
// userland). It is verified, unpacked next to the live root on the same
// filesystem, and swapped in file-by-file with rename(2). Every replaced entry is
// kept in a rollback tree; data (/var, /root, /home, /data) and local /etc config
// are never overwritten.

const (
	upgradeRepo    = "ziro-os/ziro-os"
	upgradeRelDir  = "var/lib/ziro/upgrade"
	maxSumsBytes   = 64 << 10
	maxImageBytes  = 1 << 30
	maxExtractSize = 2 << 30
	prevGrubMarker = "Ziro-OS (previous version)"
)

var (
	githubAPI = "https://api.github.com"
	// Release downloads redirect from github.com to *.githubusercontent.com.
	trustedHosts   = []string{"github.com", "api.github.com"}
	trustedSuffix  = ".githubusercontent.com"
	upgradeTagRe   = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
	upgradeHTTP    = &http.Client{Timeout: 30 * time.Minute, CheckRedirect: checkUpgradeRedirect}
	sumsLineRe     = regexp.MustCompile(`^([0-9a-f]{64})\s+\*?(\S+)$`)
	replaceTopDirs = map[string]bool{"bin": true, "sbin": true, "lib": true, "lib64": true, "usr": true, "opt": true, "init": true}
	etcAlwaysNew   = map[string]bool{"etc/os-release": true, "etc/ziro-release": true}
	requiredImage  = []string{"sbin/init", "bin/busybox", "boot/vmlinuz", "usr/bin/ziroctl", "etc/ziro-release"}
	grubCfgPaths   = []string{"boot/grub/grub.cfg", "boot/efi/boot/grub/grub.cfg", "boot/efi/EFI/BOOT/grub.cfg", "boot/efi/EFI/ziro-os/grub.cfg"}
)

// ---------------------------------------------------------------------------
// Image extraction (cpio newc, gzip). This is the trust boundary for image
// content, so it is done in Go rather than by an external cpio binary.

func extractInitramfs(gzPath, dst string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return fmt.Errorf("image is not gzip: %w", err)
	}
	defer gz.Close()
	r := bufio.NewReaderSize(gz, 1<<20)

	isRoot := os.Geteuid() == 0
	buf := make([]byte, 1<<20)
	symlinks := map[string]bool{}
	pendingLinks := map[string][]string{} // inode key -> names whose data comes later
	dataFor := map[string]string{}        // inode key -> extracted path holding the data
	var total int64
	hdr := make([]byte, 110)

	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return fmt.Errorf("cpio header: %w", err)
		}
		if m := string(hdr[:6]); m != "070701" && m != "070702" {
			return fmt.Errorf("bad cpio magic %q", m)
		}
		var fld [13]uint64
		for i := range fld {
			v, err := strconv.ParseUint(string(hdr[6+i*8:14+i*8]), 16, 32)
			if err != nil {
				return fmt.Errorf("cpio field %d: %w", i, err)
			}
			fld[i] = v
		}
		ino, mode, uid, gid, nlink, mtime, size := fld[0], fld[1], int(fld[2]), int(fld[3]), fld[4], int64(fld[5]), int64(fld[6])
		namesize := int(fld[11])
		if namesize < 1 || namesize > 4096 {
			return fmt.Errorf("cpio name size %d out of range", namesize)
		}
		nameBuf := make([]byte, namesize+pad4(110+namesize))
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return err
		}
		name := strings.TrimRight(string(nameBuf[:namesize]), "\x00")
		if name == "TRAILER!!!" {
			break
		}
		dataPad := pad4(int(size))
		discard := func() error { _, err := r.Discard(int(size) + dataPad); return err }

		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return fmt.Errorf("member %q contains '..'", name)
			}
		}
		name = strings.TrimPrefix(filepath.Clean("/"+name), "/")
		if name == "" || name == "." {
			if err := discard(); err != nil {
				return err
			}
			continue
		}
		if err := checkMemberName(name, symlinks); err != nil {
			return err
		}
		if symlinks[name] && mode&0170000 != 0120000 {
			return fmt.Errorf("member %q replaces a symlink shipped in the same image", name)
		}
		total += size
		if total > maxExtractSize {
			return fmt.Errorf("image expands beyond %d bytes", int64(maxExtractSize))
		}
		p := filepath.Join(dst, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return err
		}
		perm := os.FileMode(mode & 0777)
		special := mode & 07000

		switch mode & 0170000 {
		case 0040000: // directory
			if err := os.MkdirAll(p, 0755); err != nil {
				return err
			}
			if err := finishMeta(p, isRoot, uid, gid, perm, special, 0); err != nil {
				return err
			}
			if err := discard(); err != nil {
				return err
			}
		case 0120000: // symlink
			if size > 4096 {
				return fmt.Errorf("symlink %q target too long", name)
			}
			target := make([]byte, int(size)+dataPad)
			if _, err := io.ReadFull(r, target); err != nil {
				return err
			}
			_ = os.Remove(p)
			if err := os.Symlink(string(target[:size]), p); err != nil {
				return err
			}
			if isRoot {
				_ = os.Lchown(p, uid, gid)
			}
			symlinks[name] = true
		case 0100000: // regular file (possibly hardlinked)
			key := fmt.Sprintf("%d:%d:%d", fld[7], fld[8], ino)
			if nlink > 1 && size == 0 {
				if src, ok := dataFor[key]; ok {
					_ = os.Remove(p)
					if err := os.Link(src, p); err != nil {
						return err
					}
				} else {
					pendingLinks[key] = append(pendingLinks[key], name)
				}
				if err := discard(); err != nil {
					return err
				}
				continue
			}
			if err := writeMember(r, p, size, buf); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if _, err := r.Discard(dataPad); err != nil {
				return err
			}
			if err := finishMeta(p, isRoot, uid, gid, perm, special, mtime); err != nil {
				return err
			}
			for _, other := range pendingLinks[key] {
				op := filepath.Join(dst, other)
				_ = os.Remove(op)
				if err := os.Link(p, op); err != nil {
					return err
				}
			}
			delete(pendingLinks, key)
			if nlink > 1 {
				dataFor[key] = p
			}
		default: // device nodes, fifos, sockets: never shipped by an upgrade
			if err := discard(); err != nil {
				return err
			}
		}
	}
	// Hardlink groups whose members all had size 0 are legitimately empty files.
	for _, names := range pendingLinks {
		first := filepath.Join(dst, names[0])
		if err := os.WriteFile(first, nil, 0644); err != nil {
			return err
		}
		for _, other := range names[1:] {
			if err := os.Link(first, filepath.Join(dst, other)); err != nil {
				return err
			}
		}
	}
	return nil
}

func pad4(n int) int { return (4 - n%4) % 4 }

// checkMemberName rejects newlines (the rollback journal is
// line-based) and writes through a symlink shipped earlier in the archive.
func checkMemberName(name string, symlinks map[string]bool) error {
	if strings.ContainsAny(name, "\n\r") {
		return fmt.Errorf("member %q has a control character", name)
	}
	for dir := filepath.Dir(name); dir != "." && dir != "/"; dir = filepath.Dir(dir) {
		if symlinks[dir] {
			return fmt.Errorf("member %q would be written through symlink %q", name, dir)
		}
	}
	return nil
}

func writeMember(r io.Reader, p string, size int64, buf []byte) error {
	_ = os.Remove(p)
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err := io.CopyBuffer(out, io.LimitReader(r, size), buf); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// finishMeta applies ownership before mode: chown clears setuid/setgid bits.
func finishMeta(p string, isRoot bool, uid, gid int, perm os.FileMode, special uint64, mtime int64) error {
	if isRoot {
		if err := os.Lchown(p, uid, gid); err != nil {
			return err
		}
	}
	mode := perm
	if special&04000 != 0 {
		mode |= os.ModeSetuid
	}
	if special&02000 != 0 {
		mode |= os.ModeSetgid
	}
	if special&01000 != 0 {
		mode |= os.ModeSticky
	}
	if err := os.Chmod(p, mode); err != nil {
		return err
	}
	if mtime > 0 {
		t := time.Unix(mtime, 0)
		return os.Chtimes(p, t, t)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Apply / rollback

type upgradeState struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"` // applying | applied | rolled-back
	Time   string `json:"time"`
}

// journal records what a swap did so rollback can undo it exactly.
type journal struct {
	root, rollback string
	moved, added   []string
}

func (j *journal) moveAside(rel string) error {
	rb := filepath.Join(j.rollback, rel)
	if err := os.MkdirAll(filepath.Dir(rb), 0700); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(j.root, rel), rb); err != nil {
		return err
	}
	j.moved = append(j.moved, rel)
	return nil
}

func (j *journal) place(staging, rel string, isNew bool) error {
	dst := filepath.Join(j.root, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(staging, rel), dst); err != nil {
		return err
	}
	if isNew {
		j.added = append(j.added, rel)
	}
	return nil
}

func (j *journal) save() error {
	if err := writeFileAtomic(filepath.Join(j.rollback, ".moved"), []byte(strings.Join(j.moved, "\n")), 0600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(j.rollback, ".added"), []byte(strings.Join(j.added, "\n")), 0600)
}

// replaceTree swaps staging/rel into root/rel, recursing while both sides are
// directories so untouched host entries (e.g. old /lib/modules/<krel>) survive.
func replaceTree(staging string, j *journal, rel string) error {
	sfi, err := os.Lstat(filepath.Join(staging, rel))
	if err != nil {
		return err
	}
	dfi, derr := os.Lstat(filepath.Join(j.root, rel))
	if derr != nil && !os.IsNotExist(derr) {
		return derr
	}
	if derr == nil && sfi.IsDir() && dfi.IsDir() {
		children, err := os.ReadDir(filepath.Join(staging, rel))
		if err != nil {
			return err
		}
		for _, c := range children {
			if err := replaceTree(staging, j, filepath.Join(rel, c.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if derr == nil {
		if err := j.moveAside(rel); err != nil {
			return err
		}
	}
	return j.place(staging, rel, derr != nil)
}

// mergeEtc adds files the host lacks and only replaces release metadata.
func mergeEtc(staging string, j *journal) error {
	return filepath.WalkDir(filepath.Join(staging, "etc"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(staging, p)
		_, derr := os.Lstat(filepath.Join(j.root, rel))
		switch {
		case os.IsNotExist(derr):
			if err := j.place(staging, rel, true); err != nil {
				return err
			}
			if d.IsDir() {
				return fs.SkipDir
			}
		case derr != nil:
			return derr
		case etcAlwaysNew[rel]:
			if err := j.moveAside(rel); err != nil {
				return err
			}
			return j.place(staging, rel, false)
		}
		return nil
	})
}

// ensureVarDirs creates directories the new OS expects; files under /var are data.
func ensureVarDirs(staging, root string) error {
	return filepath.WalkDir(filepath.Join(staging, "var"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(staging, p)
		if rel == upgradeRelDir || strings.HasPrefix(rel, upgradeRelDir+"/") {
			return fs.SkipDir
		}
		dst := filepath.Join(root, rel)
		if _, err := os.Lstat(dst); os.IsNotExist(err) {
			info, _ := d.Info()
			if err := os.Mkdir(dst, info.Mode().Perm()); err != nil {
				return err
			}
		}
		return nil
	})
}

func readRelease(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out
}

func lockUpgrade(base string) (*os.File, error) {
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(base, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another upgrade or rollback is already running")
	}
	return f, nil
}

func applyUpgrade(root, image string) (*upgradeState, error) {
	base := filepath.Join(root, upgradeRelDir)
	lock, err := lockUpgrade(base)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	staging := filepath.Join(base, "staging")
	if err := os.RemoveAll(staging); err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	fmt.Println("📦 Unpacking OS image...")
	if err := extractInitramfs(image, staging); err != nil {
		return nil, fmt.Errorf("unpack image: %w", err)
	}

	oldRel := readRelease(filepath.Join(root, "etc/ziro-release"))
	newRel := readRelease(filepath.Join(staging, "etc/ziro-release"))
	for _, req := range requiredImage {
		if _, err := os.Lstat(filepath.Join(staging, req)); err != nil {
			return nil, fmt.Errorf("image is incomplete: missing /%s", req)
		}
	}
	if newRel["VERSION"] == "" {
		return nil, errors.New("image has no VERSION in /etc/ziro-release")
	}
	if a, b := oldRel["ARCH"], newRel["ARCH"]; a != "" && b != "" && a != b {
		return nil, fmt.Errorf("architecture mismatch: host %s, image %s", a, b)
	}
	if a, b := oldRel["KERNEL_FLAVOR"], newRel["KERNEL_FLAVOR"]; a != "" && b != "" && a != b {
		fmt.Printf("⚠️  Kernel flavor changes from %s to %s\n", a, b)
	}

	// One rollback generation keeps disk usage bounded.
	rollback := filepath.Join(base, "rollback")
	if err := os.RemoveAll(rollback); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(rollback, 0700); err != nil {
		return nil, err
	}
	state := &upgradeState{From: oldRel["VERSION"], To: newRel["VERSION"], Status: "applying", Time: time.Now().UTC().Format(time.RFC3339)}
	if err := saveState(base, state); err != nil {
		return nil, err
	}

	fmt.Printf("🔁 Swapping OS files %s → %s...\n", state.From, state.To)
	j := &journal{root: root, rollback: rollback}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case replaceTopDirs[name]:
			err = replaceTree(staging, j, name)
		case name == "etc":
			err = mergeEtc(staging, j)
		case name == "var":
			err = ensureVarDirs(staging, root)
		}
		if err != nil {
			_ = j.save()
			return nil, fmt.Errorf("swap %s: %w (run 'ziroctl upgrade rollback')", name, err)
		}
	}
	if err := j.save(); err != nil {
		return nil, err
	}

	fmt.Println("🥾 Installing kernel and boot image...")
	if err := installBootFiles(root, filepath.Join(staging, "boot/vmlinuz"), image); err != nil {
		return nil, fmt.Errorf("boot files: %w (run 'ziroctl upgrade rollback')", err)
	}
	syscall.Sync()
	state.Status = "applied"
	return state, saveState(base, state)
}

// installBootFiles stages new boot files, points a GRUB entry at *.prev, then
// renames: at every instant either the current or the previous pair boots.
func installBootFiles(root, kernel, initramfs string) error {
	boot := filepath.Join(root, "boot")
	pairs := [][2]string{{kernel, "vmlinuz"}, {initramfs, "initramfs.cpio.gz"}}
	for _, p := range pairs {
		if err := copyFileSync(p[0], filepath.Join(boot, p[1]+".new")); err != nil {
			return err
		}
	}
	if err := addPrevGrubEntry(root); err != nil {
		return err
	}
	for _, p := range pairs {
		cur := filepath.Join(boot, p[1])
		if fileExists(cur) {
			if err := os.Rename(cur, cur+".prev"); err != nil {
				return err
			}
		}
		if err := os.Rename(cur+".new", cur); err != nil {
			return err
		}
	}
	return nil
}

func addPrevGrubEntry(root string) error {
	entry := `
menuentry "` + prevGrubMarker + `" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz.prev root=LABEL=ZIRO_ROOT rootflags=rw console=ttyS0,115200 console=tty0
    initrd /boot/initramfs.cpio.gz.prev
}
`
	for _, rel := range grubCfgPaths {
		p := filepath.Join(root, rel)
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.Contains(string(data), prevGrubMarker) {
			continue
		}
		if err := writeFileAtomic(p, append(data, entry...), 0644); err != nil {
			return err
		}
	}
	return nil
}

func rollbackUpgrade(root string) (*upgradeState, error) {
	base := filepath.Join(root, upgradeRelDir)
	lock, err := lockUpgrade(base)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	rollback := filepath.Join(base, "rollback")
	moved, err1 := readLines(filepath.Join(rollback, ".moved"))
	added, err2 := readLines(filepath.Join(rollback, ".added"))
	if err1 != nil || err2 != nil {
		return nil, errors.New("no rollback data found (nothing to roll back)")
	}
	for i := len(added) - 1; i >= 0; i-- {
		if err := os.RemoveAll(filepath.Join(root, added[i])); err != nil {
			return nil, err
		}
	}
	for _, rel := range moved {
		dst := filepath.Join(root, rel)
		if err := os.RemoveAll(dst); err != nil {
			return nil, err
		}
		if err := os.Rename(filepath.Join(rollback, rel), dst); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"vmlinuz", "initramfs.cpio.gz"} {
		cur := filepath.Join(root, "boot", name)
		if fileExists(cur + ".prev") {
			if err := os.Rename(cur+".prev", cur); err != nil {
				return nil, err
			}
		}
	}
	if err := os.RemoveAll(rollback); err != nil {
		return nil, err
	}
	syscall.Sync()
	state := loadState(base)
	state.Status = "rolled-back"
	state.Time = time.Now().UTC().Format(time.RFC3339)
	return state, saveState(base, state)
}

func readLines(p string) ([]string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func saveState(base string, s *upgradeState) error {
	data, _ := json.MarshalIndent(s, "", "  ")
	return writeFileAtomic(filepath.Join(base, "state"), data, 0600)
}

func loadState(base string) *upgradeState {
	s := &upgradeState{}
	if data, err := os.ReadFile(filepath.Join(base, "state")); err == nil {
		_ = json.Unmarshal(data, s)
	}
	return s
}

func writeFileAtomic(p string, data []byte, perm os.FileMode) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------------------
// Release discovery, download and verification

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

func (r *ghRelease) asset(name string) *ghAsset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

func isTrustedURL(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	h := u.Hostname()
	for _, t := range trustedHosts {
		if h == t {
			return true
		}
	}
	return strings.HasSuffix(h, trustedSuffix)
}

func checkUpgradeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if !isTrustedURL(req.URL) {
		return fmt.Errorf("refusing redirect to untrusted host %s", req.URL.Host)
	}
	return nil
}

func fetchRelease(ctx context.Context, tag string) (*ghRelease, error) {
	endpoint := githubAPI + "/repos/" + upgradeRepo + "/releases/latest"
	if tag != "" {
		if !upgradeTagRe.MatchString(tag) {
			return nil, fmt.Errorf("invalid version %q (want vX.Y.Z)", tag)
		}
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		endpoint = githubAPI + "/repos/" + upgradeRepo + "/releases/tags/" + tag
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ziroctl/"+Version)
	resp, err := upgradeHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query releases: HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	if !upgradeTagRe.MatchString(rel.TagName) {
		return nil, fmt.Errorf("release has invalid tag %q", rel.TagName)
	}
	return &rel, nil
}

// download streams url to dst (via dst.part), hashing while writing, and
// returns the hex SHA-256. Bodies larger than max are rejected.
func download(rawURL, dst string, max int64) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !isTrustedURL(u) {
		return "", fmt.Errorf("refusing untrusted download URL %q", rawURL)
	}
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("User-Agent", "ziroctl/"+Version)
	resp, err := upgradeHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", filepath.Base(dst), resp.StatusCode)
	}
	if resp.ContentLength > max {
		return "", fmt.Errorf("download %s: %d bytes exceeds limit", filepath.Base(dst), resp.ContentLength)
	}
	part := dst + ".part"
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("download %s exceeds limit", filepath.Base(dst))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(part)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), os.Rename(part, dst)
}

func parseSums(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if m := sumsLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			out[m[2]] = m[1]
		}
	}
	return out
}

func parseSemver(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	s, _, _ = strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// compareSemver returns -1, 0 or 1. Unparseable versions compare as older.
func compareSemver(a, b string) int {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	if !oka || !okb {
		switch {
		case oka:
			return 1
		case okb:
			return -1
		}
		return 0
	}
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			if va[i] < vb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func hostArch() string {
	if a := readRelease("/etc/ziro-release")["ARCH"]; a != "" {
		return a
	}
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

func imageAssetName(arch, flavor string) string {
	suffix := ""
	if flavor == "custom" {
		suffix = "-custom"
	}
	return fmt.Sprintf("ziro-initramfs-%s%s.cpio.gz", arch, suffix)
}

// ---------------------------------------------------------------------------
// Preflight

func upgradeGuards() error {
	if os.Geteuid() != 0 {
		return errors.New("ziroctl upgrade must run as root")
	}
	if !fileExists("/etc/ziro-installed") {
		return errors.New("not an installed Ziro-OS host (live ISO or container); upgrade the image instead")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return err
	}
	if uint64(st.Type)&0xffff != 0xef53 {
		return errors.New("root filesystem is not the installed ext4 ZIRO_ROOT")
	}
	return nil
}

func freeBytes(path string) uint64 {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}

// validateHostConfig catches configuration that would break the host after a
// reboot, most importantly remote (SSH) access.
func validateHostConfig(root string) []string {
	var problems []string
	if data, err := os.ReadFile(filepath.Join(root, "etc/fstab")); err != nil || !strings.Contains(string(data), "LABEL=ZIRO_ROOT") {
		problems = append(problems, "/etc/fstab does not mount LABEL=ZIRO_ROOT")
	}
	if !fileExists(filepath.Join(root, "boot/grub/grub.cfg")) {
		problems = append(problems, "/boot/grub/grub.cfg is missing")
	}
	if readRelease(filepath.Join(root, "etc/ziro-release"))["VERSION"] == "" {
		problems = append(problems, "/etc/ziro-release has no VERSION")
	}
	if root == "/" {
		if sshd, err := exec.LookPath("sshd"); err == nil {
			if out, err := exec.Command(sshd, "-t").CombinedOutput(); err != nil {
				problems = append(problems, "sshd -t: "+strings.TrimSpace(string(out)))
			}
		}
	}
	return problems
}

// ---------------------------------------------------------------------------
// Commands

var (
	upgradeCheckOnly bool
	upgradeVersion   string
	upgradeYes       bool
	upgradeReboot    bool
	upgradeForce     bool
	upgradeRoot      string
	upgradeImage     string
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade the Ziro-OS host to a newer release (keeps all data)",
	Long: `ziroctl upgrade checks the public GitHub releases for a newer Ziro-OS version,
runs doctor and configuration validation, snapshots the configuration,
downloads the OS image, verifies it against the release SHA256SUMS and swaps
it in atomically. The previous OS stays available via 'ziroctl upgrade rollback'
and the "Ziro-OS (previous version)" boot entry.

Only the host is upgraded. Containers keep running their own images; pull newer
images manually.`,
	Args: cobra.NoArgs,
	RunE: runUpgrade,
}

var upgradeRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Restore the OS files and kernel from before the last upgrade",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return errors.New("rollback must run as root")
		}
		state, err := rollbackUpgrade(upgradeRoot)
		if err != nil {
			return err
		}
		return reportUpgrade(state, "✅ Rolled back to "+state.From+". Reboot to finish.")
	},
}

var upgradeApplyCmd = &cobra.Command{
	Use:    "apply",
	Short:  "Apply a verified OS image to a mounted root (used by the installer)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if upgradeImage == "" {
			return errors.New("--initramfs is required")
		}
		if os.Geteuid() != 0 {
			return errors.New("apply must run as root")
		}
		if !fileExists(filepath.Join(upgradeRoot, "etc/ziro-installed")) {
			return fmt.Errorf("%s is not an installed Ziro-OS root", upgradeRoot)
		}
		state, err := applyUpgrade(upgradeRoot, upgradeImage)
		if err != nil {
			return err
		}
		return reportUpgrade(state, fmt.Sprintf("✅ Upgraded %s → %s", state.From, state.To))
	},
}

func reportUpgrade(state *upgradeState, msg string) error {
	if jsonOutput {
		data, _ := json.MarshalIndent(state, "", "  ")
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(msg)
	return nil
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	if !upgradeCheckOnly {
		if err := upgradeGuards(); err != nil {
			return err
		}
	}
	current := readRelease("/etc/ziro-release")["VERSION"]
	if current == "" {
		current = Version
	}
	rel, err := fetchRelease(cmd.Context(), upgradeVersion)
	if err != nil {
		return err
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	cmpv := compareSemver(latest, current)

	if upgradeCheckOnly {
		if jsonOutput {
			data, _ := json.MarshalIndent(map[string]any{"current": current, "latest": latest, "update_available": cmpv > 0}, "", "  ")
			fmt.Println(string(data))
		} else if cmpv > 0 {
			fmt.Printf("⬆️  Ziro-OS %s is available (installed: %s). Run 'ziroctl upgrade'.\n", latest, current)
		} else {
			fmt.Printf("✅ Ziro-OS %s is up to date (latest: %s).\n", current, latest)
		}
		return nil
	}
	if cmpv == 0 {
		fmt.Printf("✅ Ziro-OS %s is already installed.\n", current)
		return nil
	}
	if cmpv < 0 {
		return fmt.Errorf("refusing to downgrade %s → %s", current, latest)
	}

	hostRel := readRelease("/etc/ziro-release")
	assetName := imageAssetName(hostArch(), hostRel["KERNEL_FLAVOR"])
	asset, sums := rel.asset(assetName), rel.asset("SHA256SUMS")
	if asset == nil || sums == nil {
		return fmt.Errorf("release %s has no %s or SHA256SUMS", rel.TagName, assetName)
	}

	fmt.Printf("🔎 Preflight for Ziro-OS %s → %s\n", current, latest)
	checks := runDoctor()
	need := uint64(asset.Size) * 4
	free := freeBytes("/")
	checks = append(checks, doctorCheck{"Free space on ZIRO_ROOT", free >= need,
		fmt.Sprintf("%d MB free, %d MB needed", free>>20, need>>20), true})
	printDoctor(checks)
	var blocking []string
	for _, c := range checks {
		if c.Critical && !c.Passed {
			blocking = append(blocking, c.Name)
		}
	}
	blocking = append(blocking, validateHostConfig("/")...)
	if len(blocking) > 0 {
		for _, b := range blocking {
			fmt.Printf(" ❌ %s\n", b)
		}
		if !upgradeForce {
			return errors.New("preflight failed; fix the issues above or pass --force")
		}
		fmt.Println("⚠️  --force: continuing despite preflight failures")
	}

	dir := filepath.Join("/", upgradeRelDir, latest)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fmt.Printf("⬇️  Downloading %s (%d MB)...\n", assetName, asset.Size>>20)
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if _, err := download(sums.URL, sumsPath, maxSumsBytes); err != nil {
		return err
	}
	sumsData, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	want, ok := parseSums(sumsData)[assetName]
	if !ok {
		return fmt.Errorf("SHA256SUMS has no entry for %s", assetName)
	}
	image := filepath.Join(dir, assetName)
	got, err := download(asset.URL, image, maxImageBytes)
	if err != nil {
		return err
	}
	if got != want {
		os.Remove(image)
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetName, want, got)
	}
	fmt.Println("✓ SHA-256 verified:", got)

	backup, err := createBackup(filepath.Join(defaultBackupDir,
		fmt.Sprintf("ziro-backup-preupgrade-%s-%s.tar.gz", current, time.Now().Format("20060102-150405"))))
	if err != nil {
		return fmt.Errorf("pre-upgrade snapshot: %w", err)
	}

	if !upgradeYes && !confirm(fmt.Sprintf("Upgrade Ziro-OS %s → %s now? Snapshot: %s [y/N]: ", current, latest, backup)) {
		fmt.Println("Upgrade cancelled. Nothing was changed.")
		return nil
	}
	state, err := applyUpgrade("/", image)
	if err != nil {
		return err
	}
	_ = reportUpgrade(state, fmt.Sprintf("✅ Ziro-OS upgraded %s → %s. Rollback: 'ziroctl upgrade rollback'.", state.From, state.To))

	if upgradeReboot || (!upgradeYes && confirm("Reboot now to finish? [y/N]: ")) {
		fmt.Println("🔄 Rebooting...")
		return exec.Command("/sbin/reboot").Run()
	}
	fmt.Println("Reboot to start the new version.")
	return nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func init() {
	upgradeCmd.Flags().BoolVar(&upgradeCheckOnly, "check", false, "Only check whether a newer release is available")
	upgradeCmd.Flags().StringVar(&upgradeVersion, "version", "", "Upgrade to a specific release (e.g. v1.1.0) instead of the latest")
	upgradeCmd.Flags().BoolVarP(&upgradeYes, "yes", "y", false, "Do not prompt for confirmation")
	upgradeCmd.Flags().BoolVar(&upgradeReboot, "reboot", false, "Reboot automatically after a successful upgrade")
	upgradeCmd.Flags().BoolVar(&upgradeForce, "force", false, "Continue despite doctor/config preflight failures (never skips checksum verification)")

	upgradeRollbackCmd.Flags().StringVar(&upgradeRoot, "root", "/", "Root filesystem to roll back")
	upgradeApplyCmd.Flags().StringVar(&upgradeRoot, "root", "/", "Mounted target root filesystem")
	upgradeApplyCmd.Flags().StringVar(&upgradeImage, "initramfs", "", "Verified Ziro-OS initramfs image (.cpio.gz)")

	upgradeCmd.AddCommand(upgradeRollbackCmd, upgradeApplyCmd)
	rootCmd.AddCommand(upgradeCmd)
}

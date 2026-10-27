package cmd

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var defaultBackupDir = "/var/backups/ziro"

// backupPaths are the only locations a backup may contain or restore into: the configuration
// and the state of the host (gateway certificates, apps, stacks, deployments, sandboxes, DNS,
// cluster state and keys, the audit log). Volumes and the data of Postgres clusters are not in
// the default set (see backupBulkExcludes).
var backupPaths = []string{
	"/etc/ziro",
	"/etc/ssh",
	"/etc/wireguard",
	"/etc/network",
	"/etc/crontabs",
	"/etc/hostname",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/sysctl.conf",
	"/etc/sysctl.d",
	"/etc/exports.d",
	"/etc/cni/net.d",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/ziro-release",
	"/etc/ziro-installed",
	"/etc/ziro-config",
	"/var/lib/ziro",
	"/var/lib/zirocd-moon",
	"/var/log/ziro",
}

// Local accounts are in a backup, but a restore leaves them alone unless asked (--users): an older
// archive restored over a newer image would otherwise drop system users the image added since.
var backupUserFiles = []string{"etc/passwd", "etc/shadow", "etc/group"}

// backupAlwaysExcludes never go into an archive: the backup key (it would sit next to what it
// protects), the Tailscale node key (a restored copy would clone the node's identity), upgrade
// staging (whole OS images) and plugin binaries (downloaded again).
func backupAlwaysExcludes() []string {
	return append([]string{strings.TrimPrefix(backupKeyPath, "/"), strings.TrimPrefix(tsStateDir, "/")}, backupStateExcludes...)
}

var backupStateExcludes = []string{"var/lib/ziro/upgrade", "var/lib/ziro/plugins", "var/lib/ziro/.update-*"}

// backupBulkExcludes are large or live data that a file copy cannot capture consistently:
// volumes, storage, app data (databases of catalog apps and Postgres members: use pg_dump or WAL
// archiving) and sandboxes (short-lived workspaces). --include-volumes adds them.
var backupBulkExcludes = []string{"var/lib/ziro/volumes", "var/lib/ziro/storage", "var/lib/ziro/apps", "var/lib/ziro/sandbox"}

// BackupInfo is one archive in the backup directory (the SDK's api.Backup).
type BackupInfo = sdkapi.Backup

const (
	backupExt    = ".tar.gz"
	backupEncExt = ".tar.gz.enc"
)

func isBackupName(n string) bool {
	return strings.HasSuffix(n, backupExt) || strings.HasSuffix(n, backupEncExt)
}

func listBackups() []BackupInfo {
	out := []BackupInfo{}
	entries, _ := os.ReadDir(defaultBackupDir)
	for _, e := range entries {
		if e.IsDir() || !isBackupName(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, BackupInfo{Name: e.Name(), Bytes: fi.Size(), Created: fi.ModTime(), Checksum: fileExists(filepath.Join(defaultBackupDir, e.Name()+".sha256"))})
		}
	}
	return out
}

type backupStream struct {
	io.Reader
	io.Closer
}

// openBackup opens an archive for reading, decrypting it when it is an encrypted one.
func openBackup(p string) (io.ReadCloser, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(p, ".enc") {
		return f, nil
	}
	key, _, err := loadBackupKey(backupKeyFile(), false)
	if err != nil {
		f.Close()
		return nil, err
	}
	d, err := newDecryptReader(f, key)
	if err != nil {
		f.Close()
		return nil, err
	}
	return backupStream{d, f}, nil
}

func backupKeyFile() string {
	if backupKeyArg != "" {
		return backupKeyArg
	}
	return backupKeyPath
}

type backupMember struct {
	Name string
	Size int64
}

// scanBackup reads a whole archive and rejects members outside backupPaths, path traversal,
// hard links and devices, and writes through a symlink shipped in the same archive. Reading to the
// end also checks the gzip checksum and, for an encrypted archive, every authentication tag, so a
// damaged or truncated archive fails here and not half way through a restore.
func scanBackup(p string) ([]backupMember, error) {
	src, err := openBackup(p)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	gz, err := gzip.NewReader(src)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)

	var members []backupMember
	var symlinks []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := filepath.Clean("/" + h.Name)
		if strings.Contains(h.Name, "..") {
			return nil, fmt.Errorf("member %q contains '..'", h.Name)
		}
		allowed := false
		for _, p := range backupPaths {
			if name == p || strings.HasPrefix(name, p+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("member %q is outside the backup allowlist", h.Name)
		}
		for _, l := range symlinks {
			if strings.HasPrefix(name, l+"/") {
				return nil, fmt.Errorf("member %q would be written through symlink %q", h.Name, l)
			}
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeSymlink:
			symlinks = append(symlinks, name)
		default:
			return nil, fmt.Errorf("member %q has disallowed type %q", h.Name, string(h.Typeflag))
		}
		members = append(members, backupMember{Name: name, Size: h.Size})
	}
	if _, err := io.Copy(io.Discard, gz); err != nil { // the rest of the gzip stream, and its checksum
		return nil, err
	}
	if _, err := io.Copy(io.Discard, src); err != nil { // and every remaining sealed chunk
		return nil, err
	}
	return members, nil
}

func validateBackupArchive(p string) error {
	_, err := scanBackup(p)
	return err
}

var (
	backupRemote         string
	backupOutPath        string
	backupForce          bool
	backupIncludeSecrets bool // deprecated: secrets are in the (encrypted) archive by default
	backupNoSecrets      bool
	backupKeyArg         string
	backupIncludeVols    bool
	backupAuto           bool
	backupKeep           int
	backupKeepSafety     int
	backupDryRun         bool
	backupNoSnapshot     bool
	backupRestoreUsers   bool
)

var backupCmd = &cobra.Command{
	Use:     "backup",
	Aliases: []string{"snapshot"},
	Short:   "Back up and restore host and cluster state",
	Long: `Backs up the configuration and state of this host: /etc/ziro, SSH and WireGuard keys, gateway certificates,
apps, stacks, deployments, DNS, cluster state, the audit log. An archive that carries secrets is encrypted with this
host's backup key (/etc/ziro/backup.key, made at the first backup): copy the key somewhere safe with
"ziroctl backup key show", because without it an encrypted backup cannot be opened. Volumes and the data of Postgres
clusters are not in the default set.`,
	Example: `  ziroctl backup create
  ziroctl backup restore /var/backups/ziro/ziro-backup-20261003.tar.gz`,
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Back up host configuration and state",
	Example: `  ziroctl backup create
  ziroctl backup create --output /data/ziro.tar.gz
  ziroctl backup create --remote ziro_s3:ziro-backups
  ziroctl backup create --auto --keep 7`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupRemote != "" {
			if err := checkRemote(backupRemote); err != nil {
				return err
			}
		}
		out, err := createBackup(backupOutPath)
		if err != nil {
			if backupAuto {
				_ = auditLog("root", "cron", "backup create", backupOutPath, err)
			}
			return err
		}
		if backupRemote != "" {
			dst := strings.TrimSuffix(backupRemote, "/") + "/" + filepath.Base(out)
			for _, f := range []string{out + ".sha256", out} { // checksum first: a remote archive is never without one
				if err := rclone("copyto", f, dst+strings.TrimPrefix(f, out)); err != nil {
					return err
				}
			}
			fmt.Printf(" ✓ Uploaded to %s\n", dst)
		}
		if backupKeep > 0 {
			removed, err := pruneBackups(backupKeep, backupKeepSafety)
			if err != nil {
				return err
			}
			if !backupAuto {
				for _, r := range removed {
					fmt.Printf(" ✓ Pruned %s\n", r)
				}
			}
		}
		return nil
	},
}

// rclone remotes: the operator's in rcloneConfig (rclone-ziro plugin), and plugin-provided ones
// as env files in rcloneEnvDir (RCLONE_CONFIG_<NAME>_*; s3-ziro adds ziro_s3). Env files are
// accepted only root-owned and not world-readable (readEnvFile).
var (
	rcloneConfig = "/etc/ziro/rclone.conf"
	rcloneEnvDir = "/etc/ziro/rclone.d"
	remoteRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}:[A-Za-z0-9._/-]{0,512}$`)
)

// checkRemote accepts "remote:path" only: no flags, no "..", no local paths.
func checkRemote(r string) error {
	if !remoteRe.MatchString(r) || strings.Contains(r, "..") {
		return fmt.Errorf("invalid remote %q (want name:path, e.g. ziro_s3:ziro-backups)", r)
	}
	return nil
}

func isRemoteRef(s string) bool { return !fileExists(s) && remoteRe.MatchString(s) }

func rclone(args ...string) error {
	bin, err := exec.LookPath("rclone")
	if err != nil {
		return fmt.Errorf("rclone not found (ziroctl plugin enable rclone-ziro)")
	}
	c := exec.Command(bin, append([]string{"--config", rcloneConfig}, args...)...)
	c.Env = os.Environ()
	envFiles, _ := filepath.Glob(filepath.Join(rcloneEnvDir, "*.env"))
	for _, f := range envFiles {
		env, err := readEnvFile(f)
		if err != nil {
			return err
		}
		c.Env = append(c.Env, env...)
	}
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("rclone %s: %w", args[0], err)
	}
	return nil
}

// createBackup archives backupPaths into out (default: timestamped file in defaultBackupDir),
// writes a .sha256 manifest next to it and returns the path. An archive with secrets (the default)
// is encrypted and gets the ".enc" suffix; --no-secrets makes a plain one without them.
func createBackup(out string) (string, error) {
	encrypt := !backupNoSecrets
	ext := backupExt
	if encrypt {
		ext = backupEncExt
	}
	if out == "" {
		ts := time.Now().Format("20060102-150405")
		out = filepath.Join(defaultBackupDir, fmt.Sprintf("ziro-backup-%s%s", ts, ext))
	} else if encrypt && !strings.HasSuffix(out, ".enc") {
		out += ".enc"
	}
	// A fresh install has no backup directory (and --output may name a new one): make it.
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return "", err
	}

	if !backupAuto {
		fmt.Printf("📦 Creating Ziro-OS backup at %s...\n", out)
	}

	var existingPaths []string
	for _, p := range backupPaths {
		if _, err := os.Lstat(p); err == nil {
			existingPaths = append(existingPaths, strings.TrimPrefix(p, "/"))
		}
	}
	if len(existingPaths) == 0 {
		return "", fmt.Errorf("no standard configuration directories found to back up")
	}

	// Never truncate an existing archive or follow an output symlink. The
	// descriptor is private before tar writes its first secret-bearing byte.
	if _, err := os.Lstat(out); err == nil {
		return "", fmt.Errorf("backup output already exists: %s", out)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var key []byte
	if encrypt {
		var created bool
		var err error
		if key, created, err = loadBackupKey(backupKeyFile(), true); err != nil {
			return "", err
		}
		if created {
			fmt.Fprintf(os.Stderr, "⚠ Made the backup key %s. Copy it somewhere safe (ziroctl backup key show): without it encrypted backups cannot be opened.\n", backupKeyFile())
		}
	}
	f, err := os.CreateTemp(filepath.Dir(out), ".ziro-backup-*")
	if err != nil {
		return "", err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	if err := validateBackupStaging(f); err != nil {
		return "", err
	}
	tarArgs := []string{"-czf", "-", "-C", "/"}
	for _, x := range backupAlwaysExcludes() {
		tarArgs = append(tarArgs, "--exclude", x)
	}
	if !backupIncludeVols {
		for _, x := range backupBulkExcludes {
			tarArgs = append(tarArgs, "--exclude", x)
		}
	}
	if backupNoSecrets {
		// Cluster app secrets stay on the master unless the (encrypted) default is used.
		tarArgs = append(tarArgs, "--exclude", strings.TrimPrefix(clusterSecretsPath(), "/"))
		// The Raft log and snapshots replicate those secrets; CA and master keys are credentials.
		// sealed.bin is ciphertext and stays in; the data key that opens it does not.
		for _, p := range []string{raftDir(), clusterCAKeyPath(), masterKeyPath(), dekPath()} {
			tarArgs = append(tarArgs, "--exclude", strings.TrimPrefix(p, "/"))
		}
		// Plugin secrets and storage credentials: a backup shipped to that same storage must not
		// carry the keys to it.
		tarArgs = append(tarArgs, "--exclude", strings.TrimPrefix(moduleStateDir, "/")+"/*.secrets",
			"--exclude", strings.TrimPrefix(rcloneConfig, "/"), "--exclude", strings.TrimPrefix(rcloneEnvDir, "/"))
	}
	tarArgs = append(tarArgs, existingPaths...)
	archive := exec.Command("tar", tarArgs...)
	var enc *encryptWriter
	if encrypt {
		if enc, err = newEncryptWriter(f, key); err != nil {
			return "", err
		}
		archive.Stdout = enc
	} else {
		archive.Stdout = f
	}
	archive.Stderr = os.Stderr
	if err := archive.Run(); err != nil {
		return "", fmt.Errorf("tar: %w", err)
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	hashStr, err := computeFileSHA256(f.Name())
	if err != nil {
		return "", fmt.Errorf("checksum: %w", err)
	}
	manifest := fmt.Sprintf("%s  %s\n", hashStr, filepath.Base(out))
	checksum, err := os.OpenFile(out+".sha256", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := checksum.WriteString(manifest)
	closeErr := checksum.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(out + ".sha256")
		if writeErr != nil {
			return "", writeErr
		}
		return "", closeErr
	}
	// Link publishes the finished archive atomically and refuses existing files,
	// including a symlink introduced after the initial destination check.
	if err := os.Link(f.Name(), out); err != nil {
		os.Remove(out + ".sha256")
		return "", err
	}

	fi, _ := os.Stat(out)
	if backupAuto {
		fmt.Printf("backup %s (%d KB)\n", out, fi.Size()/1024)
		return out, nil
	}
	fmt.Println("================================================================")
	fmt.Printf(" ✓ Backup successfully created: %s (%d KB)\n", out, fi.Size()/1024)
	fmt.Printf(" ✓ SHA-256 Manifest:           %s\n", hashStr)
	if encrypt {
		fmt.Printf(" ✓ Encrypted with the backup key %s\n", backupKeyFile())
	}
	fmt.Println("================================================================")
	return out, nil
}

func validateBackupStaging(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("backup filesystem must enforce private 0600 files")
	}
	// Refuse filesystems without safe exclusive publication before reading keys.
	probe := f.Name() + ".link-check"
	if err := os.Link(f.Name(), probe); err != nil {
		return fmt.Errorf("backup filesystem must support hard links: %w", err)
	}
	return os.Remove(probe)
}

// Safety archives (before an upgrade, an update or a restore) are the way back from a bad
// change, so retention counts them separately from the regular ones.
func isSafetyBackup(name string) bool {
	for _, s := range []string{"-preupgrade-", "-preupdate-", "-prerestore-"} {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

// pruneBackups keeps the newest keep regular archives and the newest keepSafety safety archives
// in defaultBackupDir and removes the others with their checksum files.
func pruneBackups(keep, keepSafety int) ([]string, error) {
	if keep < 1 || keepSafety < 1 {
		return nil, errors.New("--keep and --keep-safety must be at least 1")
	}
	var regular, safety []BackupInfo
	for _, b := range listBackups() {
		if isSafetyBackup(b.Name) {
			safety = append(safety, b)
		} else {
			regular = append(regular, b)
		}
	}
	var removed []string
	for _, g := range []struct {
		list []BackupInfo
		keep int
	}{{regular, keep}, {safety, keepSafety}} {
		sort.Slice(g.list, func(i, j int) bool { return g.list[i].Created.After(g.list[j].Created) })
		for i := g.keep; i < len(g.list); i++ {
			if err := removeBackup(g.list[i].Name); err != nil {
				return removed, err
			}
			removed = append(removed, g.list[i].Name)
		}
	}
	return removed, nil
}

var backupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)

func removeBackup(name string) error {
	if !backupNameRe.MatchString(name) || !isBackupName(name) {
		return fmt.Errorf("%q is not a backup archive name", name)
	}
	p := filepath.Join(defaultBackupDir, name)
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("no backup %s in %s", name, defaultBackupDir)
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	if err := os.Remove(p + ".sha256"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

var backupListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List backup archives",
	Example: `  ziroctl backup list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		backups := listBackups()
		return printResult(backups, func() {
			if len(backups) == 0 {
				fmt.Printf("No backups found in %s\n", defaultBackupDir)
				return
			}
			fmt.Printf("%-52s %10s %-20s %s\n", "BACKUP ARCHIVE", "SIZE", "CREATED", "CHECKSUM")
			for _, b := range backups {
				fmt.Printf("%-52s %10s %-20s %v\n", b.Name, humanBytes(uint64(b.Bytes)), b.Created.Format("2006-01-02 15:04:05"), b.Checksum)
			}
		})
	},
}

// locateBackup resolves a name, a path or a remote reference to a local archive.
func locateBackup(arg string) (string, error) {
	archivePath := arg
	if isRemoteRef(archivePath) {
		// Fetch the archive and its checksum; a remote archive is restored only when both match.
		if err := os.MkdirAll(defaultBackupDir, 0700); err != nil {
			return "", err
		}
		local := filepath.Join(defaultBackupDir, path.Base(archivePath))
		if fileExists(local) {
			return "", fmt.Errorf("%s already exists locally; use it by name", local)
		}
		for _, sfx := range []string{".sha256", ""} {
			if err := rclone("copyto", archivePath+sfx, local+sfx); err != nil {
				return "", err
			}
		}
		return local, nil
	}
	if fileExists(archivePath) {
		return archivePath, nil
	}
	if alt := filepath.Join(defaultBackupDir, archivePath); fileExists(alt) {
		return alt, nil
	}
	return "", fmt.Errorf("backup file '%s' not found", archivePath)
}

// checkBackupChecksum compares an archive with its .sha256 file. A missing file or a mismatch is
// an error unless force is set.
func checkBackupChecksum(archivePath string, force bool) error {
	manifestPath := archivePath + ".sha256"
	if !fileExists(manifestPath) {
		if force {
			fmt.Println("⚠ No .sha256 file next to the archive; continuing because of --force.")
			return nil
		}
		return fmt.Errorf("no checksum file %s (use --force to skip the integrity check)", manifestPath)
	}
	fmt.Println("Verifying SHA-256 archive integrity...")
	expectedData, _ := os.ReadFile(manifestPath)
	expectedHash := ""
	if f := strings.Fields(string(expectedData)); len(f) > 0 {
		expectedHash = f[0]
	}
	actualHash, err := computeFileSHA256(archivePath)
	if err != nil {
		return err
	}
	if actualHash != expectedHash {
		if force {
			fmt.Printf("⚠ SHA-256 mismatch (expected %s, got %s); continuing because of --force.\n", expectedHash, actualHash)
			return nil
		}
		return fmt.Errorf("integrity failure: SHA-256 mismatch (expected %s, got %s); use --force to override", expectedHash, actualHash)
	}
	fmt.Println("✓ SHA-256 Checksum verified OK.")
	return nil
}

var backupVerifyCmd = &cobra.Command{
	Use:   "verify <backup-file | remote:path/file>",
	Short: "Check a backup archive without restoring it",
	Example: `  ziroctl backup verify ziro-backup-20261003-030000.tar.gz.enc
  ziroctl backup verify /data/ziro.tar.gz.enc --key-file /root/ziro-backup.key`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := locateBackup(args[0])
		if err != nil {
			return err
		}
		if err := checkBackupChecksum(p, backupForce); err != nil {
			return err
		}
		members, err := scanBackup(p)
		if err != nil {
			return fmt.Errorf("archive is not usable: %w", err)
		}
		var total int64
		for _, m := range members {
			total += m.Size
		}
		return printResult(map[string]any{"archive": p, "files": len(members), "bytes": total, "encrypted": strings.HasSuffix(p, ".enc")}, func() {
			fmt.Printf("✓ %s: %d entries, %s uncompressed, every checksum and tag verified\n", p, len(members), humanBytes(uint64(total)))
		})
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <backup-file | remote:path/file>",
	Short: "Restore configuration from a backup archive",
	Long: `Restores the files of a backup over this host. The archive is verified end to end first (checksum,
allowlist, every tag of an encrypted one), then a "prerestore" snapshot of the current state is taken, then the
files are written. Local accounts (/etc/passwd, shadow, group) are left alone unless --users is given. Restart the
affected services afterwards.`,
	Example: `  ziroctl backup restore /var/backups/ziro/ziro-backup-20261003.tar.gz
  ziroctl backup restore ziro-backup-20261003.tar.gz.enc --dry-run
  ziroctl backup restore ziro_s3:ziro-backups/ziro-backup-20261003.tar.gz.enc`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		archivePath, err := locateBackup(args[0])
		if err != nil {
			return err
		}
		if err := checkBackupChecksum(archivePath, backupForce); err != nil {
			return err
		}
		members, err := scanBackup(archivePath)
		if err != nil {
			return fmt.Errorf("refusing to restore: %w", err)
		}
		if backupDryRun {
			fmt.Printf("Dry run: %s would restore %d entries over this host:\n", archivePath, len(members))
			for _, m := range members {
				fmt.Printf("  %s\n", m.Name)
			}
			return nil
		}
		if !backupNoSnapshot {
			snap, err := snapshotBeforeChange("prerestore")
			if err != nil {
				return fmt.Errorf("refusing to restore without a snapshot of the current state (%w); use --no-snapshot to skip it", err)
			}
			fmt.Printf("✓ Current state saved to %s\n", snap)
		}
		fmt.Printf("Restoring from %s to / ...\n", archivePath)
		src, err := openBackup(archivePath)
		if err != nil {
			return err
		}
		defer src.Close()
		// No -P: leading '/' is stripped and everything lands under -C /.
		tarArgs := []string{"-xzf", "-", "-C", "/"}
		if !backupRestoreUsers {
			for _, u := range backupUserFiles {
				tarArgs = append(tarArgs, "--exclude", u)
			}
		}
		tarCmd := exec.Command("tar", tarArgs...)
		tarCmd.Stdin = src
		tarCmd.Stdout, tarCmd.Stderr = os.Stdout, os.Stderr
		if err := tarCmd.Run(); err != nil {
			return fmt.Errorf("restore: %w (the state before it is in the prerestore snapshot)", err)
		}

		fmt.Println("✓ System state restored successfully.")
		fmt.Println("Note: You may need to reload or restart affected services (ziroctl service restart <name>).")
		return nil
	},
}

// snapshotBeforeChange saves the current state under a safety name that retention keeps.
func snapshotBeforeChange(kind string) (string, error) {
	oldAuto := backupAuto
	backupAuto = true // quiet: the caller reports it
	defer func() { backupAuto = oldAuto }()
	ext := backupEncExt
	if backupNoSecrets {
		ext = backupExt
	}
	return createBackup(filepath.Join(defaultBackupDir, fmt.Sprintf("ziro-backup-%s-%s%s", kind, time.Now().Format("20060102-150405"), ext)))
}

var backupPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete old backup archives",
	Example: `  ziroctl backup prune --keep 7
  ziroctl backup prune --keep 14 --keep-safety 3`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupKeep < 1 {
			return errors.New("--keep is required (at least 1)")
		}
		removed, err := pruneBackups(backupKeep, backupKeepSafety)
		if err != nil {
			return err
		}
		return printResult(removed, func() {
			for _, r := range removed {
				fmt.Printf(" ✓ Removed %s\n", r)
			}
			fmt.Printf("%d archives removed\n", len(removed))
		})
	},
}

var backupRmCmd = &cobra.Command{
	Use:     "rm <archive-name>",
	Short:   "Delete one backup archive",
	Example: `  ziroctl backup rm ziro-backup-20261003-030000.tar.gz.enc`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := removeBackup(args[0]); err != nil {
			return err
		}
		fmt.Printf("✓ Removed %s\n", args[0])
		return nil
	},
}

var backupKeyCmd = &cobra.Command{
	Use:     "key",
	Short:   "Show the key that encrypts backups",
	Example: `  ziroctl backup key show`,
}

var backupKeyShowCmd = &cobra.Command{
	Use:     "show",
	Short:   "Print the backup key",
	Example: `  ziroctl backup key show`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, _, err := loadBackupKey(backupKeyFile(), false)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Keep this key outside this host: it is the only way to open encrypted backups.")
		fmt.Println(hex.EncodeToString(key))
		return nil
	},
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func init() {
	backupCreateCmd.Flags().StringVar(&backupRemote, "remote", "", "Also upload to an rclone remote (name:path, e.g. ziro_s3:ziro-backups; needs the rclone-ziro plugin)")
	backupCreateCmd.Flags().StringVarP(&backupOutPath, "output", "o", "", "Destination path for the archive (the directory is created)")
	backupCreateCmd.Flags().BoolVar(&backupNoSecrets, "no-secrets", false, "Plain archive without cluster secrets, keys and storage credentials (default: everything, encrypted)")
	backupCreateCmd.Flags().BoolVar(&backupIncludeSecrets, "include-secrets", false, "Deprecated: secrets are included (encrypted) by default")
	_ = backupCreateCmd.Flags().MarkHidden("include-secrets")
	backupCreateCmd.Flags().BoolVar(&backupIncludeVols, "include-volumes", false, "Also include volumes, storage, app data and sandboxes (large; not crash-consistent)")
	backupCreateCmd.Flags().BoolVar(&backupAuto, "auto", false, "Quiet output for cron; failures go to the audit log")
	backupCreateCmd.Flags().IntVar(&backupKeep, "keep", 0, "Afterwards keep only this many regular archives")
	backupCreateCmd.Flags().IntVar(&backupKeepSafety, "keep-safety", 5, "With --keep: how many pre-upgrade, pre-update and pre-restore archives to keep")
	backupPruneCmd.Flags().IntVar(&backupKeep, "keep", 0, "Regular archives to keep (required)")
	backupPruneCmd.Flags().IntVar(&backupKeepSafety, "keep-safety", 5, "Pre-upgrade, pre-update and pre-restore archives to keep")
	backupRestoreCmd.Flags().BoolVarP(&backupForce, "force", "f", false, "Restore despite a missing or wrong checksum")
	backupRestoreCmd.Flags().BoolVar(&backupDryRun, "dry-run", false, "List what would be restored and change nothing")
	backupRestoreCmd.Flags().BoolVar(&backupNoSnapshot, "no-snapshot", false, "Do not save the current state first")
	backupRestoreCmd.Flags().BoolVar(&backupRestoreUsers, "users", false, "Also restore /etc/passwd, /etc/shadow and /etc/group")
	backupVerifyCmd.Flags().BoolVarP(&backupForce, "force", "f", false, "Continue despite a missing or wrong checksum")
	for _, c := range []*cobra.Command{backupCreateCmd, backupRestoreCmd, backupVerifyCmd, backupKeyShowCmd} {
		c.Flags().StringVar(&backupKeyArg, "key-file", "", "Backup key file (default "+backupKeyPath+")")
	}

	backupKeyCmd.AddCommand(backupKeyShowCmd)
	backupCmd.AddCommand(backupCreateCmd, backupListCmd, backupVerifyCmd, backupRestoreCmd, backupPruneCmd, backupRmCmd, backupKeyCmd)
	rootCmd.AddCommand(backupCmd)
}

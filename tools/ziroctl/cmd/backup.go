package cmd

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const defaultBackupDir = "/var/backups/ziro"

// backupPaths are the only locations a backup may contain or restore into.
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
}

// validateBackupArchive rejects members outside backupPaths, path traversal,
// hardlinks/devices, and writes through a symlink shipped in the same archive.
// BackupInfo is one archive in the backup directory (the SDK's api.Backup).
type BackupInfo = sdkapi.Backup

func listBackups() []BackupInfo {
	out := []BackupInfo{}
	entries, _ := os.ReadDir(defaultBackupDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, BackupInfo{Name: e.Name(), Bytes: fi.Size(), Created: fi.ModTime(), Checksum: fileExists(filepath.Join(defaultBackupDir, e.Name()+".sha256"))})
		}
	}
	return out
}

func validateBackupArchive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)

	var symlinks []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean("/" + h.Name)
		if strings.Contains(h.Name, "..") {
			return fmt.Errorf("member %q contains '..'", h.Name)
		}
		allowed := false
		for _, p := range backupPaths {
			if name == p || strings.HasPrefix(name, p+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("member %q is outside the backup allowlist", h.Name)
		}
		for _, l := range symlinks {
			if strings.HasPrefix(name, l+"/") {
				return fmt.Errorf("member %q would be written through symlink %q", h.Name, l)
			}
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeSymlink:
			symlinks = append(symlinks, name)
		default:
			return fmt.Errorf("member %q has disallowed type %q", h.Name, string(h.Typeflag))
		}
	}
}

var (
	backupRemote         string
	backupOutPath        string
	backupForce          bool
	backupIncludeSecrets bool
)

var backupCmd = &cobra.Command{
	Use:     "backup",
	Aliases: []string{"snapshot"},
	Short:   "Back up and restore host and cluster configuration",
	Example: `  ziroctl backup create
  ziroctl backup restore /var/backups/ziro/ziro-backup-20261003.tar.gz`,
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Back up host configuration and cluster state",
	Example: `  ziroctl backup create
  ziroctl backup create --output /data/ziro.tar.gz
  ziroctl backup create --remote ziro_s3:ziro-backups`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupRemote != "" {
			if err := checkRemote(backupRemote); err != nil {
				return err
			}
		}
		out, err := createBackup(backupOutPath)
		if err != nil || backupRemote == "" {
			return err
		}
		dst := strings.TrimSuffix(backupRemote, "/") + "/" + filepath.Base(out)
		for _, f := range []string{out + ".sha256", out} { // checksum first: a remote archive is never without one
			if err := rclone("copyto", f, dst+strings.TrimPrefix(f, out)); err != nil {
				return err
			}
		}
		fmt.Printf(" ✓ Uploaded to %s\n", dst)
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

// createBackup archives backupPaths into out (default: timestamped file in
// defaultBackupDir), writes a .sha256 manifest next to it and returns the path.
func createBackup(out string) (string, error) {
	if out == "" {
		if err := os.MkdirAll(defaultBackupDir, 0700); err != nil {
			return "", err
		}
		ts := time.Now().Format("20060102-150405")
		out = filepath.Join(defaultBackupDir, fmt.Sprintf("ziro-backup-%s.tar.gz", ts))
	}

	fmt.Printf("📦 Creating Ziro-OS configuration backup at %s...\n", out)

	var existingPaths []string
	for _, p := range backupPaths {
		if _, err := os.Stat(p); err == nil {
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
	if !backupIncludeSecrets {
		// Cluster app secrets stay on the master unless explicitly requested.
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
	archive.Stdout = f
	archive.Stderr = os.Stderr
	if err := archive.Run(); err != nil {
		return "", fmt.Errorf("tar: %w", err)
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
	fmt.Println("================================================================")
	fmt.Printf(" ✓ Backup successfully created: %s (%d KB)\n", out, fi.Size()/1024)
	fmt.Printf(" ✓ SHA-256 Manifest:           %s\n", hashStr)
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
			fmt.Printf("%-48s %10s %-20s %s\n", "BACKUP ARCHIVE", "SIZE", "CREATED", "CHECKSUM")
			for _, b := range backups {
				fmt.Printf("%-48s %10s %-20s %v\n", b.Name, humanBytes(uint64(b.Bytes)), b.Created.Format("2006-01-02 15:04:05"), b.Checksum)
			}
		})
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <backup-file | remote:path/file>",
	Short: "Restore configuration from a backup archive",
	Example: `  ziroctl backup restore /var/backups/ziro/ziro-backup-20261003.tar.gz
  ziroctl backup restore ziro_s3:ziro-backups/ziro-backup-20261003.tar.gz`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		archivePath := args[0]
		if isRemoteRef(archivePath) {
			// Fetch the archive and its checksum; a remote archive is restored only when both match.
			if err := os.MkdirAll(defaultBackupDir, 0700); err != nil {
				return err
			}
			local := filepath.Join(defaultBackupDir, path.Base(archivePath))
			if fileExists(local) {
				return fmt.Errorf("%s already exists locally; restore it by name", local)
			}
			for _, sfx := range []string{".sha256", ""} {
				if err := rclone("copyto", archivePath+sfx, local+sfx); err != nil {
					return err
				}
			}
			archivePath = local
		}
		if !fileExists(archivePath) {
			// Check default dir
			altPath := filepath.Join(defaultBackupDir, archivePath)
			if fileExists(altPath) {
				archivePath = altPath
			} else {
				return fmt.Errorf("backup file '%s' not found", archivePath)
			}
		}

		// Verify manifest if exists
		manifestPath := archivePath + ".sha256"
		if fileExists(manifestPath) {
			fmt.Println("Verifying SHA-256 archive integrity...")
			expectedData, _ := os.ReadFile(manifestPath)
			expectedHash := ""
			if f := strings.Fields(string(expectedData)); len(f) > 0 {
				expectedHash = f[0]
			}

			actualHash, err := computeFileSHA256(archivePath)
			if err != nil || actualHash != expectedHash {
				fmt.Printf("❌ Integrity failure! SHA256 mismatch.\nExpected: %s\nActual:   %s\n", expectedHash, actualHash)
				if !backupForce {
					fmt.Println("Aborting restore. Use --force to override.")
					return nil
				}
			} else {
				fmt.Println("✓ SHA-256 Checksum verified OK.")
			}
		}

		fmt.Printf("Restoring configurations from %s to / ...\n", archivePath)
		if err := validateBackupArchive(archivePath); err != nil {
			return fmt.Errorf("refusing to restore: %w", err)
		}
		// No -P: leading '/' is stripped and everything lands under -C /.
		tarCmd := exec.Command("tar", "-xzf", archivePath, "-C", "/")
		tarCmd.Stdout = os.Stdout
		tarCmd.Stderr = os.Stderr
		if err := tarCmd.Run(); err != nil {
			return fmt.Errorf("restore: %w", err)
		}

		fmt.Println("✓ System configurations restored successfully.")
		fmt.Println("Note: You may need to reload or restart affected services (ziroctl service restart <name>).")
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
	backupCreateCmd.Flags().StringVarP(&backupOutPath, "output", "o", "", "Destination path for backup tar.gz")
	backupCreateCmd.Flags().BoolVar(&backupIncludeSecrets, "include-secrets", false, "Also include cluster app secrets (/etc/ziro/cluster/secrets.json)")
	backupRestoreCmd.Flags().BoolVarP(&backupForce, "force", "f", false, "Force restore despite checksum mismatch")

	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	rootCmd.AddCommand(backupCmd)
}

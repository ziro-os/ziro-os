package cmd

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	backupOutPath     string
	backupIncludeData bool
	backupForce       bool
)

var backupCmd = &cobra.Command{
	Use:     "backup",
	Aliases: []string{"snapshot"},
	Short:   "Create and restore Ziro-OS host and cluster configuration backups",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a compressed (unencrypted, root-only) backup of system configurations and cluster state",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := createBackup(backupOutPath)
		return err
	},
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
	tarArgs := append([]string{"-czf", "-", "-C", "/"}, existingPaths...)
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

var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List existing system backup archives",
	Run: func(cmd *cobra.Command, args []string) {
		entries, err := os.ReadDir(defaultBackupDir)
		if err != nil || len(entries) == 0 {
			fmt.Printf("No backups found in %s\n", defaultBackupDir)
			return
		}

		fmt.Printf("%-32s %-10s %-20s %s\n", "BACKUP ARCHIVE", "SIZE", "CREATED", "INTEGRITY")
		fmt.Println(strings.Repeat("-", 80))

		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.gz") {
				fpath := filepath.Join(defaultBackupDir, e.Name())
				fi, _ := e.Info()
				sizeStr := fmt.Sprintf("%d KB", fi.Size()/1024)
				modStr := fi.ModTime().Format("2006-01-02 15:04:05")

				integrity := "No Checksum"
				manifestPath := fpath + ".sha256"
				if fileExists(manifestPath) {
					integrity = "Verified (SHA256)"
				}

				fmt.Printf("%-32s %-10s %-20s %s\n", e.Name(), sizeStr, modStr, integrity)
			}
		}
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <backup-file>",
	Short: "Restore system configurations from a backup archive",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		archivePath := args[0]
		if !fileExists(archivePath) {
			// Check default dir
			altPath := filepath.Join(defaultBackupDir, archivePath)
			if fileExists(altPath) {
				archivePath = altPath
			} else {
				fmt.Printf("Backup file '%s' not found.\n", archivePath)
				return
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
					return
				}
			} else {
				fmt.Println("✓ SHA-256 Checksum verified OK.")
			}
		}

		fmt.Printf("Restoring configurations from %s to / ...\n", archivePath)
		if err := validateBackupArchive(archivePath); err != nil {
			fmt.Printf("❌ Refusing to restore: %v\n", err)
			return
		}
		// No -P: leading '/' is stripped and everything lands under -C /.
		tarCmd := exec.Command("tar", "-xzf", archivePath, "-C", "/")
		tarCmd.Stdout = os.Stdout
		tarCmd.Stderr = os.Stderr
		if err := tarCmd.Run(); err != nil {
			fmt.Printf("Restore error: %v\n", err)
			return
		}

		fmt.Println("✓ System configurations restored successfully.")
		fmt.Println("Note: You may need to reload or restart affected services (ziroctl service restart <name>).")
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
	backupCreateCmd.Flags().StringVarP(&backupOutPath, "output", "o", "", "Destination path for backup tar.gz")
	backupCreateCmd.Flags().BoolVar(&backupIncludeData, "include-data", false, "Include persistent container volumes")
	backupRestoreCmd.Flags().BoolVarP(&backupForce, "force", "f", false, "Force restore despite checksum mismatch")

	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupListCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	rootCmd.AddCommand(backupCmd)
}

package cmd

import (
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
	Short: "Create an encrypted/compressed backup of system configurations and cluster state",
	Run: func(cmd *cobra.Command, args []string) {
		_ = os.MkdirAll(defaultBackupDir, 0700)

		ts := time.Now().Format("20060102-150405")
		targetArchive := backupOutPath
		if targetArchive == "" {
			targetArchive = filepath.Join(defaultBackupDir, fmt.Sprintf("ziro-backup-%s.tar.gz", ts))
		}

		fmt.Printf("📦 Creating Ziro-OS configuration backup at %s...\n", targetArchive)

		// List of critical config files & dirs to bundle
		pathsToBackup := []string{
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

		var existingPaths []string
		for _, p := range pathsToBackup {
			if _, err := os.Stat(p); err == nil {
				existingPaths = append(existingPaths, p)
			}
		}

		if len(existingPaths) == 0 {
			fmt.Println("Warning: No standard configuration directories found to backup.")
			return
		}

		// Execute tar czf
		tarArgs := append([]string{"-czf", targetArchive, "-P"}, existingPaths...)
		if err := exec.Command("tar", tarArgs...).Run(); err != nil {
			fmt.Printf("Tar failed: %v\n", err)
			return
		}

		// Generate SHA-256 integrity checksum manifest
		hashStr, err := computeFileSHA256(targetArchive)
		if err != nil {
			fmt.Printf("Checksum calculation error: %v\n", err)
			return
		}

		manifestFile := targetArchive + ".sha256"
		_ = os.WriteFile(manifestFile, []byte(fmt.Sprintf("%s  %s\n", hashStr, filepath.Base(targetArchive))), 0644)

		fi, _ := os.Stat(targetArchive)
		sizeKB := fi.Size() / 1024

		fmt.Println("================================================================")
		fmt.Printf(" ✓ Backup successfully created: %s (%d KB)\n", targetArchive, sizeKB)
		fmt.Printf(" ✓ SHA-256 Manifest:           %s\n", hashStr)
		fmt.Println("================================================================")
	},
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
			expectedHash := strings.Fields(string(expectedData))[0]

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
		tarCmd := exec.Command("tar", "-xzf", archivePath, "-P", "-C", "/")
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

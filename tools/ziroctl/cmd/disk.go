package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var diskCmd = &cobra.Command{
	Use:   "disk",
	Short: "Disk storage and partition management",
}

var diskListCmd = &cobra.Command{
	Use:   "list",
	Short: "List storage disks, partitions, models, and sizes",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("==================================================")
		fmt.Println(" 💾 Ziro-OS Storage Disks & Partitions")
		fmt.Println("==================================================")

		blocks, err := filepath.Glob("/sys/block/*")
		if err != nil || len(blocks) == 0 {
			// Fallback to lsblk or fdisk
			out, err := exec.Command("fdisk", "-l").CombinedOutput()
			if err == nil && len(out) > 0 {
				fmt.Println(string(out))
				return nil
			}
			fmt.Println("No storage block devices detected.")
			return nil
		}

		found := 0
		for _, b := range blocks {
			name := filepath.Base(b)
			if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") {
				continue
			}

			found++
			sizeBytes := readBlockSize(b)
			sizeGB := float64(sizeBytes) / (1024 * 1024 * 1024)
			model := readSysAttr(filepath.Join(b, "device/model"))
			if model == "" {
				model = readSysAttr(filepath.Join(b, "device/name"))
			}
			if model == "" {
				model = "Virtual / Generic Block Device"
			}

			driverType := "SCSI / SATA"
			if strings.HasPrefix(name, "vd") {
				driverType = "VirtIO Block (virtio_blk)"
			} else if strings.HasPrefix(name, "nvme") {
				driverType = "NVMe Storage"
			} else if strings.HasPrefix(name, "xvd") {
				driverType = "Xen Virtual Disk"
			}

			fmt.Printf("Disk /dev/%s:\n", name)
			fmt.Printf("  Capacity: %.2f GB (%d bytes)\n", sizeGB, sizeBytes)
			fmt.Printf("  Model:    %s\n", model)
			fmt.Printf("  Type:     %s\n", driverType)

			// Find partitions
			parts, _ := filepath.Glob(filepath.Join(b, name+"*"))
			if len(parts) > 0 {
				fmt.Println("  Partitions:")
				for _, p := range parts {
					pname := filepath.Base(p)
					psize := readBlockSize(p)
					psizeMB := float64(psize) / (1024 * 1024)
					fmt.Printf("    • /dev/%-10s (%.1f MB)\n", pname, psizeMB)
				}
			} else {
				fmt.Println("  Partitions: (No partitions on disk)")
			}
			fmt.Println()
		}

		if found == 0 {
			fmt.Println("⚠️  No physical or virtual disks detected in /sys/block.")
			fmt.Println("Ensure virtio-blk, sd_mod, or nvme kernel drivers are loaded.")
		}
		fmt.Println("==================================================")
		return nil
	},
}

var diskUsageCmd = &cobra.Command{
	Use:   "usage",
	Short: "Show filesystem disk space and inode utilization",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := exec.Command("df", "-h").CombinedOutput()
		if err == nil {
			fmt.Println(string(out))
		} else {
			return fmt.Errorf("query disk usage: %w", err)
		}
		return nil
	},
}

func readSysAttr(path string) string {
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func readBlockSize(path string) int64 {
	sizeStr := readSysAttr(filepath.Join(path, "size"))
	if sizeStr == "" {
		return 0
	}
	sectors, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}
	return sectors * 512
}

func init() {
	diskCmd.AddCommand(diskListCmd)
	diskCmd.AddCommand(diskUsageCmd)
	rootCmd.AddCommand(diskCmd)
}

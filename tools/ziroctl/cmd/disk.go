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
	Short: "Add, grow and inspect disks",
	Example: `  ziroctl disk list
  ziroctl disk add /dev/vdb --mount /data`,
}

var diskListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List disks and partitions",
	Example: `  ziroctl disk list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		disks := blockDevices()
		return printResult(disks, func() {
			if len(disks) == 0 {
				fmt.Println("No disks found in /sys/block (are the virtio-blk, sd_mod or nvme drivers loaded?)")
				return
			}
			for _, d := range disks {
				fmt.Printf("/dev/%s  %s  %s  %s\n", d.Name, humanBytes(uint64(d.Bytes)), d.Type, d.Model)
				for _, p := range d.Partitions {
					fmt.Printf("  /dev/%-12s %s\n", p.Name, humanBytes(uint64(p.Bytes)))
				}
			}
		})
	},
}

// BlockDevice is a disk with its partitions (from /sys/block).
type BlockDevice struct {
	Name       string        `json:"name"`
	Bytes      int64         `json:"bytes"`
	Model      string        `json:"model,omitempty"`
	Type       string        `json:"type"`
	Partitions []BlockDevice `json:"partitions,omitempty"`
}

func blockDevices() []BlockDevice {
	out := []BlockDevice{}
	blocks, _ := filepath.Glob("/sys/block/*")
	for _, b := range blocks {
		name := filepath.Base(b)
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "zram") {
			continue
		}
		d := BlockDevice{Name: name, Bytes: readBlockSize(b), Model: readSysAttr(filepath.Join(b, "device/model")), Type: "scsi/sata"}
		if d.Model == "" {
			d.Model = readSysAttr(filepath.Join(b, "device/name"))
		}
		switch {
		case strings.HasPrefix(name, "vd"):
			d.Type = "virtio"
		case strings.HasPrefix(name, "nvme"):
			d.Type = "nvme"
		case strings.HasPrefix(name, "xvd"):
			d.Type = "xen"
		}
		parts, _ := filepath.Glob(filepath.Join(b, name+"*"))
		for _, p := range parts {
			d.Partitions = append(d.Partitions, BlockDevice{Name: filepath.Base(p), Bytes: readBlockSize(p), Type: "partition"})
		}
		out = append(out, d)
	}
	return out
}

var diskUsageCmd = &cobra.Command{
	Use:     "usage",
	Short:   "Show filesystem space and inode use",
	Example: `  ziroctl disk usage`,
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

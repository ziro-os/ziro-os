package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

type SystemStatus struct {
	OSName        string `json:"os_name"`
	OSVersion     string `json:"os_version"`
	KernelVersion string `json:"kernel_version"`
	ContainerdOK  bool   `json:"containerd_ok"`
	CgroupsV2     bool   `json:"cgroups_v2"`
	TotalMemMB    uint64 `json:"total_mem_mb"`
	FreeMemMB     uint64 `json:"free_mem_mb"`
}

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System inspection and diagnostics",
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display Ziro-OS host status and services",
	RunE: func(cmd *cobra.Command, args []string) error {
		status := inspectSystem()
		if jsonOutput {
			data, _ := json.MarshalIndent(status, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Println("=== Ziro-OS Host Status ===")
		fmt.Printf("OS:               %s (%s)\n", status.OSName, status.OSVersion)
		fmt.Printf("Kernel:           %s\n", status.KernelVersion)
		if status.ContainerdOK {
			fmt.Println("containerd:       [RUNNING] (/run/containerd/containerd.sock)")
		} else {
			fmt.Println("containerd:       [STOPPED] (socket not reachable)")
		}
		if status.CgroupsV2 {
			fmt.Println("cgroups:          [ENABLED] (cgroup2 mounted)")
		} else {
			fmt.Println("cgroups:          [DISABLED / LEGACY]")
		}
		if status.TotalMemMB > 0 {
			fmt.Printf("Memory:           %d MB used / %d MB total\n", status.TotalMemMB-status.FreeMemMB, status.TotalMemMB)
		}
		return nil
	},
}

func inspectSystem() SystemStatus {
	st := SystemStatus{
		OSName:    "Ziro-OS",
		OSVersion: "1.0",
	}

	// Read os-release
	if f, err := os.Open("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				st.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION=") {
				st.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
			}
		}
		f.Close()
	}

	st.KernelVersion = "unknown"
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		st.KernelVersion = strings.TrimSpace(string(b))
	}

	// containerd check
	conn, err := net.Dial("unix", "/run/containerd/containerd.sock")
	if err == nil {
		st.ContainerdOK = true
		conn.Close()
	}

	// cgroup2 check
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		st.CgroupsV2 = true
	}

	mi := readMeminfo()
	st.TotalMemMB, st.FreeMemMB = mi["MemTotal"]>>20, mi["MemAvailable"]>>20

	return st
}

var rebootCmd = &cobra.Command{
	Use:   "reboot",
	Short: "Cleanly sync filesystems and reboot the host system",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Syncing filesystems and rebooting Ziro-OS host...")
		_ = exec.Command("sync").Run()
		if err := exec.Command("/sbin/reboot").Run(); err != nil {
			if err := exec.Command("reboot").Run(); err != nil {
				_ = exec.Command("kill", "-TERM", "1").Run()
			}
		}
		return nil
	},
}

var poweroffCmd = &cobra.Command{
	Use:     "poweroff",
	Aliases: []string{"shutdown", "halt"},
	Short:   "Cleanly sync filesystems and power off the host system",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Syncing filesystems and powering off Ziro-OS host...")
		_ = exec.Command("sync").Run()
		if err := exec.Command("/sbin/poweroff").Run(); err != nil {
			if err := exec.Command("poweroff").Run(); err != nil {
				_ = exec.Command("kill", "-USR2", "1").Run()
			}
		}
		return nil
	},
}

func init() {
	systemCmd.AddCommand(statusCmd)
	systemCmd.AddCommand(rebootCmd)
	systemCmd.AddCommand(poweroffCmd)
	rootCmd.AddCommand(systemCmd)
}

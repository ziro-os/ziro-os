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
	Run: func(cmd *cobra.Command, args []string) {
		status := inspectSystem()
		if jsonOutput {
			data, _ := json.MarshalIndent(status, "", "  ")
			fmt.Println(string(data))
			return
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

	// Kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		st.KernelVersion = strings.TrimSpace(string(out))
	} else {
		st.KernelVersion = "unknown"
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

	// Memory info
	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			var val uint64
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscanf(line, "MemTotal: %d kB", &val)
				st.TotalMemMB = val / 1024
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fmt.Sscanf(line, "MemAvailable: %d kB", &val)
				st.FreeMemMB = val / 1024
			}
		}
		f.Close()
	}

	return st
}

func init() {
	systemCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(systemCmd)
}

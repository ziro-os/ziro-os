package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security audit and hardening inspection",
}

var securityAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run security and hardening checks on the host OS",
	Run: func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		fmt.Fprintln(out, "=== Ziro-OS Security & Hardening Audit ===")

		// Check 1: Seccomp support
		seccompFound := false
		if f, err := os.Open("/proc/self/status"); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "Seccomp:") {
					seccompFound = true
					break
				}
			}
			f.Close()
		}
		printCheck(out, "Kernel Seccomp Support", seccompFound)

		// Check 2: Linux Namespaces
		nsDir, err := os.ReadDir("/proc/self/ns")
		nsCount := len(nsDir)
		printCheck(out, "Namespaces Enabled (pid, net, ipc, uts, user, mnt)", err == nil && nsCount >= 5)

		// Check 3: cgroups v2
		_, cgroupErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
		printCheck(out, "Unified cgroups v2 Hierarchy", cgroupErr == nil)

		// Check 4: IP Forwarding
		ipForward := false
		if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
			if strings.TrimSpace(string(data)) == "1" {
				ipForward = true
			}
		}
		printCheck(out, "Container IPv4 Forwarding Enabled", ipForward)

		// Check 5: /tmp sticky bit
		tmpStat, tmpErr := os.Stat("/tmp")
		if tmpErr == nil && (tmpStat.Mode()&os.ModeSticky != 0) {
			printCheck(out, "/tmp sticky bit configured correctly", true)
		} else {
			printCheck(out, "/tmp sticky bit configured correctly", false)
		}
	},
}

func printCheck(out io.Writer, name string, passed bool) {
	if passed {
		fmt.Fprintf(out, " [PASS] %s\n", name)
	} else {
		fmt.Fprintf(out, " [WARN] %s\n", name)
	}
}

func init() {
	securityCmd.AddCommand(securityAuditCmd)
	rootCmd.AddCommand(securityCmd)
}

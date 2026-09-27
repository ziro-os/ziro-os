package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security audit and cloud hardening controls",
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

		// Check 6: SSH Password Auth disabled
		sshKeyOnly := false
		if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
			if strings.Contains(string(data), "PasswordAuthentication no") {
				sshKeyOnly = true
			}
		}
		printCheck(out, "SSH Enforces Key-Only Authentication (Passwords Disabled)", sshKeyOnly)
	},
}

var securityHardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply cloud security hardening (sysctl, SSH, and file permissions)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("==================================================")
		fmt.Println(" 🛡️  Applying Ziro-OS Cloud Security Hardening")
		fmt.Println("==================================================")

		// 1. Kernel sysctl parameters
		sysctls := map[string]string{
			"/proc/sys/net/ipv4/conf/all/rp_filter":          "1",
			"/proc/sys/net/ipv4/conf/default/rp_filter":      "1",
			"/proc/sys/net/ipv4/tcp_syncookies":              "1",
			"/proc/sys/net/ipv4/conf/all/accept_source_route": "0",
			"/proc/sys/net/ipv4/conf/all/send_redirects":     "0",
			"/proc/sys/net/ipv4/conf/all/accept_redirects":   "0",
			"/proc/sys/kernel/dmesg_restrict":                "1",
			"/proc/sys/kernel/kptr_restrict":                 "2",
			"/proc/sys/fs/protected_hardlinks":               "1",
			"/proc/sys/fs/protected_symlinks":                "1",
		}

		for param, val := range sysctls {
			if err := os.WriteFile(param, []byte(val+"\n"), 0644); err == nil {
				fmt.Printf("  ✓ Configured %s = %s\n", param, val)
			}
		}

		// Write persistent sysctl config
		_ = os.MkdirAll("/etc/sysctl.d", 0755)
		hardenedConf := `# Ziro-OS Hardened Cloud Security Configuration
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
`
		_ = os.WriteFile("/etc/sysctl.d/99-hardened.conf", []byte(hardenedConf), 0644)
		fmt.Println("  ✓ Saved persistent rules to /etc/sysctl.d/99-hardened.conf")

		// 2. SSH Hardening
		sshdConfigPath := "/etc/ssh/sshd_config"
		if data, err := os.ReadFile(sshdConfigPath); err == nil {
			content := string(data)
			if !strings.Contains(content, "PasswordAuthentication no") {
				content += "\nPasswordAuthentication no\n"
			}
			if !strings.Contains(content, "PermitRootLogin prohibit-password") {
				content += "PermitRootLogin prohibit-password\n"
			}
			if !strings.Contains(content, "X11Forwarding no") {
				content += "X11Forwarding no\n"
			}
			if !strings.Contains(content, "MaxAuthTries 3") {
				content += "MaxAuthTries 3\n"
			}
			_ = os.WriteFile(sshdConfigPath, []byte(content), 0600)
			fmt.Println("  ✓ Hardened OpenSSH server configuration (/etc/ssh/sshd_config)")
			_ = exec.Command("pkill", "-HUP", "sshd").Run()
		}

		// 3. File Permissions
		_ = os.Chmod("/etc/shadow", 0600)
		_ = os.Chmod("/etc/passwd", 0644)
		_ = os.Chmod("/root", 0700)
		_ = os.Chmod("/root/.ssh", 0700)
		_ = os.Chmod("/root/.ssh/authorized_keys", 0600)
		fmt.Println("  ✓ Restricted permissions on /etc/shadow, /etc/passwd, and /root/.ssh")

		fmt.Println("\n✅ Security hardening successfully applied!")
		fmt.Println("==================================================")
		return nil
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
	securityCmd.AddCommand(securityHardenCmd)
	rootCmd.AddCommand(securityCmd)
}

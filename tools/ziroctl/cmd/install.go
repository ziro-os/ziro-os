package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	installDisk          string
	installHostname      string
	installSSHKey        string
	installUserData      string
	installPassword      string
	installAutoYes       bool
	installUpgrade       bool
	installErase         bool
	installForce         bool
	installNoReboot      bool
	installRebootTimeout int
	installNetMode       string
	installIP            string
	installGateway       string
	installDNS           string
	installIface         string
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Ziro-OS to physical or virtual disk (TUI / Automated)",
	Long: `ziroctl install launches the Ziro-OS system installer.
It formats and partitions the target disk, installs UEFI and BIOS bootloaders,
deploys the minimal container host operating system, configures networking (DHCP / Static IP),
and provisions SSH keys and user-data.`,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().StringVarP(&installDisk, "disk", "d", "", "Target disk device (e.g., /dev/vda, /dev/sda, /dev/nvme0n1)")
	installCmd.Flags().StringVarP(&installHostname, "hostname", "n", "", "System hostname (default: ziro-host)")
	installCmd.Flags().StringVarP(&installSSHKey, "ssh-key", "k", "", "SSH public key or path to public key file for root")
	installCmd.Flags().StringVarP(&installPassword, "password", "p", "", "Root password (prefer the ZIRO_ROOT_PASSWORD environment variable)")
	installCmd.Flags().StringVarP(&installUserData, "user-data", "u", "", "URL or path to user-data / cloud post-install script")
	installCmd.Flags().StringVar(&installNetMode, "net-mode", "", "Network mode: 'dhcp', 'static', or 'skip'")
	installCmd.Flags().StringVar(&installIP, "ip", "", "Static IPv4 address and CIDR (e.g. 192.168.1.50/24)")
	installCmd.Flags().StringVar(&installGateway, "gateway", "", "Default gateway IPv4 address")
	installCmd.Flags().StringVar(&installDNS, "dns", "", "DNS nameservers (default: 1.1.1.1 8.8.8.8)")
	installCmd.Flags().StringVar(&installIface, "iface", "", "Target network interface (e.g. eth0)")
	installCmd.Flags().BoolVarP(&installAutoYes, "yes", "y", false, "Confirm installation without interactive prompts")
	installCmd.Flags().BoolVar(&installUpgrade, "upgrade", false, "Upgrade an existing Ziro-OS install in place (keeps all data)")
	installCmd.Flags().BoolVar(&installErase, "erase", false, "Allow wiping a disk that already holds Ziro-OS (unattended mode)")
	installCmd.Flags().BoolVar(&installForce, "force", false, "Upgrade even if the pre-upgrade config snapshot fails")
	installCmd.Flags().BoolVar(&installNoReboot, "no-reboot", false, "Do not automatically reboot after installation or upgrade")
	installCmd.Flags().IntVar(&installRebootTimeout, "reboot-timeout", 0, "Seconds to count down before auto-rebooting (default: 10)")

	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	installerPaths := []string{
		"/usr/sbin/ziro-install",
		"/bin/ziro-install",
		"/usr/local/sbin/ziro-install",
		"./scripts/installer/ziro-install.sh",
	}

	var installerBin string
	for _, p := range installerPaths {
		if _, err := os.Stat(p); err == nil {
			installerBin = p
			break
		}
	}

	if installerBin == "" {
		installerBin = "ziro-install"
	}

	cmdArgs := []string{}
	if installDisk != "" {
		cmdArgs = append(cmdArgs, "--disk", installDisk)
	}
	if installHostname != "" {
		cmdArgs = append(cmdArgs, "--hostname", installHostname)
	}
	if installSSHKey != "" {
		cmdArgs = append(cmdArgs, "--ssh-key", installSSHKey)
	}
	if installUserData != "" {
		cmdArgs = append(cmdArgs, "--user-data", installUserData)
	}
	if installNetMode != "" {
		cmdArgs = append(cmdArgs, "--net-mode", installNetMode)
	}
	if installIP != "" {
		cmdArgs = append(cmdArgs, "--ip", installIP)
	}
	if installGateway != "" {
		cmdArgs = append(cmdArgs, "--gateway", installGateway)
	}
	if installDNS != "" {
		cmdArgs = append(cmdArgs, "--dns", installDNS)
	}
	if installIface != "" {
		cmdArgs = append(cmdArgs, "--iface", installIface)
	}
	if installAutoYes {
		cmdArgs = append(cmdArgs, "--yes")
	}
	if installUpgrade {
		cmdArgs = append(cmdArgs, "--upgrade")
	}
	if installErase {
		cmdArgs = append(cmdArgs, "--erase")
	}
	if installForce {
		cmdArgs = append(cmdArgs, "--force")
	}
	if installNoReboot {
		cmdArgs = append(cmdArgs, "--no-reboot")
	}
	if installRebootTimeout > 0 {
		cmdArgs = append(cmdArgs, "--reboot-timeout", strconv.Itoa(installRebootTimeout))
	}
	cmdArgs = append(cmdArgs, args...)

	execCmd := exec.Command(installerBin, cmdArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()
	if installPassword != "" {
		// Passed through the environment, never argv (visible to every user in ps/proc).
		execCmd.Env = append(execCmd.Env, "ZIRO_ROOT_PASSWORD="+installPassword)
	}

	err := execCmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("installer failed: %w", err)
	}

	return nil
}

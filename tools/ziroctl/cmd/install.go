package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	installDisk      string
	installHostname  string
	installSSHKey    string
	installUserData  string
	installPassword  string
	installAutoYes   bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Ziro-OS to physical or virtual disk (TUI / Automated)",
	Long: `ziroctl install launches the Ziro-OS system installer.
It formats and partitions the target disk, installs UEFI and BIOS bootloaders,
deploys the minimal container host operating system, and provisions SSH keys and user-data.`,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().StringVarP(&installDisk, "disk", "d", "", "Target disk device (e.g., /dev/vda, /dev/sda, /dev/nvme0n1)")
	installCmd.Flags().StringVarP(&installHostname, "hostname", "n", "", "System hostname (default: ziro-host)")
	installCmd.Flags().StringVarP(&installSSHKey, "ssh-key", "k", "", "SSH public key or path to public key file for root")
	installCmd.Flags().StringVarP(&installPassword, "password", "p", "", "Root password")
	installCmd.Flags().StringVarP(&installUserData, "user-data", "u", "", "URL or path to user-data / cloud post-install script")
	installCmd.Flags().BoolVarP(&installAutoYes, "yes", "y", false, "Confirm installation without interactive prompts")

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
	if installPassword != "" {
		cmdArgs = append(cmdArgs, "--password", installPassword)
	}
	if installUserData != "" {
		cmdArgs = append(cmdArgs, "--user-data", installUserData)
	}
	if installAutoYes {
		cmdArgs = append(cmdArgs, "--yes")
	}
	cmdArgs = append(cmdArgs, args...)

	execCmd := exec.Command(installerBin, cmdArgs...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Env = os.Environ()

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

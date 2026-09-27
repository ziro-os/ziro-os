package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var pkgCmd = &cobra.Command{
	Use:     "pkg",
	Aliases: []string{"package", "packages"},
	Short:   "Package management operations (powered by ziropkg)",
}

var pkgInstallCmd = &cobra.Command{
	Use:     "install <package...>",
	Aliases: []string{"add", "i"},
	Short:   "Install packages into Ziro-OS",
	Example: "  ziroctl pkg install curl\n  ziroctl pkg install htop git",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZiropkg(cmd, append([]string{"install"}, args...)...)
	},
}

var pkgRemoveCmd = &cobra.Command{
	Use:     "remove <package...>",
	Aliases: []string{"del", "rm"},
	Short:   "Remove packages from Ziro-OS",
	Example: "  ziroctl pkg remove curl",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZiropkg(cmd, append([]string{"remove"}, args...)...)
	},
}

var pkgSearchCmd = &cobra.Command{
	Use:     "search <query>",
	Short:   "Search available packages",
	Example: "  ziroctl pkg search curl",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZiropkg(cmd, "search", args[0])
	},
}

var pkgListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZiropkg(cmd, "list")
	},
}

var pkgUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update package repository index",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZiropkg(cmd, "update")
	},
}

func runZiropkg(cmd *cobra.Command, args ...string) error {
	// Check for ziropkg binary first, fallback to apk
	if bin, err := exec.LookPath("ziropkg"); err == nil {
		proc := exec.Command(bin, args...)
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()
		proc.Stdin = os.Stdin
		return proc.Run()
	}

	if bin, err := exec.LookPath("apk"); err == nil {
		var apkArgs []string
		switch args[0] {
		case "install":
			apkArgs = append([]string{"add", "--no-cache"}, args[1:]...)
		case "remove":
			apkArgs = append([]string{"del"}, args[1:]...)
		case "update":
			apkArgs = []string{"update"}
		case "list":
			apkArgs = []string{"info", "-v"}
		case "search":
			apkArgs = []string{"search", "-v", args[1]}
		default:
			apkArgs = args
		}
		proc := exec.Command(bin, apkArgs...)
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()
		proc.Stdin = os.Stdin
		return proc.Run()
	}

	return fmt.Errorf("neither 'ziropkg' nor 'apk' backend found in PATH")
}

func init() {
	pkgCmd.AddCommand(pkgInstallCmd)
	pkgCmd.AddCommand(pkgRemoveCmd)
	pkgCmd.AddCommand(pkgSearchCmd)
	pkgCmd.AddCommand(pkgListCmd)
	pkgCmd.AddCommand(pkgUpdateCmd)
	rootCmd.AddCommand(pkgCmd)
}

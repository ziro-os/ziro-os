package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func ensureDBInitialized() {
	_ = os.MkdirAll("/lib/apk/db", 0755)
	installedPath := "/lib/apk/db/installed"
	if _, err := os.Stat(installedPath); os.IsNotExist(err) {
		if f, err := os.Create(installedPath); err == nil {
			_ = f.Close()
		}
	}
	worldPath := "/etc/apk/world"
	if _, err := os.Stat(worldPath); os.IsNotExist(err) {
		if f, err := os.Create(worldPath); err == nil {
			_ = f.Close()
		}
	}
}

var installCmd = &cobra.Command{
	Use:     "install <package...>",
	Aliases: []string{"add", "i"},
	Short:   "Install one or more packages into Ziro-OS",
	Example: "  ziropkg install curl\n  ziropkg install htop git",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ensureDBInitialized()
		cmd.Printf("📦 Installing package(s): %v\n", args)
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		apkArgs := append([]string{"add", "--no-cache", "--initdb"}, args...)
		proc := exec.Command(apkPath, apkArgs...)
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()
		proc.Stdin = os.Stdin

		if err := proc.Run(); err != nil {
			return fmt.Errorf("failed to install packages: %w", err)
		}

		cmd.Printf("✅ Successfully installed: %v\n", args)
		return nil
	},
}

var removeCmd = &cobra.Command{
	Use:     "remove <package...>",
	Aliases: []string{"del", "rm"},
	Short:   "Remove one or more packages from Ziro-OS",
	Example: "  ziropkg remove curl",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Printf("🗑️ Removing package(s): %v\n", args)
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		apkArgs := append([]string{"del"}, args...)
		proc := exec.Command(apkPath, apkArgs...)
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()
		proc.Stdin = os.Stdin

		if err := proc.Run(); err != nil {
			return fmt.Errorf("failed to remove packages: %w", err)
		}

		cmd.Printf("✅ Successfully removed: %v\n", args)
		return nil
	},
}

var updateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"up"},
	Short:   "Update package repositories index",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("🔄 Updating package repositories...")
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		proc := exec.Command(apkPath, "update")
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()

		return proc.Run()
	},
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List installed packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("=== Installed Packages ===")
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		proc := exec.Command(apkPath, "info", "-v")
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()

		return proc.Run()
	},
}

var searchCmd = &cobra.Command{
	Use:     "search <query>",
	Aliases: []string{"find"},
	Short:   "Search for available packages in the repository",
	Example: "  ziropkg search curl",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Printf("🔍 Searching for '%s'...\n", args[0])
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		proc := exec.Command(apkPath, "search", "-v", args[0])
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()

		return proc.Run()
	},
}

var infoCmd = &cobra.Command{
	Use:     "info <package>",
	Short:   "Show detailed package information",
	Example: "  ziropkg info curl",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		apkPath, err := exec.LookPath("apk")
		if err != nil {
			return fmt.Errorf("package backend (apk) not found in PATH")
		}

		proc := exec.Command(apkPath, "info", "-a", args[0])
		proc.Stdout = cmd.OutOrStdout()
		proc.Stderr = cmd.ErrOrStderr()

		return proc.Run()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ziropkg version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "ziropkg version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(versionCmd)
}

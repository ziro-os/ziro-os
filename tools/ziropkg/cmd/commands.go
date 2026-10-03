package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// Packages installed on top of the image are recorded in packagesFile; at boot ziroctl
// reinstalls any that an OS upgrade (which replaces /usr) removed.
var (
	packagesFile  = "/etc/ziro/packages"
	packageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,99}$`) // same as sdk/schema.PackageNameRe
)

func validNames(names []string) error {
	for _, n := range names {
		if !packageNameRe.MatchString(n) {
			return fmt.Errorf("invalid package name %q", n)
		}
	}
	return nil
}

// recordPackages adds and removes names in packagesFile (sorted, one per line, atomic write).
func recordPackages(add, remove []string) error {
	var cur []string
	if b, err := os.ReadFile(packagesFile); err == nil {
		for _, l := range strings.Fields(string(b)) {
			if packageNameRe.MatchString(l) {
				cur = append(cur, l)
			}
		}
	}
	for _, a := range add {
		if !slices.Contains(cur, a) {
			cur = append(cur, a)
		}
	}
	cur = slices.DeleteFunc(cur, func(p string) bool { return slices.Contains(remove, p) })
	slices.Sort(cur)
	data := strings.Join(cur, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.MkdirAll(filepath.Dir(packagesFile), 0755); err != nil {
		return err
	}
	tmp := packagesFile + ".new"
	if err := os.WriteFile(tmp, []byte(data), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, packagesFile)
}

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
	Short:   "Install one or more packages",
	Long:    "Install packages from the Alpine repositories. They are recorded in /etc/ziro/packages and\nreinstalled at boot after an OS upgrade.",
	Example: "  ziropkg install curl\n  ziropkg install htop git",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validNames(args); err != nil {
			return err
		}
		ensureDBInitialized()
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

		return recordPackages(args, nil)
	},
}

var removeCmd = &cobra.Command{
	Use:     "remove <package...>",
	Aliases: []string{"del", "rm"},
	Short:   "Remove one or more packages",
	Example: "  ziropkg remove curl",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validNames(args); err != nil {
			return err
		}
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

		return recordPackages(nil, args)
	},
}

var updateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"up"},
	Short:   "Refresh the package index",
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
	Short:   "Search available packages",
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

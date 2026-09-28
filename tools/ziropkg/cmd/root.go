package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "1.0.10"
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "ziropkg",
	Short: "ziropkg - Ziro-OS Package Manager",
	Long: `ziropkg is the official package management utility for Ziro-OS.
It installs, updates, and manages additional packages and utilities (e.g., curl, git, htop)
with minimal dependencies and fast verification.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

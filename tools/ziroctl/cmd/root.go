package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "ziroctl",
	Short: "ziroctl - Ziro-OS Container Host Management CLI",
	Long: `ziroctl is the official control utility for Ziro-OS.
It manages container workloads, inspects system and cgroup health,
monitors containerd status, and enforces security configurations.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output format as JSON")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

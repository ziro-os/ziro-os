package cmd

import (
	"encoding/json"
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
	// Errors are printed once by Execute (not twice, and without the usage dump).
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI; any command error exits non-zero so scripts and fleet tooling see it.
func Execute() {
	c, err := rootCmd.ExecuteC()
	auditCommand(c, err)
	if err != nil {
		if jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

// printResult writes v as JSON when --json is set, otherwise calls text.
func printResult(v interface{}, text func()) error {
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	text()
	return nil
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output format as JSON")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

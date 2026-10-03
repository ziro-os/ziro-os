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
	Short: "Manage a Ziro OS host",
	Long: `ziroctl manages a Ziro OS host: containers and apps, networking, security, clusters
and upgrades. Add --json to any command for machine-readable output.`,
	Example: `  ziroctl motd
  ziroctl system top
  ziroctl apps deploy postgres:17
  ziroctl firewall allow 443/tcp`,
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

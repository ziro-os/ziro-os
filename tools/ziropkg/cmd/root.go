package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "1.0.21"
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "ziropkg",
	Short: "Install extra packages on Ziro OS",
	Long: `ziropkg installs packages from the Alpine repositories on top of the Ziro OS image.
Installed packages are reinstalled after an OS upgrade.`,
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

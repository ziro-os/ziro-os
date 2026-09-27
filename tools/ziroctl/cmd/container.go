package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var containerCmd = &cobra.Command{
	Use:     "container",
	Aliases: []string{"c", "app"},
	Short:   "Container workload operations",
}

var containerRunCmd = &cobra.Command{
	Use:   "run <image> [cmd...]",
	Short: "Run an OCI container image",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		image := args[0]
		cmdArgs := args[1:]

		ctrArgs := []string{"run", "--rm", "-t", "--net-host", image, fmt.Sprintf("ziro-%d", os.Getpid())}
		ctrArgs = append(ctrArgs, cmdArgs...)

		runCtr(ctrArgs...)
	},
}

var containerListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "ps"},
	Short:   "List active containers",
	Run: func(cmd *cobra.Command, args []string) {
		runCtr("containers", "list")
	},
}

var containerImagesCmd = &cobra.Command{
	Use:     "images",
	Aliases: []string{"image"},
	Short:   "List downloaded container images",
	Run: func(cmd *cobra.Command, args []string) {
		runCtr("images", "list")
	},
}

var containerPullCmd = &cobra.Command{
	Use:   "pull <image>",
	Short: "Pull an image from an OCI container registry",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runCtr("images", "pull", args[0])
	},
}

var containerStopCmd = &cobra.Command{
	Use:   "stop <container-id>",
	Short: "Stop a running container",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runCtr("tasks", "kill", args[0])
	},
}

func runCtr(args ...string) {
	ctrPath, err := exec.LookPath("ctr")
	if err != nil {
		fmt.Println("❌ 'ctr' client not found in PATH. Make sure containerd is installed.")
		return
	}

	execCmd := exec.Command(ctrPath, args...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Stdin = os.Stdin

	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
	}
}

func init() {
	containerCmd.AddCommand(containerRunCmd)
	containerCmd.AddCommand(containerListCmd)
	containerCmd.AddCommand(containerImagesCmd)
	containerCmd.AddCommand(containerPullCmd)
	containerCmd.AddCommand(containerStopCmd)
	rootCmd.AddCommand(containerCmd)
}

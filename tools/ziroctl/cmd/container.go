package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// normalizeImageRef standardizes Docker/OCI image references to fully-qualified format.
// e.g. "nginx" -> "docker.io/library/nginx:latest"
// e.g. "alpine:3.20" -> "docker.io/library/alpine:3.20"
// e.g. "redis/redis-stack" -> "docker.io/redis/redis-stack:latest"
// e.g. "quay.io/coreos/etcd" -> "quay.io/coreos/etcd:latest"
func normalizeImageRef(img string) string {
	img = strings.TrimSpace(img)
	if img == "" {
		return img
	}

	// Extract digest if any (@sha256:...)
	digest := ""
	if atIdx := strings.Index(img, "@"); atIdx != -1 {
		digest = img[atIdx:]
		img = img[:atIdx]
	}

	// Extract tag if any (:tag)
	tag := ""
	slashIdx := strings.LastIndex(img, "/")
	lastPart := img
	if slashIdx != -1 {
		lastPart = img[slashIdx+1:]
	}
	if colonIdx := strings.Index(lastPart, ":"); colonIdx != -1 {
		tag = lastPart[colonIdx:]
		img = img[:len(img)-len(lastPart)+colonIdx]
	} else if digest == "" {
		tag = ":latest"
	}

	// Determine registry domain prefix
	parts := strings.Split(img, "/")
	var fullRepo string
	if len(parts) == 1 {
		// Official Docker Hub library image (e.g., "nginx", "alpine")
		fullRepo = "docker.io/library/" + parts[0]
	} else if len(parts) == 2 {
		// Either domain/image or docker-user/image
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
			fullRepo = parts[0] + "/" + parts[1]
		} else {
			fullRepo = "docker.io/" + parts[0] + "/" + parts[1]
		}
	} else {
		// Multi-level path (e.g. "quay.io/org/repo")
		if !strings.Contains(parts[0], ".") && !strings.Contains(parts[0], ":") && parts[0] != "localhost" {
			fullRepo = "docker.io/" + strings.Join(parts, "/")
		} else {
			fullRepo = strings.Join(parts, "/")
		}
	}

	return fullRepo + tag + digest
}

// getContainerBackend determines whether nerdctl or ctr is available.
func getContainerBackend() (backend string, path string, err error) {
	if p, err := exec.LookPath("nerdctl"); err == nil {
		return "nerdctl", p, nil
	}
	if p, err := exec.LookPath("ctr"); err == nil {
		return "ctr", p, nil
	}
	return "", "", fmt.Errorf("neither 'nerdctl' nor 'ctr' found in PATH. Ensure containerd is installed")
}

func executeBackend(args ...string) error {
	_, path, err := getContainerBackend()
	if err != nil {
		return err
	}

	execCmd := exec.Command(path, args...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Stdin = os.Stdin

	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

var containerCmd = &cobra.Command{
	Use:     "container",
	Aliases: []string{"c", "app"},
	Short:   "Container workload and lifecycle management",
	Long: `Manage high-performance container workloads on Ziro-OS.
Provides seamless Docker-compatible command line experience backed by containerd,
with automatic image registry resolution, cgroups v2 resource control, and CNI networking.`,
}

var (
	runDetach      bool
	runName        string
	runPublish     []string
	runEnv         []string
	runVolume      []string
	runRm          bool
	runInteractive bool
	runTty         bool
	runNet         string
	runRestart     string

	execInteractive bool
	execTty         bool
	execDetach      bool
)

// containerRunCmd handles starting a container with Docker-like semantics
var containerRunCmd = &cobra.Command{
	Use:   "run [flags] <image> [command] [args...]",
	Short: "Run a container from an image",
	Example: `  ziroctl container run -d --name web -p 80:80 nginx
  ziroctl container run --rm -it alpine sh
  ziroctl container run -v /data:/data redis`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		rawImage := args[0]
		normImage := normalizeImageRef(rawImage)
		cmdArgs := args[1:]

		if backend == "nerdctl" {
			var backendArgs []string
			backendArgs = append(backendArgs, "run")
			if runDetach {
				backendArgs = append(backendArgs, "-d")
			}
			if runName != "" {
				backendArgs = append(backendArgs, "--name", runName)
			}
			for _, p := range runPublish {
				backendArgs = append(backendArgs, "-p", p)
			}
			for _, e := range runEnv {
				backendArgs = append(backendArgs, "-e", e)
			}
			for _, v := range runVolume {
				backendArgs = append(backendArgs, "-v", v)
			}
			if runRm && !runDetach {
				backendArgs = append(backendArgs, "--rm")
			}
			if runInteractive {
				backendArgs = append(backendArgs, "-i")
			}
			if runTty {
				backendArgs = append(backendArgs, "-t")
			}
			if runNet != "" {
				backendArgs = append(backendArgs, "--net", runNet)
			}
			if runRestart != "" {
				backendArgs = append(backendArgs, "--restart", runRestart)
			}

			backendArgs = append(backendArgs, normImage)
			backendArgs = append(backendArgs, cmdArgs...)
			return executeBackend(backendArgs...)
		}

		// Fallback to ctr
		containerID := runName
		if containerID == "" {
			containerID = fmt.Sprintf("ziro-%d", os.Getpid())
		}
		ctrArgs := []string{"run"}
		if runRm {
			ctrArgs = append(ctrArgs, "--rm")
		}
		if runTty {
			ctrArgs = append(ctrArgs, "-t")
		}
		ctrArgs = append(ctrArgs, "--net-host", normImage, containerID)
		ctrArgs = append(ctrArgs, cmdArgs...)
		return executeBackend(ctrArgs...)
	},
}

var containerPullCmd = &cobra.Command{
	Use:     "pull <image>",
	Short:   "Pull an image from an OCI container registry",
	Example: "  ziroctl container pull nginx\n  ziroctl container pull redis:alpine\n  ziroctl container pull quay.io/coreos/etcd",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		normImage := normalizeImageRef(args[0])
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		cmd.Printf("📥 Pulling image: %s\n", normImage)
		if backend == "nerdctl" {
			return executeBackend("pull", normImage)
		}
		return executeBackend("images", "pull", normImage)
	},
}

var containerListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "ps"},
	Short:   "List active or all containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"ps"}, args...)...)
		}
		return executeBackend("containers", "list")
	},
}

var containerImagesCmd = &cobra.Command{
	Use:     "images",
	Aliases: []string{"image"},
	Short:   "List downloaded container images",
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"images"}, args...)...)
		}
		return executeBackend("images", "list")
	},
}

var containerStopCmd = &cobra.Command{
	Use:   "stop <container...>",
	Short: "Stop one or more running containers",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"stop"}, args...)...)
		}
		for _, id := range args {
			_ = executeBackend("tasks", "kill", id)
		}
		return nil
	},
}

var containerStartCmd = &cobra.Command{
	Use:   "start <container...>",
	Short: "Start one or more stopped containers",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"start"}, args...)...)
		}
		for _, id := range args {
			_ = executeBackend("tasks", "start", id)
		}
		return nil
	},
}

var containerRestartCmd = &cobra.Command{
	Use:   "restart <container...>",
	Short: "Restart one or more containers",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"restart"}, args...)...)
		}
		for _, id := range args {
			_ = executeBackend("tasks", "kill", id)
			_ = executeBackend("tasks", "start", id)
		}
		return nil
	},
}

var containerRmCmd = &cobra.Command{
	Use:     "rm [flags] <container...>",
	Aliases: []string{"remove"},
	Short:   "Remove one or more containers",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"rm"}, args...)...)
		}
		for _, id := range args {
			_ = executeBackend("containers", "delete", id)
		}
		return nil
	},
}

var containerLogsCmd = &cobra.Command{
	Use:   "logs [flags] <container>",
	Short: "Fetch logs of a container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"logs"}, args...)...)
		}
		return fmt.Errorf("container logs require 'nerdctl' backend")
	},
}

var containerExecCmd = &cobra.Command{
	Use:   "exec [flags] <container> <command> [args...]",
	Short: "Run a command in a running container",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		containerID := args[0]
		cmdArgs := args[1:]

		if backend == "nerdctl" {
			var backendArgs []string
			backendArgs = append(backendArgs, "exec")
			if execInteractive {
				backendArgs = append(backendArgs, "-i")
			}
			if execTty {
				backendArgs = append(backendArgs, "-t")
			}
			if execDetach {
				backendArgs = append(backendArgs, "-d")
			}
			backendArgs = append(backendArgs, containerID)
			backendArgs = append(backendArgs, cmdArgs...)
			return executeBackend(backendArgs...)
		}

		ctrArgs := []string{"tasks", "exec", "--exec-id", fmt.Sprintf("exec-%d", os.Getpid())}
		if execTty {
			ctrArgs = append(ctrArgs, "-t")
		}
		ctrArgs = append(ctrArgs, containerID)
		ctrArgs = append(ctrArgs, cmdArgs...)
		return executeBackend(ctrArgs...)
	},
}

var containerInspectCmd = &cobra.Command{
	Use:   "inspect <container...>",
	Short: "Return low-level information on container objects",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, _, err := getContainerBackend()
		if err != nil {
			return err
		}

		if backend == "nerdctl" {
			return executeBackend(append([]string{"inspect"}, args...)...)
		}
		return executeBackend("containers", "info", args[0])
	},
}

func init() {
	// Flags for run
	containerRunCmd.Flags().SetInterspersed(false)
	containerRunCmd.Flags().BoolVarP(&runDetach, "detach", "d", false, "Run container in background and print container ID")
	containerRunCmd.Flags().StringVar(&runName, "name", "", "Assign a name to the container")
	containerRunCmd.Flags().StringArrayVarP(&runPublish, "publish", "p", nil, "Publish a container port(s) to the host")
	containerRunCmd.Flags().StringArrayVarP(&runEnv, "env", "e", nil, "Set environment variables")
	containerRunCmd.Flags().StringArrayVar(&runVolume, "volume", nil, "Bind mount a volume")
	containerRunCmd.Flags().BoolVar(&runRm, "rm", false, "Automatically remove the container when it exits")
	containerRunCmd.Flags().BoolVarP(&runInteractive, "interactive", "i", false, "Keep STDIN open even if not attached")
	containerRunCmd.Flags().BoolVarP(&runTty, "tty", "t", false, "Allocate a pseudo-TTY")
	containerRunCmd.Flags().StringVar(&runNet, "net", "", "Connect a container to a network (default: bridge)")
	containerRunCmd.Flags().StringVar(&runRestart, "restart", "", "Restart policy to apply when a container exits")

	// Flags for exec
	containerExecCmd.Flags().SetInterspersed(false)
	containerExecCmd.Flags().BoolVarP(&execInteractive, "interactive", "i", false, "Keep STDIN open")
	containerExecCmd.Flags().BoolVarP(&execTty, "tty", "t", false, "Allocate a pseudo-TTY")
	containerExecCmd.Flags().BoolVarP(&execDetach, "detach", "d", false, "Detached mode: run command in the background")

	containerCmd.AddCommand(containerRunCmd)
	containerCmd.AddCommand(containerPullCmd)
	containerCmd.AddCommand(containerListCmd)
	containerCmd.AddCommand(containerImagesCmd)
	containerCmd.AddCommand(containerStopCmd)
	containerCmd.AddCommand(containerStartCmd)
	containerCmd.AddCommand(containerRestartCmd)
	containerCmd.AddCommand(containerRmCmd)
	containerCmd.AddCommand(containerLogsCmd)
	containerCmd.AddCommand(containerExecCmd)
	containerCmd.AddCommand(containerInspectCmd)
	rootCmd.AddCommand(containerCmd)
}

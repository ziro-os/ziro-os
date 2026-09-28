package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type ComposeService struct {
	Name        string
	Image       string
	Ports       []string
	Environment []string
	Volumes     []string
	Restart     string
	Command     string
}

var composeFile string
var composeDetach bool

var composeCmd = &cobra.Command{
	Use:     "compose",
	Aliases: []string{"docker-compose"},
	Short:   "Declarative multi-container application management (Docker Compose)",
}

var composeUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Create and start multi-container services defined in docker-compose.yml",
	Run: func(cmd *cobra.Command, args []string) {
		services, err := parseComposeFile(composeFile)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", composeFile, err)
			return
		}
		if len(services) == 0 {
			fmt.Println("No services found in compose file.")
			return
		}

		projectName := getProjectName(composeFile)
		fmt.Printf("🚀 Starting Ziro Compose project: %s (%d services)\n", projectName, len(services))

		for _, s := range services {
			containerName := fmt.Sprintf("%s_%s_1", projectName, s.Name)
			fmt.Printf("Creating and starting service '%s' (container: %s)...\n", s.Name, containerName)

			var runArgs []string
			runArgs = append(runArgs, "run")
			if composeDetach {
				runArgs = append(runArgs, "-d")
			}
			runArgs = append(runArgs, "--name", containerName)
			if s.Restart != "" {
				runArgs = append(runArgs, "--restart", s.Restart)
			}
			for _, p := range s.Ports {
				runArgs = append(runArgs, "-p", p)
			}
			for _, e := range s.Environment {
				runArgs = append(runArgs, "-e", e)
			}
			for _, v := range s.Volumes {
				runArgs = append(runArgs, "-v", v)
			}
			runArgs = append(runArgs, s.Image)
			if s.Command != "" {
				runArgs = append(runArgs, strings.Fields(s.Command)...)
			}

			// Execute using nerdctl or ctr
			runner := exec.Command("nerdctl", runArgs...)
			runner.Stdout = os.Stdout
			runner.Stderr = os.Stderr
			if err := runner.Run(); err != nil {
				fmt.Printf("⚠️  Service %s launch failed: %v\n", s.Name, err)
			} else {
				fmt.Printf("✓ Service '%s' started successfully.\n", s.Name)
			}
		}
	},
}

var composeDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop and remove containers defined in docker-compose.yml",
	Run: func(cmd *cobra.Command, args []string) {
		services, err := parseComposeFile(composeFile)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", composeFile, err)
			return
		}

		projectName := getProjectName(composeFile)
		fmt.Printf("Stopping Ziro Compose project: %s\n", projectName)

		for _, s := range services {
			containerName := fmt.Sprintf("%s_%s_1", projectName, s.Name)
			fmt.Printf("Stopping container %s...\n", containerName)
			_ = exec.Command("nerdctl", "stop", containerName).Run()
			_ = exec.Command("nerdctl", "rm", "-f", containerName).Run()
		}
		fmt.Println("✓ All compose services stopped and removed.")
	},
}

var composePsCmd = &cobra.Command{
	Use:   "ps",
	Short: "List containers for the current compose project",
	Run: func(cmd *cobra.Command, args []string) {
		projectName := getProjectName(composeFile)
		out, err := exec.Command("nerdctl", "ps", "-a", "--filter", fmt.Sprintf("name=%s_", projectName)).Output()
		if err != nil || len(out) == 0 {
			// Fallback standard listing
			_ = exec.Command("nerdctl", "ps").Run()
			return
		}
		fmt.Print(string(out))
	},
}

var composeLogsCmd = &cobra.Command{
	Use:   "logs [service]",
	Short: "View output from containers",
	Run: func(cmd *cobra.Command, args []string) {
		projectName := getProjectName(composeFile)
		target := fmt.Sprintf("%s_", projectName)
		if len(args) > 0 {
			target = fmt.Sprintf("%s_%s_1", projectName, args[0])
		}
		cmdRun := exec.Command("nerdctl", "logs", target)
		cmdRun.Stdout = os.Stdout
		cmdRun.Stderr = os.Stderr
		_ = cmdRun.Run()
	},
}

func getProjectName(file string) string {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "ziro"
	}
	dir := filepath.Base(filepath.Dir(abs))
	if dir == "" || dir == "." || dir == "/" {
		return "ziro"
	}
	return strings.ToLower(dir)
}

// Lightweight, zero-dependency YAML parser for standard docker-compose files
func parseComposeFile(path string) ([]ComposeService, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var services []ComposeService
	var currentSvc *ComposeService
	inServices := false
	currentList := "" // "ports", "environment", "volumes"

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if trimmed == "services:" {
			inServices = true
			continue
		}

		if !inServices {
			continue
		}

		// Detect indent
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Service declaration at indent level 2 (e.g. "  web:")
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			if currentSvc != nil {
				services = append(services, *currentSvc)
			}
			svcName := strings.TrimSuffix(trimmed, ":")
			currentSvc = &ComposeService{Name: svcName}
			currentList = ""
			continue
		}

		if currentSvc == nil {
			continue
		}

		// Direct service keys at indent 4
		if indent == 4 {
			currentList = ""
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := ""
			if len(parts) > 1 {
				val = strings.Trim(strings.TrimSpace(parts[1]), "\"'\t ")
			}

			switch key {
			case "image":
				currentSvc.Image = val
			case "restart":
				currentSvc.Restart = val
			case "command":
				currentSvc.Command = val
			case "ports":
				currentList = "ports"
			case "environment":
				currentList = "environment"
			case "volumes":
				currentList = "volumes"
			}
			continue
		}

		// List items at indent 6 (e.g. "      - 80:80")
		if indent >= 6 && strings.HasPrefix(trimmed, "-") {
			val := strings.Trim(strings.TrimPrefix(trimmed, "-"), "\"'\t ")
			switch currentList {
			case "ports":
				currentSvc.Ports = append(currentSvc.Ports, val)
			case "environment":
				currentSvc.Environment = append(currentSvc.Environment, val)
			case "volumes":
				currentSvc.Volumes = append(currentSvc.Volumes, val)
			}
		}
	}

	if currentSvc != nil {
		services = append(services, *currentSvc)
	}

	return services, nil
}

func init() {
	composeCmd.PersistentFlags().StringVarP(&composeFile, "file", "f", "docker-compose.yml", "Path to docker-compose file")
	composeUpCmd.Flags().BoolVarP(&composeDetach, "detach", "d", true, "Run containers in the background")

	composeCmd.AddCommand(composeUpCmd)
	composeCmd.AddCommand(composeDownCmd)
	composeCmd.AddCommand(composePsCmd)
	composeCmd.AddCommand(composeLogsCmd)
	rootCmd.AddCommand(composeCmd)
}

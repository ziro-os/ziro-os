package cmd

import (
	"sort"

	"fmt"
	"go.yaml.in/yaml/v3"
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
	Command     []string
	DependsOn   []string
	Health      []string // from healthcheck.test
	Unsupported []string // keys with no Ziro equivalent (build, privileged, ...)
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
	RunE: func(cmd *cobra.Command, args []string) error {
		services, err := parseComposeFile(composeFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", composeFile, err)
		}
		if len(services) == 0 {
			fmt.Println("No services found in compose file.")
			return nil
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
			runArgs = append(runArgs, "--", s.Image) // "--": an image can never be read as a flag
			runArgs = append(runArgs, s.Command...)

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
		return nil
	},
}

var composeDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop and remove containers defined in docker-compose.yml",
	RunE: func(cmd *cobra.Command, args []string) error {
		services, err := parseComposeFile(composeFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", composeFile, err)
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
		return nil
	},
}

var composePsCmd = &cobra.Command{
	Use:   "ps",
	Short: "List containers for the current compose project",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := getProjectName(composeFile)
		out, err := exec.Command("nerdctl", "ps", "-a", "--filter", fmt.Sprintf("name=%s_", projectName)).Output()
		if err != nil || len(out) == 0 {
			// Fallback standard listing
			_ = exec.Command("nerdctl", "ps").Run()
			return nil
		}
		fmt.Print(string(out))
		return nil
	},
}

var composeLogsCmd = &cobra.Command{
	Use:   "logs [service]",
	Short: "View output from containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := getProjectName(composeFile)
		if len(args) == 0 {
			return fmt.Errorf("specify a service: ziroctl compose logs <service>")
		}
		target := fmt.Sprintf("%s_%s_1", projectName, args[0])
		cmdRun := exec.Command("nerdctl", "logs", target)
		cmdRun.Stdout = os.Stdout
		cmdRun.Stderr = os.Stderr
		_ = cmdRun.Run()
		return nil
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

// parseComposeFile reads a docker-compose file (YAML) into the services it defines, normalizing
// the forms compose allows (environment as a list or a map, command as a string or a list,
// depends_on as a list or a map). Keys this tool doesn't use are ignored.
func parseComposeFile(path string) ([]ComposeService, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []ComposeService
	for _, n := range names {
		raw := doc.Services[n]
		svc := ComposeService{Name: n, Image: str(raw["image"]), Restart: str(raw["restart"]), Ports: strList(raw["ports"]),
			Volumes: strList(raw["volumes"]), DependsOn: keysOrList(raw["depends_on"])}
		switch e := raw["environment"].(type) {
		case map[string]any:
			keys := make([]string, 0, len(e))
			for k := range e {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				svc.Environment = append(svc.Environment, k+"="+str(e[k]))
			}
		default:
			svc.Environment = strList(e)
		}
		switch c := raw["command"].(type) {
		case string:
			svc.Command = strings.Fields(c)
		default:
			svc.Command = strList(c)
		}
		if hc, ok := raw["healthcheck"].(map[string]any); ok {
			switch t := hc["test"].(type) {
			case string:
				svc.Health = []string{"sh", "-c", t}
			default:
				if l := strList(t); len(l) > 1 && l[0] == "CMD" {
					svc.Health = l[1:]
				} else if len(l) > 1 && l[0] == "CMD-SHELL" {
					svc.Health = []string{"sh", "-c", strings.Join(l[1:], " ")}
				}
			}
		}
		for _, k := range []string{"build", "privileged", "network_mode", "cap_add", "devices", "pid", "ipc"} {
			if _, ok := raw[k]; ok {
				svc.Unsupported = append(svc.Unsupported, k)
			}
		}
		out = append(out, svc)
	}
	return out, nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func strList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, str(x))
	}
	return out
}

func keysOrList(v any) []string {
	if m, ok := v.(map[string]any); ok {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return strList(v)
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

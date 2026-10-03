package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
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
	Build       bool     // has build:
	Risks       []string // settings that weaken isolation (privileged: true, network_mode: host, ...)
}

// `ziroctl compose` is `nerdctl compose` (built into the nerdctl binary the OS ships; no
// docker-compose) behind a security preflight: before anything is created, the compose file
// is checked for settings that hand a container the host (privileged, host namespaces, added
// capabilities, devices, unconfined profiles, sensitive bind mounts) and for images the
// cluster image policy refuses. Then ziroctl execs nerdctl, so it isn't left in memory.

var composeCmd = &cobra.Command{
	Use:     "compose [flags] <command>",
	Aliases: []string{"docker-compose"},
	Short:   "Run multi-container apps from a compose file",
	Long: `Run a Compose project with nerdctl compose. Every compose command and flag works (up, down,
ps, logs, pull, restart, config, ...).

Before up, create and run, the file is checked. These are refused unless --allow-privileged
is given: privileged, host network/pid/ipc, cap_add, devices, unconfined security_opt, and
bind mounts of /, /etc, /proc, /sys, /dev, /run/containerd, /var/lib/ziro or a socket.
build: is refused (no image builder on the host): build elsewhere and push.`,
	Example: `  ziroctl compose up -d
  ziroctl compose -f shop/compose.yaml ps
  ziroctl compose logs -f web
  ziroctl compose down`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			return cmd.Help()
		}
		allow := false
		pass := args[:0:0]
		for _, a := range args {
			if a == "--allow-privileged" {
				allow = true
				continue
			}
			pass = append(pass, a)
		}
		files, sub := composeArgs(pass)
		if sub == "up" || sub == "create" || sub == "run" {
			if len(files) == 0 {
				for _, f := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
					if fileExists(f) {
						files = []string{f}
						break
					}
				}
			}
			for _, f := range files {
				svcs, err := parseComposeFile(f)
				if err != nil {
					return fmt.Errorf("%s: %w", f, err)
				}
				if problems := composePreflight(svcs, allow); len(problems) > 0 {
					return fmt.Errorf("%s:\n  %s", f, strings.Join(problems, "\n  "))
				}
			}
		}
		nerdctl, err := exec.LookPath("nerdctl")
		if err != nil {
			return errors.New("nerdctl not found")
		}
		return syscall.Exec(nerdctl, append([]string{"nerdctl", "compose"}, pass...), os.Environ())
	},
}

// composeArgs finds the compose files (-f/--file, repeatable) and the subcommand in args.
func composeArgs(args []string) (files []string, sub string) {
	withValue := map[string]bool{"-f": true, "--file": true, "-p": true, "--project-name": true,
		"--project-directory": true, "--env-file": true, "--profile": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := strings.CutPrefix(a, "--file="); ok {
			files = append(files, v)
		} else if withValue[a] && i+1 < len(args) {
			if a == "-f" || a == "--file" {
				files = append(files, args[i+1])
			}
			i++
		} else if sub == "" && !strings.HasPrefix(a, "-") {
			sub = a
		}
	}
	return files, sub
}

// composeSensitive are host paths a container must not bind-mount without --allow-privileged.
var composeSensitive = []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/run/containerd", "/var/run/containerd",
	"/var/lib/containerd", "/var/lib/ziro", "/run/ziro", "/var/run/docker.sock"}

// composePreflight lists what in svcs breaks out of the container sandbox, and images the
// cluster image policy refuses.
func composePreflight(svcs []ComposeService, allowPrivileged bool) []string {
	var out []string
	var policy ImagePolicy
	if st, err := readState(); err == nil {
		policy = st.ImagePolicy
	}
	for _, s := range svcs {
		if s.Build {
			out = append(out, s.Name+": build is not supported on the host: build the image elsewhere, push it and set image:")
		}
		if s.Image != "" {
			if err := checkImage(policy, s.Image); err != nil {
				out = append(out, s.Name+": "+err.Error())
			}
		}
		if allowPrivileged {
			continue
		}
		for _, r := range s.Risks {
			out = append(out, s.Name+": "+r+" (gives the container the host; --allow-privileged to permit)")
		}
	}
	return out
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
		_, svc.Build = raw["build"]
		svc.Risks = composeRisks(raw)
		out = append(out, svc)
	}
	return out, nil
}

// composeRisks lists the settings in one service that weaken container isolation.
func composeRisks(raw map[string]any) []string {
	var out []string
	if b, _ := raw["privileged"].(bool); b {
		out = append(out, "privileged: true")
	}
	for _, k := range []string{"network_mode", "pid", "ipc", "userns_mode", "uts"} {
		if v := str(raw[k]); v == "host" {
			out = append(out, k+": host")
		}
	}
	for _, k := range []string{"cap_add", "devices"} {
		if l := strList(raw[k]); len(l) > 0 {
			out = append(out, k+": "+strings.Join(l, ", "))
		}
	}
	for _, o := range strList(raw["security_opt"]) {
		if strings.Contains(o, "unconfined") {
			out = append(out, "security_opt: "+o)
		}
	}
	vols, _ := raw["volumes"].([]any)
	for _, v := range vols {
		src := ""
		switch x := v.(type) {
		case string:
			src, _, _ = strings.Cut(x, ":")
		case map[string]any:
			if str(x["type"]) == "bind" {
				src = str(x["source"])
			}
		}
		if src == "" || !strings.HasPrefix(src, "/") {
			continue // named volume or relative path (inside the project)
		}
		if p := filepath.Clean(src); composeSensitivePath(p) {
			out = append(out, "bind mount of "+p)
		}
	}
	return out
}

func composeSensitivePath(p string) bool {
	if p == "/" || strings.HasSuffix(p, ".sock") {
		return true
	}
	if p == "/var/lib/ziro/volumes" || strings.HasPrefix(p, "/var/lib/ziro/volumes/") {
		return false // where volumes are meant to live
	}
	for _, s := range composeSensitive {
		if p == s || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
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
	rootCmd.AddCommand(composeCmd)
}

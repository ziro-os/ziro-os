package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

// What `docker version`, `docker --version` and `docker compose version` print on Ziro OS.
//
// `docker` is nerdctl, whose version output has no Docker "Server: Engine" section. Tools that
// manage a Docker host (Coolify checks `docker version --format json` for Server.Version >= 24)
// read that section, so /usr/bin/docker is a small wrapper that sends these three commands here and
// everything else to nerdctl untouched.
//
// dockerCompatVersion is the Docker Engine release whose API we serve (dockerAPIVersion 1.43 is
// Docker 24.0). It is an API compatibility level, not a claim that Docker Engine is installed: the
// real engine (containerd, runc, nerdctl) is listed under Components. Raise it only together with
// the API surface in docker_api.go.
const dockerCompatVersion = "24.0.0"

type dockerVerComponent struct {
	Name    string            `json:"Name"`
	Version string            `json:"Version"`
	Details map[string]string `json:"Details,omitempty"`
}

type dockerVerSide struct {
	Platform      struct{ Name string } `json:"Platform"`
	Version       string                `json:"Version"`
	ApiVersion    string                `json:"ApiVersion"`
	MinAPIVersion string                `json:"MinAPIVersion,omitempty"`
	GoVersion     string                `json:"GoVersion"`
	Os            string                `json:"Os"`
	Arch          string                `json:"Arch"`
	KernelVersion string                `json:"KernelVersion,omitempty"`
	Components    []dockerVerComponent  `json:"Components"`
}

type dockerVersionInfo struct {
	Client dockerVerSide `json:"Client"`
	Server dockerVerSide `json:"Server"`
}

// toolVersion runs `bin args...` and returns the first version-looking token of its output.
var verTokenRe = regexp.MustCompile(`v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.]+)?`)

func toolVersion(bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(verTokenRe.FindString(string(out)), "v")
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// buildDockerVersion fills the version document. look gives the version of a tool (injected for tests).
func buildDockerVersion(look func(bin string, args ...string) string) dockerVersionInfo {
	side := func(server bool) dockerVerSide {
		var s dockerVerSide
		s.Platform.Name = "Ziro OS"
		s.Version, s.ApiVersion = dockerCompatVersion, dockerAPIVersion
		s.GoVersion, s.Os, s.Arch = runtime.Version(), "linux", runtime.GOARCH
		if server {
			s.MinAPIVersion = dockerMinVersion
			s.KernelVersion = kernelRelease()
		}
		return s
	}
	info := dockerVersionInfo{Client: side(false), Server: side(true)}
	nerd := look("nerdctl", "--version")
	info.Client.Components = []dockerVerComponent{{Name: "nerdctl", Version: nerd}}
	info.Server.Components = []dockerVerComponent{
		{Name: "Engine", Version: dockerCompatVersion, Details: map[string]string{
			"ApiVersion": dockerAPIVersion, "MinAPIVersion": dockerMinVersion, "Os": "linux", "Arch": runtime.GOARCH,
			"Note": "Docker API compatibility level; the runtime is containerd via nerdctl " + nerd}},
		{Name: "containerd", Version: look("containerd", "--version")},
		{Name: "runc", Version: look("runc", "--version")},
	}
	return info
}

func (v dockerVersionInfo) text() string {
	var b strings.Builder
	side := func(title string, s dockerVerSide) {
		fmt.Fprintf(&b, "%s:\n Version:           %s\n API version:       %s", title, s.Version, s.ApiVersion)
		if s.MinAPIVersion != "" {
			fmt.Fprintf(&b, " (minimum version %s)", s.MinAPIVersion)
		}
		fmt.Fprintf(&b, "\n Go version:        %s\n OS/Arch:           %s/%s\n", s.GoVersion, s.Os, s.Arch)
		if s.KernelVersion != "" {
			fmt.Fprintf(&b, " Kernel version:    %s\n", s.KernelVersion)
		}
	}
	side("Client", v.Client)
	fmt.Fprintf(&b, " Context:           default\n\n")
	side("Server", v.Server)
	fmt.Fprintf(&b, " Components:\n")
	for _, c := range v.Server.Components {
		fmt.Fprintf(&b, "  %s:\n   Version:          %s\n", c.Name, c.Version)
	}
	return b.String()
}

// renderDockerVersion applies --format: "json" (or empty for the default text), or a Go template as
// Docker accepts it, e.g. '{{.Server.Version}}'.
func renderDockerVersion(v dockerVersionInfo, format string) (string, error) {
	switch format {
	case "":
		return v.text(), nil
	case "json":
		b, err := json.Marshal(v)
		return string(b) + "\n", err
	}
	t, err := template.New("version").Funcs(template.FuncMap{"json": func(x any) (string, error) {
		b, err := json.Marshal(x)
		return string(b), err
	}}).Parse(format)
	if err != nil {
		return "", fmt.Errorf("template parsing error: %v", err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, v); err != nil {
		return "", fmt.Errorf("template execution error: %v", err)
	}
	return out.String() + "\n", nil
}

// parseVersionArgs reads the flags `docker version` takes that matter here.
func parseVersionArgs(args []string) (format string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format" || a == "-f":
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag needs an argument: %s", a)
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		default:
			return "", fmt.Errorf("unknown flag: %s", a)
		}
	}
	return format, nil
}

// composeVersion is the version of the Compose implementation (nerdctl's), without the leading v.
func composeVersion(look func(bin string, args ...string) string) string {
	if v := look("nerdctl", "compose", "version"); v != "" {
		return v
	}
	return look("nerdctl", "--version")
}

var dockerCompatCmd = &cobra.Command{
	Use:                "docker-compat",
	Hidden:             true,
	DisableFlagParsing: true,
	Short:              "Version output for the docker wrapper",
	Example:            `  ziroctl docker-compat version --format json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: docker-compat version|--version|compose|network [args]")
		}
		if isDockerVersionCmd(args) {
			out, err := dockerCompat(args, toolVersion)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		}
		nargs, notes := translateDocker(args)
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, "docker: note: "+n)
		}
		bin, err := exec.LookPath("nerdctl")
		if err != nil {
			return err
		}
		return syscall.Exec(bin, append([]string{"nerdctl"}, nargs...), os.Environ())
	},
}

func isDockerVersionCmd(args []string) bool {
	return args[0] == "version" || args[0] == "--version" || args[0] == "-v" ||
		(args[0] == "compose" && len(args) >= 2 && args[1] == "version")
}

// Flags of `docker compose` that take a value, to find the subcommand behind them.
var composeValueFlags = map[string]bool{"-f": true, "--file": true, "-p": true, "--project-name": true, "--project-directory": true,
	"--env-file": true, "--profile": true, "--parallel": true, "--ansi": true, "--progress": true}

// translateDocker rewrites a docker command line for nerdctl and returns notes for the user. Only
// flags nerdctl rejects are touched: "network create --attachable" (every nerdctl network is
// attachable), "compose pull --ignore-buildable", "compose up --wait/--wait-timeout" and "--rm" of a
// detached "run" (nerdctl refuses -d with --rm; Coolify's helper container uses both).
//
// Known limitation: nerdctl compose has no --wait, so `up --wait` returns once the containers are
// started and does not wait for health checks; poll `docker ps` or the service's own check when
// that matters.
//
// Known limitation: without --rm a detached container that exits stays until it is removed; tools that
// start one this way (Coolify) remove it themselves with `docker rm -f`.
func translateDocker(args []string) (out, notes []string) {
	switch {
	case len(args) >= 2 && args[0] == "network" && args[1] == "create":
		out = append(out, args[:2]...)
		for _, a := range args[2:] {
			if a != "--attachable" && !strings.HasPrefix(a, "--attachable=") {
				out = append(out, a)
			}
		}
		return out, nil
	case args[0] == "run" || (len(args) >= 2 && args[0] == "container" && args[1] == "run"):
		return translateRun(args)
	case args[0] == "compose":
		i := 1
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			if composeValueFlags[args[i]] {
				i++ // its value
			}
			i++
		}
		if i >= len(args) {
			return args, nil
		}
		sub := args[i]
		out = append(out, args[:i+1]...)
		rest := args[i+1:]
		for j := 0; j < len(rest); j++ {
			a := rest[j]
			switch {
			case sub == "pull" && a == "--ignore-buildable":
			case sub == "up" && a == "--wait":
				notes = append(notes, "--wait is not supported by nerdctl compose: the containers are started, not waited for")
			case sub == "up" && a == "--wait-timeout":
				j++ // its value
			case sub == "up" && strings.HasPrefix(a, "--wait-timeout="):
			case sub == "up" && strings.HasPrefix(a, "--wait="):
				notes = append(notes, "--wait is not supported by nerdctl compose: the containers are started, not waited for")
			default:
				out = append(out, a)
			}
		}
		return out, notes
	}
	return args, nil
}

// runValueFlags are the `docker run` flags that take a separate value, to find where the image starts.
var runValueFlags = map[string]bool{"--name": true, "--network": true, "--net": true, "-v": true, "--volume": true, "-e": true, "--env": true,
	"--env-file": true, "-p": true, "--publish": true, "-l": true, "--label": true, "-w": true, "--workdir": true, "-u": true, "--user": true,
	"--entrypoint": true, "--restart": true, "--add-host": true, "--platform": true, "-h": true, "--hostname": true, "--ip": true,
	"-m": true, "--memory": true, "--cpus": true, "--cap-add": true, "--cap-drop": true, "--security-opt": true, "--mount": true,
	"--dns": true, "--log-driver": true, "--pull": true, "--health-cmd": true, "--health-interval": true, "--network-alias": true,
	"--tmpfs": true, "--device": true, "--pid": true, "--shm-size": true, "--stop-signal": true, "--stop-timeout": true}

// translateRun drops --rm from a detached run. Only the flags before the image are looked at, so a
// "--rm" that belongs to the container's own command is kept.
func translateRun(args []string) (out, notes []string) {
	start := 1
	if args[0] == "container" {
		start = 2
	}
	end, detached, rm := len(args), false, -1
	for i := start; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			end = i
		case !strings.HasPrefix(a, "-"):
			end = i // the image
		case a == "--detach" || a == "--detach=true" || (len(a) > 1 && a[1] != '-' && strings.Trim(a[1:], "dit") == "" && strings.Contains(a, "d")):
			detached = true
			continue
		case a == "--rm" || a == "--rm=true":
			rm = i
			continue
		case runValueFlags[a]:
			i++
			continue
		default:
			continue
		}
		break
	}
	if !detached || rm < 0 || rm >= end {
		return args, nil
	}
	out = append(append(out, args[:rm]...), args[rm+1:]...)
	return out, []string{"--rm is not supported by nerdctl together with -d: the container is not removed when it exits"}
}

// dockerCompat answers the commands the docker wrapper hands over: `version [--format F]`,
// `--version`/`-v`, and `compose version [--short] [--format F]`.
func dockerCompat(args []string, look func(bin string, args ...string) string) (string, error) {
	switch {
	case args[0] == "--version" || args[0] == "-v":
		return fmt.Sprintf("Docker version %s, build ziro-os (nerdctl %s)\n", dockerCompatVersion, look("nerdctl", "--version")), nil
	case args[0] == "version":
		format, err := parseVersionArgs(args[1:])
		if err != nil {
			return "", err
		}
		return renderDockerVersion(buildDockerVersion(look), format)
	case args[0] == "compose" && len(args) >= 2 && args[1] == "version":
		v := composeVersion(look)
		short, format := false, ""
		for i := 2; i < len(args); i++ {
			switch {
			case args[i] == "--short":
				short = true
			case args[i] == "--format" && i+1 < len(args):
				format = args[i+1]
				i++
			case strings.HasPrefix(args[i], "--format="):
				format = strings.TrimPrefix(args[i], "--format=")
			default:
				return "", fmt.Errorf("unknown flag: %s", args[i])
			}
		}
		switch {
		case short:
			return v + "\n", nil
		case format == "json":
			b, _ := json.Marshal(map[string]string{"version": "v" + v})
			return string(b) + "\n", nil
		case format != "":
			return "", fmt.Errorf("unsupported --format %q (json is)", format)
		}
		return "Docker Compose version v" + v + "\n", nil
	}
	return "", fmt.Errorf("docker-compat: unsupported command %q", args[0])
}

func init() { rootCmd.AddCommand(dockerCompatCmd) }

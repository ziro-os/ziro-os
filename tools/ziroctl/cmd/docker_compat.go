package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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
		os.Exit(runDockerPlan(planDocker(args, time.Now)))
		return nil
	},
}

// runNerdctlOut runs nerdctl and returns its stdout; its stderr goes to ours.
func runNerdctlOut(args ...string) ([]byte, error) {
	c := exec.Command("nerdctl", args...)
	c.Stderr = os.Stderr
	return c.Output()
}

// runDockerPlan carries out a plan and returns the exit code. A plain rewrite replaces this process
// with nerdctl, so signals, the terminal and the exit code are nerdctl's own.
func runDockerPlan(p dockerPlan) int {
	for _, n := range p.notes {
		fmt.Fprintln(os.Stderr, "docker: note: "+n)
	}
	if p.before != nil {
		if err := p.before(runNerdctlOut); err != nil {
			fmt.Fprintln(os.Stderr, "docker: warning: "+err.Error())
		}
	}
	bin, err := exec.LookPath("nerdctl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "docker: "+err.Error())
		return 127
	}
	if p.output == nil && !p.ignoreFailure {
		err := syscall.Exec(bin, append([]string{"nerdctl"}, p.args...), os.Environ())
		fmt.Fprintln(os.Stderr, "docker: "+err.Error())
		return 126
	}
	c := exec.Command(bin, p.args...)
	c.Stdin, c.Stderr = os.Stdin, os.Stderr
	var stdout bytes.Buffer
	if p.output != nil {
		c.Stdout = &stdout
	} else {
		c.Stdout = os.Stdout
	}
	err = c.Run()
	code := 0
	if err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	if p.output != nil && stdout.Len() > 0 {
		out, ferr := p.output(stdout.Bytes(), runNerdctlOut)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "docker: "+ferr.Error())
			return 1
		}
		os.Stdout.Write(out)
	}
	if code != 0 && p.ignoreFailure {
		fmt.Fprintln(os.Stderr, "docker: warning: the pull failed (--ignore-pull-failures): continuing")
		return 0
	}
	return code
}

func isDockerVersionCmd(args []string) bool {
	return args[0] == "version" || args[0] == "--version" || args[0] == "-v" ||
		(args[0] == "compose" && len(args) >= 2 && args[1] == "version")
}

// Flags of `docker compose` that take a value, to find the subcommand behind them.
var composeValueFlags = map[string]bool{"-f": true, "--file": true, "-p": true, "--project-name": true, "--project-directory": true,
	"--env-file": true, "--profile": true, "--parallel": true, "--ansi": true, "--progress": true}

// composeSplit finds the compose subcommand behind the global flags: args is a docker command line
// starting with "compose". sub is "" when there is none.
func composeSplit(args []string) (globals []string, sub string, rest []string) {
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if composeValueFlags[args[i]] {
			i++ // its value
		}
		i++
	}
	if i >= len(args) {
		return args, "", nil
	}
	return args[:i], args[i], args[i+1:]
}

// composeCreateFlags are the flags of `compose up` that `nerdctl compose create` also takes. createValue
// are those with a separate value.
var (
	composeCreateFlags = map[string]bool{"--build": true, "--no-build": true, "--force-recreate": true, "--no-recreate": true, "--pull": true}
	composeUpValue     = map[string]bool{"--pull": true, "--scale": true, "--wait-timeout": true, "-t": true, "--timeout": true, "--exit-code-from": true}
)

// translateDocker rewrites a docker command line for nerdctl and returns notes for the user. Only
// flags nerdctl rejects are touched:
//   - "network create --attachable" (every nerdctl network is attachable);
//   - "compose up --no-start" (Coolify, to connect networks before the start) becomes "compose create",
//     which takes only --build, --no-build, --force-recreate, --no-recreate and --pull; the
//     --remove-orphans it drops is done by the wrapper (see dockerPlan);
//   - "compose up --wait/--wait-timeout", "compose pull --ignore-buildable/--ignore-pull-failures"
//     (the wrapper keeps the second's meaning), "compose config --no-interpolate/--no-path-resolution";
//   - "--rm" of a detached "run" (nerdctl refuses -d with --rm; Coolify's helper container uses both).
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
	case args[0] == "run" || args[0] == "create" || (len(args) >= 2 && args[0] == "container" && (args[1] == "run" || args[1] == "create")):
		return translateRun(args)
	case args[0] == "compose":
		globals, sub, rest := composeSplit(args)
		if sub == "" {
			return args, nil
		}
		if sub == "up" && slices.Contains(rest, "--no-start") {
			return composeUpNoStart(globals, rest), nil
		}
		out = append(append(out, globals...), sub)
		quiet := slices.Contains(rest, "-q") || slices.Contains(rest, "--quiet")
		for j := 0; j < len(rest); j++ {
			a := rest[j]
			switch {
			case sub == "pull" && (a == "--ignore-buildable" || a == "--ignore-pull-failures"):
			case sub == "config" && (a == "--no-interpolate" || a == "--no-path-resolution"):
				if !quiet {
					notes = append(notes, a+" is not supported by nerdctl compose: the configuration is printed resolved")
				}
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

// composeUpNoStart turns `compose up … --no-start` into `compose create` with the flags create takes.
// Services named after the flags are kept.
func composeUpNoStart(globals, rest []string) []string {
	out := append(append([]string(nil), globals...), "create")
	for j := 0; j < len(rest); j++ {
		a := rest[j]
		name, _, hasValue := strings.Cut(a, "=")
		switch {
		case a == "--":
			return append(out, rest[j:]...)
		case !strings.HasPrefix(a, "-"):
			out = append(out, a) // a service
		case composeCreateFlags[name]:
			out = append(out, a)
			if composeUpValue[name] && !hasValue && j+1 < len(rest) {
				out = append(out, rest[j+1])
				j++
			}
		case composeUpValue[name] && !hasValue:
			j++ // a flag create does not take, and its value
		}
	}
	return out
}

// dockerPlan is what the wrapper does with one docker command line besides running nerdctl.
type dockerPlan struct {
	args  []string // the nerdctl command line
	notes []string
	// before runs first (removing orphans for `up --no-start --remove-orphans`); its error is a warning.
	before func(run nerdctlRunner) error
	// ignoreFailure turns a failed command into a warning (compose pull --ignore-pull-failures).
	ignoreFailure bool
	// output, when set, rewrites nerdctl's stdout into Docker's shape.
	output func(stdout []byte, run nerdctlRunner) ([]byte, error)
}

// planDocker plans a docker command line: the rewrite of translateDocker, plus the steps nerdctl has
// no flag for and the Docker-shaped output of ps, inspect and network inspect.
func planDocker(args []string, now func() time.Time) dockerPlan {
	nargs, notes := translateDocker(args)
	p := dockerPlan{args: nargs, notes: notes}
	sub, rest := args[0], args[1:]
	if sub == "container" && len(args) >= 2 {
		switch args[1] {
		case "ls", "list", "ps":
			sub, rest = "ps", args[2:]
		case "inspect":
			sub, rest = "inspect", args[2:]
		}
	}
	switch {
	case sub == "compose":
		globals, csub, crest := composeSplit(args)
		if csub == "up" && slices.Contains(crest, "--no-start") && slices.Contains(crest, "--remove-orphans") {
			p.before = func(run nerdctlRunner) error { return removeComposeOrphans(globals[1:], run) }
		}
		if csub == "pull" && slices.Contains(crest, "--ignore-pull-failures") {
			p.ignoreFailure = true
		}
	case sub == "ps":
		r, format, ok := takeFormat(rest, false)
		if !ok || format == "" || strings.HasPrefix(format, "table") || format == "wide" || slices.Contains(r, "-q") || slices.Contains(r, "--quiet") {
			return p
		}
		p.args = append(append([]string{"ps"}, r...), "--format", psFormat)
		p.output = func(b []byte, _ nerdctlRunner) ([]byte, error) { return formatPs(b, format, now()) }
	case sub == "inspect":
		r, format, _ := takeFormat(rest, true)
		p.args = append([]string{"inspect"}, r...)
		if args[0] == "container" {
			p.args = append([]string{"container", "inspect"}, r...)
		}
		p.output = func(b []byte, _ nerdctlRunner) ([]byte, error) { return formatInspect(b, format) }
	case sub == "network" && len(args) >= 2 && args[1] == "inspect":
		r, format, _ := takeFormat(args[2:], true)
		p.args = append([]string{"network", "inspect"}, r...)
		p.output = func(b []byte, run nerdctlRunner) ([]byte, error) { return formatNetworkInspect(b, format, run) }
	}
	return p
}

// composeProject is the compose project name, as Compose derives it: -p/--project-name, then
// COMPOSE_PROJECT_NAME, then the name of the project directory (or of the first file's directory, or
// the working directory), lowercased with characters outside [a-z0-9_-] removed.
func composeProject(globals []string, getenv func(string) string, wd string) string {
	var name, dir, file string
	for i := 0; i < len(globals); i++ {
		a := globals[i]
		flag, val, hasVal := strings.Cut(a, "=")
		if !hasVal && composeValueFlags[a] && i+1 < len(globals) {
			val = globals[i+1]
			i++
		}
		switch flag {
		case "-p", "--project-name":
			name = val
		case "--project-directory":
			dir = val
		case "-f", "--file":
			if file == "" {
				file = val
			}
		}
	}
	if name == "" {
		name = getenv("COMPOSE_PROJECT_NAME")
	}
	if name == "" {
		switch {
		case dir != "":
			name = filepath.Base(dir)
		case file != "" && file != "-":
			name = filepath.Base(filepath.Dir(filepath.Join(wd, file)))
		default:
			name = filepath.Base(wd)
		}
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// removeComposeOrphans does `up --remove-orphans` for the create path: containers of the project whose
// service is no longer in the compose file are removed. globals are the compose flags (-f, -p, …).
func removeComposeOrphans(globals []string, run nerdctlRunner) error {
	wd, _ := os.Getwd()
	project := composeProject(globals, os.Getenv, wd)
	if project == "" {
		return fmt.Errorf("--remove-orphans: the compose project name is unknown; no container was removed")
	}
	cfg, err := run(append(append([]string{"compose"}, globals...), "config", "--services")...)
	if err != nil {
		return fmt.Errorf("--remove-orphans: %v", err)
	}
	keep := map[string]bool{}
	for _, s := range strings.Fields(string(cfg)) {
		keep[s] = true
	}
	if len(keep) == 0 {
		return fmt.Errorf("--remove-orphans: the compose file lists no services; no container was removed")
	}
	list, err := run("ps", "-a", "--filter", "label=com.docker.compose.project="+project,
		"--format", `{{.ID}}{{"\t"}}{{.Label "com.docker.compose.service"}}`)
	if err != nil {
		return fmt.Errorf("--remove-orphans: %v", err)
	}
	var orphans []string
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		id, svc, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if id != "" && svc != "" && !keep[svc] {
			orphans = append(orphans, id)
		}
	}
	if len(orphans) == 0 {
		return nil
	}
	_, err = run(append([]string{"rm", "-f"}, orphans...)...)
	return err
}

// runValueFlags are the `docker run` flags that take a separate value, to find where the image starts.
var runValueFlags = map[string]bool{"--name": true, "--network": true, "--net": true, "-v": true, "--volume": true, "-e": true, "--env": true,
	"--env-file": true, "-p": true, "--publish": true, "-l": true, "--label": true, "-w": true, "--workdir": true, "-u": true, "--user": true,
	"--entrypoint": true, "--restart": true, "--add-host": true, "--platform": true, "-h": true, "--hostname": true, "--ip": true,
	"-m": true, "--memory": true, "--cpus": true, "--cap-add": true, "--cap-drop": true, "--security-opt": true, "--mount": true,
	"--dns": true, "--log-driver": true, "--pull": true, "--health-cmd": true, "--health-interval": true, "--network-alias": true,
	"--tmpfs": true, "--device": true, "--pid": true, "--shm-size": true, "--stop-signal": true, "--stop-timeout": true}

// translateRun adapts the flags of docker run and docker create that nerdctl lacks: --rm of a
// detached run is dropped, and the first --network-alias becomes --hostname (nerdctl makes a hostname
// resolvable on the container's network; see buildCreateArgs), the others are dropped. Only the flags
// before the image are looked at, so the same text in the container's own command is kept.
func translateRun(args []string) (out, notes []string) {
	start := 1
	if args[0] == "container" {
		start = 2
	}
	run := args[start-1] == "run"
	end, detached, rm := len(args), false, -1
	var alias []int
	hostname := false
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
		case a == "--hostname" || a == "-h" || strings.HasPrefix(a, "--hostname="):
			hostname = true
			if !strings.Contains(a, "=") {
				i++
			}
			continue
		case a == "--network-alias" || strings.HasPrefix(a, "--network-alias="):
			alias = append(alias, i)
			if a == "--network-alias" {
				i++
			}
			continue
		case runValueFlags[a]:
			i++
			continue
		default:
			continue
		}
		break
	}
	out = append([]string(nil), args...)
	var drop []int
	for n, i := range alias {
		if i >= end {
			continue
		}
		val := strings.TrimPrefix(out[i], "--network-alias=")
		if out[i] == "--network-alias" {
			val = out[i+1]
			drop = append(drop, i+1)
		}
		if n == 0 && !hostname {
			out[i] = "--hostname=" + val // a separate value token, if any, is already in drop
		} else {
			drop = append(drop, i)
		}
	}
	slices.SortFunc(drop, func(a, b int) int { return b - a })
	for _, i := range drop {
		out = slices.Delete(out, i, i+1)
		if rm > i {
			rm--
		}
		end--
	}
	if run && detached && rm >= 0 && rm < end {
		out = append(out[:rm], out[rm+1:]...)
		notes = append(notes, "--rm is not supported by nerdctl together with -d: the container is not removed when it exits")
	}
	return out, notes
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

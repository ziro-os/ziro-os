package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func fakeLook(bin string, args ...string) string {
	switch strings.Join(append([]string{bin}, args...), " ") {
	case "nerdctl --version":
		return "2.2.1"
	case "nerdctl compose version":
		return "2.2.1"
	case "containerd --version":
		return "2.3.7"
	case "runc --version":
		return "1.4.3"
	}
	return ""
}

// What Coolify does: docker version --format json, then Server.Version, compared by major version to 24.
func TestDockerVersionJSONHasTheServerVersionToolsRead(t *testing.T) {
	out, err := dockerCompat([]string{"version", "--format", "json"}, fakeLook)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Client struct{ Version string }
		Server struct {
			Version    string
			ApiVersion string
			Components []struct{ Name, Version string }
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not pure JSON: %v\n%s", err, out)
	}
	major, _, _ := strings.Cut(doc.Server.Version, ".")
	if n, err := strconv.Atoi(major); err != nil || n < 24 {
		t.Fatalf("Server.Version %q is below Docker 24", doc.Server.Version)
	}
	if doc.Server.Version == Version {
		t.Fatal("the server version is Ziro's own release number")
	}
	if doc.Server.ApiVersion != dockerAPIVersion {
		t.Fatalf("API version %q differs from the one the socket serves (%s)", doc.Server.ApiVersion, dockerAPIVersion)
	}
	var names []string
	for _, c := range doc.Server.Components {
		names = append(names, c.Name+"="+c.Version)
	}
	if got := strings.Join(names, " "); got != "Engine=24.0.0 containerd=2.3.7 runc=1.4.3" {
		t.Fatalf("components: %s", got)
	}
	if !strings.HasPrefix(out, "{") || strings.Count(out, "\n") != 1 {
		t.Fatalf("the JSON must be one line on stdout, nothing else: %q", out)
	}
}

func TestDockerVersionFormats(t *testing.T) {
	for format, want := range map[string]string{
		"{{.Server.Version}}":             "24.0.0\n",
		"{{.Client.Version}}":             "24.0.0\n",
		"{{.Server.ApiVersion}}":          "1.43\n",
		"{{json .Server.Platform}}":       `{"Name":"Ziro OS"}` + "\n",
		"{{.Server.Os}}/{{.Server.Arch}}": "linux/" + dockerArchGo() + "\n",
	} {
		out, err := dockerCompat([]string{"version", "--format=" + format}, fakeLook)
		if err != nil || out != want {
			t.Errorf("--format %s: %q, %v (want %q)", format, out, err, want)
		}
		out, err = dockerCompat([]string{"version", "-f", format}, fakeLook)
		if err != nil || out != want {
			t.Errorf("-f %s: %q, %v", format, out, err)
		}
	}
	if _, err := dockerCompat([]string{"version", "--format", "{{.Server.Nope}}"}, fakeLook); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := dockerCompat([]string{"version", "--format", "{{"}, fakeLook); err == nil {
		t.Error("a broken template was accepted")
	}
	if _, err := dockerCompat([]string{"version", "--bogus"}, fakeLook); err == nil {
		t.Error("an unknown flag was accepted")
	}
	if _, err := dockerCompat([]string{"version", "--format"}, fakeLook); err == nil {
		t.Error("a flag without its value was accepted")
	}
}

func dockerArchGo() string {
	b, _ := json.Marshal(buildDockerVersion(fakeLook).Server.Arch)
	return strings.Trim(string(b), `"`)
}

func TestDockerVersionTextAndShortForms(t *testing.T) {
	text, err := dockerCompat([]string{"version"}, fakeLook)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Client:", "Server:", "API version:       1.43 (minimum version 1.24)", "Components:", "  Engine:", "  containerd:", "   Version:          2.3.7"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output lacks %q:\n%s", want, text)
		}
	}
	line, err := dockerCompat([]string{"--version"}, fakeLook)
	if err != nil || !strings.HasPrefix(line, "Docker version 24.0.0, build ") {
		t.Fatalf("--version: %q %v", line, err)
	}
	if l2, _ := dockerCompat([]string{"-v"}, fakeLook); l2 != line {
		t.Fatalf("-v differs from --version: %q", l2)
	}
}

func TestDockerComposeVersionForms(t *testing.T) {
	for args, want := range map[string]string{
		"compose version":               "Docker Compose version v2.2.1\n",
		"compose version --short":       "2.2.1\n",
		"compose version --format json": `{"version":"v2.2.1"}` + "\n",
		"compose version --format=json": `{"version":"v2.2.1"}` + "\n",
	} {
		out, err := dockerCompat(strings.Fields(args), fakeLook)
		if err != nil || out != want {
			t.Errorf("%s: %q, %v (want %q)", args, out, err, want)
		}
	}
	// without `compose version` output, nerdctl's own version stands in
	only := func(bin string, args ...string) string {
		if bin == "nerdctl" && len(args) == 1 {
			return "2.2.1"
		}
		return ""
	}
	if out, _ := dockerCompat([]string{"compose", "version", "--short"}, only); out != "2.2.1\n" {
		t.Errorf("fallback: %q", out)
	}
	for _, bad := range []string{"compose version --format {{.x}}", "compose version --nope", "compose up", "ps"} {
		if _, err := dockerCompat(strings.Fields(bad), fakeLook); err == nil {
			t.Errorf("%q was handled; only version output belongs to the shim", bad)
		}
	}
}

// The socket and the CLI must report the same engine, or a tool that reads both sees two versions.
func TestDockerSocketReportsTheCompatVersion(t *testing.T) {
	f := &fakeDocker{out: map[string]string{"ps -q --no-trunc -a": ""}}
	h := f.api().handler()
	var v struct{ Version string }
	if err := json.Unmarshal(do(h, "GET", "/version").Body.Bytes(), &v); err != nil || v.Version != dockerCompatVersion {
		t.Fatalf("/version: %+v %v", v, err)
	}
	var info struct{ ServerVersion string }
	if err := json.Unmarshal(do(h, "GET", "/info").Body.Bytes(), &info); err != nil || info.ServerVersion != dockerCompatVersion {
		t.Fatalf("/info: %+v %v", info, err)
	}
}

// Runs the real wrapper with stand-ins for nerdctl and ziroctl that print their arguments: only the
// version commands, "network" and "compose" go through ziroctl; everything else is nerdctl untouched.
func TestDockerWrapperRouting(t *testing.T) {
	src, err := os.ReadFile("../../../rootfs/usr/bin/docker")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stub := func(name, tag string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\nprintf '"+tag+":'; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; echo\n"), 0o755)
		return p
	}
	script := strings.NewReplacer("/usr/bin/nerdctl", stub("nerdctl", "NERDCTL"), "/usr/bin/ziroctl", stub("ziroctl", "ZIROCTL")).Replace(string(src))
	wrapper := filepath.Join(dir, "docker")
	os.WriteFile(wrapper, []byte(script), 0o755)
	run := func(args ...string) string {
		out, err := exec.Command("sh", append([]string{wrapper}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"version", "--format", "json"}, "ZIROCTL: [docker-compat] [version] [--format] [json]"},
		{[]string{"--version"}, "ZIROCTL: [docker-compat] [--version]"},
		{[]string{"-v"}, "ZIROCTL: [docker-compat] [-v]"},
		{[]string{"compose", "-f", "a.yml", "up", "-d"}, "ZIROCTL: [docker-compat] [compose] [-f] [a.yml] [up] [-d]"},
		{[]string{"network", "create", "x", "--attachable"}, "ZIROCTL: [docker-compat] [network] [create] [x] [--attachable]"},
		{[]string{"run", "--rm", "-v", "/a:/b", "alpine", "sh", "-c", "echo hi"}, "ZIROCTL: [docker-compat] [run] [--rm] [-v] [/a:/b] [alpine] [sh] [-c] [echo hi]"},
		{[]string{"ps", "-a", "--format", "{{json .}}"}, "NERDCTL: [ps] [-a] [--format] [{{json .}}]"},
		{[]string{"container", "inspect", "--format", "{{json .}}", "abc"}, "NERDCTL: [container] [inspect] [--format] [{{json .}}] [abc]"},
	} {
		if got := run(c.args...); got != c.want {
			t.Errorf("docker %q:\n got %s\nwant %s", c.args, got, c.want)
		}
	}
}

func TestTranslateDockerDropsOnlyWhatNerdctlRejects(t *testing.T) {
	type c struct {
		in, out string
		notes   int
	}
	for _, tc := range []c{
		// network create
		{"network create coolify --attachable", "network create coolify", 0},
		{"network create --attachable x --subnet 10.0.0.0/24", "network create x --subnet 10.0.0.0/24", 0},
		{"network create --attachable=true x", "network create x", 0},
		{"network create --label a=b x", "network create --label a=b x", 0},
		{"network create not--attachable", "network create not--attachable", 0},
		{"network ls", "network ls", 0},
		{"network connect coolify web", "network connect coolify web", 0},
		// run: --rm is dropped from a detached run only, and only before the image
		{"run -d --network coolify --name x --rm -v /a:/b img", "run -d --network coolify --name x -v /a:/b img", 1},
		{"run --rm -d img", "run -d img", 1},
		{"run -dit --rm img sh", "run -dit img sh", 1},
		{"container run --detach --rm img", "container run --detach img", 1},
		{"run --rm img", "run --rm img", 0},
		{"run -d img tool --rm", "run -d img tool --rm", 0},
		{"run -d -e A=--rm img", "run -d -e A=--rm img", 0},
		{"run -d img", "run -d img", 0},
		// compose: the subcommand is found behind the global flags and their values
		{"compose -f a.yml pull --ignore-buildable", "compose -f a.yml pull", 0},
		{"compose --env-file e -f a.yml --project-name p pull --ignore-buildable web", "compose --env-file e -f a.yml --project-name p pull web", 0},
		{"compose -f a.yml up -d --wait --remove-orphans", "compose -f a.yml up -d --remove-orphans", 1},
		{"compose up -d --wait-timeout 60 --wait", "compose up -d", 1},
		{"compose up -d --wait-timeout=60", "compose up -d", 0},
		{"compose up -d --wait=true", "compose up -d", 1},
		{"compose -p p up -d", "compose -p p up -d", 0},
		{"compose -f a.yml down --remove-orphans", "compose -f a.yml down --remove-orphans", 0},
		{"compose ps", "compose ps", 0},
		{"compose", "compose", 0},
		{"compose -f a.yml", "compose -f a.yml", 0},
		// flags of other subcommands are not touched, even when the name matches
		{"compose logs --wait", "compose logs --wait", 0},
		{"compose exec web --ignore-buildable", "compose exec web --ignore-buildable", 0},
		// the flag after the service name or a value of another flag is kept
		{"compose pull -q --ignore-buildable", "compose pull -q", 0},
	} {
		out, notes := translateDocker(strings.Fields(tc.in))
		if got := strings.Join(out, " "); got != tc.out || len(notes) != tc.notes {
			t.Errorf("%s:\n got %q (%d notes)\nwant %q (%d notes)", tc.in, got, len(notes), tc.out, tc.notes)
		}
	}
}

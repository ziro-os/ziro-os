package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
// version commands, network, compose, run, create, ps, inspect and container go through ziroctl;
// everything else is nerdctl untouched.
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
		{[]string{"create", "--name", "x", "alpine"}, "ZIROCTL: [docker-compat] [create] [--name] [x] [alpine]"},
		{[]string{"ps", "-a", "--format", "{{json .}}"}, "ZIROCTL: [docker-compat] [ps] [-a] [--format] [{{json .}}]"},
		{[]string{"container", "inspect", "--format", "{{json .}}", "abc"}, "ZIROCTL: [docker-compat] [container] [inspect] [--format] [{{json .}}] [abc]"},
		{[]string{"inspect", "abc"}, "ZIROCTL: [docker-compat] [inspect] [abc]"},
		{[]string{"logs", "-n", "10", "abc"}, "NERDCTL: [logs] [-n] [10] [abc]"},
		{[]string{"exec", "abc", "ps"}, "NERDCTL: [exec] [abc] [ps]"},
		{[]string{"images", "--format", "{{json .}}"}, "NERDCTL: [images] [--format] [{{json .}}]"},
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
		// --network-alias: the first becomes the hostname (nerdctl has no alias), before the image only
		{"run -d --network-alias web --network n img", "run -d --hostname=web --network n img", 0},
		{"create --network-alias=web img", "create --hostname=web img", 0},
		{"create --network-alias a --network-alias b img", "create --hostname=a img", 0},
		{"create --hostname h --network-alias a img", "create --hostname h img", 0},
		{"run -d --rm --network-alias a --network-alias b img", "run -d --hostname=a img", 1},
		{"run img tool --network-alias x", "run img tool --network-alias x", 0},
		{"create --rm img", "create --rm img", 0},
		// compose: the subcommand is found behind the global flags and their values
		{"compose -f a.yml pull --ignore-buildable", "compose -f a.yml pull", 0},
		{"compose --env-file e -f a.yml --project-name p pull --ignore-buildable web", "compose --env-file e -f a.yml --project-name p pull web", 0},
		{"compose -f a.yml up -d --wait --remove-orphans", "compose -f a.yml up -d --remove-orphans", 1},
		{"compose up -d --wait-timeout 60 --wait", "compose up -d", 1},
		{"compose up -d --wait-timeout=60", "compose up -d", 0},
		{"compose up -d --wait=true", "compose up -d", 1},
		{"compose -p p up -d", "compose -p p up -d", 0},
		{"compose -f a.yml down --remove-orphans", "compose -f a.yml down --remove-orphans", 0},
		// Coolify's StartService with "connect to docker network": create now, connect, then start
		{"compose --project-directory /w -f /w/docker-compose.yml --project-name u up -d --remove-orphans --force-recreate --build --no-start",
			"compose --project-directory /w -f /w/docker-compose.yml --project-name u create --force-recreate --build", 0},
		{"compose up --no-start --pull always --wait-timeout 30 web db", "compose create --pull always web db", 0},
		{"compose up --no-start --pull=never --quiet-pull -- web", "compose create --pull=never -- web", 0},
		{"compose -p u start", "compose -p u start", 0},
		// Coolify's log drain and compose validation
		{"compose -f f.yml pull --quiet --ignore-pull-failures", "compose -f f.yml pull --quiet", 0},
		{"compose -f x.yml config --no-interpolate --no-path-resolution -q", "compose -f x.yml config -q", 0},
		{"compose -f x.yml config --no-interpolate", "compose -f x.yml config", 1},
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

func TestPlanDockerStepsNerdctlHasNoFlagFor(t *testing.T) {
	now := func() time.Time { return time.Unix(0, 0) }
	p := planDocker(strings.Fields("compose -p u up -d --remove-orphans --build --no-start"), now)
	if p.before == nil || p.ignoreFailure || p.output != nil {
		t.Fatalf("up --no-start --remove-orphans: %+v", p)
	}
	if p := planDocker(strings.Fields("compose -p u up -d --remove-orphans"), now); p.before != nil {
		t.Fatal("nerdctl compose up removes orphans itself: no extra step")
	}
	if p := planDocker(strings.Fields("compose pull --ignore-pull-failures"), now); !p.ignoreFailure {
		t.Fatal("pull --ignore-pull-failures must not fail the script")
	}
	for in, want := range map[string]string{
		"ps -a --format {{.State}}":                    "ps -a --format " + psFormat,
		"container ls --filter name=x --format json":   "ps --filter name=x --format " + psFormat,
		"inspect --format {{.State}} c1 c2":            "inspect c1 c2",
		"container inspect -f {{.Config.OpenStdin}} c": "container inspect c",
		"network inspect coolify -f {{.Containers}}":   "network inspect coolify",
	} {
		p := planDocker(strings.Fields(in), now)
		if got := strings.Join(p.args, " "); got != want || p.output == nil {
			t.Errorf("%s: %q (output %v), want %q", in, got, p.output != nil, want)
		}
	}
	for _, in := range []string{"ps", "ps -a", "ps -q", "ps --format table", "ps -a -q --format {{.ID}}", "logs c"} {
		if p := planDocker(strings.Fields(in), now); p.output != nil || strings.Join(p.args, " ") != in {
			t.Errorf("%s is nerdctl's own output: %q", in, p.args)
		}
	}
}

func TestComposeProject(t *testing.T) {
	env := func(map[string]string) func(string) string { return func(string) string { return "" } }
	for _, c := range []struct {
		globals []string
		env     string
		want    string
	}{
		{[]string{"--project-name", "U-1"}, "", "u-1"},
		{[]string{"-p=abc"}, "", "abc"},
		{[]string{"--project-directory", "/data/My App"}, "", "myapp"},
		{[]string{"-f", "/srv/shop/docker-compose.yml"}, "", "shop"},
		{nil, "fromenv", "fromenv"},
		{nil, "", "wd"},
	} {
		getenv := env(nil)
		if c.env != "" {
			getenv = func(k string) string {
				if k == "COMPOSE_PROJECT_NAME" {
					return c.env
				}
				return ""
			}
		}
		if got := composeProject(c.globals, getenv, "/home/wd"); got != c.want {
			t.Errorf("%v: %q, want %q", c.globals, got, c.want)
		}
	}
}

func TestRemoveComposeOrphans(t *testing.T) {
	var calls []string
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch {
		case args[len(args)-1] == "--services":
			return []byte("web\ndb\n"), nil
		case args[0] == "ps":
			return []byte("a1\tweb\nb2\told-worker\nc3\tdb\nd4\t\n"), nil
		}
		return nil, nil
	}
	if err := removeComposeOrphans([]string{"-f", "/w/c.yml", "--project-name", "u"}, run); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"compose -f /w/c.yml --project-name u config --services",
		`ps -a --filter label=com.docker.compose.project=u --format {{.ID}}{{"\t"}}{{.Label "com.docker.compose.service"}}`,
		"rm -f b2",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	calls = nil
	run2 := func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}
	if err := removeComposeOrphans([]string{"-p", "u"}, run2); err == nil || len(calls) != 1 {
		t.Fatalf("an empty service list must not remove every container: %v %v", err, calls)
	}
}

// nerdctl 2.2.1 `inspect` of a container on two networks, as it prints it.
const nerdctlInspectFixture = `[
    {
        "Id": "3c1f",
        "Created": "2026-11-03T04:57:47.1Z",
        "Path": "/docker-entrypoint.sh",
        "Args": ["nginx", "-g", "daemon off;"],
        "State": {"Status": "running", "Running": true, "Paused": false, "Restarting": false, "Pid": 4242, "ExitCode": 0, "FinishedAt": ""},
        "Image": "docker.io/library/nginx:alpine",
        "Name": "web-u1",
        "HostConfig": {"NetworkMode": "unknown-eth0"},
        "Config": {"Hostname": "web", "AttachStdin": false, "Labels": {"com.docker.compose.service": "web", "nerdctl/networks": "[\"u1\",\"coolify\"]"}, "Image": "nginx"},
        "NetworkSettings": {
            "Ports": {},
            "IPAddress": "10.4.1.2", "IPPrefixLen": 24, "MacAddress": "aa:bb",
            "Networks": {
                "unknown-eth0": {"IPAddress": "10.4.1.2", "IPPrefixLen": 24, "MacAddress": "aa:bb"},
                "unknown-eth1": {"IPAddress": "10.4.0.7", "IPPrefixLen": 24, "MacAddress": "cc:dd"}
            }
        }
    }
]
`

func TestFormatInspectNamesNetworksAndFillsFields(t *testing.T) {
	for format, want := range map[string]string{
		// Coolify StartService: is the container already on the destination network?
		`{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}`: "coolify\nu1\n\n",
		// proxy.php: the networks of coolify-proxy
		`{{json .NetworkSettings.Networks }}`: `{"coolify":{"Aliases":null,"IPAddress":"10.4.0.7","IPPrefixLen":24,"MacAddress":"cc:dd","NetworkID":"coolify"},"u1":{"Aliases":null,"IPAddress":"10.4.1.2","IPPrefixLen":24,"MacAddress":"aa:bb","NetworkID":"u1"}}` + "\n",
		// Terminal.php
		`{{.Config.OpenStdin}}`:                                 "false\n",
		`{{.HostConfig.NetworkMode}}`:                           "u1\n",
		`{{.State.Pid}} {{.Name}}`:                              "4242 web-u1\n",
		`{{index .Config.Labels "com.docker.compose.service"}}`: "web\n",
		`{{upper .State.Status}}`:                               "RUNNING\n",
	} {
		out, err := formatInspect([]byte(nerdctlInspectFixture), format)
		if err != nil || string(out) != want {
			t.Errorf("%s:\n got %q %v\nwant %q", format, out, err, want)
		}
	}
	out, err := formatInspect([]byte(nerdctlInspectFixture), "")
	if err != nil || !strings.HasPrefix(string(out), "[\n") || strings.Contains(string(out), "unknown-eth") {
		t.Fatalf("plain inspect: %v\n%s", err, out)
	}
	// Health is absent until a check ran: never "healthy" (Docker errors on the nil pointer instead).
	if out, _ := formatInspect([]byte(nerdctlInspectFixture), `{{json .State.Health.Status}}`); strings.Contains(string(out), "healthy") {
		t.Fatalf("no health check, yet %q", out)
	}
	// images and other objects are left as they are
	img := `[{"Id":"sha256:1","RepoTags":["nginx:alpine"],"Config":{"Labels":null}}]`
	if out, err := formatInspect([]byte(img), "{{index .RepoTags 0}}"); err != nil || string(out) != "nginx:alpine\n" {
		t.Fatalf("image: %q %v", out, err)
	}
}

func TestFormatNetworkInspect(t *testing.T) {
	raw := `[{"Name":"coolify","Id":"9a","IPAM":{"Config":[{"Subnet":"10.4.0.0/24","Gateway":"10.4.0.1"}]},"Labels":{},"Containers":{"3c1f":{"Name":"web-u1"}}}]`
	run := func(args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "container inspect 3c1f" {
			t.Fatalf("unexpected nerdctl %v", args)
		}
		return []byte(nerdctlInspectFixture), nil
	}
	for format, want := range map[string]string{
		`{{json .Containers}}`:                   `{"3c1f":{"EndpointID":"","IPv4Address":"10.4.0.7/24","IPv6Address":"","MacAddress":"cc:dd","Name":"web-u1"}}` + "\n",
		`{{.EnableIPv6}}`:                        "false\n",
		`{{.Driver}} {{.Scope}} {{.Attachable}}`: "bridge local true\n",
	} {
		out, err := formatNetworkInspect([]byte(raw), format, run)
		if err != nil || string(out) != want {
			t.Errorf("%s:\n got %q %v\nwant %q", format, out, err, want)
		}
	}
	v6 := `[{"Name":"v6","IPAM":{"Config":[{"Subnet":"fd00::/64"}]},"Containers":{}}]`
	if out, _ := formatNetworkInspect([]byte(v6), "{{.EnableIPv6}} {{.Id}}", run); string(out) != "true v6\n" {
		t.Fatalf("ipv6: %q", out)
	}
}

func TestFormatPsHasDockerFields(t *testing.T) {
	created := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
	row := func(name, status, nets string) string {
		labels := `{"com.docker.compose.project":"u1","nerdctl/networks":"` + strings.ReplaceAll(nets, `"`, `\"`) + `","a":"x,y"}`
		return `{"Command":"\"nginx\"","CreatedAt":"` + created.Format(time.RFC3339Nano) + `","ID":"3c1f","Image":"nginx","Platform":"linux","Names":"` + name +
			`","Ports":"","Status":"` + status + `","Runtime":"io.containerd.runc.v2","Size":"","Labels":"ignored"}` + "\t" + labels
	}
	raw := row("coolify-sentinel", "Up 5 minutes", `["coolify"]`) + "\n" + row("old", "Exited (0) 2 minutes ago", `["a","b"]`) + "\n" + row("new", "Created", `[]`) + "\n"
	now := created.Add(90 * time.Minute)
	for format, want := range map[string]string{
		// CheckAndStartSentinelJob
		`{{.State}} {{.Status}}`:                                 "running Up 5 minutes\nexited Exited (0) 2 minutes ago\ncreated Created\n",
		`{{.Names}} {{.Networks}}`:                               "coolify-sentinel coolify\nold a,b\nnew \n",
		`{{.Label "com.docker.compose.project"}} {{.Label "a"}}`: "u1 x,y\nu1 x,y\nu1 x,y\n",
		`{{.RunningFor}}`:                                        "2 hours ago\n2 hours ago\n2 hours ago\n",
	} {
		out, err := formatPs([]byte(raw), format, now)
		if err != nil || string(out) != want {
			t.Errorf("%s:\n got %q %v\nwant %q", format, out, err, want)
		}
	}
	out, err := formatPs([]byte(raw), "json", now)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(string(out), "\n", 2)[0]), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"State", "Status", "Names", "Networks", "RunningFor", "CreatedAt", "Labels", "Mounts", "LocalVolumes"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("ps JSON has no %s: %v", k, doc)
		}
	}
	if doc["Labels"] != "a=x,y,com.docker.compose.project=u1,nerdctl/networks=[\"coolify\"]" || doc["CreatedAt"] != "2026-11-03 04:00:00 +0000 UTC" {
		t.Errorf("labels/created: %v %v", doc["Labels"], doc["CreatedAt"])
	}
	if out, _ := formatPs(nil, "{{.ID}}", now); len(out) != 0 {
		t.Fatalf("no containers, no output: %q", out)
	}
}

func TestDockerState(t *testing.T) {
	for in, want := range map[string]string{"Up 3 seconds": "running", "Up 1 hour (Paused)": "paused", "Created": "created",
		"Exited (137) 1 second ago": "exited", "Restarting (1) 2 seconds ago": "restarting", "Removing": "removing"} {
		if got := dockerState(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

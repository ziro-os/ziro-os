package cmd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func post(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec
}

func (f *fakeDocker) last() string { return f.calls[len(f.calls)-1] }

const createBody = `{"Image":"nginx:1","Cmd":["-g","daemon off;"],"Env":["A=1","B=two words"],
 "Labels":{"traefik.enable":"true","a":"b"},
 "HostConfig":{"NetworkMode":"coolify","PortBindings":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},
  "Binds":["data:/data","/etc/x:/x:ro"],"RestartPolicy":{"Name":"unless-stopped"},"Memory":268435456,"NanoCpus":500000000,"CapAdd":["NET_ADMIN"]},
 "NetworkingConfig":{"EndpointsConfig":{"coolify":{"Aliases":["web"]}}}}`

func TestDockerAPIContainerCreate(t *testing.T) {
	f := &fakeDocker{out: map[string]string{}}
	want := "create --name=web --env=A=1 --env=B=two words --label=a=b --label=traefik.enable=true --network-alias=web --network=coolify " +
		"--publish=0.0.0.0:8080:80/tcp --volume=data:/data --volume=/etc/x:/x:ro --restart=unless-stopped --memory=268435456 --cpus=0.500 " +
		"--cap-add=NET_ADMIN -- nginx:1 -g daemon off;"
	f.out[want] = "d0c0ffee\n"
	h := f.api().handler()
	r := post(h, "POST", "/v1.43/containers/create?name=web", createBody)
	var resp map[string]any
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &resp) != nil || resp["Id"] != "d0c0ffee" {
		t.Fatalf("create: %d %s\ncalls: %q", r.Code, r.Body, f.calls)
	}
	if f.last() != want {
		t.Fatalf("args:\n got %q\nwant %q", f.last(), want)
	}

	// The entrypoint array: its first word is the entrypoint, the rest leads the command.
	post(h, "POST", "/containers/create", `{"Image":"alpine","Entrypoint":["/bin/sh","-c"],"Cmd":["echo hi"]}`)
	if f.last() != "create --entrypoint=/bin/sh -- alpine -c echo hi" {
		t.Fatalf("entrypoint: %q", f.last())
	}

	// A taken name is a conflict; a missing image is a 404.
	f.err = map[string]error{
		"create --name=dup -- alpine": errors.New(`name "dup" is already in use`),
		"create -- missing":           errors.New("failed to resolve reference: not found"),
	}
	if r := post(h, "POST", "/containers/create?name=dup", `{"Image":"alpine"}`); r.Code != 409 {
		t.Fatalf("conflict: %d", r.Code)
	}
	if r := post(h, "POST", "/containers/create", `{"Image":"missing"}`); r.Code != 404 {
		t.Fatalf("missing image: %d", r.Code)
	}
}

func TestDockerAPIContainerCreateRejectsUnsafeInput(t *testing.T) {
	f := &fakeDocker{}
	h := f.api().handler()
	for name, c := range map[string]struct{ q, body string }{
		"option as image":     {"", `{"Image":"--privileged"}`},
		"option as name":      {"?name=-v", `{"Image":"alpine"}`},
		"image with space":    {"", `{"Image":"alpine --rm"}`},
		"env key with equals": {"", `{"Image":"alpine","Env":["=x"]}`},
		"env key with dash":   {"", `{"Image":"alpine","Env":["--x=1"]}`},
		"label key equals":    {"", `{"Image":"alpine","Labels":{"a=b":"c"}}`},
		"bad port":            {"", `{"Image":"alpine","HostConfig":{"PortBindings":{"80":[{}]}}}`},
		"port range":          {"", `{"Image":"alpine","HostConfig":{"PortBindings":{"99999/tcp":[{}]}}}`},
		"bad host ip":         {"", `{"Image":"alpine","HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"x;y"}]}}}`},
		"bind relative dst":   {"", `{"Image":"alpine","HostConfig":{"Binds":["a:b"]}}`},
		"bind too many parts": {"", `{"Image":"alpine","HostConfig":{"Binds":["a:/b:ro:x"]}}`},
		"bind option junk":    {"", `{"Image":"alpine","HostConfig":{"Binds":["/a:/b:ro;rm"]}}`},
		"bad network mode":    {"", `{"Image":"alpine","HostConfig":{"NetworkMode":"-x"}}`},
		"bad alias":           {"", `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"n":{"Aliases":["a b"]}}}}`},
		"bad restart":         {"", `{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"sometimes"}}}`},
		"negative memory":     {"", `{"Image":"alpine","HostConfig":{"Memory":-1}}`},
		"bad cap":             {"", `{"Image":"alpine","HostConfig":{"CapAdd":["all; x"]}}`},
		"bad dns":             {"", `{"Image":"alpine","HostConfig":{"Dns":["not-an-ip"]}}`},
		"bad extra host":      {"", `{"Image":"alpine","HostConfig":{"ExtraHosts":["a b:1.2.3.4"]}}`},
		"bad sysctl":          {"", `{"Image":"alpine","HostConfig":{"Sysctls":{"a b":"1"}}}`},
		"not json":            {"", `{`},
	} {
		if r := post(h, "POST", "/containers/create"+c.q, c.body); r.Code != 400 {
			t.Errorf("%s: %d, want 400 (%s)", name, r.Code, r.Body)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("unsafe input reached nerdctl: %q", f.calls)
	}
}

func TestDockerAPIImages(t *testing.T) {
	f := &fakeDocker{out: map[string]string{
		"images --format {{.Repository}}:{{.Tag}}": "nginx:1\nalpine:latest\n<none>:<none>\nnginx:1\n",
		"image inspect nginx:1 alpine:latest":      `[{"ID":"sha256:aa","RepoTags":["nginx:1"],"Created":"2026-10-20T10:00:00Z","Size":100},{"ID":"sha256:bb","RepoTags":["alpine:latest"],"Created":"2026-10-21T10:00:00Z","Size":7}]`,
		"image inspect docker.io/library/nginx:1":  `[{"ID":"sha256:aa","Os":"linux"}]`,
		"pull docker.io/library/alpine:3.20":       "",
	}, err: map[string]error{"pull docker.io/library/gone:1": errors.New("not found: docker.io/library/gone:1")}}
	h := f.api().handler()
	var list []map[string]any
	r := do(h, "GET", "/images/json")
	if json.Unmarshal(r.Body.Bytes(), &list) != nil || len(list) != 2 || list[0]["Id"] != "sha256:aa" || list[0]["Created"].(float64) != 1792490400 || list[1]["Size"].(float64) != 7 {
		t.Fatalf("images: %d %s", r.Code, r.Body)
	}
	if r := do(h, "GET", "/images/docker.io/library/nginx:1/json"); r.Code != 200 || !strings.Contains(r.Body.String(), `"Os":"linux"`) {
		t.Fatalf("inspect with slashes: %d %s", r.Code, r.Body)
	}
	if r := do(h, "GET", "/images/--all/json"); r.Code == 200 {
		t.Fatal("option accepted as an image name")
	}
	// pull: progress lines, the tag joined to a bare name, and the failure inside the stream.
	r = post(h, "POST", "/images/create?fromImage=docker.io/library/alpine&tag=3.20", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Downloaded newer image for docker.io/library/alpine:3.20") {
		t.Fatalf("pull: %d %s", r.Code, r.Body)
	}
	r = post(h, "POST", "/images/create?fromImage=docker.io/library/gone:1", "")
	if !strings.Contains(r.Body.String(), `"errorDetail"`) {
		t.Fatalf("pull failure must be in the stream: %s", r.Body)
	}
	for _, bad := range []string{"fromImage=--rm", "fromImage=a%20b", "fromImage=", "fromImage=alpine&platform=x%20y"} {
		if r := post(h, "POST", "/images/create?"+bad, ""); r.Code != 400 {
			t.Errorf("%s: %d", bad, r.Code)
		}
	}
}

func readFrames(t *testing.T, b []byte) (out []string) {
	t.Helper()
	for len(b) > 0 {
		if len(b) < 8 {
			t.Fatalf("short frame header: %q", b)
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		out = append(out, string('0'+rune(b[0]))+":"+string(b[8:8+n]))
		b = b[8+n:]
	}
	return out
}

func TestDockerAPILogs(t *testing.T) {
	f := &fakeDocker{out: map[string]string{
		"inspect web": `[{"Id":"w","Config":{"Tty":false}}]`,
		"inspect tt":  `[{"Id":"t","Config":{"Tty":true}}]`,
	}}
	a := f.api()
	var got []string
	a.stream = func(_ context.Context, args []string, stdout, stderr io.Writer) error {
		got = args
		stdout.Write([]byte("hello\n"))
		stderr.Write([]byte("oops\n"))
		return nil
	}
	h := a.handler()
	r := do(h, "GET", "/v1.43/containers/web/logs?stdout=1&stderr=1&follow=1&tail=10&timestamps=1")
	if r.Code != 200 || r.Header().Get("Content-Type") != "application/vnd.docker.multiplexed-stream" {
		t.Fatalf("logs: %d %v", r.Code, r.Header())
	}
	if strings.Join(got, " ") != "logs --follow --timestamps --tail=10 web" {
		t.Fatalf("args %q", got)
	}
	if fr := readFrames(t, r.Body.Bytes()); strings.Join(fr, "|") != "1:hello\n|2:oops\n" {
		t.Fatalf("frames %q", fr)
	}
	// stdout only: stderr is dropped, and a terminal container is a raw stream.
	r = do(h, "GET", "/containers/web/logs?stdout=true")
	if fr := readFrames(t, r.Body.Bytes()); strings.Join(fr, "|") != "1:hello\n" {
		t.Fatalf("stdout only: %q", fr)
	}
	r = do(h, "GET", "/containers/tt/logs?stdout=1")
	if r.Header().Get("Content-Type") != "application/vnd.docker.raw-stream" || r.Body.String() != "hello\n" {
		t.Fatalf("tty: %v %q", r.Header(), r.Body)
	}
	for _, bad := range []string{"/containers/web/logs", "/containers/web/logs?stdout=1&tail=-3", "/containers/web/logs?stdout=1&tail=x"} {
		if r := do(h, "GET", bad); r.Code != 400 {
			t.Errorf("%s: %d", bad, r.Code)
		}
	}
	if r := do(h, "GET", "/containers/-f/logs?stdout=1"); r.Code != 404 {
		t.Errorf("option as a container: %d", r.Code)
	}
}

func TestDockerAPIVolumesAndNetworks(t *testing.T) {
	f := &fakeDocker{out: map[string]string{
		"volume ls -q":                   "data\n",
		"volume inspect data":            `[{"Name":"data","Driver":"local","Mountpoint":"/var/lib/x"}]`,
		"volume create --label=a=b data": "data\n",
		"network create --label=x=y --subnet=10.9.0.0/24 --gateway=10.9.0.1 coolify": "n123\n",
	}}
	h := f.api().handler()
	var vl struct{ Volumes []map[string]any }
	r := do(h, "GET", "/volumes")
	if json.Unmarshal(r.Body.Bytes(), &vl) != nil || len(vl.Volumes) != 1 || vl.Volumes[0]["Name"] != "data" {
		t.Fatalf("volumes: %s", r.Body)
	}
	if r := post(h, "POST", "/volumes/create", `{"Name":"data","Labels":{"a":"b"}}`); r.Code != 201 || !strings.Contains(r.Body.String(), `"Mountpoint"`) {
		t.Fatalf("volume create: %d %s", r.Code, r.Body)
	}
	if r := do(h, "GET", "/volumes/data"); r.Code != 200 {
		t.Fatalf("volume inspect: %d", r.Code)
	}
	if r := do(h, "DELETE", "/volumes/data?force=1"); r.Code != 204 || f.last() != "volume rm --force data" {
		t.Fatalf("volume rm: %d %q", r.Code, f.last())
	}
	for _, c := range []struct{ target, body string }{
		{"/volumes/create", `{"Name":""}`}, {"/volumes/create", `{"Name":"-x"}`},
		{"/volumes/create", `{"Name":"a","Driver":"nfs"}`}, {"/volumes/create", `{"Name":"a","Labels":{"k=v":"x"}}`},
		{"/networks/create", `{"Name":"-x"}`}, {"/networks/create", `{"Name":"n","Driver":"overlay"}`},
		{"/networks/create", `{"Name":"n","IPAM":{"Config":[{"Subnet":"nope"}]}}`}, {"/networks/create", `{"Name":"n","IPAM":{"Config":[{"Gateway":"x y"}]}}`},
	} {
		if r := post(h, "POST", c.target, c.body); r.Code != 400 {
			t.Errorf("%s %s: %d", c.target, c.body, r.Code)
		}
	}
	r = post(h, "POST", "/networks/create", `{"Name":"coolify","Driver":"bridge","Labels":{"x":"y"},"IPAM":{"Config":[{"Subnet":"10.9.0.0/24","Gateway":"10.9.0.1"}]}}`)
	var nw map[string]string
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &nw) != nil || nw["Id"] != "n123" {
		t.Fatalf("network create: %d %s", r.Code, r.Body)
	}
	if r := do(h, "DELETE", "/networks/coolify"); r.Code != 204 || f.last() != "network rm coolify" {
		t.Fatalf("network rm: %d %q", r.Code, f.last())
	}
	// every one of these is audited, and exec is still a clear 501
	if r := post(h, "POST", "/containers/web/exec", `{}`); r.Code != 501 {
		t.Fatalf("exec: %d", r.Code)
	}
	joined := strings.Join(f.logs, "\n")
	for _, want := range []string{"DELETE /volumes/data|", "POST /networks/create|", "DELETE /networks/coolify|", "POST /containers/web/exec|"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %q:\n%s", want, joined)
		}
	}
}

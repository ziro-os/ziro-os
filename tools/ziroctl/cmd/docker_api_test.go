package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeDocker struct {
	mu     sync.Mutex
	out    map[string]string // joined args -> stdout
	err    map[string]error
	calls  []string
	logs   []string // audit entries "action|target|ok"
	actors []string // who each audit entry names
}

func (f *fakeDocker) api() *dockerAPI {
	return &dockerAPI{
		run: func(_ context.Context, args ...string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			k := strings.Join(args, " ")
			f.calls = append(f.calls, k)
			if e := f.err[k]; e != nil {
				return nil, e
			}
			return []byte(f.out[k]), nil
		},
		audit: func(actor, action, target string, err error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.actors = append(f.actors, actor)
			f.logs = append(f.logs, action+"|"+target+"|"+map[bool]string{true: "ok", false: "err"}[err == nil])
		},
	}
}

const dockerInspectTwo = `[
 {"Id":"aaa111","Created":"2026-10-20T10:00:00.5Z","Path":"nginx","Args":["-g","daemon off;"],"Name":"/web","Image":"sha256:img1",
  "State":{"Status":"running","Running":true},"Config":{"Image":"nginx:1","Labels":{"traefik.enable":"true"}},
  "HostConfig":{"NetworkMode":"coolify"},
  "NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}],"443/tcp":null},"Networks":{"coolify":{}}}},
 {"Id":"bbb222","Created":"2026-10-20T11:00:00Z","Path":"sh","Name":"/job","Image":"sha256:img2",
  "State":{"Status":"exited","Running":false},"Config":{"Image":"busybox"},"HostConfig":{},"NetworkSettings":{}}
]`

func do(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestDockerAPIPingAndVersion(t *testing.T) {
	h := (&fakeDocker{}).api().handler()
	for _, m := range []string{"GET", "HEAD"} {
		r := do(h, m, "/_ping")
		if r.Code != 200 || r.Header().Get("Api-Version") != dockerAPIVersion || r.Header().Get("Ostype") != "linux" {
			t.Fatalf("%s ping: %d %v", m, r.Code, r.Header())
		}
	}
	if b := do(h, "GET", "/_ping").Body.String(); b != "OK" {
		t.Fatalf("ping body %q", b)
	}
	r := do(h, "GET", "/v1.43/version") // clients prefix the API version
	var v map[string]any
	if json.Unmarshal(r.Body.Bytes(), &v) != nil || v["ApiVersion"] != dockerAPIVersion || v["Os"] != "linux" {
		t.Fatalf("version: %d %s", r.Code, r.Body)
	}
}

func TestDockerAPIContainers(t *testing.T) {
	f := &fakeDocker{out: map[string]string{
		"ps -q --no-trunc -a":            "aaa111\nbbb222\n",
		"ps -q --no-trunc":               "aaa111\n",
		"inspect aaa111 bbb222":          dockerInspectTwo,
		"inspect aaa111":                 "[" + strings.SplitN(dockerInspectTwo[1:], "},\n {", 2)[0] + "}]",
		"network ls --format {{.Name}}":  "bridge\ncoolify\n",
		"network inspect bridge coolify": `[{"Name":"bridge"},{"Name":"coolify"}]`,
		"network inspect coolify":        `[{"Name":"coolify","Id":"n1"}]`,
	}}
	h := f.api().handler()

	var list []map[string]any
	r := do(h, "GET", "/containers/json?all=1")
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list: %v %s", err, r.Body)
	}
	web := list[0]
	if web["Id"] != "aaa111" || web["Image"] != "nginx:1" || web["State"] != "running" || web["Status"] != "Up" ||
		web["Command"] != "nginx -g daemon off;" || web["Created"].(float64) != 1792490400 ||
		web["Names"].([]any)[0] != "/web" || web["Labels"].(map[string]any)["traefik.enable"] != "true" {
		t.Fatalf("summary: %v", web)
	}
	if ports := web["Ports"].([]any); len(ports) != 2 {
		t.Fatalf("ports: %v", ports)
	}
	if list[1]["Status"] != "Exited" || list[1]["Labels"] == nil {
		t.Fatalf("exited summary: %v", list[1])
	}

	// A running-only listing, and a status filter on a full listing.
	if r := do(h, "GET", "/containers/json"); !strings.Contains(strings.Join(f.calls, ";"), "ps -q --no-trunc;") && r.Code != 200 {
		t.Fatalf("running list: %d", r.Code)
	}
	r = do(h, "GET", `/containers/json?all=1&filters={"status":["exited"]}`)
	list = nil
	if json.Unmarshal(r.Body.Bytes(), &list); len(list) != 1 || list[0]["Id"] != "bbb222" {
		t.Fatalf("filtered: %s", r.Body)
	}
	if r := do(h, "GET", "/containers/json?filters=%7B"); r.Code != 400 {
		t.Fatalf("bad filters: %d", r.Code)
	}

	// Inspect is the runtime's own document.
	r = do(h, "GET", "/containers/aaa111/json")
	var one map[string]any
	if json.Unmarshal(r.Body.Bytes(), &one) != nil || one["Id"] != "aaa111" {
		t.Fatalf("inspect: %d %s", r.Code, r.Body)
	}

	if r := do(h, "GET", "/networks"); r.Code != 200 || !strings.Contains(r.Body.String(), "coolify") {
		t.Fatalf("networks: %d %s", r.Code, r.Body)
	}
	if r := do(h, "GET", "/networks/coolify"); !strings.HasPrefix(strings.TrimSpace(r.Body.String()), `{"Name":"coolify"`) {
		t.Fatalf("network: %s", r.Body)
	}
}

func TestDockerAPIRefusesUnsafeNames(t *testing.T) {
	f := &fakeDocker{}
	h := f.api().handler()
	for _, id := range []string{"-rf", "a%2Fb", "..", "a;b", "x%20--all"} {
		for _, c := range []struct{ m, p string }{{"GET", "/containers/" + id + "/json"}, {"POST", "/containers/" + id + "/start"}, {"DELETE", "/containers/" + id}, {"GET", "/networks/" + id}} {
			if r := do(h, c.m, c.p); r.Code == 200 || r.Code == 204 {
				t.Errorf("%s %s accepted (%d)", c.m, c.p, r.Code)
			}
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("an unsafe name reached nerdctl: %v", f.calls)
	}
}

func TestDockerAPILifecycleIsAudited(t *testing.T) {
	f := &fakeDocker{err: map[string]error{"start gone": errors.New("no such container: gone")}}
	h := f.api().handler()
	for _, c := range []struct {
		m, p string
		code int
		call string
	}{
		{"POST", "/v1.43/containers/web/start", 204, "start web"},
		{"POST", "/containers/web/stop?t=5", 204, "stop --time 5 web"},
		{"POST", "/containers/web/restart", 204, "restart web"},
		{"POST", "/containers/web/kill?signal=SIGKILL", 204, "kill --signal SIGKILL web"},
		{"DELETE", "/containers/web?force=1", 204, "rm --force web"},
		{"POST", "/containers/gone/start", 404, ""},
		{"POST", "/containers/web/stop?t=x", 400, ""},
		{"POST", "/containers/web/kill?signal=-9", 400, ""},
		{"POST", "/containers/web/exec", 501, ""},
		{"GET", "/swarm", 501, ""},
	} {
		r := do(h, c.m, c.p)
		if r.Code != c.code {
			t.Errorf("%s %s: %d, want %d (%s)", c.m, c.p, r.Code, c.code, r.Body)
		}
		if c.call != "" && f.calls[len(f.calls)-1] != c.call {
			t.Errorf("%s ran %q, want %q", c.p, f.calls[len(f.calls)-1], c.call)
		}
	}
	// every mutating call is in the audit log, failures marked; reads are not
	if len(f.logs) != 9 || f.logs[0] != "POST /containers/web/start||ok" || !strings.HasSuffix(f.logs[5], "|err") || !strings.HasSuffix(f.logs[8], "|err") {
		t.Fatalf("audit: %q", f.logs)
	}
	var msg map[string]string
	r := do(h, "POST", "/containers/web/exec")
	if json.Unmarshal(r.Body.Bytes(), &msg) != nil || !strings.Contains(msg["message"], "/containers/web/exec") {
		t.Fatalf("501 must name the route: %s", r.Body)
	}
}

func TestDiffContainers(t *testing.T) {
	now := time.Unix(1000, 0)
	prev := map[string]ctrState{"a": {Name: "a", Image: "i", Running: true}, "b": {Name: "b", Running: true}, "c": {Name: "c"}, "d": {Name: "d"}}
	cur := map[string]ctrState{"a": {Name: "a", Image: "i"}, "b": {Name: "b", Running: true}, "c": {Name: "c", Running: true}, "e": {Name: "e", Running: true}}
	var got []string
	for _, e := range diffContainers(prev, cur, now) {
		got = append(got, e.ID+":"+e.Action)
		if e.Type != "container" || e.Time != 1000 || e.Actor.Attributes["name"] != e.ID {
			t.Errorf("event shape: %+v", e)
		}
	}
	if want := "a:die c:start d:destroy e:start"; strings.Join(got, " ") != want {
		t.Fatalf("events %v, want %s", got, want)
	}
	if got := diffContainers(map[string]ctrState{"x": {Running: true}}, map[string]ctrState{}, now); len(got) != 2 || got[0].Action != "die" || got[1].Action != "destroy" {
		t.Fatalf("a removed running container dies then is destroyed: %+v", got)
	}
}

func TestDockerAPIEventsStream(t *testing.T) {
	old := dockerEventPoll
	dockerEventPoll = 10 * time.Millisecond
	t.Cleanup(func() { dockerEventPoll = old })
	var mu sync.Mutex
	running, gone := false, false
	d := &dockerAPI{audit: func(string, string, string, error) {}, run: func(_ context.Context, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if gone {
			return nil, nil // no containers
		}
		if args[0] == "ps" {
			return []byte("aaa111\n"), nil
		}
		st := map[bool]string{true: `{"Status":"running","Running":true}`, false: `{"Status":"exited","Running":false}`}[running]
		return []byte(`[{"Id":"aaa111","Name":"/web","State":` + st + `,"Config":{"Image":"nginx"}}]`), nil
	}}
	srv := httptest.NewServer(d.handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	mu.Lock()
	running = true
	mu.Unlock()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var e dockerEvent
	if json.Unmarshal([]byte(line), &e) != nil || e.Action != "start" || e.Actor.Attributes["name"] != "web" || e.Actor.Attributes["image"] != "nginx" {
		t.Fatalf("event: %s", line)
	}
	// The container is removed while the stream is open: die, then destroy.
	mu.Lock()
	gone = true
	mu.Unlock()
	rd := bufio.NewReader(resp.Body)
	for _, want := range []string{"die", "destroy"} {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for %s: %v", want, err)
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Action != want {
			t.Fatalf("want %s, got %s", want, line)
		}
	}
}

func TestListenDockerSock(t *testing.T) {
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0600)
	if _, err := listenDockerSock(file); err == nil {
		t.Fatal("replaced a regular file")
	}
	sock := filepath.Join(dir, "d.sock")
	ln, err := listenDockerSock(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false) // leave a stale socket behind, as a crash does
	ln.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatal("no stale socket to replace")
	}
	ln, err = listenDockerSock(sock)
	if err != nil {
		t.Fatalf("a stale socket must be replaced: %v", err)
	}
	ln.Close()
}

func TestLinkDockerSock(t *testing.T) {
	root, err := os.MkdirTemp("", "dl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	run, varRun := filepath.Join(root, "run"), filepath.Join(root, "var", "run")
	os.MkdirAll(run, 0o755)
	os.MkdirAll(varRun, 0o755)
	sock, link := filepath.Join(run, "docker.sock"), filepath.Join(varRun, "docker.sock")
	if err := linkDockerSock(sock, link); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(link); got != sock {
		t.Fatalf("link -> %q", got)
	}
	if err := linkDockerSock(sock, link); err != nil { // a second start replaces its own link
		t.Fatal(err)
	}
	// A socket nobody listens on (left by a crashed daemon) is replaced; a live one is not.
	os.Remove(link)
	ln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	if err := linkDockerSock(sock, link); err == nil {
		t.Fatal("replaced a socket that is in use")
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if err := linkDockerSock(sock, link); err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	if got, _ := os.Readlink(link); got != sock {
		t.Fatalf("link -> %q", got)
	}
	// An empty directory (a bind mount of the missing path) goes; one with content stays.
	os.Remove(link)
	os.Mkdir(link, 0o755)
	if err := linkDockerSock(sock, link); err != nil {
		t.Fatalf("an empty directory was not replaced: %v", err)
	}
	os.Remove(link)
	os.MkdirAll(filepath.Join(link, "x"), 0o755)
	if err := linkDockerSock(sock, link); err == nil {
		t.Fatal("removed a directory with content")
	}
	os.RemoveAll(link)
	os.WriteFile(link, []byte("data"), 0o600)
	if err := linkDockerSock(sock, link); err == nil {
		t.Fatal("replaced a regular file with content")
	}
	// /var/run -> /run: nothing to do, and no link to itself
	os.Remove(link)
	os.RemoveAll(varRun)
	os.Symlink(run, varRun)
	if err := linkDockerSock(sock, filepath.Join(varRun, "docker.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("created a socket path")
	}
}

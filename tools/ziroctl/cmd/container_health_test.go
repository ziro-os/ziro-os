package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthSchedulerFollowsTheContainersSchedule(t *testing.T) {
	s := newHealthScheduler()
	t0 := time.Unix(1000, 0)
	hc := healthConfig{Test: []string{"CMD", "true"}, Interval: 30 * time.Second, StartPeriod: 20 * time.Second}
	tg := []healthTarget{{ID: "a", Pid: 10, HC: hc}}
	if got := s.due(t0, tg); len(got) != 0 {
		t.Fatal("the first check waits for an interval, as in Docker")
	}
	// in the start period the start interval (5s) applies, so a ready service turns healthy soon
	if got := s.due(t0.Add(5*time.Second), tg); len(got) != 1 {
		t.Fatal("start-period check not due")
	}
	if got := s.due(t0.Add(6*time.Second), tg); len(got) != 0 {
		t.Fatal("a running check is not started twice")
	}
	s.done("a", hc, t0.Add(6*time.Second))
	if got := s.due(t0.Add(10*time.Second), tg); len(got) != 0 {
		t.Fatal("too early")
	}
	if got := s.due(t0.Add(11*time.Second), tg); len(got) != 1 {
		t.Fatal("second start-period check not due")
	}
	s.done("a", hc, t0.Add(25*time.Second)) // past the start period: the interval
	if got := s.due(t0.Add(50*time.Second), tg); len(got) != 0 {
		t.Fatal("after the start period the interval applies")
	}
	if got := s.due(t0.Add(56*time.Second), tg); len(got) != 1 {
		t.Fatal("interval check not due")
	}
	// a restart (new pid) starts the schedule again; a removed container is dropped
	tg[0].Pid = 11
	if got := s.due(t0.Add(57*time.Second), tg); len(got) != 0 {
		t.Fatal("restarted container: schedule from the start")
	}
	s.due(t0.Add(58*time.Second), nil)
	if len(s.entries) != 0 {
		t.Fatal("a container that is gone keeps no state")
	}
	// defaults: 30s interval when none is set
	if d := (healthConfig{}).withDefaults(); d.Interval != 30*time.Second || d.Retries != 3 || d.Timeout != 30*time.Second {
		t.Fatalf("defaults: %+v", d)
	}
	if (healthConfig{Test: []string{"NONE"}}).enabled() || !(healthConfig{Test: []string{"CMD-SHELL", "x"}}).enabled() {
		t.Fatal("NONE disables a check")
	}
}

const composeConfigFixture = `name: svc1
services:
  db:
    image: postgres:17
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 1m30s
  cache:
    image: redis
    healthcheck:
      test: redis-cli ping
  app:
    image: app
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
  worker:
    image: app
    depends_on: [app]
    healthcheck:
      disable: true
`

func TestParseComposeHealth(t *testing.T) {
	p, err := parseComposeHealth([]byte(composeConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "svc1" || strings.Join(p.Services, ",") != "db,cache,app,worker" {
		t.Fatalf("project: %+v", p)
	}
	db := p.Health["db"]
	if strings.Join(db.Test, "|") != "CMD-SHELL|pg_isready -U postgres" || db.Interval != 5*time.Second || db.Timeout != 3*time.Second ||
		db.Retries != 10 || db.StartPeriod != 90*time.Second {
		t.Fatalf("db: %+v", db)
	}
	if strings.Join(p.Health["cache"].Test, "|") != "CMD-SHELL|redis-cli ping" || p.Health["worker"].enabled() {
		t.Fatalf("cache/worker: %+v %+v", p.Health["cache"], p.Health["worker"])
	}
	if p.Depends["app"]["db"] != "service_healthy" || p.Depends["worker"]["app"] != "service_started" || !p.needsOrderedStart() {
		t.Fatalf("depends: %v", p.Depends)
	}
	// the label is nerdctl's Healthcheck JSON (durations in nanoseconds)
	b, _ := json.Marshal(db)
	if string(b) != `{"Test":["CMD-SHELL","pg_isready -U postgres"],"Interval":5000000000,"Timeout":3000000000,"Retries":10,"StartPeriod":90000000000}` {
		t.Fatalf("label: %s", b)
	}
	order, err := composeStartOrder(p, nil)
	if err != nil || strings.Join(order, ",") != "db,cache,app,worker" {
		t.Fatalf("order %v %v", order, err)
	}
	order, _ = composeStartOrder(p, []string{"worker"})
	if strings.Join(order, ",") != "db,cache,app,worker" {
		t.Fatalf("a named service brings its dependencies: %v", order)
	}
	cyc, _ := parseComposeHealth([]byte("services:\n  a:\n    depends_on: [b]\n  b:\n    depends_on: [a]\n"))
	if _, err := composeStartOrder(cyc, nil); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
	plain, _ := parseComposeHealth([]byte("services:\n  web:\n    image: nginx\n"))
	if plain.needsOrderedStart() || len(plain.Health) != 0 {
		t.Fatal("a plain file keeps nerdctl's own up")
	}
}

func TestComposeUpFlags(t *testing.T) {
	svcs, detached, wait, timeout := composeUpFlags(strings.Fields("-d --wait --wait-timeout 180 --pull always web db"))
	if !detached || !wait || timeout != 180*time.Second || strings.Join(svcs, ",") != "web,db" {
		t.Fatalf("%v %v %v %v", svcs, detached, wait, timeout)
	}
	if _, d, w, _ := composeUpFlags(strings.Fields("--detach --wait=false")); !d || w {
		t.Fatal("--wait=false")
	}
}

func TestPlanDockerNativeCommands(t *testing.T) {
	now := time.Now
	if p := planDocker(strings.Fields("network connect --alias web coolify web"), now); p.native == nil {
		t.Fatal("network connect is done by ziroctl")
	}
	if p := planDocker(strings.Fields("network disconnect coolify web"), now); p.native == nil {
		t.Fatal("network disconnect is done by ziroctl")
	}
	if p := planDocker(strings.Fields("network connect --ip 1.2.3.4 n c"), now); p.native == nil || p.native() == nil {
		t.Fatal("--ip is refused with a clear error")
	}
	if p := planDocker(strings.Fields("compose -p u up -d --wait --remove-orphans"), now); p.native == nil || len(p.notes) != 0 {
		t.Fatalf("up -d goes through the health-aware start: %+v", p.notes)
	}
	if p := planDocker(strings.Fields("compose -p u up"), now); p.native != nil {
		t.Fatal("an attached up is nerdctl's (it streams the logs)")
	}
	for _, in := range []string{"compose -p u create", "compose -p u up -d --no-start"} {
		if p := planDocker(strings.Fields(in), now); p.after == nil || p.native != nil {
			t.Errorf("%s: health labels after nerdctl", in)
		}
	}
	if p := planDocker(strings.Fields("compose -p u ps"), now); p.after != nil || p.native != nil {
		t.Fatal("other compose commands are nerdctl's")
	}
}

func TestNetworkForAddress(t *testing.T) {
	confs := cniNetworks(writeConfs(t, map[string]string{"u1": "10.4.1.0/24", "coolify": "10.4.0.0/24"}))
	if got := networkForAddress("10.4.0.7", []string{"u1", "coolify"}, confs); got != "coolify" {
		t.Fatal(got)
	}
	if got := networkForAddress("10.4.0.7", []string{"u1"}, confs); got != "" {
		t.Fatalf("not one of the container's networks: %q", got)
	}
	// after a disconnect in the middle, eth2 is still named by its address, not by its index
	old := cniConfigs
	cniConfigs = func() []cniNetwork { return confs }
	defer func() { cniConfigs = old }()
	raw := `[{"Id":"x","State":{},"Config":{"Labels":{"nerdctl/networks":"[\"u1\",\"coolify\"]"}},"NetworkSettings":{"Networks":{"unknown-eth0":{"IPAddress":"10.4.1.2"},"unknown-eth2":{"IPAddress":"10.4.0.9"}}}}]`
	out, err := formatInspect([]byte(raw), `{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}`)
	if err != nil || string(out) != "coolify u1 \n" {
		t.Fatalf("%q %v", out, err)
	}
}

func writeConfs(t *testing.T, nets map[string]string) string {
	dir := t.TempDir()
	for name, subnet := range nets {
		os.WriteFile(filepath.Join(dir, "nerdctl-"+name+".conflist"), []byte(`{"name":"`+name+`","plugins":[{"type":"bridge","ipam":{"type":"host-local","ranges":[[{"subnet":"`+subnet+`"}]]}}]}`), 0o644)
	}
	return dir
}

func TestDockerAPINetworkConnect(t *testing.T) {
	f := &fakeDocker{}
	api := f.api()
	var got []string
	api.netOp = func(_ context.Context, connect bool, op dockerNetOp) error {
		got = append(got, map[bool]string{true: "connect", false: "disconnect"}[connect]+" "+op.Network+" "+op.Container+" "+strings.Join(op.Aliases, ",")+map[bool]string{true: " force"}[op.Force])
		if op.Container == "dup" {
			return errors.New("endpoint with name dup already exists in network coolify")
		}
		return nil
	}
	h := api.handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rec
	}
	if r := post("/v1.43/networks/coolify/connect", `{"Container":"web","EndpointConfig":{"Aliases":["web"]}}`); r.Code != 200 {
		t.Fatalf("connect: %d %s", r.Code, r.Body)
	}
	if r := post("/networks/coolify/disconnect", `{"Container":"web","Force":true}`); r.Code != 200 {
		t.Fatalf("disconnect: %d %s", r.Code, r.Body)
	}
	if r := post("/networks/coolify/connect", `{"Container":"dup"}`); r.Code != 403 {
		t.Fatalf("already connected is 403, as in Docker: %d", r.Code)
	}
	if r := post("/networks/coolify/connect", `{"Container":"-rf"}`); r.Code != 404 {
		t.Fatalf("unsafe name: %d", r.Code)
	}
	if r := post("/networks/coolify/connect", `{"Container":"web","EndpointConfig":{"IPAMConfig":{"IPv4Address":"10.0.0.9"}}}`); r.Code != 501 {
		t.Fatalf("fixed address: %d", r.Code)
	}
	if strings.Join(got, "|") != "connect coolify web web|disconnect coolify web  force|connect coolify dup " {
		t.Fatalf("calls: %q", got)
	}
}

func TestDockerStatsFromCgroup(t *testing.T) {
	cg, proc := t.TempDir(), t.TempDir()
	oldCg, oldProc := cgroupRoot, procRoot
	cgroupRoot, procRoot = cg, proc
	defer func() { cgroupRoot, procRoot = oldCg, oldProc }()
	dir := filepath.Join(cg, "default", "abc")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 2000\nuser_usec 1500\nsystem_usec 500\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.current"), []byte("1048576\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "memory.stat"), []byte("anon 900000\ninactive_file 1000\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "pids.current"), []byte("7\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "io.stat"), []byte("8:0 rbytes=100 wbytes=50 rios=1 wios=1\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  100 0 100 800 0 0 0 0 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal:        2048000 kB\nMemAvailable:    1024000 kB\n"), 0o644)
	os.MkdirAll(filepath.Join(proc, "42", "net"), 0o755)
	os.WriteFile(filepath.Join(proc, "42", "net", "dev"), []byte("Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n    lo: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n  eth0: 1000 3 0 0 0 0 0 0 2000 4 0 0 0 0 0 0\n"), 0o644)
	s := sampleCgroup("default/abc", 42)
	doc := dockerStats("abc", "web", s, cgroupSample{})
	b, _ := json.Marshal(doc)
	var v struct {
		CPU struct {
			Usage struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			System uint64 `json:"system_cpu_usage"`
			CPUs   int    `json:"online_cpus"`
		} `json:"cpu_stats"`
		Mem struct {
			Usage, Limit uint64
		} `json:"memory_stats"`
		Pids struct{ Current uint64 } `json:"pids_stats"`
		Nets map[string]struct {
			Rx uint64 `json:"rx_bytes"`
			Tx uint64 `json:"tx_bytes"`
		} `json:"networks"`
		Name string `json:"name"`
	}
	json.Unmarshal(b, &v)
	if v.CPU.Usage.Total != 2000000 || v.CPU.System != 10000000000 || v.CPU.CPUs == 0 || v.Mem.Usage != 1048576 || v.Mem.Limit == 0 ||
		v.Pids.Current != 7 || v.Nets["eth0"].Rx != 1000 || v.Nets["eth0"].Tx != 2000 || len(v.Nets) != 1 || v.Name != "/web" {
		t.Fatalf("stats: %s", b)
	}
}

func TestDockerAPIRenameDFAndSize(t *testing.T) {
	f := &fakeDocker{out: map[string]string{
		"images --format {{json .}}":           `{"ID":"sha1","Repository":"nginx","Tag":"1","Size":"45.2MB"}`,
		"ps -a --size --format {{json .}}":     `{"ID":"aaa111","Names":"web","Image":"nginx","Status":"Up 2 hours","Size":"1.5kB (virtual 45.2MB)"}`,
		"volume ls --size --format {{json .}}": `{"Name":"data","Mountpoint":"/var/lib/nerdctl/v/data","Size":"2MiB"}`,
		"ps -q --no-trunc":                     "aaa111\n",
		"inspect aaa111": strings.Replace(dockerInspectTwo, `,
 {"Id":"bbb222"`, `]//`, 1)[:strings.Index(dockerInspectTwo, `,
 {"Id":"bbb222"`)] + "]",
		"ps -a --no-trunc --size --format {{.ID}}\t{{.Size}}": "aaa111\t1.5kB (virtual 45.2MB)\n",
	}}
	h := f.api().handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/containers/aaa111/rename?name=web-old", nil))
	if rec.Code != 204 || f.calls[len(f.calls)-1] != "rename aaa111 web-old" {
		t.Fatalf("rename: %d %v", rec.Code, f.calls)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/containers/aaa111/rename?name=-x", nil))
	if rec.Code != 400 {
		t.Fatalf("bad name: %d", rec.Code)
	}
	r := do(h, "GET", "/system/df")
	var df struct {
		LayersSize int64
		Images     []struct{ Size int64 }
		Containers []struct {
			SizeRw, SizeRootFs int64
			State              string
		}
		Volumes []struct{ UsageData struct{ Size int64 } }
	}
	if json.Unmarshal(r.Body.Bytes(), &df) != nil || df.LayersSize != 45200000 || df.Containers[0].SizeRw != 1500 ||
		df.Containers[0].SizeRootFs != 45200000 || df.Containers[0].State != "running" || df.Volumes[0].UsageData.Size != 2<<20 {
		t.Fatalf("df: %s", r.Body)
	}
	r = do(h, "GET", "/containers/json?size=1")
	var list []map[string]any
	if json.Unmarshal(r.Body.Bytes(), &list) != nil || len(list) != 1 || list[0]["SizeRw"] != float64(1500) {
		t.Fatalf("size=1: %s", r.Body)
	}
}

func TestServiceDefinitionForHealthChecks(t *testing.T) {
	b, err := os.ReadFile("../../../rootfs/etc/ziro/services/container-health.conf")
	if err != nil || !strings.Contains(string(b), "args=container health serve") || !strings.Contains(string(b), "autostart=true") {
		t.Fatalf("%s %v", b, err)
	}
	for _, s := range defaultServices {
		if s.Name == "container-health" && s.Args == "container health serve" {
			return
		}
	}
	t.Fatal("container-health is not a built-in service")
}

var _ http.Handler = (*fakeContainerd)(nil)

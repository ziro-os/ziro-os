package cmd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
)

// fakeContainerd serves the four calls the minimal client makes, over HTTP/2 on a unix socket, from
// an in-memory store. It decodes requests with the same wire helpers, so a test also proves the
// encoding round-trips through a real HTTP/2 connection.
type fakeContainerd struct {
	mu         sync.Mutex
	containers map[string]*ctrdContainer
	tasks      map[string]ctrdTask
	updates    []string // the update masks received
	namespace  string
}

func (f *fakeContainerd) encode(ct *ctrdContainer) []byte {
	var b, anyv pbBuf
	b.str(1, ct.ID)
	for k, v := range ct.Labels {
		var e pbBuf
		e.str(1, k)
		e.str(2, v)
		b.msg(2, e.b)
	}
	b.str(3, "docker.io/library/alpine:latest") // a field the client does not use
	anyv.str(1, ct.SpecType)
	anyv.bytes(2, ct.Spec)
	b.msg(5, anyv.b)
	return b.b
}

func (f *fakeContainerd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.namespace = r.Header.Get("Containerd-Namespace")
	body, _ := io.ReadAll(r.Body)
	req := body[5:]
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	fail := func(code, msg string) {
		w.Header().Set("Grpc-Status", code)
		w.Header().Set("Grpc-Message", msg)
	}
	var out pbBuf
	field := func(n int) string {
		var s string
		_ = pbEach(req, func(num int, v []byte) error {
			if num == n {
				s = string(v)
			}
			return nil
		})
		return s
	}
	switch r.URL.Path {
	case "/containerd.services.containers.v1.Containers/Get":
		ct := f.containers[field(1)]
		if ct == nil {
			fail("5", "container \"x\" in namespace \"default\": not found")
			return
		}
		out.msg(1, f.encode(ct))
	case "/containerd.services.containers.v1.Containers/List":
		filter := field(1)
		for _, ct := range f.containers {
			if filter != "" && !strings.Contains(filter, `"`+ct.Labels["nerdctl/name"]+`"`) {
				continue
			}
			out.msg(1, f.encode(ct))
		}
	case "/containerd.services.containers.v1.Containers/Update":
		var upd ctrdContainer
		var mask []string
		_ = pbEach(req, func(num int, v []byte) error {
			switch num {
			case 1:
				upd, _ = decodeCtrdContainer(v)
			case 2:
				_ = pbEach(v, func(n int, p []byte) error { mask = append(mask, string(p)); return nil })
			}
			return nil
		})
		ct := f.containers[upd.ID]
		for _, p := range mask {
			switch {
			case p == "spec":
				ct.Spec, ct.SpecType = upd.Spec, upd.SpecType
			case strings.HasPrefix(p, "labels."):
				k := strings.TrimPrefix(p, "labels.")
				ct.Labels[k] = upd.Labels[k]
			}
		}
		f.updates = append(f.updates, strings.Join(mask, ","))
		out.msg(1, f.encode(ct))
	case "/containerd.services.tasks.v1.Tasks/Get":
		t, ok := f.tasks[field(1)]
		if !ok {
			fail("5", "no running task found: task x not found")
			return
		}
		var p pbBuf
		p.str(1, field(1))
		p.b = binary.AppendUvarint(p.b, 3<<3) // field 3, varint
		p.b = binary.AppendUvarint(p.b, uint64(t.Pid))
		p.b = binary.AppendUvarint(p.b, 4<<3) // field 4, varint
		p.b = binary.AppendUvarint(p.b, uint64(t.Status))
		out.msg(1, p.b)
	default:
		fail("12", "unknown method")
		return
	}
	frame := make([]byte, 5+len(out.b))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(out.b)))
	copy(frame[5:], out.b)
	_, _ = w.Write(frame)
	w.Header().Set("Grpc-Status", "0")
}

func startFakeContainerd(t *testing.T) (*fakeContainerd, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "containerd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeContainerd{containers: map[string]*ctrdContainer{}, tasks: map[string]ctrdTask{}}
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: f, Protocols: &protos}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f, sock
}

const testSpecType = "types.containerd.io/opencontainers/runtime-spec/1/Spec"

// networkFixture is a data store, a CNI config dir with two networks, and a container on "u1".
func networkFixture(t *testing.T, f *fakeContainerd) (dataStore, confDir string) {
	t.Helper()
	root := t.TempDir()
	dataStore = filepath.Join(root, "nerdctl", "1935db59")
	confDir = filepath.Join(root, "net.d")
	os.MkdirAll(confDir, 0o755)
	for name, subnet := range map[string]string{"u1": "10.4.1.0/24", "coolify": "10.4.0.0/24"} {
		conf := `{"cniVersion":"1.0.0","name":"` + name + `","nerdctlID":"` + strings.Repeat("a", 60) + name + `","plugins":[{"type":"bridge","ipam":{"type":"host-local","ranges":[[{"subnet":"` + subnet + `"}]]}}]}`
		os.WriteFile(filepath.Join(confDir, "nerdctl-"+name+".conflist"), []byte(conf), 0o644)
	}
	stateDir := filepath.Join(dataStore, "containers", "default", "3c1f")
	os.MkdirAll(stateDir, 0o755)
	spec := `{"ociVersion":"1.2.0","process":{"args":["sleep","600"]},"hooks":{"createRuntime":[{"path":"/usr/bin/nerdctl","args":["nerdctl","internal","oci-hook","createRuntime","--cni-path=/opt/cni","--cni-netconfpath=` + confDir + `"]}]},"annotations":{"nerdctl/networks":"[\"u1\"]","x-unknown":"kept"},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO"}}}`
	f.containers["3c1f"] = &ctrdContainer{ID: "3c1f", SpecType: testSpecType, Spec: []byte(spec), Labels: map[string]string{
		"nerdctl/name": "web-u1", "nerdctl/hostname": "web", "nerdctl/networks": `["u1"]`, "nerdctl/state-dir": stateDir}}
	return dataStore, confDir
}

func TestCtrdClientRoundTrip(t *testing.T) {
	f, sock := startFakeContainerd(t)
	networkFixture(t, f)
	c := newCtrdClient(sock, "default")
	ctx := context.Background()
	ct, err := c.Container(ctx, "3c1f")
	if err != nil || ct.Labels["nerdctl/name"] != "web-u1" || ct.SpecType != testSpecType || !strings.Contains(string(ct.Spec), "x-unknown") {
		t.Fatalf("get: %+v %v", ct, err)
	}
	if f.namespace != "default" {
		t.Fatalf("namespace header: %q", f.namespace)
	}
	if _, err := c.Container(ctx, "nope"); !isCtrdNotFound(err) {
		t.Fatalf("missing container: %v", err)
	}
	if _, err := c.Task(ctx, "3c1f"); !isCtrdNotFound(err) {
		t.Fatalf("no task: %v", err)
	}
	f.tasks["3c1f"] = ctrdTask{Pid: 4242, Status: ctrdTaskRunning}
	if tk, err := c.Task(ctx, "3c1f"); err != nil || tk.Pid != 4242 || tk.Status != ctrdTaskRunning {
		t.Fatalf("task: %+v %v", tk, err)
	}
	if list, err := c.Containers(ctx, ctrdLabelFilter("nerdctl/name", "web-u1")); err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	if got := ctrdLabelFilter("nerdctl/name", `a"b`); got != `labels."nerdctl/name"=="a\"b"` {
		t.Fatalf("filter: %s", got)
	}
}

func TestNetworkConnectCreatedContainer(t *testing.T) {
	f, sock := startFakeContainerd(t)
	networkFixture(t, f)
	c := newCtrdClient(sock, "default")
	ctx := context.Background()
	st, err := loadContainerNetState(ctx, c, "web-u1")
	if err != nil || st.pid != 0 {
		t.Fatalf("state: %+v %v", st, err)
	}
	called := false
	ops := cniOps{add: func(context.Context, []byte, *libcni.RuntimeConf, string) (*types100.Result, error) {
		called = true
		return nil, nil
	}}
	if err := connectContainer(ctx, c, st, dockerNetOp{Network: "coolify", Container: "web-u1", Aliases: []string{"web-u1"}}, ops); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("a created container is attached by nerdctl's hook when it starts, not now")
	}
	ct := f.containers["3c1f"]
	if ct.Labels["nerdctl/networks"] != `["u1","coolify"]` || f.updates[0] != "labels.nerdctl/networks,spec" {
		t.Fatalf("label %q, masks %v", ct.Labels["nerdctl/networks"], f.updates)
	}
	var spec map[string]any
	json.Unmarshal(ct.Spec, &spec)
	ann := spec["annotations"].(map[string]any)
	if ann["nerdctl/networks"] != `["u1","coolify"]` || ann["x-unknown"] != "kept" || spec["linux"] == nil {
		t.Fatalf("spec: %s", ct.Spec)
	}
	// already there: Docker's error, nothing changes
	st, _ = loadContainerNetState(ctx, c, "3c1f")
	if err := connectContainer(ctx, c, st, dockerNetOp{Network: "coolify"}, ops); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second connect: %v", err)
	}
	if err := connectContainer(ctx, c, st, dockerNetOp{Network: "nope"}, ops); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown network: %v", err)
	}
	// by nerdctl's network ID prefix
	if n, ok := findCNINetwork(cniNetworks(filepath.Dir(cniNetworks(hookConfDir(st))[0].Path)), strings.Repeat("a", 12)); !ok || n.Name == "" {
		t.Fatalf("network by ID: %v %v", n, ok)
	}
	if err := disconnectContainer(ctx, c, st, dockerNetOp{Network: "coolify"}, ops); err != nil {
		t.Fatal(err)
	}
	if got := f.containers["3c1f"].Labels["nerdctl/networks"]; got != `["u1"]` {
		t.Fatalf("after disconnect: %s", got)
	}
	st, _ = loadContainerNetState(ctx, c, "3c1f")
	if err := disconnectContainer(ctx, c, st, dockerNetOp{Network: "coolify"}, ops); err == nil {
		t.Fatal("disconnecting a network the container is not on must fail")
	}
	if err := disconnectContainer(ctx, c, st, dockerNetOp{Network: "coolify", Force: true}, ops); err != nil {
		t.Fatalf("-f: %v", err)
	}
}

func hookConfDir(st *containerNetState) string {
	_, conf, _ := hookPaths(st.spec, st.ct.Labels)
	return conf
}

func TestNetworkConnectRunningContainer(t *testing.T) {
	f, sock := startFakeContainerd(t)
	dataStore, _ := networkFixture(t, f)
	f.tasks["3c1f"] = ctrdTask{Pid: uint32(os.Getpid()), Status: ctrdTaskRunning}
	// another container on coolify already, and this one on u1, as nerdctl's hook left them
	hs, _ := newNerdctlHostsStore(dataStore, "default")
	ip := func(s string) *types100.Result {
		_, n, _ := net.ParseCIDR(s)
		a, _, _ := net.ParseCIDR(s)
		n.IP = a
		return &types100.Result{IPs: []*types100.IPConfig{{Address: *n}}}
	}
	hs.update("9a", func(m *nerdctlHostsMeta) {
		m.Name, m.Hostname, m.Networks = "coolify-proxy", "coolify-proxy", map[string]*types100.Result{"coolify": ip("10.4.0.2/24")}
	})
	hs.update("3c1f", func(m *nerdctlHostsMeta) {
		m.Name, m.Hostname, m.Networks = "web-u1", "web", map[string]*types100.Result{"u1": ip("10.4.1.2/24")}
	})
	tmp := t.TempDir()
	old := cniCacheDir
	cniCacheDir = tmp
	defer func() { cniCacheDir = old }()

	c := newCtrdClient(sock, "default")
	ctx := context.Background()
	st, _ := loadContainerNetState(ctx, c, "web-u1")
	var addRT *libcni.RuntimeConf
	var addBin string
	ops := cniOps{
		add: func(_ context.Context, conf []byte, rt *libcni.RuntimeConf, bin string) (*types100.Result, error) {
			addRT, addBin = rt, bin
			if !strings.Contains(string(conf), `"name":"coolify"`) {
				t.Errorf("conf: %s", conf)
			}
			os.MkdirAll(filepath.Join(tmp, "results"), 0o755)
			os.WriteFile(filepath.Join(tmp, "results", "coolify-"+rt.ContainerID+"-"+rt.IfName), []byte("{}"), 0o600)
			return ip("10.4.0.7/24"), nil
		},
		del: func(_ context.Context, _ []byte, rt *libcni.RuntimeConf, _ string) error {
			if rt.IfName != addRT.IfName {
				t.Errorf("del %s, added %s", rt.IfName, addRT.IfName)
			}
			return nil
		},
	}
	if err := connectContainer(ctx, c, st, dockerNetOp{Network: "coolify"}, ops); err != nil {
		t.Fatal(err)
	}
	if addRT == nil || addRT.ContainerID != "default-3c1f" || addRT.NetNS != "/proc/"+itoa(os.Getpid())+"/ns/net" || addBin != "/opt/cni" || !strings.HasPrefix(addRT.IfName, "eth") {
		t.Fatalf("CNI ADD: %+v %s", addRT, addBin)
	}
	hosts := func(id string) string {
		b, _ := os.ReadFile(filepath.Join(dataStore, "etchosts", "default", id, "hosts"))
		return string(b)
	}
	// the proxy now resolves the service, and the service the proxy, both with nerdctl's names
	if !strings.Contains(hosts("9a"), "10.4.0.7        web web.coolify web-u1 web-u1.coolify\n") ||
		!strings.Contains(hosts("3c1f"), "10.4.0.2        coolify-proxy coolify-proxy.coolify coolify-proxy coolify-proxy.coolify\n") ||
		!strings.Contains(hosts("3c1f"), "10.4.1.2        web web.u1 web-u1 web-u1.u1\n") {
		t.Fatalf("hosts:\n%s\n---\n%s", hosts("9a"), hosts("3c1f"))
	}
	if strings.Contains(hosts("9a"), "10.4.1.2") {
		t.Fatal("the proxy is not on u1: it must not see that address")
	}
	if f.containers["3c1f"].Labels["nerdctl/networks"] != `["u1","coolify"]` {
		t.Fatalf("label: %s", f.containers["3c1f"].Labels["nerdctl/networks"])
	}
	st, _ = loadContainerNetState(ctx, c, "3c1f")
	if err := disconnectContainer(ctx, c, st, dockerNetOp{Network: "coolify"}, ops); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hosts("9a"), "10.4.0.7") || f.containers["3c1f"].Labels["nerdctl/networks"] != `["u1"]` {
		t.Fatalf("after disconnect:\n%s", hosts("9a"))
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestNerdctlHostsFormat(t *testing.T) {
	// a hosts file as nerdctl 2.2.1 writes it, with a line the user added outside the region
	current := "192.168.1.9 printer\n# <nerdctl>\n127.0.0.1	localhost localhost.localdomain\n::1		localhost localhost.localdomain\n10.4.0.9        old\n# </nerdctl>\n"
	res := func(s string) *types100.Result {
		a, n, _ := net.ParseCIDR(s)
		n.IP = a
		return &types100.Result{IPs: []*types100.IPConfig{{Address: *n}}}
	}
	me := &nerdctlHostsMeta{ID: "1", Name: "a", Hostname: "a", Networks: map[string]*types100.Result{"bridge": res("10.4.0.2/24")},
		ExtraHosts: map[string]string{"host.docker.internal": "10.4.0.1"}}
	other := &nerdctlHostsMeta{ID: "2", Name: "b", Hostname: "bh", Domainname: "example.com", Networks: map[string]*types100.Result{"bridge": res("10.4.0.3/24")}}
	got := string(renderHosts([]byte(current), me, []*nerdctlHostsMeta{me, other}))
	want := "192.168.1.9 printer\n# <nerdctl>\n127.0.0.1	localhost localhost.localdomain\n::1		localhost localhost.localdomain\n" +
		"10.4.0.1        host.docker.internal\n10.4.0.2        a a\n10.4.0.3        bh.example.com bh b\n# </nerdctl>\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestParseNetworkConnect(t *testing.T) {
	op, err := parseNetworkConnect(strings.Fields("--alias web-u1 coolify web-u1"))
	if err != nil || op.Network != "coolify" || op.Container != "web-u1" || len(op.Aliases) != 1 {
		t.Fatalf("%+v %v", op, err)
	}
	if op, err := parseNetworkConnect(strings.Fields("-f u1 coolify-proxy")); err != nil || !op.Force {
		t.Fatalf("%+v %v", op, err)
	}
	for _, bad := range []string{"coolify", "--ip 10.0.0.9 n c", "--bogus n c", "a b c"} {
		if _, err := parseNetworkConnect(strings.Fields(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReleaseStaleCNILeases(t *testing.T) {
	dir := t.TempDir()
	lease := func(net, ip, owner string) string {
		p := filepath.Join(dir, "networks", net, ip)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(owner+"\neth1"), 0o600)
		return p
	}
	gone := lease("coolify", "10.4.0.7", "default-dead")
	live := lease("coolify", "10.4.0.8", "default-alive")
	stopped := lease("coolify", "10.4.0.9", "default-stopped")
	other := lease("coolify", "10.4.0.10", "k8s.io-dead")
	os.WriteFile(filepath.Join(dir, "networks", "coolify", "last_reserved_ip.0"), []byte("10.4.0.10"), 0o600)
	got := releaseStaleCNILeases(dir, "default", map[string]bool{"alive": true}, map[string]bool{"alive": true, "stopped": true})
	if len(got) != 1 || got[0] != "coolify/10.4.0.7" {
		t.Fatalf("released %v", got)
	}
	for p, want := range map[string]bool{gone: false, live: true, stopped: true, other: true} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", p, err == nil, want)
		}
	}
}

func TestNextIfName(t *testing.T) {
	if got := nextIfName(map[string]bool{"lo": true, "eth0": true}, 1); got != "eth1" {
		t.Fatal(got)
	}
	if got := nextIfName(map[string]bool{"eth0": true, "eth1": true, "eth2": true}, 1); got != "eth3" {
		t.Fatal(got)
	}
}

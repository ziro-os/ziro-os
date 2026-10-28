package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The write side of the Docker Engine API subset (RFC 0006, phase 2): images, container create and
// logs, volumes, and network create and remove. Each call becomes one nerdctl command whose arguments
// are validated first and passed as --flag=value, so a value can never be read as an option.
//
// Known limitations: exec, attach, stats, build and the registry auth header are not translated
// (private registries need `docker login` on the host); container create ignores the fields it does
// not map (health checks, devices, security options, log config) instead of rejecting them, because
// clients send many zero-valued defaults. Map a field when a tool needs it.

var (
	dockerImageRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)
	dockerEnvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)
	dockerPortRe   = regexp.MustCompile(`^([0-9]{1,5})/(tcp|udp|sctp)$`)
	dockerCapRe    = regexp.MustCompile(`^[A-Z_]{1,32}$`)
	dockerHostRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	dockerRestartR = regexp.MustCompile(`^(no|always|unless-stopped|on-failure)$`)
)

// streamFunc runs nerdctl with its output copied to the writers while it runs.
type streamFunc func(ctx context.Context, args []string, stdout, stderr io.Writer) error

func streamNerdctl(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	c := exec.CommandContext(ctx, "nerdctl", args...)
	c.Stdout, c.Stderr = stdout, stderr
	return c.Run()
}

func (d *dockerAPI) registerWrite(mux *http.ServeMux) {
	mux.HandleFunc("GET /images/json", d.images)
	mux.HandleFunc("POST /images/create", d.imagePull)
	mux.HandleFunc("GET /images/", d.imageInspect) // /images/{name}/json: the name holds slashes
	mux.HandleFunc("POST /containers/create", d.containerCreate)
	mux.HandleFunc("GET /containers/{id}/logs", d.containerLogs)
	mux.HandleFunc("GET /volumes", d.volumes)
	mux.HandleFunc("POST /volumes/create", d.volumeCreate)
	mux.HandleFunc("GET /volumes/{name}", d.volumeInspect)
	mux.HandleFunc("DELETE /volumes/{name}", d.volumeRemove)
	mux.HandleFunc("POST /networks/create", d.networkCreate)
	mux.HandleFunc("DELETE /networks/{id}", d.networkRemove)
}

// ---- images ----

func (d *dockerAPI) images(w http.ResponseWriter, r *http.Request) {
	out, err := d.run(r.Context(), "images", "--format", "{{.Repository}}:{{.Tag}}")
	if err != nil {
		d.fail(w, err)
		return
	}
	var refs []string
	seen := map[string]bool{}
	for _, ref := range strings.Fields(string(out)) {
		if !seen[ref] && !strings.Contains(ref, "<none>") && dockerImageRe.MatchString(ref) {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		dockerJSON(w, []any{})
		return
	}
	raw, err := d.run(r.Context(), append([]string{"image", "inspect"}, refs...)...)
	if err != nil {
		d.fail(w, err)
		return
	}
	var list []struct {
		ID       string
		RepoTags []string
		Created  string
		Size     int64
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		d.fail(w, fmt.Errorf("nerdctl image inspect: %v", err))
		return
	}
	sum := make([]map[string]any, 0, len(list))
	for _, im := range list {
		sum = append(sum, map[string]any{"Id": im.ID, "RepoTags": im.RepoTags, "Created": parseDockerTime(im.Created), "Size": im.Size,
			"VirtualSize": im.Size, "ParentId": "", "Labels": map[string]string{}, "Containers": -1, "SharedSize": -1})
	}
	dockerJSON(w, sum)
}

func (d *dockerAPI) imageInspect(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/images/"), "/json")
	if !ok || !dockerImageRe.MatchString(name) {
		dockerError(w, http.StatusNotImplemented, fmt.Sprintf("ziro-dockerd: %s %s is not supported", r.Method, r.URL.Path))
		return
	}
	raw, err := d.run(r.Context(), "image", "inspect", name)
	if err != nil {
		d.fail(w, err)
		return
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		dockerError(w, http.StatusNotFound, "no such image: "+name)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(list[0])
}

// imagePull is POST /images/create?fromImage=X&tag=Y: the response is a stream of JSON progress lines.
func (d *dockerAPI) imagePull(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ref := q.Get("fromImage")
	if t := q.Get("tag"); t != "" && !strings.ContainsAny(ref[strings.LastIndex(ref, "/")+1:], ":@") {
		ref += ":" + t // fromImage without its own tag or digest
	}
	if !dockerImageRe.MatchString(ref) {
		dockerError(w, http.StatusBadRequest, "invalid image reference")
		return
	}
	args := []string{"pull"}
	if p := q.Get("platform"); p != "" {
		if !regexp.MustCompile(`^[a-z0-9]+(/[a-z0-9]+)?(/[a-z0-9.]+)?$`).MatchString(p) {
			dockerError(w, http.StatusBadRequest, "invalid platform")
			return
		}
		args = append(args, "--platform="+p)
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	_ = enc.Encode(map[string]string{"status": "Pulling from " + ref})
	flush()
	if _, err := d.run(r.Context(), append(args, ref)...); err != nil {
		_ = enc.Encode(map[string]any{"errorDetail": map[string]string{"message": err.Error()}, "error": err.Error()})
		return
	}
	_ = enc.Encode(map[string]string{"status": "Status: Downloaded newer image for " + ref})
}

// parseDockerTime is a creation time as the unix seconds the list endpoints use.
func parseDockerTime(s string) int64 {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Unix()
	}
	return 0
}

// ---- container create ----

type dockerCreateBody struct {
	Image        string
	Cmd          []string
	Entrypoint   []string
	Env          []string
	Labels       map[string]string
	User         string
	WorkingDir   string
	Hostname     string
	Tty          bool
	OpenStdin    bool
	ExposedPorts map[string]struct{}
	HostConfig   struct {
		Binds  []string
		Mounts []struct {
			Type, Source, Target string
			ReadOnly             bool
		}
		NetworkMode   string
		PortBindings  map[string][]struct{ HostIp, HostPort string }
		RestartPolicy struct {
			Name              string
			MaximumRetryCount int
		}
		Memory       int64
		NanoCpus     int64
		Privileged   bool
		CapAdd       []string
		CapDrop      []string
		ExtraHosts   []string
		Dns          []string
		Init         *bool
		Sysctls      map[string]string
		Tmpfs        map[string]string
		PublishAll   bool
		ReadonlyRoot bool
	}
	NetworkingConfig struct {
		EndpointsConfig map[string]struct{ Aliases []string }
	}
}

func okText(s string, max int) bool { return len(s) <= max && !strings.ContainsRune(s, 0) }

// buildCreateArgs validates a create request and returns the nerdctl arguments.
func buildCreateArgs(name, platform string, b dockerCreateBody) ([]string, error) {
	if !dockerImageRe.MatchString(b.Image) {
		return nil, fmt.Errorf("invalid image reference")
	}
	args := []string{"create"}
	add := func(f string, v ...string) {
		for _, x := range v {
			args = append(args, f+"="+x)
		}
	}
	if name != "" {
		if !dockerIDRe.MatchString(name) {
			return nil, fmt.Errorf("invalid container name")
		}
		add("--name", name)
	}
	if platform != "" {
		if !regexp.MustCompile(`^[a-z0-9]+(/[a-z0-9]+)?(/[a-z0-9.]+)?$`).MatchString(platform) {
			return nil, fmt.Errorf("invalid platform")
		}
		add("--platform", platform)
	}
	for _, e := range b.Env {
		k, _, _ := strings.Cut(e, "=")
		if !dockerEnvKeyRe.MatchString(k) || !okText(e, 32<<10) {
			return nil, fmt.Errorf("invalid environment entry")
		}
		add("--env", e)
	}
	keys := make([]string, 0, len(b.Labels))
	for k := range b.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" || strings.Contains(k, "=") || !okText(k, 255) || !okText(b.Labels[k], 32<<10) {
			return nil, fmt.Errorf("invalid label %q", k)
		}
		add("--label", k+"="+b.Labels[k])
	}
	for _, f := range []struct{ flag, v string }{{"--user", b.User}, {"--workdir", b.WorkingDir}, {"--hostname", b.Hostname}} {
		if f.v != "" {
			if !okText(f.v, 255) {
				return nil, fmt.Errorf("invalid %s", strings.TrimPrefix(f.flag, "--"))
			}
			add(f.flag, f.v)
		}
	}
	if b.Tty {
		args = append(args, "--tty")
	}
	if b.OpenStdin {
		args = append(args, "--interactive")
	}
	hc := b.HostConfig
	// Networks: the mode first, then any other the container joins, with their aliases.
	var nets []string
	switch hc.NetworkMode {
	case "", "default", "bridge":
	case "host", "none":
		nets = append(nets, hc.NetworkMode)
	default:
		n := strings.TrimPrefix(hc.NetworkMode, "container:")
		if !dockerIDRe.MatchString(n) {
			return nil, fmt.Errorf("invalid network mode")
		}
		nets = append(nets, hc.NetworkMode)
	}
	epNames := make([]string, 0, len(b.NetworkingConfig.EndpointsConfig))
	for n := range b.NetworkingConfig.EndpointsConfig {
		epNames = append(epNames, n)
	}
	sort.Strings(epNames)
	for _, n := range epNames {
		if !dockerIDRe.MatchString(n) {
			return nil, fmt.Errorf("invalid network name")
		}
		if !slices.Contains(nets, n) {
			nets = append(nets, n)
		}
		for _, a := range b.NetworkingConfig.EndpointsConfig[n].Aliases {
			if !dockerHostRe.MatchString(a) {
				return nil, fmt.Errorf("invalid network alias")
			}
			add("--network-alias", a)
		}
	}
	add("--network", nets...)
	// Ports.
	pspecs := make([]string, 0, len(hc.PortBindings))
	for p := range hc.PortBindings {
		pspecs = append(pspecs, p)
	}
	sort.Strings(pspecs)
	for _, spec := range pspecs {
		m := dockerPortRe.FindStringSubmatch(spec)
		if m == nil {
			return nil, fmt.Errorf("invalid port %q", spec)
		}
		if n, _ := strconv.Atoi(m[1]); n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", spec)
		}
		for _, bnd := range hc.PortBindings[spec] {
			pub := ""
			if bnd.HostIp != "" {
				if _, err := netip.ParseAddr(bnd.HostIp); err != nil {
					return nil, fmt.Errorf("invalid host ip %q", bnd.HostIp)
				}
				pub = bnd.HostIp + ":"
			}
			if bnd.HostPort != "" {
				if n, err := strconv.Atoi(bnd.HostPort); err != nil || n < 0 || n > 65535 {
					return nil, fmt.Errorf("invalid host port %q", bnd.HostPort)
				}
				pub += bnd.HostPort + ":"
			} else if pub != "" {
				pub += ":"
			}
			add("--publish", pub+spec)
		}
	}
	if hc.PublishAll {
		args = append(args, "--publish-all")
	}
	binds := slices.Clone(hc.Binds)
	for _, m := range hc.Mounts {
		if (m.Type != "volume" && m.Type != "bind") || m.Source == "" || strings.Contains(m.Source+m.Target, ":") {
			return nil, fmt.Errorf("unsupported mount")
		}
		v := m.Source + ":" + m.Target
		if m.ReadOnly {
			v += ":ro"
		}
		binds = append(binds, v)
	}
	for _, v := range binds {
		parts := strings.Split(v, ":")
		if len(parts) < 2 || len(parts) > 3 || !okText(v, 4096) || !strings.HasPrefix(parts[1], "/") ||
			(!strings.HasPrefix(parts[0], "/") && !dockerIDRe.MatchString(parts[0])) {
			return nil, fmt.Errorf("invalid bind %q", v)
		}
		if len(parts) == 3 && !regexp.MustCompile(`^[a-z,]{1,40}$`).MatchString(parts[2]) {
			return nil, fmt.Errorf("invalid bind options %q", parts[2])
		}
		add("--volume", v)
	}
	if rp := hc.RestartPolicy.Name; rp != "" {
		if !dockerRestartR.MatchString(rp) || hc.RestartPolicy.MaximumRetryCount < 0 {
			return nil, fmt.Errorf("invalid restart policy")
		}
		if rp == "on-failure" && hc.RestartPolicy.MaximumRetryCount > 0 {
			rp += ":" + strconv.Itoa(hc.RestartPolicy.MaximumRetryCount)
		}
		add("--restart", rp)
	}
	if hc.Memory < 0 || hc.NanoCpus < 0 {
		return nil, fmt.Errorf("invalid resource limit")
	}
	if hc.Memory > 0 {
		add("--memory", strconv.FormatInt(hc.Memory, 10))
	}
	if hc.NanoCpus > 0 {
		add("--cpus", strconv.FormatFloat(float64(hc.NanoCpus)/1e9, 'f', 3, 64))
	}
	if hc.Privileged {
		args = append(args, "--privileged")
	}
	for _, f := range []struct {
		flag string
		caps []string
	}{{"--cap-add", hc.CapAdd}, {"--cap-drop", hc.CapDrop}} {
		for _, c := range f.caps {
			if !dockerCapRe.MatchString(c) {
				return nil, fmt.Errorf("invalid capability %q", c)
			}
			add(f.flag, c)
		}
	}
	for _, h := range hc.ExtraHosts {
		name, ip, ok := strings.Cut(h, ":")
		_, err := netip.ParseAddr(ip)
		if !ok || !dockerHostRe.MatchString(name) || (err != nil && ip != "host-gateway") {
			return nil, fmt.Errorf("invalid extra host %q", h)
		}
		add("--add-host", h)
	}
	for _, s := range hc.Dns {
		if _, err := netip.ParseAddr(s); err != nil {
			return nil, fmt.Errorf("invalid dns server %q", s)
		}
		add("--dns", s)
	}
	if hc.Init != nil && *hc.Init {
		args = append(args, "--init")
	}
	if hc.ReadonlyRoot {
		args = append(args, "--read-only")
	}
	for _, k := range slices.Sorted(maps.Keys(hc.Sysctls)) {
		v := hc.Sysctls[k]
		if !regexp.MustCompile(`^[a-z0-9_.]{1,100}$`).MatchString(k) || !okText(v, 100) || strings.ContainsAny(v, "\n") {
			return nil, fmt.Errorf("invalid sysctl %q", k)
		}
		add("--sysctl", k+"="+v)
	}
	for _, p := range slices.Sorted(maps.Keys(hc.Tmpfs)) {
		o := hc.Tmpfs[p]
		if !strings.HasPrefix(p, "/") || !okText(p, 4096) || !okText(o, 256) {
			return nil, fmt.Errorf("invalid tmpfs %q", p)
		}
		if o != "" {
			p += ":" + o
		}
		add("--tmpfs", p)
	}
	// Entrypoint: nerdctl takes one word; the rest of an array leads the command.
	cmd := b.Cmd
	if len(b.Entrypoint) > 0 {
		if !okText(b.Entrypoint[0], 4096) {
			return nil, fmt.Errorf("invalid entrypoint")
		}
		add("--entrypoint", b.Entrypoint[0])
		cmd = append(append([]string(nil), b.Entrypoint[1:]...), b.Cmd...)
	}
	for _, c := range cmd {
		if !okText(c, 64<<10) {
			return nil, fmt.Errorf("invalid command")
		}
	}
	args = append(args, "--", b.Image)
	return append(args, cmd...), nil
}

func (d *dockerAPI) containerCreate(w http.ResponseWriter, r *http.Request) {
	var b dockerCreateBody
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&b); err != nil {
		dockerError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	args, err := buildCreateArgs(r.URL.Query().Get("name"), r.URL.Query().Get("platform"), b)
	if err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := d.run(r.Context(), args...)
	if err != nil {
		d.fail(w, err)
		return
	}
	lines := strings.Fields(string(out))
	if len(lines) == 0 || !dockerIDRe.MatchString(lines[len(lines)-1]) {
		dockerError(w, http.StatusInternalServerError, "nerdctl create printed no container id")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"Id": lines[len(lines)-1], "Warnings": []string{}})
}

// ---- logs ----

// muxWriter frames a stream the way Docker does for a container without a terminal: an 8-byte header
// (stream type, three zero bytes, big-endian length) before every chunk.
type muxWriter struct {
	mu    *sync.Mutex
	w     io.Writer
	kind  byte
	flush func()
}

func (m *muxWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for off := 0; off < len(p); {
		n := min(len(p)-off, 1<<20)
		var hdr [8]byte
		hdr[0] = m.kind
		binary.BigEndian.PutUint32(hdr[4:], uint32(n))
		if _, err := m.w.Write(append(hdr[:], p[off:off+n]...)); err != nil {
			return off, err
		}
		off += n
	}
	if m.flush != nil {
		m.flush()
	}
	return len(p), nil
}

type flushWriter struct {
	w     io.Writer
	flush func()
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if f.flush != nil {
		f.flush()
	}
	return n, err
}

func (d *dockerAPI) containerLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	q := r.URL.Query()
	truthy := func(k string) bool { return q.Get(k) == "1" || q.Get(k) == "true" }
	wantOut, wantErr := truthy("stdout"), truthy("stderr")
	if !wantOut && !wantErr {
		dockerError(w, http.StatusBadRequest, "you must choose at least one stream")
		return
	}
	args := []string{"logs"}
	if truthy("follow") {
		args = append(args, "--follow")
	}
	if truthy("timestamps") {
		args = append(args, "--timestamps")
	}
	if t := q.Get("tail"); t != "" && t != "all" {
		if n, err := strconv.Atoi(t); err != nil || n < 0 {
			dockerError(w, http.StatusBadRequest, "invalid tail")
			return
		}
		args = append(args, "--tail="+t)
	}
	raw, err := d.run(r.Context(), "inspect", id)
	if err != nil {
		d.fail(w, err)
		return
	}
	var info []struct{ Config struct{ Tty bool } }
	if json.Unmarshal(raw, &info) != nil || len(info) == 0 {
		dockerError(w, http.StatusNotFound, "no such container: "+id)
		return
	}
	tty := info[0].Config.Tty
	fl, _ := w.(http.Flusher)
	flush := func() {
		if fl != nil {
			fl.Flush()
		}
	}
	var stdout, stderr io.Writer = io.Discard, io.Discard
	if tty {
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		stdout = flushWriter{w, flush}
	} else {
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		mu := &sync.Mutex{}
		if wantOut {
			stdout = &muxWriter{mu: mu, w: w, kind: 1, flush: flush}
		}
		if wantErr {
			stderr = &muxWriter{mu: mu, w: w, kind: 2, flush: flush}
		}
	}
	w.WriteHeader(http.StatusOK)
	flush()
	_ = d.stream(r.Context(), append(args, id), stdout, stderr) // the client sees the stream end
}

// ---- volumes ----

func (d *dockerAPI) volumes(w http.ResponseWriter, r *http.Request) {
	out, err := d.run(r.Context(), "volume", "ls", "-q")
	if err != nil {
		d.fail(w, err)
		return
	}
	var names []string
	for _, n := range strings.Fields(string(out)) {
		if dockerIDRe.MatchString(n) {
			names = append(names, n)
		}
	}
	list := []json.RawMessage{}
	if len(names) > 0 {
		raw, err := d.run(r.Context(), append([]string{"volume", "inspect"}, names...)...)
		if err != nil {
			d.fail(w, err)
			return
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			d.fail(w, fmt.Errorf("nerdctl volume inspect: %v", err))
			return
		}
	}
	dockerJSON(w, map[string]any{"Volumes": list, "Warnings": []string{}})
}

func (d *dockerAPI) volumeInspect(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !dockerIDRe.MatchString(name) {
		dockerError(w, http.StatusNotFound, "no such volume")
		return
	}
	d.inspectOne(w, r.Context(), http.StatusOK, "volume", "inspect", name)
}

// inspectOne writes the first document of an inspect command's JSON array.
func (d *dockerAPI) inspectOne(w http.ResponseWriter, ctx context.Context, code int, args ...string) {
	raw, err := d.run(ctx, args...)
	if err != nil {
		d.fail(w, err)
		return
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		dockerError(w, http.StatusNotFound, "not found: "+args[len(args)-1])
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(list[0])
}

func (d *dockerAPI) volumeCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name   string
		Driver string
		Labels map[string]string
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		dockerError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.Name == "" || !dockerIDRe.MatchString(b.Name) {
		dockerError(w, http.StatusBadRequest, "a volume needs a valid name")
		return
	}
	if b.Driver != "" && b.Driver != "local" {
		dockerError(w, http.StatusBadRequest, "only the local volume driver is supported")
		return
	}
	args := []string{"volume", "create"}
	labels, err := labelArgs(b.Labels)
	if err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := d.run(r.Context(), append(append(args, labels...), b.Name)...); err != nil {
		d.fail(w, err)
		return
	}
	d.inspectOne(w, r.Context(), http.StatusCreated, "volume", "inspect", b.Name)
}

func labelArgs(m map[string]string) ([]string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		if k == "" || strings.Contains(k, "=") || !okText(k, 255) || !okText(m[k], 32<<10) {
			return nil, fmt.Errorf("invalid label %q", k)
		}
		out = append(out, "--label="+k+"="+m[k])
	}
	return out, nil
}

func (d *dockerAPI) volumeRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !dockerIDRe.MatchString(name) {
		dockerError(w, http.StatusNotFound, "no such volume")
		return
	}
	args := []string{"volume", "rm"}
	if q := r.URL.Query(); q.Get("force") == "1" || q.Get("force") == "true" {
		args = append(args, "--force")
	}
	if _, err := d.run(r.Context(), append(args, name)...); err != nil {
		d.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- networks ----

func (d *dockerAPI) networkCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name   string
		Driver string
		Labels map[string]string
		IPAM   struct {
			Config []struct{ Subnet, Gateway string }
		}
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		dockerError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !dockerIDRe.MatchString(b.Name) {
		dockerError(w, http.StatusBadRequest, "a network needs a valid name")
		return
	}
	if b.Driver != "" && b.Driver != "bridge" {
		dockerError(w, http.StatusBadRequest, "only the bridge network driver is supported")
		return
	}
	args := []string{"network", "create"}
	labels, err := labelArgs(b.Labels)
	if err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	args = append(args, labels...)
	for _, c := range b.IPAM.Config {
		if c.Subnet != "" {
			if _, err := netip.ParsePrefix(c.Subnet); err != nil {
				dockerError(w, http.StatusBadRequest, "invalid subnet")
				return
			}
			args = append(args, "--subnet="+c.Subnet)
		}
		if c.Gateway != "" {
			if _, err := netip.ParseAddr(c.Gateway); err != nil {
				dockerError(w, http.StatusBadRequest, "invalid gateway")
				return
			}
			args = append(args, "--gateway="+c.Gateway)
		}
	}
	out, err := d.run(r.Context(), append(args, b.Name)...)
	if err != nil {
		d.fail(w, err)
		return
	}
	id := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if !dockerIDRe.MatchString(id) {
		id = b.Name
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": id, "Warning": ""})
}

func (d *dockerAPI) networkRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such network")
		return
	}
	if _, err := d.run(r.Context(), "network", "rm", id); err != nil {
		d.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

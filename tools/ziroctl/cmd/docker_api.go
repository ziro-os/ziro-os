package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// A subset of the Docker Engine API on a unix socket, translated to nerdctl (RFC 0006). Off by
// default: the socket is root on the host, so an administrator turns it on with
// `ziroctl docker-api enable`. It exists for tools that manage a Docker host (Coolify's proxy and
// Traefik's docker provider read containers, networks and events through it).
//
// Supported: _ping, version, info, container list/inspect/start/stop/restart/kill/remove, network
// list/inspect and events. Everything else answers 501 naming the route, so a missing call is
// visible instead of silently wrong.
//
// Known limitation: container create, exec, logs, image pull and volumes are not translated yet;
// add them route by route (each is a nerdctl command plus a response mapping) when a tool needs one.

const (
	dockerSock       = "/run/docker.sock"
	dockerSockLink   = "/var/run/docker.sock" // where tools look; /var/run is not always a link to /run
	dockerAPIVersion = "1.43"
	dockerMinVersion = "1.24"
	dockerService    = "dockerd"
)

// dockerEventPoll is how often the event stream looks at the containers.
var dockerEventPoll = 2 * time.Second

// Container and network names and IDs reach nerdctl as separate arguments; the pattern keeps one from
// ever starting with a dash (an option) or carrying a separator.
var (
	dockerIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	dockerSignalRe = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
	dockerVerRe    = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)
)

// nerdctlFunc runs nerdctl with args and returns its stdout.
type nerdctlFunc func(ctx context.Context, args ...string) ([]byte, error)

func dockerNerdctl(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "nerdctl", args...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return out, errors.New(strings.TrimSpace(sanitizeLabel(string(ee.Stderr), 300)))
	}
	return out, err
}

type dockerAPI struct {
	run    nerdctlFunc
	stream streamFunc
	audit  func(action, target string, err error)
}

func newDockerAPI() *dockerAPI {
	return &dockerAPI{run: dockerNerdctl, stream: streamNerdctl, audit: func(action, target string, err error) {
		_ = auditLog("root", "docker-api", action, target, err)
	}}
}

func dockerError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func dockerJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// fail maps a nerdctl failure to the status Docker would answer.
func (d *dockerAPI) fail(w http.ResponseWriter, err error) {
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "no such") || strings.Contains(strings.ToLower(msg), "not found") {
		dockerError(w, http.StatusNotFound, msg)
		return
	}
	for _, s := range []string{"already in use", "already exists", "already used", "is in use"} {
		if strings.Contains(strings.ToLower(msg), s) {
			dockerError(w, http.StatusConflict, msg)
			return
		}
	}
	dockerError(w, http.StatusInternalServerError, msg)
}

// dockerStatusWriter records the status for the audit entry and keeps Flush for the event stream.
type dockerStatusWriter struct {
	http.ResponseWriter
	code int
}

func (s *dockerStatusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *dockerStatusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (d *dockerAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", d.ping)
	mux.HandleFunc("GET /version", d.version)
	mux.HandleFunc("GET /info", d.info)
	mux.HandleFunc("GET /containers/json", d.containers)
	mux.HandleFunc("GET /containers/{id}/json", d.containerInspect)
	for _, op := range []string{"start", "stop", "restart", "kill"} {
		mux.HandleFunc("POST /containers/{id}/"+op, d.containerOp(op))
	}
	mux.HandleFunc("DELETE /containers/{id}", d.containerRemove)
	mux.HandleFunc("GET /networks", d.networks)
	mux.HandleFunc("GET /networks/{id}", d.networkInspect)
	mux.HandleFunc("GET /events", d.events)
	d.registerWrite(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dockerError(w, http.StatusNotImplemented, fmt.Sprintf("ziro-dockerd: %s %s is not supported", r.Method, r.URL.Path))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = dockerVerRe.ReplaceAllString(r.URL.Path, "/") // clients prefix /v1.43
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		sw := &dockerStatusWriter{ResponseWriter: w, code: http.StatusOK}
		mux.ServeHTTP(sw, r)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			var err error
			if sw.code >= 400 {
				err = fmt.Errorf("status %d", sw.code)
			}
			d.audit(r.Method+" "+r.URL.Path, sanitizeLabel(r.URL.RawQuery, 200), err)
		}
	})
}

func (d *dockerAPI) ping(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Api-Version", dockerAPIVersion)
	h.Set("Docker-Experimental", "false")
	h.Set("Ostype", "linux")
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("OK"))
	}
}

func dockerArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}

func (d *dockerAPI) version(w http.ResponseWriter, r *http.Request) {
	dockerJSON(w, map[string]any{
		"Platform":      map[string]string{"Name": "Ziro OS"},
		"Components":    []map[string]any{{"Name": "Engine", "Version": Version, "Details": map[string]string{"ApiVersion": dockerAPIVersion, "MinAPIVersion": dockerMinVersion, "Os": "linux", "Arch": runtime.GOARCH}}},
		"Version":       Version,
		"ApiVersion":    dockerAPIVersion,
		"MinAPIVersion": dockerMinVersion,
		"GoVersion":     runtime.Version(),
		"Os":            "linux",
		"Arch":          runtime.GOARCH,
	})
}

// dockerInspect is the part of a container's inspect output the summaries need.
type dockerInspect struct {
	ID      string   `json:"Id"`
	Created string   `json:"Created"`
	Path    string   `json:"Path"`
	Args    []string `json:"Args"`
	Name    string   `json:"Name"`
	Image   string   `json:"Image"`
	State   struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]struct{ HostIp, HostPort string } `json:"Ports"`
		Networks map[string]json.RawMessage                     `json:"Networks"`
	} `json:"NetworkSettings"`
}

// containerSummary is the /containers/json shape of one inspected container.
func containerSummary(c dockerInspect) map[string]any {
	created := int64(0)
	if t, err := time.Parse(time.RFC3339Nano, c.Created); err == nil {
		created = t.Unix()
	}
	ports := []map[string]any{}
	for spec, binds := range c.NetworkSettings.Ports {
		port, proto, _ := strings.Cut(spec, "/")
		priv, _ := strconv.Atoi(port)
		if len(binds) == 0 {
			ports = append(ports, map[string]any{"PrivatePort": priv, "Type": proto})
		}
		for _, b := range binds {
			pub, _ := strconv.Atoi(b.HostPort)
			ports = append(ports, map[string]any{"IP": b.HostIp, "PrivatePort": priv, "PublicPort": pub, "Type": proto})
		}
	}
	status := "Exited"
	if c.State.Running {
		status = "Up"
	}
	labels := c.Config.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	image := c.Config.Image
	if image == "" {
		image = c.Image
	}
	return map[string]any{
		"Id": c.ID, "Names": []string{"/" + strings.TrimPrefix(c.Name, "/")}, "Image": image, "ImageID": c.Image,
		"Command": strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " ")), "Created": created, "Ports": ports,
		"Labels": labels, "State": strings.ToLower(c.State.Status), "Status": status,
		"HostConfig":      map[string]string{"NetworkMode": c.HostConfig.NetworkMode},
		"NetworkSettings": map[string]any{"Networks": c.NetworkSettings.Networks},
	}
}

// inspectContainers lists the containers (running only unless all) and inspects them in one call.
func (d *dockerAPI) inspectContainers(ctx context.Context, all bool) ([]dockerInspect, error) {
	args := []string{"ps", "-q", "--no-trunc"}
	if all {
		args = append(args, "-a")
	}
	out, err := d.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil, nil
	}
	raw, err := d.run(ctx, append([]string{"inspect"}, ids...)...)
	if err != nil {
		return nil, err
	}
	var list []dockerInspect
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("nerdctl inspect: %v", err)
	}
	return list, nil
}

func (d *dockerAPI) containers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	all := q.Get("all") == "1" || q.Get("all") == "true"
	list, err := d.inspectContainers(r.Context(), all)
	if err != nil {
		d.fail(w, err)
		return
	}
	var status []string
	if f := q.Get("filters"); f != "" {
		var m map[string][]string
		if err := json.Unmarshal([]byte(f), &m); err != nil {
			dockerError(w, http.StatusBadRequest, "invalid filters")
			return
		}
		status = m["status"]
	}
	out := []map[string]any{}
	for _, c := range list {
		if len(status) > 0 && !containsFold(status, c.State.Status) {
			continue
		}
		out = append(out, containerSummary(c))
	}
	dockerJSON(w, out)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func (d *dockerAPI) info(w http.ResponseWriter, r *http.Request) {
	list, err := d.inspectContainers(r.Context(), true)
	if err != nil {
		d.fail(w, err)
		return
	}
	running := 0
	for _, c := range list {
		if c.State.Running {
			running++
		}
	}
	host, _ := os.Hostname()
	dockerJSON(w, map[string]any{
		"ID": host, "Containers": len(list), "ContainersRunning": running, "ContainersPaused": 0,
		"ContainersStopped": len(list) - running, "Driver": "overlayfs", "Name": host, "ServerVersion": Version,
		"OperatingSystem": "Ziro OS", "OSType": "linux", "Architecture": dockerArch(), "NCPU": runtime.NumCPU(),
		"MemTotal": int64(inspectSystem().TotalMemMB) << 20, "DockerRootDir": "/var/lib/containerd",
	})
}

func (d *dockerAPI) containerInspect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	out, err := d.run(r.Context(), "inspect", id)
	if err != nil {
		d.fail(w, err)
		return
	}
	var list []json.RawMessage
	if err := json.Unmarshal(out, &list); err != nil || len(list) == 0 {
		dockerError(w, http.StatusNotFound, "no such container: "+id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(list[0])
}

func (d *dockerAPI) containerOp(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !dockerIDRe.MatchString(id) {
			dockerError(w, http.StatusNotFound, "no such container")
			return
		}
		args := []string{op}
		q := r.URL.Query()
		switch op {
		case "stop", "restart":
			if t := q.Get("t"); t != "" {
				if n, err := strconv.Atoi(t); err != nil || n < 0 || n > 3600 {
					dockerError(w, http.StatusBadRequest, "invalid t")
					return
				}
				args = append(args, "--time", t)
			}
		case "kill":
			if s := q.Get("signal"); s != "" {
				if !dockerSignalRe.MatchString(s) {
					dockerError(w, http.StatusBadRequest, "invalid signal")
					return
				}
				args = append(args, "--signal", s)
			}
		}
		if _, err := d.run(r.Context(), append(args, id)...); err != nil {
			d.fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d *dockerAPI) containerRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	args := []string{"rm"}
	if q := r.URL.Query(); q.Get("force") == "1" || q.Get("force") == "true" {
		args = append(args, "--force")
	}
	if _, err := d.run(r.Context(), append(args, id)...); err != nil {
		d.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *dockerAPI) networks(w http.ResponseWriter, r *http.Request) {
	out, err := d.run(r.Context(), "network", "ls", "--format", "{{.Name}}")
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
	if len(names) == 0 {
		dockerJSON(w, []any{})
		return
	}
	raw, err := d.run(r.Context(), append([]string{"network", "inspect"}, names...)...)
	if err != nil {
		d.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (d *dockerAPI) networkInspect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such network")
		return
	}
	raw, err := d.run(r.Context(), "network", "inspect", id)
	if err != nil {
		d.fail(w, err)
		return
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		dockerError(w, http.StatusNotFound, "no such network: "+id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(list[0])
}

// ---- events ----

type ctrState struct {
	Name, Image string
	Running     bool
}

// dockerEvent is one entry of the /events stream.
type dockerEvent struct {
	Type     string `json:"Type"`
	Action   string `json:"Action"`
	Status   string `json:"status"`
	ID       string `json:"id"`
	From     string `json:"from"`
	Scope    string `json:"scope"`
	Time     int64  `json:"time"`
	TimeNano int64  `json:"timeNano"`
	Actor    struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// diffContainers turns two snapshots into start, die and destroy events (sorted by ID so the order
// is stable). nerdctl's own event stream differs between versions; looking at the containers is
// the same everywhere.
func diffContainers(prev, cur map[string]ctrState, now time.Time) []dockerEvent {
	ids := map[string]bool{}
	for id := range prev {
		ids[id] = true
	}
	for id := range cur {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	slices.Sort(sorted)
	var out []dockerEvent
	emit := func(id, action string, s ctrState) {
		e := dockerEvent{Type: "container", Action: action, Status: action, ID: id, From: s.Image, Scope: "local", Time: now.Unix(), TimeNano: now.UnixNano()}
		e.Actor.ID = id
		e.Actor.Attributes = map[string]string{"name": s.Name, "image": s.Image}
		out = append(out, e)
	}
	for _, id := range sorted {
		p, hadPrev := prev[id]
		c, hasCur := cur[id]
		switch {
		case hasCur && c.Running && (!hadPrev || !p.Running):
			emit(id, "start", c)
		case hadPrev && p.Running && (!hasCur || !c.Running):
			emit(id, "die", p)
			if !hasCur {
				emit(id, "destroy", p)
			}
		case hadPrev && !hasCur:
			emit(id, "destroy", p)
		}
	}
	return out
}

func (d *dockerAPI) snapshot(ctx context.Context) (map[string]ctrState, error) {
	list, err := d.inspectContainers(ctx, true)
	if err != nil {
		return nil, err
	}
	m := make(map[string]ctrState, len(list))
	for _, c := range list {
		m[c.ID] = ctrState{Name: strings.TrimPrefix(c.Name, "/"), Image: c.Config.Image, Running: c.State.Running}
	}
	return m, nil
}

func (d *dockerAPI) events(w http.ResponseWriter, r *http.Request) {
	prev, err := d.snapshot(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	enc := json.NewEncoder(w)
	lastErr := ""
	t := time.NewTicker(dockerEventPoll)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case now := <-t.C:
			cur, err := d.snapshot(r.Context())
			if err != nil {
				if err.Error() != lastErr { // a failed look is retried at the next tick; say why once
					fmt.Fprintf(os.Stderr, "docker-api: events: %v\n", err)
					lastErr = err.Error()
				}
				continue
			}
			lastErr = ""
			for _, e := range diffContainers(prev, cur, now) {
				if enc.Encode(e) != nil {
					return
				}
			}
			if fl != nil {
				fl.Flush()
			}
			prev = cur
		}
	}
}

// ---- serving and commands ----

// listenDockerSock replaces a stale socket (never any other kind of file) and opens it for root only.
func listenDockerSock(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o177) // created 0600: no other user can connect before the chmod
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// linkDockerSock makes link (the path tools expect) lead to sock, unless both already name the same
// directory. Only an existing symlink is replaced.
func linkDockerSock(sock, link string) error {
	a, errA := os.Stat(filepath.Dir(sock))
	b, errB := os.Stat(filepath.Dir(link))
	if errA == nil && errB == nil && os.SameFile(a, b) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(link); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s exists and is not a symlink", link)
		}
		_ = os.Remove(link)
	}
	return os.Symlink(sock, link)
}

func serveDockerAPI(ctx context.Context, path string, d *dockerAPI) error {
	ln, err := listenDockerSock(path)
	if err != nil {
		return err
	}
	if path == dockerSock {
		if err := linkDockerSock(path, dockerSockLink); err != nil {
			ln.Close()
			return err
		}
		defer os.Remove(dockerSockLink)
	}
	srv := &http.Server{Handler: d.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
		_ = os.Remove(path)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

var dockerAPICmd = &cobra.Command{
	Use:   "docker-api",
	Short: "Opt-in Docker Engine API socket",
	Long: `Serves a subset of the Docker Engine API on /run/docker.sock, translated to nerdctl. Whoever can use the
socket is root on this host, so it is off until an administrator enables it. Supported: container list, inspect,
start, stop, restart, kill and remove; network list and inspect; version, info and events. Other calls answer
501.`,
	Example: `  ziroctl docker-api enable
  ziroctl docker-api status`,
}

var dockerAPIServeCmd = &cobra.Command{
	Use:     "serve",
	Short:   "Run the socket service",
	Long:    "Runs in the foreground; init starts it when the socket is enabled.",
	Example: `  ziroctl docker-api serve`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return serveDockerAPI(ctx, dockerSock, newDockerAPI())
	},
}

var dockerAPIEnableCmd = &cobra.Command{
	Use:     "enable",
	Short:   "Turn the Docker API socket on",
	Example: `  ziroctl docker-api enable`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return errors.New("docker-api enable must run as root")
		}
		err := enableService(dockerService)
		if err == nil {
			err = startService(dockerService)
		}
		_ = auditLog("root", "cli", "docker-api enable", dockerSock, err)
		if err != nil {
			return err
		}
		return printResult(map[string]any{"enabled": true, "socket": dockerSock}, func() {
			fmt.Printf("Docker API enabled on %s. Anyone who can use it is root on this host.\n", dockerSock)
		})
	},
}

var dockerAPIDisableCmd = &cobra.Command{
	Use:     "disable",
	Short:   "Turn the Docker API socket off",
	Example: `  ziroctl docker-api disable`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return errors.New("docker-api disable must run as root")
		}
		_ = stopService(dockerService)
		err := disableService(dockerService)
		_ = os.Remove(dockerSock)
		_ = os.Remove(dockerSockLink)
		_ = auditLog("root", "cli", "docker-api disable", dockerSock, err)
		if err != nil {
			return err
		}
		return printResult(map[string]any{"enabled": false}, func() { fmt.Println("Docker API disabled.") })
	},
}

var dockerAPIStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show whether the socket answers",
	Example: `  ziroctl docker-api status`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", dockerSock)
			}}}
		up := false
		if resp, err := c.Get("http://docker/_ping"); err == nil {
			resp.Body.Close()
			up = resp.StatusCode == http.StatusOK
		}
		return printResult(map[string]any{"socket": dockerSock, "running": up}, func() {
			if up {
				fmt.Printf("running on %s\n", dockerSock)
			} else {
				fmt.Println("not running (enable it with `ziroctl docker-api enable`)")
			}
		})
	},
}

func init() {
	dockerAPICmd.AddCommand(dockerAPIServeCmd, dockerAPIEnableCmd, dockerAPIDisableCmd, dockerAPIStatusCmd)
	rootCmd.AddCommand(dockerAPICmd)
}

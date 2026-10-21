package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// ziro-sandboxd: the sandbox daemon (ziroctl run as /usr/bin/ziro-sandboxd, or `ziroctl sandbox
// serve`). It answers on a root-only unix socket; see sandbox.go for the model.

const (
	sandboxExecMaxOutput = 64 << 20 // per exec, stdout and stderr together
	sandboxExecMaxStdin  = 1 << 20
)

var sandboxReapEvery = 15 * time.Second

func runSandboxDaemon(ctx context.Context) error {
	for _, d := range []string{filepath.Dir(sandboxSocket), sandboxRoot} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	_ = os.Remove(sandboxSocket)
	l, err := net.Listen("unix", sandboxSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(sandboxSocket, 0600); err != nil { // root only: a sandbox runs code
		l.Close()
		return err
	}
	cfg, err := loadSandboxConfig()
	if err != nil {
		l.Close()
		return err
	}
	st := loadSandboxStore()
	var ids []string
	for id := range st.all {
		ids = append(ids, id)
	}
	m := &sandboxManager{st: st, net: newSandboxNet(cfg.Subnet), access: loadAccessStore(ids), mesh: &meshState{}, now: time.Now}
	for _, sb := range m.st.all { // a create the last daemon didn't finish
		if sb.State == "pending" {
			sb.State, sb.Error = "failed", "interrupted: ziro-sandboxd restarted while it was starting"
			_ = m.st.save(sb)
		}
	}
	// The network comes up before anything runs; sandboxes without one work even if it can't.
	if err := sandboxNetSetup(m.net); err != nil {
		fmt.Printf("[sandboxd] sandbox network: %v (sandboxes with a network will fail to start)\n", err)
	} else {
		m.net.ready = true
		if err := m.applyNet(); err != nil {
			fmt.Printf("[sandboxd] sandbox network rules: %v\n", err)
		}
	}
	if cfg.SecretPort > 0 && m.net.ready {
		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(cfg.SecretPort)))
		if err != nil {
			fmt.Printf("[sandboxd] egress proxy: %v (sandboxes with secrets will fail to start)\n", err)
		} else {
			m.egress, m.net.proxyPort = newEgressProxy(m), cfg.SecretPort
			allowFirewall([]FirewallRule{{Port: cfg.SecretPort, Protocol: "tcp", Source: cfg.Subnet, Comment: "Ziro sandbox egress proxy"}}, "")
			go func() { _ = m.egress.serve(ctx, ln) }()
			if err := m.applyNet(); err != nil {
				fmt.Printf("[sandboxd] sandbox network rules: %v\n", err)
			}
		}
	}
	if cfg.PreviewPort > 0 {
		key, err := loadPreviewKey()
		if err != nil {
			l.Close()
			return fmt.Errorf("preview key: %w", err)
		}
		m.previewKey, m.previewPort = key, cfg.PreviewPort
		ps := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.PreviewPort)), Handler: m.previewHandler(),
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		go func() { <-ctx.Done(); _ = ps.Close() }()
		go func() {
			if err := ps.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("[sandboxd] preview proxy: %v\n", err)
			}
		}()
	}
	if cfg.SSHPort > 0 {
		signer, err := sandboxHostKey()
		if err != nil {
			l.Close()
			return fmt.Errorf("ssh host key: %w", err)
		}
		m.ssh = newSSHGateway(m, signer)
		m.ssh.port = cfg.SSHPort
		allowFirewall([]FirewallRule{{Port: cfg.SSHPort, Protocol: "tcp", Comment: "Ziro sandbox SSH"}}, "")
		go func() {
			if err := m.ssh.serve(ctx, net.JoinHostPort("", strconv.Itoa(cfg.SSHPort))); err != nil {
				fmt.Printf("[sandboxd] ssh gateway: %v\n", err)
			}
		}()
	}
	go func() {
		for {
			rctx, cancel := context.WithTimeout(ctx, time.Minute)
			m.reconcile(rctx)
			cancel()
			if cfg, err := loadSandboxConfig(); err == nil {
				m.fillPools(cfg)
			}
			m.syncMesh()
			select {
			case <-ctx.Done():
				return
			case <-time.After(sandboxReapEvery):
			}
		}
	}()
	srv := &http.Server{Handler: m.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	fmt.Printf("ziro-sandboxd listening on %s\n", sandboxSocket)
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func serveSandboxDaemon() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return runSandboxDaemon(ctx)
}

// sandboxCallerOf reads the identity the REST API passed on; a request without one came from
// the host CLI (only root can open the socket).
func sandboxCallerOf(r *http.Request) sandboxCaller {
	if o := r.Header.Get(hdrOwner); o != "" {
		return sandboxCaller{Owner: o, Role: r.Header.Get(hdrRole)}
	}
	return sandboxCaller{Owner: "root", Role: "admin"}
}

func (m *sandboxManager) routes() *http.ServeMux {
	mux := http.NewServeMux()
	// with resolves {id} and checks it before the handler runs.
	with := func(h func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if !sandboxIDRe.MatchString(id) {
				apiReply(w, errNotFound("no sandbox "+id), nil)
				return
			}
			h(w, r, id, sandboxCallerOf(r))
		}
	}
	mux.HandleFunc("GET /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		list, err := filterSandboxes(m.st.list(sandboxCallerOf(r)), r.URL.Query())
		apiReply(w, err, list)
	})
	mux.HandleFunc("POST /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		var spec schema.SandboxSpec
		if err := decodeStrict(w, r, &spec, 1<<20); err != nil {
			apiReply(w, err, nil)
			return
		}
		sb, err := m.create(r.Context(), spec, sandboxCallerOf(r))
		apiReply(w, err, sb)
	})
	mux.HandleFunc("GET /v1/sandboxes/templates", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, listTemplates())
	})
	mux.HandleFunc("GET /v1/sandboxes/snapshots", func(w http.ResponseWriter, r *http.Request) {
		list, err := m.snapshots(r.Context(), sandboxCallerOf(r))
		apiReply(w, err, list)
	})
	mux.HandleFunc("DELETE /v1/sandboxes/snapshots", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, m.removeSnapshot(r.Context(), sandboxCallerOf(r), r.URL.Query().Get("image")), APIMessage{Status: "ok", Message: "snapshot removed"})
	})
	mux.HandleFunc("POST /v1/sandboxes/{id}/snapshot", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var req struct {
			Name string `json:"name"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		s, err := m.snapshot(r.Context(), id, c, req.Name)
		apiReply(w, err, s)
	}))
	mux.HandleFunc("GET /v1/sandboxes/{id}", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		sb, err := m.st.get(id, c)
		apiReply(w, err, sb)
	}))
	mux.HandleFunc("GET /v1/sandboxes/{id}/stats", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		s, err := m.stats(r.Context(), id, c)
		apiReply(w, err, s)
	}))
	mux.HandleFunc("GET /v1/sandboxes/{id}/logs", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		l, err := m.logs(r.Context(), id, c, r.URL.Query().Get("tail"))
		apiReply(w, err, l)
	}))
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		apiReply(w, m.remove(id, c), APIMessage{Status: "ok", Message: "sandbox " + id + " deleted"})
	}))
	for verb, pause := range map[string]bool{"pause": true, "resume": false} {
		mux.HandleFunc("POST /v1/sandboxes/{id}/"+verb, with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
			sb, err := m.setPaused(r.Context(), id, c, pause)
			apiReply(w, err, sb)
		}))
	}
	mux.HandleFunc("POST /v1/sandboxes/{id}/renew", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var req struct {
			Timeout string `json:"timeout,omitempty"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		sb, err := m.renew(id, c, req.Timeout)
		apiReply(w, err, sb)
	}))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/metadata", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var md map[string]string
		if err := decodeStrict(w, r, &md, 64<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		sb, err := m.setMetadata(id, c, md)
		apiReply(w, err, sb)
	}))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/network", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var n schema.SandboxNetwork
		if err := decodeStrict(w, r, &n, 64<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		sb, err := m.setNetwork(r.Context(), id, c, n)
		apiReply(w, err, sb)
	}))
	mux.HandleFunc("POST /v1/sandboxes/{id}/access", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var req sdkapi.SandboxAccessRequest
		if err := decodeStrict(w, r, &req, 16<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		v, err := m.createAccess(id, c, req, r.Header.Get(hdrHost))
		apiReply(w, err, v)
	}))
	mux.HandleFunc("GET /v1/sandboxes/{id}/access", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		if _, err := m.st.get(id, c); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, m.access.list(id))
	}))
	mux.HandleFunc("DELETE /v1/sandboxes/{id}/access/{aid}", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		if _, err := m.st.get(id, c); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, m.access.revoke(id, r.PathValue("aid")), APIMessage{Status: "ok", Message: "access token revoked"})
	}))
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		mux.HandleFunc(method+" /v1/sandboxes/{id}/files", with(m.serveFiles))
	}
	mux.HandleFunc("POST /v1/sandboxes/{id}/previews", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var req sdkapi.SandboxPreviewRequest
		if err := decodeStrict(w, r, &req, 4<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		pv, err := m.expose(id, c, req)
		apiReply(w, err, pv)
	}))
	mux.HandleFunc("DELETE /v1/sandboxes/{id}/previews/{port}", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		port, err := strconv.Atoi(r.PathValue("port"))
		if err == nil {
			err = m.unexpose(id, c, port)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "preview removed"})
	}))
	mux.HandleFunc("POST /v1/sandboxes/{id}/exec", with(func(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
		var req sdkapi.SandboxExecRequest
		if err := decodeStrict(w, r, &req, sandboxExecMaxStdin+(64<<10)); err != nil {
			apiReply(w, err, nil)
			return
		}
		m.serveExec(w, r, id, c, req)
	}))
	return mux
}

// sandboxExecArgs is the nerdctl command line of an exec request.
func sandboxExecArgs(id string, req sdkapi.SandboxExecRequest) ([]string, time.Duration, error) {
	if len(req.Command) == 0 || len(req.Command) > 256 {
		return nil, 0, errors.New("command: 1 to 256 arguments")
	}
	for _, a := range req.Command {
		if len(a) > 64<<10 || strings.ContainsRune(a, 0) {
			return nil, 0, errors.New("command: arguments must be under 64 KiB, without NUL")
		}
	}
	if err := schema.ValidateSandboxEnv(req.Env); err != nil {
		return nil, 0, err
	}
	probe := schema.SandboxSpec{Image: "x", User: req.User, Workdir: req.Workdir}
	if err := probe.Validate(); err != nil {
		return nil, 0, err
	}
	if len(req.Stdin) > sandboxExecMaxStdin {
		return nil, 0, errors.New("stdin is over 1 MiB")
	}
	timeout := 5 * time.Minute
	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil || d <= 0 || d > time.Hour {
			return nil, 0, errors.New("timeout must be between 1s and 1h")
		}
		timeout = d
	}
	args := []string{"exec"}
	if req.Stdin != "" {
		args = append(args, "-i")
	}
	if req.Workdir != "" {
		args = append(args, "-w", req.Workdir)
	}
	if req.User != "" {
		args = append(args, "-u", req.User)
	}
	keys := make([]string, 0, len(req.Env))
	for k := range req.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+req.Env[k])
	}
	return append(append(args, sandboxContainer(id), "--"), req.Command...), timeout, nil
}

// serveExec runs a command in a sandbox and streams its output as NDJSON (SandboxExecEvent):
// output lines as they come, then the exit code.
func (m *sandboxManager) serveExec(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller, req sdkapi.SandboxExecRequest) {
	sb, err := m.st.get(id, c)
	if err == nil && sb.State != "running" {
		err = fmt.Errorf("sandbox %s is %s", id, sb.State)
	}
	args, timeout, aerr := sandboxExecArgs(id, req)
	if err == nil {
		err = aerr
	}
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	m.touch(id)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	cmd := sandboxExecCommand(ctx, args...)
	// On timeout or a client hanging up, SIGTERM goes to nerdctl, which forwards it to the
	// command in the sandbox; killing nerdctl alone would leave the command running there.
	// Known limitation: a command that ignores SIGTERM keeps running until the sandbox's lifetime ends.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	ev := &execStream{enc: json.NewEncoder(w), flush: func() { _ = http.NewResponseController(w).Flush() }, cancel: cancel}
	stderr := newExitFilter(ev.writer("stderr"))
	cmd.Stdout, cmd.Stderr = ev.writer("stdout"), stderr
	err = cmd.Run()
	code := stderr.finish(0)
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		ev.send(sdkapi.SandboxExecEvent{Error: "timed out after " + timeout.String()})
		return
	case ev.over:
		ev.send(sdkapi.SandboxExecEvent{Error: "output over 64 MiB: stopped"})
		return
	case errors.As(err, &exitErr):
		code = stderr.finish(exitErr.ExitCode())
	case err != nil:
		ev.send(sdkapi.SandboxExecEvent{Error: err.Error()})
		return
	}
	m.touch(id)
	ev.send(sdkapi.SandboxExecEvent{ExitCode: &code})
}

// execStream serialises a command's stdout and stderr into one NDJSON stream.
// Known limitation: output is sent as JSON strings, so bytes that aren't UTF-8 become U+FFFD; add a
// base64 encoding when binary output matters (the files API is the way to move binaries).
type execStream struct {
	mu     sync.Mutex
	enc    *json.Encoder
	flush  func()
	cancel func()
	total  int
	over   bool
}

func (e *execStream) send(v sdkapi.SandboxExecEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.enc.Encode(v)
	e.flush()
}

type streamWriter struct {
	e    *execStream
	name string
}

func (e *execStream) writer(name string) io.Writer { return &streamWriter{e, name} }

func (s *streamWriter) Write(p []byte) (int, error) {
	s.e.mu.Lock()
	s.e.total += len(p)
	over := s.e.total > sandboxExecMaxOutput
	if over && !s.e.over {
		s.e.over = true
		s.e.cancel()
	}
	s.e.mu.Unlock()
	if over {
		return len(p), nil
	}
	s.e.send(sdkapi.SandboxExecEvent{Stream: s.name, Data: string(p)})
	return len(p), nil
}

// ---- client (ziroctl sandbox, the REST API) ----

var sandboxHTTP = unixClient(&sandboxSocket)

func startSandboxDaemon(ctx context.Context) error {
	return startSocketService(ctx, "ziro-sandboxd", sandboxSocket, "sandbox")
}

func sandboxRaw(ctx context.Context, method, path string, body any) (*http.Response, error) {
	return daemonRaw(ctx, sandboxCLIHTTP, "ziro-sandboxd", sandboxSocket, startSandboxDaemon, method, path, body)
}

// sandboxCLIHTTP is how the host CLI reaches sandboxes. On a cluster master with sandbox nodes
// it goes through the cluster (every node's sandboxes, placement, snapshots on any node) with
// the forwarding the REST API uses, as root; anywhere else to the local daemon.
var sandboxCLIHTTP = &http.Client{Transport: sandboxCLITransport{}}

type sandboxCLITransport struct{}

func (sandboxCLITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if v, ok := sandboxClusterState(); ok && v.token != "" && len(v.sandboxNodes()) > 0 {
		return inProcess{h: http.HandlerFunc(serveCLIOnCluster), ctx: asHostRoot}.RoundTrip(req)
	}
	return sandboxHTTP.Transport.RoundTrip(req)
}

// serveCLIOnCluster answers a daemon request (/v1/sandboxes...) with the master's cluster
// handler (/api/v1/sandboxes...).
func serveCLIOnCluster(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = "/api" + r.URL.Path
	r.Host = "" // no client-facing host name: nodes use their configured ssh_host for access commands
	if !serveClusterSandboxes(w, r) {
		apiError(w, http.StatusServiceUnavailable, "this host is no longer a cluster master")
	}
}

// asHostRoot gives a request the identity of the host CLI: root, with every sandbox in view.
func asHostRoot(ctx context.Context) context.Context {
	return context.WithValue(context.WithValue(ctx, apiNameKey{}, "root"), apiRoleKey{}, "admin")
}

// sandboxCall sends a request to ziro-sandboxd and decodes its JSON answer into out.
func sandboxCall(method, path string, body, out any) error {
	resp, err := sandboxRaw(context.Background(), method, path, body)
	if err != nil {
		return err
	}
	return daemonDecode("ziro-sandboxd", resp, out)
}

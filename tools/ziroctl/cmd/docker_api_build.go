package cmd

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// What `docker buildx` needs from the Docker API to build with its docker-container driver (RFC 0006):
// it creates a privileged moby/buildkit container, copies its configuration in (PUT archive), starts
// it, talks to buildkitd through `buildctl dial-stdio` run with exec over a hijacked connection, and
// loads the finished image with POST /images/load. Coolify's `docker compose build` goes this way.
//
// Known limitation: exec runs through `nerdctl exec`, which has no terminal here, so Tty execs are
// refused; and a client that half-closes its input but keeps reading is served only while the command
// prints something (see dockerExecIdle). Archive upload accepts regular files and directories only.

const (
	dockerArchiveMax = 256 << 20 // bytes of tar a PUT archive may carry
	dockerLoadMax    = 64 << 30  // bytes of tar an image load may carry
	dockerExecMax    = 256       // execs remembered at once
	dockerExecIdle   = 30 * time.Second
)

// dockerExec is one exec instance: created by POST /containers/{id}/exec, run by POST /exec/{id}/start.
type dockerExec struct {
	ID, Container, User, WorkDir string
	Cmd, Env                     []string
	In, Out, Err, Tty            bool
	mu                           sync.Mutex
	started, running             bool
	exit                         int
	at                           time.Time
}

var dockerExecs = struct {
	sync.Mutex
	m map[string]*dockerExec
}{m: map[string]*dockerExec{}}

func newDockerExec(e *dockerExec) error {
	dockerExecs.Lock()
	defer dockerExecs.Unlock()
	for id, x := range dockerExecs.m { // forget finished execs after a while
		x.mu.Lock()
		old := !x.running && time.Since(x.at) > 10*time.Minute
		x.mu.Unlock()
		if old {
			delete(dockerExecs.m, id)
		}
	}
	if len(dockerExecs.m) >= dockerExecMax {
		return errors.New("too many exec instances")
	}
	e.ID = randomHex(32)
	e.at = time.Now()
	dockerExecs.m[e.ID] = e
	return nil
}

func lookupDockerExec(id string) *dockerExec {
	dockerExecs.Lock()
	defer dockerExecs.Unlock()
	return dockerExecs.m[id]
}

func (d *dockerAPI) registerBuild(mux *http.ServeMux) {
	mux.HandleFunc("PUT /containers/{id}/archive", d.containerPutArchive)
	mux.HandleFunc("POST /containers/{id}/exec", d.execCreate)
	mux.HandleFunc("POST /exec/{id}/start", d.execStart)
	mux.HandleFunc("POST /exec/{id}/resize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /exec/{id}/json", d.execInspect)
	mux.HandleFunc("POST /images/load", d.imageLoad)
}

// ---- exec ----

// buildExecArgs validates an exec and returns the nerdctl arguments.
func buildExecArgs(e *dockerExec) ([]string, error) {
	if !dockerIDRe.MatchString(e.Container) {
		return nil, errors.New("invalid container")
	}
	if len(e.Cmd) == 0 {
		return nil, errors.New("no command")
	}
	args := []string{"exec"}
	if e.In {
		args = append(args, "--interactive")
	}
	if e.User != "" {
		if !okText(e.User, 255) {
			return nil, errors.New("invalid user")
		}
		args = append(args, "--user="+e.User)
	}
	if e.WorkDir != "" {
		if !okText(e.WorkDir, 4096) {
			return nil, errors.New("invalid working directory")
		}
		args = append(args, "--workdir="+e.WorkDir)
	}
	for _, v := range e.Env {
		k, _, _ := strings.Cut(v, "=")
		if !dockerEnvKeyRe.MatchString(k) || !okText(v, 32<<10) {
			return nil, errors.New("invalid environment entry")
		}
		args = append(args, "--env="+v)
	}
	for _, c := range e.Cmd {
		if !okText(c, 64<<10) {
			return nil, errors.New("invalid command")
		}
	}
	return append(append(args, "--", e.Container), e.Cmd...), nil
}

func (d *dockerAPI) execCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AttachStdin, AttachStdout, AttachStderr, Tty bool
		Cmd, Env                                     []string
		User, WorkingDir                             string
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		dockerError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	e := &dockerExec{Container: r.PathValue("id"), Cmd: b.Cmd, Env: b.Env, User: b.User, WorkDir: b.WorkingDir,
		In: b.AttachStdin, Out: b.AttachStdout, Err: b.AttachStderr, Tty: b.Tty}
	if _, err := buildExecArgs(e); err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := newDockerExec(e); err != nil {
		dockerError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	// The exec itself is the sensitive act: record what it will run, not only that one was created.
	d.audit(dockerActor(r), "POST /containers/"+e.Container+"/exec", sanitizeLabel(strings.Join(e.Cmd, " "), 200), nil)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": e.ID})
}

func dockerActor(r *http.Request) string {
	if peer, ok := r.Context().Value(dockerPeerKey{}).(string); ok {
		return peer
	}
	return "docker-socket"
}

func (d *dockerAPI) execInspect(w http.ResponseWriter, r *http.Request) {
	e := lookupDockerExec(r.PathValue("id"))
	if e == nil {
		dockerError(w, http.StatusNotFound, "no such exec instance")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	dockerJSON(w, map[string]any{"ID": e.ID, "ContainerID": e.Container, "Running": e.running, "ExitCode": e.exit, "Pid": 0,
		"OpenStdin": e.In, "OpenStdout": e.Out, "OpenStderr": e.Err, "CanRemove": !e.running, "DetachKeys": "",
		"ProcessConfig": map[string]any{"entrypoint": e.Cmd[0], "arguments": e.Cmd[1:], "tty": e.Tty, "user": e.User, "privileged": false}})
}

// dockerProc runs a command with the given streams and returns its exit code.
type dockerProc func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error)

func runNerdctlProc(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	c := exec.CommandContext(ctx, "nerdctl", args...)
	c.Stdout, c.Stderr = stdout, stderr
	var pw *os.File
	if stdin != nil {
		// A pipe we own, not the reader itself: Wait would otherwise block until the reader ends.
		pr, w, err := os.Pipe()
		if err != nil {
			return 1, err
		}
		pw, c.Stdin = w, pr
		defer pr.Close()
		go func() {
			_, _ = io.Copy(pw, stdin)
			pw.Close()
		}()
	}
	c.WaitDelay = 2 * time.Second
	err := c.Run()
	if pw != nil {
		pw.Close()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func (d *dockerAPI) proc() dockerProc {
	if d.runProc != nil {
		return d.runProc
	}
	return runNerdctlProc
}

// idleWriter notes the time of the last write, so a command that has gone silent can be told apart.
type idleWriter struct {
	w    io.Writer
	last *time.Time
	mu   *sync.Mutex
}

func (i idleWriter) Write(p []byte) (int, error) {
	i.mu.Lock()
	*i.last = time.Now()
	i.mu.Unlock()
	return i.w.Write(p)
}

func (d *dockerAPI) execStart(w http.ResponseWriter, r *http.Request) {
	e := lookupDockerExec(r.PathValue("id"))
	if e == nil {
		dockerError(w, http.StatusNotFound, "no such exec instance")
		return
	}
	var b struct{ Detach, Tty bool }
	_ = json.NewDecoder(r.Body).Decode(&b)
	if b.Tty || e.Tty {
		dockerError(w, http.StatusNotImplemented, "ziro-dockerd: exec with a terminal is not supported")
		return
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		dockerError(w, http.StatusConflict, "exec instance already started")
		return
	}
	e.started, e.running = true, true
	e.mu.Unlock()
	args, err := buildExecArgs(e)
	if err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	finish := func(code int) {
		e.mu.Lock()
		e.running, e.exit, e.at = false, code, time.Now()
		e.mu.Unlock()
	}
	if b.Detach {
		go func() {
			code, _ := d.proc()(context.Background(), args, nil, io.Discard, io.Discard)
			finish(code)
		}()
		w.WriteHeader(http.StatusOK)
		return
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		finish(126)
		dockerError(w, http.StatusInternalServerError, "the connection cannot be taken over")
		return
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	d.pumpExec(conn, rw.Reader, e, args, finish)
}

// pumpExec connects the hijacked connection to the command: the client's bytes are its stdin, its
// output goes back framed as Docker does for a command without a terminal.
func (d *dockerAPI) pumpExec(conn net.Conn, in *bufio.Reader, e *dockerExec, args []string, finish func(int)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex // serialises the frames of the two streams
	var lastOut time.Time
	var lmu sync.Mutex
	var stdout, stderr io.Writer = io.Discard, io.Discard
	if e.Out {
		stdout = idleWriter{&cancelOnErr{&muxWriter{mu: &mu, w: conn, kind: 1}, cancel}, &lastOut, &lmu}
	}
	if e.Err {
		stderr = idleWriter{&cancelOnErr{&muxWriter{mu: &mu, w: conn, kind: 2}, cancel}, &lastOut, &lmu}
	}
	var stdin io.Reader
	if e.In {
		pr, pw := io.Pipe()
		stdin = pr
		go func() {
			_, _ = io.Copy(pw, in)
			pw.Close() // the client closed its side: end of input for the command
			// nerdctl does not always pass the end of input on, and a client that closed its whole end
			// is gone: stop a command that has then said nothing for dockerExecIdle.
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(dockerExecIdle):
					lmu.Lock()
					quiet := time.Since(lastOut) >= dockerExecIdle
					lmu.Unlock()
					if quiet {
						cancel()
						return
					}
				}
			}
		}()
	}
	lmu.Lock()
	lastOut = time.Now()
	lmu.Unlock()
	code, err := d.proc()(ctx, args, stdin, stdout, stderr)
	if err != nil {
		code = 126
	}
	finish(code)
}

type cancelOnErr struct {
	w      io.Writer
	cancel context.CancelFunc
}

func (c *cancelOnErr) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		c.cancel() // the client is gone
	}
	return n, err
}

// ---- archive ----

// extractDockerTar unpacks a tar stream into dir. Only regular files and directories are taken, and
// every name must stay inside dir: the archive comes from a client of the socket.
func extractDockerTar(dir string, r io.Reader) error {
	tr := tar.NewReader(r)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid tar: %v", err)
		}
		name := path.Clean("/" + h.Name)
		if name == "/" {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; total > dockerArchiveMax {
				return errors.New("archive too large")
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode&0o777))
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, tr)
			if err := f.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		case tar.TypeXGlobalHeader:
		default:
			return fmt.Errorf("%s: only files and directories can be copied in", h.Name)
		}
	}
}

// containerPutArchive is PUT /containers/{id}/archive?path=DIR: the tar's contents go into DIR.
func (d *dockerAPI) containerPutArchive(w http.ResponseWriter, r *http.Request) {
	id, dest := r.PathValue("id"), r.URL.Query().Get("path")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	if !strings.HasPrefix(dest, "/") || !okText(dest, 4096) {
		dockerError(w, http.StatusBadRequest, "path must be absolute")
		return
	}
	dir, err := os.MkdirTemp("", "ziro-archive-")
	if err != nil {
		d.fail(w, err)
		return
	}
	defer os.RemoveAll(dir)
	if err := extractDockerTar(dir, r.Body); err != nil {
		dockerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := d.run(r.Context(), "cp", "--", dir+"/.", id+":"+dest); err != nil {
		d.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- image load ----

// imageLoad is POST /images/load: a docker image tar in the body, which `nerdctl load` reads from stdin.
func (d *dockerAPI) imageLoad(w http.ResponseWriter, r *http.Request) {
	var out strings.Builder
	var errb strings.Builder
	_, err := d.proc()(r.Context(), []string{"load"}, r.Body, &out, &errb)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err != nil || strings.Contains(errb.String(), "level=fatal") {
		msg := strings.TrimSpace(sanitizeLabel(errb.String(), 300))
		if msg == "" && err != nil {
			msg = err.Error()
		}
		_ = enc.Encode(map[string]any{"errorDetail": map[string]string{"message": msg}, "error": msg})
		return
	}
	if r.URL.Query().Get("quiet") == "1" || r.URL.Query().Get("quiet") == "true" {
		return
	}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.HasPrefix(l, "Loaded image") {
			_ = enc.Encode(map[string]string{"stream": l + "\n"})
		}
	}
}

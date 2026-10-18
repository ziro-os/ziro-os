package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// The sandbox SSH gateway: one port for every sandbox, authenticated by a session token in the
// user name (sandbox_access.go). It is not a shell on the host: a session runs `nerdctl exec`
// in the token's sandbox (with a terminal when the client asks for one), and direct-tcpip
// (ssh -L) reaches only that sandbox's own address. Remote forwarding, agent forwarding, X11
// and subsystems (sftp) are refused.

const (
	sshMaxConns       = 256
	sshMaxFailures    = 20 // per client address in sshFailWindow, then its connections are dropped
	sshFailWindow     = 10 * time.Minute
	sshHandshakeLimit = 30 * time.Second
)

var sandboxExecCommand = func(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "nerdctl", args...)
}

var sandboxHostKeyFile = func() string { return filepath.Join(sandboxRoot, "ssh_host_ed25519_key") }

// sandboxHostKey loads the gateway's host key, creating it once.
func sandboxHostKey() (ssh.Signer, error) {
	p := sandboxHostKeyFile()
	if b, err := os.ReadFile(p); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "ziro-sandboxd")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(p, pem.EncodeToMemory(blk), 0600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

type sshGateway struct {
	m      *sandboxManager
	signer ssh.Signer
	sem    chan struct{}
	mu     sync.Mutex
	fails  map[string][]time.Time
}

func newSSHGateway(m *sandboxManager, signer ssh.Signer) *sshGateway {
	return &sshGateway{m: m, signer: signer, sem: make(chan struct{}, sshMaxConns), fails: map[string][]time.Time{}}
}

func (g *sshGateway) serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("ziro-sandboxd: SSH gateway on %s (host key %s)\n", addr, ssh.FingerprintSHA256(g.signer.PublicKey()))
	return g.accept(ctx, ln)
}

func (g *sshGateway) accept(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		ip := addrIP(c.RemoteAddr())
		if g.blocked(ip) {
			c.Close()
			continue
		}
		select {
		case g.sem <- struct{}{}:
			go func() {
				defer func() { <-g.sem }()
				g.handle(c, ip)
			}()
		default:
			c.Close()
		}
	}
}

func (g *sshGateway) blocked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cut := time.Now().Add(-sshFailWindow)
	recent := g.fails[ip][:0]
	for _, t := range g.fails[ip] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(g.fails, ip)
	} else {
		g.fails[ip] = recent
	}
	return len(recent) >= sshMaxFailures
}

func (g *sshGateway) failed(ip string) {
	g.mu.Lock()
	g.fails[ip] = append(g.fails[ip], time.Now())
	g.mu.Unlock()
}

func (g *sshGateway) config(ip string) *ssh.ServerConfig {
	auth := func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		id, aid, err := g.m.access.use(c.User(), key, g.m.now())
		if err != nil {
			if !errors.Is(err, errNeedKey) {
				g.failed(ip)
				if aid != "" { // a real token used wrongly: worth a record
					_ = auditLog("sandbox-access:"+aid, "ssh:"+ip, "sandbox ssh", "", err)
				}
			}
			return nil, err
		}
		if sb, err := g.m.st.get(id, sandboxCaller{Role: "admin"}); err != nil || sb.State != "running" {
			return nil, errors.New("the sandbox isn't running")
		}
		_ = auditLog("sandbox-access:"+aid, "ssh:"+ip, "sandbox ssh", id, nil)
		return &ssh.Permissions{Extensions: map[string]string{"sandbox": id, "access": aid}}, nil
	}
	cfg := &ssh.ServerConfig{
		NoClientAuth:         true, // "none" with a token not bound to a key
		NoClientAuthCallback: func(c ssh.ConnMetadata) (*ssh.Permissions, error) { return auth(c, nil) },
		PublicKeyCallback:    auth,
		MaxAuthTries:         6,
		ServerVersion:        "SSH-2.0-ZiroSandbox",
	}
	cfg.AddHostKey(g.signer)
	return cfg
}

func (g *sshGateway) handle(c net.Conn, ip string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(sshHandshakeLimit))
	sc, chans, reqs, err := ssh.NewServerConn(c, g.config(ip))
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sc.Close()
	go ssh.DiscardRequests(reqs) // tcpip-forward and friends: refused
	id := sc.Permissions.Extensions["sandbox"]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // keep the session alive past the idle reaper, and end it with the sandbox
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if sb, err := g.m.st.get(id, sandboxCaller{Role: "admin"}); err != nil || sb.State != "running" {
					sc.Close()
					return
				}
				g.m.touch(id)
			}
		}
	}()
	g.m.touch(id)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go g.session(ctx, id, nc)
		case "direct-tcpip":
			go g.forward(id, nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "not available on the sandbox gateway")
		}
	}
}

// sessionEnv are the client variables a session passes on (ssh SendEnv).
func sessionEnv(name string) bool {
	return name == "LANG" || name == "TZ" || name == "COLORTERM" || strings.HasPrefix(name, "LC_")
}

type ptyRequest struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

// sandboxShell starts bash when the image has it, sh otherwise.
const sandboxShell = "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"

func (g *sshGateway) session(ctx context.Context, id string, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	var pty *ptyRequest
	var env []string
	var master *os.File
	started := false
	done := make(chan int, 1)
	for {
		var req *ssh.Request
		select {
		case req = <-reqs:
		case code := <-done:
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		}
		if req == nil {
			return
		}
		ok := false
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) == nil && !started {
				pty, ok = &p, true
			}
		case "window-change":
			var w struct{ Cols, Rows, Width, Height uint32 }
			if ssh.Unmarshal(req.Payload, &w) == nil && master != nil {
				ok = setWinsize(master, w.Cols, w.Rows) == nil
			}
		case "env":
			var e struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &e) == nil && sessionEnv(e.Name) && len(env) < 32 && len(e.Value) < 4096 && !strings.ContainsRune(e.Value, 0) {
				env, ok = append(env, e.Name+"="+e.Value), true
			}
		case "shell", "exec":
			if started {
				break
			}
			command := sandboxShell
			if req.Type == "exec" {
				var e struct{ Command string }
				if ssh.Unmarshal(req.Payload, &e) != nil || len(e.Command) > 64<<10 || strings.ContainsRune(e.Command, 0) {
					break
				}
				command = e.Command
			}
			m, err := g.start(ctx, id, ch, pty, env, command, done)
			if err != nil {
				fmt.Fprintf(ch.Stderr(), "ziro-sandboxd: %v\r\n", err)
				break
			}
			master, started, ok = m, true, true
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

// start runs a session's command in the sandbox and reports its exit code on done.
func (g *sshGateway) start(ctx context.Context, id string, ch ssh.Channel, pty *ptyRequest, env []string, command string, done chan<- int) (*os.File, error) {
	sb, err := g.m.st.get(id, sandboxCaller{Role: "admin"})
	if err != nil || sb.State != "running" {
		return nil, errors.New("the sandbox isn't running")
	}
	args := []string{"exec", "-i"}
	if pty != nil {
		term := pty.Term
		if term == "" || len(term) > 64 || strings.ContainsAny(term, "=\x00") {
			term = "xterm"
		}
		args = append(args, "-t", "-e", "TERM="+term)
	}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, sandboxContainer(id), "--", "/bin/sh", "-c", command)
	cmd := sandboxExecCommand(ctx, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	var filter *exitFilter // nerdctl's own "exit code N" line, kept out of the session
	wait := func(copied *sync.WaitGroup) {
		err := cmd.Wait()
		copied.Wait()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			code = 255
		}
		code = filter.finish(code)
		g.m.touch(id)
		done <- code
	}
	var copied sync.WaitGroup
	if pty != nil {
		master, err := startPTY(cmd, pty.Cols, pty.Rows)
		if err != nil {
			return nil, err
		}
		filter = newExitFilter(ch)
		go func() { _, _ = io.Copy(master, ch) }()
		copied.Add(1)
		go func() { defer copied.Done(); _, _ = io.Copy(filter, master) }() // ends with EIO when the command exits
		go func() { wait(&copied); master.Close() }()
		return master, nil
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	filter = newExitFilter(ch.Stderr())
	cmd.Stdout, cmd.Stderr = ch, filter
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _, _ = io.Copy(stdin, ch); stdin.Close() }()
	go wait(&copied)
	return nil, nil
}

// forward is ssh -L: a TCP connection to a port of the token's sandbox, and nothing else.
func (g *sshGateway) forward(id string, nc ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if ssh.Unmarshal(nc.ExtraData(), &p) != nil || p.Port == 0 || p.Port > 65535 {
		_ = nc.Reject(ssh.ConnectionFailed, "bad forward request")
		return
	}
	sb, err := g.m.st.get(id, sandboxCaller{Role: "admin"})
	if err != nil || sb.State != "running" {
		_ = nc.Reject(ssh.ConnectionFailed, "the sandbox isn't running")
		return
	}
	switch p.Host {
	case "localhost", "127.0.0.1", "::1", "sandbox", sb.IP:
	default:
		_ = nc.Reject(ssh.Prohibited, "only the sandbox itself can be reached (use localhost)")
		return
	}
	if sb.IP == "" {
		_ = nc.Reject(ssh.Prohibited, "the sandbox has no network: create it with --net or --allow to forward ports")
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(sb.IP, strconv.Itoa(int(p.Port))), 5*time.Second)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "nothing listens on that port of the sandbox (listen on 0.0.0.0)")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	g.m.touch(id)
	go func() { _, _ = io.Copy(up, ch); up.(*net.TCPConn).CloseWrite() }()
	_, _ = io.Copy(ch, up)
	ch.Close()
	up.Close()
}

// knownHostsLine is the gateway's key as a known_hosts line for host:port.
func knownHostsLine(host string, port int, key ssh.PublicKey) string {
	h := host
	if port != 22 {
		h = fmt.Sprintf("[%s]:%d", host, port)
	}
	return h + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// sshCommand is the command a client runs to reach a sandbox with a token.
func sshCommand(user, host string, port int) string {
	if port == 22 {
		return "ssh " + user + "@" + host
	}
	return "ssh -p " + strconv.Itoa(port) + " " + user + "@" + host
}

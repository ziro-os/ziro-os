package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) (ssh.Signer, string) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func TestSandboxAccessTokens(t *testing.T) {
	m, _, now := stubSandboxes(t)
	sb, err := m.create(context.Background(), schema.SandboxSpec{Image: "a", Timeout: "2h"}, alice)
	if err != nil {
		t.Fatal(err)
	}
	s := m.access
	tok, rec, err := s.create(sb.ID, sdkapi.SandboxAccessRequest{}, *now, sb.Expires)
	if err != nil || !sandboxTokenRe.MatchString(tok) || !rec.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("%s %+v %v", tok, rec, err)
	}
	if b, _ := os.ReadFile(accessFile(sb.ID)); strings.Contains(string(b), tok) || !strings.Contains(string(b), hashToken(tok)) {
		t.Fatal("the token itself was stored")
	}
	if fi, _ := os.Stat(accessFile(sb.ID)); fi.Mode().Perm() != 0600 {
		t.Fatal("access file not 0600")
	}
	// Never past the sandbox's own expiry; ttl bounds.
	if _, r, _ := s.create(sb.ID, sdkapi.SandboxAccessRequest{TTL: "24h"}, *now, sb.Expires); !r.Expires.Equal(sb.Expires) {
		t.Errorf("outlives the sandbox: %v", r.Expires)
	}
	for _, bad := range []sdkapi.SandboxAccessRequest{{TTL: "25h"}, {TTL: "10s"}, {PublicKey: "not a key"}, {PublicKey: "ssh-ed25519 AAAA x\nssh-rsa B y"}} {
		if _, _, err := s.create(sb.ID, bad, *now, sb.Expires); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if id, _, err := s.use(tok, nil, *now); err != nil || id != sb.ID {
		t.Fatalf("use: %s %v", id, err)
	}
	if _, _, err := s.use("zsbx_"+strings.Repeat("a", 26), nil, *now); err == nil {
		t.Error("unknown token accepted")
	}
	if _, _, err := s.use(tok, nil, now.Add(2*time.Hour)); err == nil {
		t.Error("expired token accepted")
	}
	// Single use.
	one, _, _ := s.create(sb.ID, sdkapi.SandboxAccessRequest{SingleUse: true}, *now, sb.Expires)
	if _, _, err := s.use(one, nil, *now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.use(one, nil, *now); err == nil {
		t.Error("single-use token used twice")
	}
	// Bound to a key: none is not enough, the wrong key fails, the right one works.
	signer, line := testKey(t)
	other, _ := testKey(t)
	bound, brec, err := s.create(sb.ID, sdkapi.SandboxAccessRequest{PublicKey: line + " me@laptop"}, *now, sb.Expires)
	if err != nil || brec.view().KeyFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal(err)
	}
	if _, _, err := s.use(bound, nil, *now); !errors.Is(err, errNeedKey) {
		t.Errorf("none on a bound token: %v", err)
	}
	if _, _, err := s.use(bound, other.PublicKey(), *now); err == nil {
		t.Error("wrong key accepted")
	}
	if _, _, err := s.use(bound, signer.PublicKey(), *now); err != nil {
		t.Errorf("right key: %v", err)
	}
	// Reload from disk, list without secrets, revoke.
	s2 := loadAccessStore([]string{sb.ID})
	list := s2.list(sb.ID)
	if len(list) != 3 || list[0].Username != "" { // the spent single-use token was pruned
		t.Fatalf("list %+v", list)
	}
	if err := s2.revoke(sb.ID, rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.use(tok, nil, *now); err == nil {
		t.Error("revoked token accepted")
	}
	if s2.revoke(sb.ID, rec.ID) == nil {
		t.Error("revoked twice")
	}
	// Deleting the sandbox drops its tokens.
	m.access = s2
	if err := m.remove(sb.ID, alice); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.use(bound, signer.PublicKey(), *now); err == nil {
		t.Error("token outlived its sandbox")
	}
}

func TestSandboxFiles(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	sb, err := m.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	if err != nil {
		t.Fatal(err)
	}
	h := m.routes()
	call := func(c sandboxCaller, method, path string, body io.Reader) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/v1/sandboxes/"+sb.ID+"/files?"+path, body)
		r.Header.Set(hdrOwner, c.Owner)
		r.Header.Set(hdrRole, c.Role)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call(alice, "PUT", "path=/workspace/src/main.py&mode=0755", strings.NewReader("print(1)\n")); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	ws := filepath.Join(sandboxDir(sb.ID), "workspace")
	if fi, err := os.Stat(filepath.Join(ws, "src/main.py")); err != nil || fi.Mode().Perm() != 0755 {
		t.Fatalf("written: %v", err)
	}
	if w := call(alice, "GET", "path=src/main.py", nil); w.Code != 200 || w.Body.String() != "print(1)\n" || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("get: %d %q", w.Code, w.Body)
	}
	w := call(alice, "GET", "path=/workspace", nil)
	var list []sdkapi.SandboxFile
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 1 || list[0].Name != "src" || !list[0].Dir {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	// Nothing outside the workspace: paths, and symlinks the sandbox planted.
	os.Symlink("/etc", filepath.Join(ws, "etc"))
	os.Symlink("/etc/passwd", filepath.Join(ws, "passwd"))
	for _, p := range []string{"path=/etc/passwd", "path=etc/passwd", "path=passwd", "path=../../../../etc/passwd"} {
		if w := call(alice, "GET", p, nil); w.Code == 200 && strings.Contains(w.Body.String(), "root:") {
			t.Errorf("%s escaped the workspace", p)
		}
	}
	if w := call(alice, "PUT", "path=etc/evil", strings.NewReader("x")); w.Code == 200 {
		t.Error("wrote through a symlink out of the workspace")
	}
	if _, err := os.Stat("/etc/evil"); err == nil {
		t.Fatal("/etc/evil exists")
	}
	if w := call(bob, "GET", "path=src/main.py", nil); w.Code != 404 {
		t.Errorf("bob read alice's file: %d", w.Code)
	}
	if w := call(alice, "PUT", "path=x&mode=4755", strings.NewReader("x")); w.Code != 400 {
		t.Errorf("setuid mode accepted: %d", w.Code)
	}
	if w := call(alice, "DELETE", "path=src", nil); w.Code != 400 {
		t.Errorf("non-empty dir removed without recursive: %d", w.Code)
	}
	if w := call(alice, "DELETE", "path=src&recursive=true", nil); w.Code != 200 {
		t.Errorf("recursive delete: %d %s", w.Code, w.Body)
	}
	if w := call(alice, "DELETE", "path=/workspace", nil); w.Code != 400 {
		t.Errorf("deleted the workspace: %d", w.Code)
	}
	if w := call(alice, "GET", "path=nope", nil); w.Code != 404 {
		t.Errorf("missing file: %d", w.Code)
	}
	for _, p := range []string{"", "/tmp/x", "/workspacex/a"} {
		if _, err := workspacePath(p); err == nil {
			t.Errorf("workspacePath(%q) accepted", p)
		}
	}
	if p, _ := workspacePath("/workspace/a/../../b"); p != "b" {
		t.Errorf("clean: %s", p)
	}
}

// The gateway end to end, over a real SSH client: token auth, exec with exit status, key-bound
// tokens, ssh -L to the sandbox only, and refusals.
func TestSandboxSSHGateway(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	m.now = time.Now
	sb, err := m.create(context.Background(), schema.SandboxSpec{Image: "a", Network: &schema.SandboxNetwork{Mode: "open"}}, alice)
	if err != nil {
		t.Fatal(err)
	}
	m.st.update(sb.ID, func(x *sdkapi.Sandbox) { x.IP = "127.0.0.1" }) // the test's "sandbox" is this host
	var gotArgs []string
	old := sandboxExecCommand
	sandboxExecCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		gotArgs = args
		// what nerdctl exec does: exit 1 and log the command's status
		return exec.CommandContext(ctx, "sh", "-c", `cat; echo out; echo err >&2; echo 'time="x" level=fatal msg="exec failed with exit code 3"' >&2; exit 1`)
	}
	defer func() { sandboxExecCommand = old }()
	host, _ := testKey(t)
	m.ssh = newSSHGateway(m, host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.ssh.accept(ctx, ln)
	addr := ln.Addr().String()

	tok, _, err := m.access.create(sb.ID, sdkapi.SandboxAccessRequest{}, time.Now(), sb.Expires)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: auth, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second})
	}
	c, err := dial(tok)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	var out, errb bytes.Buffer
	sess.Stdin, sess.Stdout, sess.Stderr = strings.NewReader("in\n"), &out, &errb
	sess.Setenv("LANG", "C.UTF-8")
	sess.Setenv("LD_PRELOAD", "/evil.so") // not passed on
	err = sess.Run("python3 app.py")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 || out.String() != "in\nout\n" || errb.String() != "err\n" {
		t.Fatalf("run: %v %q %q", err, out.String(), errb.String())
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "exec -i -e LANG=C.UTF-8 ziro-sbx-"+sb.ID+" -- /bin/sh -c python3 app.py") || strings.Contains(joined, "LD_PRELOAD") {
		t.Errorf("exec args %q", joined)
	}
	// sftp and remote forwarding are refused.
	s2, _ := c.NewSession()
	if err := s2.RequestSubsystem("sftp"); err == nil {
		t.Error("sftp accepted")
	}
	if _, err := c.Listen("tcp", "0.0.0.0:8080"); err == nil {
		t.Error("remote forwarding accepted")
	}
	// ssh -L reaches the sandbox's own address only.
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			k, err := echo.Accept()
			if err != nil {
				return
			}
			io.Copy(k, k)
			k.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	fw, err := c.Dial("tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	fw.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(fw, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("forward echo: %q %v", buf, err)
	}
	fw.Close()
	if _, err := c.Dial("tcp", "10.0.0.1:22"); err == nil {
		t.Error("forward to another host accepted")
	}
	// A bad token fails; a key-bound token needs its key.
	if _, err := dial("zsbx_" + strings.Repeat("b", 26)); err == nil {
		t.Error("unknown token logged in")
	}
	signer, line := testKey(t)
	bound, _, _ := m.access.create(sb.ID, sdkapi.SandboxAccessRequest{PublicKey: line}, time.Now(), sb.Expires)
	if _, err := dial(bound); err == nil {
		t.Error("bound token logged in without its key")
	}
	other, _ := testKey(t)
	if _, err := dial(bound, ssh.PublicKeys(other)); err == nil {
		t.Error("bound token logged in with another key")
	}
	c2, err := dial(bound, ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("bound token with its key: %v", err)
	}
	c2.Close()
	// A paused sandbox can't be entered.
	m.st.update(sb.ID, func(x *sdkapi.Sandbox) { x.State = "paused" })
	if _, err := dial(tok); err == nil {
		t.Error("logged into a paused sandbox")
	}
}

func TestSandboxAccessAPI(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	host, _ := testKey(t)
	m.ssh = newSSHGateway(m, host)
	sb, _ := m.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	h := m.routes()
	r := httptest.NewRequest("POST", "/v1/sandboxes/"+sb.ID+"/access", strings.NewReader(`{"ttl":"30m","single_use":true}`))
	r.Header.Set(hdrOwner, "alice")
	r.Header.Set(hdrRole, "deployer")
	r.Header.Set(hdrHost, "sbx.example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var v sdkapi.SandboxAccess
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if v.SSH != "ssh -p 22998 "+v.Username+"@sbx.example.com" || !strings.HasPrefix(v.HostKey, "[sbx.example.com]:22998 ssh-ed25519 ") {
		t.Errorf("%+v", v)
	}
	r = httptest.NewRequest("GET", "/v1/sandboxes/"+sb.ID+"/access", nil)
	r.Header.Set(hdrOwner, "bob")
	r.Header.Set(hdrRole, "deployer")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("bob listed alice's tokens: %d", w.Code)
	}
	_ = http.StatusOK
}

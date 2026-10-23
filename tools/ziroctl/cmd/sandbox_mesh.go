package cmd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// The node side of sandbox clustering (sandbox_cluster.go): ziro-sandboxd serves its API on
// the mesh for the master, answers token checks for SSH edges, and relays SSH sessions for
// sandboxes on other nodes.

// meshState is the node's current cluster view (nil off a cluster).
type meshState struct {
	mu     sync.Mutex
	cfg    atomic.Pointer[sandboxMeshConfig]
	listen string
	srv    *http.Server
	prv    *http.Server
}

func (m *sandboxManager) meshCfg() *sandboxMeshConfig {
	if m.mesh == nil {
		return nil
	}
	return m.mesh.cfg.Load()
}

// syncMesh (re)starts the mesh listeners when the agent wrote a new config.
func (m *sandboxManager) syncMesh() {
	c := loadSandboxMesh()
	ms := m.mesh
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.cfg.Store(c)
	clusterPreviews.Store(c != nil)
	if m.ssh != nil { // every gateway of the cluster presents the same host key
		var shared *ssh.Signer
		if c != nil && c.HostKey != "" {
			if s, err := ssh.ParsePrivateKey([]byte(c.HostKey)); err == nil {
				shared = &s
			}
		}
		m.ssh.shared.Store(shared)
	}
	want := ""
	if c != nil {
		want = c.Listen
	}
	if want == ms.listen {
		return
	}
	for _, s := range []*http.Server{ms.srv, ms.prv} {
		if s != nil {
			_ = s.Close()
		}
	}
	ms.srv, ms.prv, ms.listen = nil, nil, want
	if c == nil {
		return
	}
	ms.srv = &http.Server{Addr: c.Listen, Handler: m.meshHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func(s *http.Server) {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("[sandboxd] mesh api: %v\n", err)
		}
	}(ms.srv)
	if m.previewKey != nil { // the cluster's gateways reach previews over the mesh
		host, _, _ := net.SplitHostPort(c.Listen)
		ms.prv = &http.Server{Addr: net.JoinHostPort(host, strconv.Itoa(m.previewPort)), Handler: m.previewHandler(),
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("[sandboxd] mesh previews: %v\n", err)
			}
		}(ms.prv)
	}
	fmt.Printf("[sandboxd] cluster: sandbox API on %s\n", c.Listen)
}

var clusterPreviews atomic.Bool // the master manages preview routes on a cluster

// meshAuthorized checks the cluster's sandbox token.
func (m *sandboxManager) meshAuthorized(r *http.Request) bool {
	c := m.meshCfg()
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return c != nil && subtle.ConstantTimeCompare([]byte(got), []byte(c.Token)) == 1
}

func (m *sandboxManager) meshHandler() http.Handler {
	api := m.routes()
	mux := http.NewServeMux()
	// An SSH edge checks a token for one of this node's sandboxes (and spends a single-use one).
	mux.HandleFunc("POST /v1/access/check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
			Key   string `json:"key,omitempty"` // authorized_keys line the client proved
		}
		if err := decodeStrict(w, r, &req, 16<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		var key ssh.PublicKey
		if req.Key != "" {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.Key))
			if err != nil {
				apiReply(w, err, nil)
				return
			}
			key = k
		}
		id, aid, err := m.access.use(req.Token, key, m.now())
		switch {
		case errors.Is(err, errNeedKey):
			apiError(w, http.StatusUnauthorized, "need_key")
		case err != nil:
			apiError(w, http.StatusForbidden, err.Error())
		default:
			apiReply(w, nil, map[string]string{"sandbox": id, "access": aid})
		}
	})
	mux.HandleFunc("GET /v1/ssh/hostkey", func(w http.ResponseWriter, r *http.Request) {
		if m.ssh == nil {
			apiError(w, http.StatusNotFound, "the SSH gateway is off")
			return
		}
		apiReply(w, nil, map[string]any{"key": string(ssh.MarshalAuthorizedKey(m.ssh.signer().PublicKey())), "port": m.ssh.port})
	})
	// The master asks which nodes have warm pool sandboxes before placing a template create.
	mux.HandleFunc("GET /v1/pools", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, m.warmPools())
	})
	// Snapshot replication (sandbox_snapshot_sync.go): the master streams one node's export into
	// another's import.
	mux.HandleFunc("GET /v1/snapshots/export", m.exportSnapshot)
	mux.HandleFunc("PUT /v1/snapshots/import", m.importSnapshot)
	mux.Handle("/", api)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.meshAuthorized(r) {
			apiError(w, http.StatusUnauthorized, "invalid cluster token")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		mux.ServeHTTP(w, r)
	})
}

// meshCall sends a request to another node's sandbox API.
func meshCall(ctx context.Context, addr, token, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+addr+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := meshHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e APIMessage
		_ = json.Unmarshal(raw, &e)
		return resp.StatusCode, errors.New(e.Message)
	}
	if out != nil {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

var meshHTTP = &http.Client{Timeout: 30 * time.Second, Transport: sandboxMeshTransport} // pooled, as the master's

// remoteAccess asks the node that owns a token's sandbox to check it (the SSH edge).
func (g *sshGateway) remoteAccess(tok string, key ssh.PublicKey) (owner, sandbox, aid string, err error) {
	c := g.m.meshCfg()
	id := tokenSandbox(tok)
	if c == nil || id == "" {
		return "", "", "", errors.New("unknown token")
	}
	// Where the sandbox runs; a sandbox newer than this node's view: ask every sandbox node
	// (only the owner knows the token).
	ips := c.Nodes
	if w := c.Where[id]; w != "" {
		ips = []string{w}
	}
	body := map[string]string{"token": tok}
	if key != nil {
		body["key"] = string(ssh.MarshalAuthorizedKey(key))
	}
	// Every candidate at once: only the owner knows the token (the others refuse it at once, and
	// a single-use token is spent only by the owner), so the first acceptance is the answer.
	type answer struct {
		ip, sandbox, access string
		needKey             bool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	found := make(chan answer, len(ips))
	var wg sync.WaitGroup
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, strconv.Itoa(sandboxMeshPort))
		if addr == c.Listen {
			continue // ours, and not found
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var res map[string]string
			code, err := meshCall(ctx, addr, c.Token, "POST", "/v1/access/check", body, &res)
			switch {
			case code == http.StatusUnauthorized && err != nil && err.Error() == "need_key":
				found <- answer{needKey: true}
			case err == nil:
				found <- answer{ip: ip, sandbox: res["sandbox"], access: res["access"]}
			}
		}()
	}
	go func() { wg.Wait(); close(found) }()
	a, ok := <-found // the first answer; closed with none when every node refused the token
	switch {
	case !ok:
		return "", "", "", errors.New("unknown token")
	case a.needKey:
		return "", "", "", errNeedKey
	}
	return a.ip, a.sandbox, a.access, nil
}

// ownerHostKeys caches the gateways' host keys (the cluster's, the same everywhere and rarely
// rotated) per node, so a relayed connection doesn't cost a mesh call before its handshake.
var ownerHostKeys struct {
	sync.Mutex
	m map[string]ownerHostKey
}

type ownerHostKey struct {
	key  ssh.PublicKey
	port int
	at   time.Time
}

const ownerHostKeyTTL = 10 * time.Minute

func (g *sshGateway) ownerHostKey(c *sandboxMeshConfig, ownerIP string, fresh bool) (ssh.PublicKey, int, error) {
	ownerHostKeys.Lock()
	k, ok := ownerHostKeys.m[ownerIP]
	ownerHostKeys.Unlock()
	if ok && !fresh && time.Since(k.at) < ownerHostKeyTTL {
		return k.key, k.port, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var hk struct {
		Key  string `json:"key"`
		Port int    `json:"port"`
	}
	if _, err := meshCall(ctx, net.JoinHostPort(ownerIP, strconv.Itoa(sandboxMeshPort)), c.Token, "GET", "/v1/ssh/hostkey", nil, &hk); err != nil {
		return nil, 0, err
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk.Key))
	if err != nil {
		return nil, 0, err
	}
	ownerHostKeys.Lock()
	if ownerHostKeys.m == nil {
		ownerHostKeys.m = map[string]ownerHostKey{}
	}
	ownerHostKeys.m[ownerIP] = ownerHostKey{pinned, hk.Port, time.Now()}
	ownerHostKeys.Unlock()
	return pinned, hk.Port, nil
}

// relay serves an SSH connection for a sandbox on another node: it logs in to the owner's
// gateway as the relay (with the cluster's host key; the owner's pinned from the mesh API) and
// passes every channel and request through.
func (g *sshGateway) relay(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, ownerIP, id string) {
	c := g.m.meshCfg()
	if c == nil {
		return
	}
	dial := func(fresh bool) (*ssh.Client, error) {
		pinned, port, err := g.ownerHostKey(c, ownerIP, fresh)
		if err != nil {
			return nil, err
		}
		return ssh.Dial("tcp", net.JoinHostPort(ownerIP, strconv.Itoa(port)), &ssh.ClientConfig{
			User: "zrelay_" + id, Auth: []ssh.AuthMethod{ssh.PublicKeys(g.signer())},
			HostKeyCallback: ssh.FixedHostKey(pinned), Timeout: 10 * time.Second})
	}
	up, err := dial(false)
	if err != nil { // a rotated key or a moved port: once more with what the owner says now
		if up, err = dial(true); err != nil {
			return
		}
	}
	defer up.Close()
	go func() { _ = up.Wait(); sc.Close() }()
	for nc := range chans {
		go relayChannel(up, nc)
	}
}

func relayChannel(up *ssh.Client, nc ssh.NewChannel) {
	uch, ureqs, err := up.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		var oe *ssh.OpenChannelError
		if errors.As(err, &oe) {
			_ = nc.Reject(oe.Reason, oe.Message)
		} else {
			_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	dch, dreqs, err := nc.Accept()
	if err != nil {
		uch.Close()
		return
	}
	pipeRequests := func(in <-chan *ssh.Request, out ssh.Channel) {
		for r := range in {
			ok, err := out.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				_ = r.Reply(ok && err == nil, nil)
			}
		}
	}
	upDone := make(chan struct{})
	go pipeRequests(dreqs, uch)
	go func() { pipeRequests(ureqs, dch); close(upDone) }() // ends when the owner closes the channel
	go func() { _, _ = io.Copy(uch, dch); _ = uch.CloseWrite() }()
	go func() { _, _ = io.Copy(dch.Stderr(), uch.Stderr()) }()
	_, _ = io.Copy(dch, uch)
	_ = dch.CloseWrite()
	select { // exit-status comes as a request just before the owner closes
	case <-upDone:
	case <-time.After(5 * time.Second):
	}
	dch.Close()
	uch.Close()
}

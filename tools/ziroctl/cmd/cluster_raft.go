package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

// HA control plane. Every master runs Raft (a single master is a one-voter group). The leader's
// cluster-master process owns the live state; each change to the desired state (apps,
// placement, tokens, policy, routes, peers, secrets, CA) is committed as one log entry holding
// the whole state, and every master's FSM writes it to its state files. Node liveness
// (last seen, running containers, ...) changes with every heartbeat and stays in the leader's
// memory, so heartbeats never touch the log; a new leader gives every node a grace period.
// ponytail: whole-state entries; switch to deltas if the state grows past ~1 MB.
//
// Writes from ziroctl on any master go through a root-only unix socket to the local
// cluster-master, as compare-and-swap proposals keyed on the Raft index; followers forward
// them to the leader over mutual TLS. Agents that reach a follower are redirected to the
// leader (HTTP 421).

var localRaft *raftStore // set inside `cluster serve`

var errNotLeader = errors.New("this master is not the Raft leader")
var errConflict = errors.New("state changed concurrently")

func raftDir() string     { return filepath.Join(clusterDir, "raft") }
func clusterSock() string { return "/run/ziro/cluster-master.sock" }

// raftMode: this node is a master whose state lives in Raft (any master after its first
// cluster-master start on this version).
func raftMode() bool {
	cfg, err := loadClusterConfig()
	return err == nil && cfg.Role == "master" && fileExists(filepath.Join(raftDir(), "raft.db"))
}

type raftPayload struct {
	State   json.RawMessage              `json:"state"`
	Secrets map[string]map[string]string `json:"secrets"`
	CAKey   string                       `json:"ca_key,omitempty"`
}

func encodePayload(st *ClusterState) ([]byte, error) {
	s, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return json.Marshal(raftPayload{State: s, Secrets: st.Secrets, CAKey: st.CAKey})
}

func decodePayload(b []byte) (*ClusterState, error) {
	var p raftPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	st := &ClusterState{}
	if err := json.Unmarshal(p.State, st); err != nil {
		return nil, err
	}
	if st.NodeTokens == nil {
		st.NodeTokens = map[string]string{}
	}
	if st.History == nil {
		st.History = map[string][]ClusteredApp{}
	}
	st.Secrets, st.CAKey = p.Secrets, p.CAKey
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]string{}
	}
	return st, nil
}

// hardKey is the state without per-heartbeat liveness fields: a change here is a Raft commit.
func hardKey(st *ClusterState) []byte {
	cp := *st
	cp.Nodes = append([]ClusterNode(nil), st.Nodes...)
	for i := range cp.Nodes {
		n := &cp.Nodes[i]
		n.Status, n.LastSeen, n.Containers, n.Running, n.Failed, n.MeshError = "", time.Time{}, 0, nil, nil, ""
	}
	b, _ := encodePayload(&cp)
	return b
}

func cloneState(st *ClusterState) *ClusterState {
	b, err := encodePayload(st)
	if err != nil {
		panic(err) // state always encodes
	}
	c, err := decodePayload(b)
	if err != nil {
		panic(err)
	}
	return c
}

// ---- FSM ----

type raftFSM struct {
	mu      sync.Mutex
	dir     string // where applied state is written (state.json, secrets.json, ca.key)
	payload []byte
	index   uint64
}

func (f *raftFSM) Apply(l *raft.Log) any {
	if l.Type != raft.LogCommand {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payload, f.index = l.Data, l.Index
	return f.persist(l.Data)
}

func (f *raftFSM) persist(b []byte) error {
	st, err := decodePayload(b)
	if err != nil {
		return err
	}
	return saveStateFiles(f.dir, st)
}

func (f *raftFSM) latest() ([]byte, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.payload, f.index
}

func (f *raftFSM) Snapshot() (raft.FSMSnapshot, error) {
	b, _ := f.latest()
	return &fsmSnapshot{data: append([]byte(nil), b...)}, nil
}

func (f *raftFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payload = b
	if len(b) == 0 {
		return nil
	}
	return f.persist(b)
}

type fsmSnapshot struct{ data []byte }

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}

// ---- store ----

type raftStore struct {
	mu      sync.Mutex
	r       *raft.Raft
	fsm     *raftFSM
	id      string
	dir     string
	cur     *ClusterState // live state, leader only
	hardKey []byte
	version uint64 // Raft index of the last committed state (CAS token)
	leading bool
	grace   time.Duration
	// importFn supplies the initial state when this node bootstraps a new Raft group.
	importFn func() (*ClusterState, error)
}

func newRaftStore(id, dir string, trans raft.Transport, logs raft.LogStore, stable raft.StableStore,
	snaps raft.SnapshotStore, bootstrap bool, importFn func() (*ClusterState, error)) (*raftStore, error) {
	rs := &raftStore{id: id, dir: dir, fsm: &raftFSM{dir: dir}, grace: nodeTimeout, importFn: importFn}
	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(id)
	conf.SnapshotThreshold, conf.TrailingLogs, conf.SnapshotInterval = 64, 128, 30*time.Second
	conf.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Warn, Output: os.Stdout})
	notify := make(chan bool, 4)
	conf.NotifyCh = notify
	r, err := raft.NewRaft(conf, rs.fsm, logs, stable, snaps, trans)
	if err != nil {
		return nil, err
	}
	rs.r = r
	if bootstrap {
		has, err := raft.HasExistingState(logs, stable, snaps)
		if err != nil {
			return nil, err
		}
		if !has {
			if err := r.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
				{ID: raft.ServerID(id), Address: trans.LocalAddr(), Suffrage: raft.Voter}}}).Error(); err != nil {
				return nil, err
			}
		}
	}
	go func() {
		for leading := range notify {
			rs.onLeadership(leading)
		}
	}()
	return rs, nil
}

// onLeadership loads the committed state (after a barrier, so every entry is applied) and
// grants every node a grace period: liveness was not replicated.
func (rs *raftStore) onLeadership(leading bool) {
	if !leading {
		rs.mu.Lock()
		rs.leading, rs.cur = false, nil
		rs.mu.Unlock()
		fmt.Println("[cluster] no longer the Raft leader")
		return
	}
	if err := rs.r.Barrier(30 * time.Second).Error(); err != nil {
		fmt.Printf("[cluster] leadership barrier: %v\n", err)
		return
	}
	payload, index := rs.fsm.latest()
	var st *ClusterState
	var err error
	if len(payload) == 0 {
		if rs.importFn == nil {
			fmt.Println("[cluster] leader without state and nothing to import")
			return
		}
		st, err = rs.importFn()
	} else {
		st, err = decodePayload(payload)
	}
	if err != nil {
		fmt.Printf("[cluster] leader state: %v\n", err)
		return
	}
	now := time.Now()
	for i := range st.Nodes {
		if st.Nodes[i].Status == "Ready" {
			st.Nodes[i].LastSeen = now // grace: a full timeout to report to the new leader
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.cur, rs.version, rs.leading = st, index, true
	if len(payload) == 0 { // first leader of a new group: commit the imported state
		rs.hardKey = nil
		if err := rs.commitLocked(st); err != nil {
			fmt.Printf("[cluster] import state: %v\n", err)
			rs.leading, rs.cur = false, nil
			return
		}
	} else {
		rs.hardKey = hardKey(st)
	}
	fmt.Printf("[cluster] %s is the Raft leader (index %d)\n", rs.id, rs.version)
}

func (rs *raftStore) isLeader() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.leading
}

func (rs *raftStore) commitLocked(st *ClusterState) error {
	key := hardKey(st)
	if !bytes.Equal(key, rs.hardKey) {
		data, err := encodePayload(st)
		if err != nil {
			return err
		}
		f := rs.r.Apply(data, 15*time.Second)
		if err := f.Error(); err != nil {
			return err
		}
		if resp, ok := f.Response().(error); ok && resp != nil {
			return resp
		}
		rs.hardKey, rs.version = key, f.Index()
	}
	rs.cur = st
	// Liveness-only changes are not committed; keep the local file fresh for readers here.
	return writeJSONAtomic(filepath.Join(rs.dir, "state.json"), st)
}

func (rs *raftStore) mutate(fn func(st *ClusterState) error) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !rs.leading || rs.cur == nil {
		return errNotLeader
	}
	st := cloneState(rs.cur)
	if err := fn(st); err != nil {
		return err
	}
	return rs.commitLocked(st)
}

// snapshot returns the live state and its version (leader), or the last applied state.
func (rs *raftStore) snapshot() (*ClusterState, uint64, error) {
	rs.mu.Lock()
	if rs.leading && rs.cur != nil {
		defer rs.mu.Unlock()
		return cloneState(rs.cur), rs.version, nil
	}
	rs.mu.Unlock()
	b, idx := rs.fsm.latest()
	if len(b) == 0 {
		return nil, 0, errors.New("no cluster state replicated yet")
	}
	st, err := decodePayload(b)
	return st, idx, err
}

// propose applies a full state computed by ziroctl from version. Liveness and the CA key
// always come from the live state: the CLI never sees or changes them.
func (rs *raftStore) propose(version uint64, st *ClusterState) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !rs.leading || rs.cur == nil {
		return errNotLeader
	}
	if version != rs.version {
		return errConflict
	}
	for i := range st.Nodes {
		if live := rs.cur.node(st.Nodes[i].ID); live != nil {
			n := &st.Nodes[i]
			n.Status, n.LastSeen, n.Containers, n.Running, n.Failed, n.MeshError =
				live.Status, live.LastSeen, live.Containers, live.Running, live.Failed, live.MeshError
		}
	}
	st.CAKey = rs.cur.CAKey
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]string{}
	}
	return rs.commitLocked(st)
}

func (rs *raftStore) addNonvoter(id, addr string) error {
	return rs.r.AddNonvoter(raft.ServerID(id), raft.ServerAddress(addr), 0, 15*time.Second).Error()
}

// promote makes a caught-up non-voter a voter.
func (rs *raftStore) promote(id string, applied uint64) error {
	if !rs.isLeader() {
		return errNotLeader
	}
	f := rs.r.GetConfiguration()
	if err := f.Error(); err != nil {
		return err
	}
	for _, s := range f.Configuration().Servers {
		if string(s.ID) != id {
			continue
		}
		if s.Suffrage == raft.Voter {
			return nil
		}
		if applied+16 < rs.r.AppliedIndex() {
			return fmt.Errorf("still catching up (%d of %d)", applied, rs.r.AppliedIndex())
		}
		return rs.r.AddVoter(s.ID, s.Address, 0, 15*time.Second).Error()
	}
	return fmt.Errorf("%s is not a cluster member", id)
}

// removeMember takes a master out of the Raft group and out of the cluster state.
// The node (and its token) goes first, while this leader can still commit; then the Raft
// membership. A leader removing itself steps down afterwards.
func (rs *raftStore) removeMember(id string) error {
	if !rs.isLeader() {
		return errNotLeader
	}
	members, err := rs.members()
	if err != nil {
		return err
	}
	voters, found := 0, false
	for _, m := range members {
		if m.Suffrage == "Voter" {
			voters++
		}
		found = found || m.ID == id
	}
	if !found {
		return fmt.Errorf("%s is not a control-plane member", id)
	}
	if voters <= 1 {
		return errors.New("refusing to remove the last voting master")
	}
	if err := rs.mutate(func(st *ClusterState) error {
		removeNode(st, id)
		scheduleReplicas(st, time.Now())
		return nil
	}); err != nil {
		return err
	}
	return rs.r.RemoveServer(raft.ServerID(id), 0, 15*time.Second).Error()
}

type memberView struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage string `json:"suffrage"`
	Leader   bool   `json:"leader"`
}

func (rs *raftStore) members() ([]memberView, error) {
	f := rs.r.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	_, leader := rs.r.LeaderWithID()
	var out []memberView
	for _, s := range f.Configuration().Servers {
		out = append(out, memberView{ID: string(s.ID), Address: string(s.Address), Suffrage: s.Suffrage.String(), Leader: s.ID == leader})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// leaderAPI is the leader's cluster API address (host:port), from the replicated node list.
func (rs *raftStore) leaderAPI(port string) (string, error) {
	_, id := rs.r.LeaderWithID()
	if id == "" {
		return "", errors.New("no Raft leader elected yet")
	}
	st, _, err := rs.snapshot()
	if err != nil {
		return "", err
	}
	if n := st.node(string(id)); n != nil && n.IP != "" {
		return net.JoinHostPort(n.IP, port), nil
	}
	return "", fmt.Errorf("leader %s has no known address", id)
}

func clusterPortOf(cfg *ClusterConfig) string {
	if _, p, err := net.SplitHostPort(cfg.MasterAddr); err == nil {
		return p
	}
	return "7443"
}

// raftAddr: Raft listens on the cluster port + 1.
func raftAddr(ip string, cfg *ClusterConfig) string {
	p, _ := strconv.Atoi(clusterPortOf(cfg))
	return net.JoinHostPort(ip, strconv.Itoa(p+1))
}

// masterAddrs lists every master's cluster API address, for agents to fail over between.
func masterAddrs(st *ClusterState, cfg *ClusterConfig) []string {
	var out []string
	for _, n := range st.Nodes {
		if n.Role == "master" && n.IP != "" {
			out = append(out, net.JoinHostPort(n.IP, clusterPortOf(cfg)))
		}
	}
	sort.Strings(out)
	return out
}

// ---- TLS transport for Raft ----

type tlsStreamLayer struct {
	net.Listener
	advertise net.Addr
	client    func() (*tls.Config, error)
}

func (t *tlsStreamLayer) Addr() net.Addr { return t.advertise }

func (t *tlsStreamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	c, err := t.client()
	if err != nil {
		return nil, err
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(addr), c)
}

// openRaftStore wires the production store: bbolt log, file snapshots, mutual-TLS transport.
func openRaftStore(cfg *ClusterConfig, st *ClusterState, importFn func() (*ClusterState, error)) (*raftStore, error) {
	if err := os.MkdirAll(raftDir(), 0700); err != nil {
		return nil, err
	}
	bolt, err := raftboltdb.NewBoltStore(filepath.Join(raftDir(), "raft.db"))
	if err != nil {
		return nil, err
	}
	snaps, err := raft.NewFileSnapshotStore(raftDir(), 2, os.Stdout)
	if err != nil {
		return nil, err
	}
	caPEM := st.CACert
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	adv := raftAddr(cfg.NodeIP, cfg)
	_, port, _ := net.SplitHostPort(adv)
	ln, err := tls.Listen("tcp", ":"+port, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() },
		ClientAuth:     tls.RequireAndVerifyClientCert, ClientCAs: pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			return verifyMaster(cs.PeerCertificates[0], caPEM)
		},
	})
	if err != nil {
		return nil, err
	}
	advAddr, err := net.ResolveTCPAddr("tcp", adv)
	if err != nil {
		return nil, err
	}
	stream := &tlsStreamLayer{Listener: ln, advertise: advAddr, client: func() (*tls.Config, error) { return masterClientTLS(caPEM) }}
	trans := raft.NewNetworkTransport(stream, 3, 10*time.Second, io.Discard)
	return newRaftStore(cfg.NodeID, clusterDir, trans, bolt, bolt, snaps, !cfg.RaftJoined, importFn)
}

// ---- local socket (ziroctl <-> cluster-master) and master-to-master forwarding ----

type stateEnvelope struct {
	Version uint64          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

// sanitizedPayload drops the CA key: it never leaves the masters' own processes.
func sanitizedPayload(st *ClusterState) (json.RawMessage, error) {
	cp := *st
	cp.CAKey = ""
	return encodePayload(&cp)
}

// localHandler serves ziroctl on the unix socket and other masters on /cluster/v1/internal/.
// Requests a follower cannot answer are forwarded to the leader.
func (rs *raftStore) localHandler(cfg *ClusterConfig, forward func(path string, body []byte) (*http.Response, error)) http.Handler {
	mux := http.NewServeMux()
	fwd := func(w http.ResponseWriter, r *http.Request, path string) {
		if r.Header.Get("X-Ziro-Forwarded") != "" { // one hop only: masters that disagree on the leader never loop
			http.Error(w, "no Raft leader reachable yet", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		resp, err := forward(path, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		if !rs.isLeader() {
			fwd(w, r, "/state")
			return
		}
		st, ver, err := rs.snapshot()
		if err == nil {
			var p json.RawMessage
			if p, err = sanitizedPayload(st); err == nil {
				_ = json.NewEncoder(w).Encode(stateEnvelope{Version: ver, Payload: p})
				return
			}
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/propose", func(w http.ResponseWriter, r *http.Request) {
		if !rs.isLeader() {
			fwd(w, r, "/propose")
			return
		}
		var env stateEnvelope
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&env); err != nil {
			http.Error(w, "invalid proposal", http.StatusBadRequest)
			return
		}
		st, err := decodePayload(env.Payload)
		if err == nil {
			err = rs.propose(env.Version, st)
		}
		switch {
		case errors.Is(err, errConflict):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/members", func(w http.ResponseWriter, r *http.Request) {
		m, err := rs.members()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("/members/remove", func(w http.ResponseWriter, r *http.Request) {
		if !rs.isLeader() {
			fwd(w, r, "/members/remove")
			return
		}
		var req struct{ ID string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || validName(req.ID) != nil {
			http.Error(w, "invalid member", http.StatusBadRequest)
			return
		}
		if err := rs.removeMember(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		clusterAudit("master:"+rs.id, "cluster member remove", req.ID, nil)
	})
	mux.HandleFunc("/promote", func(w http.ResponseWriter, r *http.Request) {
		if !rs.isLeader() {
			fwd(w, r, "/promote")
			return
		}
		var req struct {
			ID      string
			Applied uint64
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := rs.promote(req.ID, req.Applied); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
	})
	return mux
}

// forwarder sends a request to the leader's internal API over mutual TLS.
func (rs *raftStore) forwarder(cfg *ClusterConfig) func(path string, body []byte) (*http.Response, error) {
	return func(path string, body []byte) (*http.Response, error) {
		addr, err := rs.leaderAPI(clusterPortOf(cfg))
		if err != nil {
			return nil, err
		}
		st, _, err := rs.snapshot()
		if err != nil {
			return nil, err
		}
		tc, err := masterClientTLS(st.CACert)
		if err != nil {
			return nil, err
		}
		c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
		req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/cluster/v1/internal"+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ziro-Forwarded", "1")
		return c.Do(req)
	}
}

func serveLocalSocket(h http.Handler) error {
	if err := os.MkdirAll(filepath.Dir(clusterSock()), 0755); err != nil {
		return err
	}
	_ = os.Remove(clusterSock())
	ln, err := net.Listen("unix", clusterSock())
	if err != nil {
		return err
	}
	if err := os.Chmod(clusterSock(), 0600); err != nil { // root only
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func socketClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", clusterSock())
		},
	}}
}

func socketCall(method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://cluster-master"+path, body)
	if err != nil {
		return 0, err
	}
	resp, err := socketClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("cluster-master is not reachable (is the service running?): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("cluster-master: %s", bytes.TrimSpace(msg))
	}
	if out != nil {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

func socketFetch() (*ClusterState, uint64, error) {
	var env stateEnvelope
	if _, err := socketCall(http.MethodGet, "/state", nil, &env); err != nil {
		return nil, 0, err
	}
	st, err := decodePayload(env.Payload)
	return st, env.Version, err
}

// socketMutate is withState for ziroctl on a Raft master: fetch, apply fn, propose; retried
// when another change landed in between.
// ponytail: fn's own output repeats on a retry; fine while retries are rare.
func socketMutate(fn func(st *ClusterState) error) error {
	for attempt := 0; ; attempt++ {
		st, ver, err := socketFetch()
		if err != nil {
			return err
		}
		if err := fn(st); err != nil {
			return err
		}
		p, err := sanitizedPayload(st)
		if err != nil {
			return err
		}
		code, err := socketCall(http.MethodPost, "/propose", stateEnvelope{Version: ver, Payload: p}, nil)
		if code != http.StatusConflict || attempt >= 20 {
			return err
		}
		time.Sleep(time.Duration(50+attempt*25) * time.Millisecond)
	}
}

// ---- CLI ----

var clusterMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List the control-plane masters (Raft members) and the leader",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		var ms []memberView
		if _, err := socketCall(http.MethodGet, "/members", nil, &ms); err != nil {
			return err
		}
		voters := 0
		for _, m := range ms {
			if m.Suffrage == "Voter" {
				voters++
			}
		}
		return printResult(ms, func() {
			fmt.Printf("%-16s %-22s %-10s %s\n", "MEMBER", "RAFT ADDRESS", "SUFFRAGE", "ROLE")
			for _, m := range ms {
				role := "follower"
				if m.Leader {
					role = "leader"
				}
				fmt.Printf("%-16s %-22s %-10s %s\n", m.ID, m.Address, m.Suffrage, role)
			}
			switch {
			case voters < 3:
				fmt.Printf("\n%d voter(s): no fault tolerance. Add masters with 'cluster join --control-plane' (3 or 5 in total).\n", voters)
			case voters%2 == 0:
				fmt.Printf("\n%d voters tolerate as many failures as %d; use an odd number.\n", voters, voters-1)
			default:
				fmt.Printf("\n%d voters: tolerates %d master failure(s).\n", voters, (voters-1)/2)
			}
		})
	},
}

var clusterMemberCmd = &cobra.Command{Use: "member", Short: "Manage control-plane masters"}

var clusterMemberRmCmd = &cobra.Command{
	Use:   "rm <member>",
	Short: "Remove a (dead) master from the control plane and revoke its node token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if _, err := socketCall(http.MethodPost, "/members/remove", map[string]string{"ID": args[0]}, nil); err != nil {
			return err
		}
		fmt.Printf("✓ %s removed from the control plane\n", args[0])
		return nil
	},
}

func init() {
	clusterMemberCmd.AddCommand(clusterMemberRmCmd)
	clusterCmd.AddCommand(clusterMembersCmd, clusterMemberCmd)
}

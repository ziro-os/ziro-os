package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	nodeTimeout      = 30 * time.Second // a node missing heartbeats this long is NotReady
	clusterBodyLimit = 1 << 20
)

const (
	maxReplicaFails = 3              // consecutive failed starts before a replica is moved
	nodeGCAfter     = 24 * time.Hour // NotReady workers are forgotten after this
)

type joinRequest struct {
	Hostname     string `json:"hostname"`
	CPUs         int    `json:"cpus"`
	MemTotal     uint64 `json:"mem_total_mb"`
	WGPubKey     string `json:"wg_pubkey,omitempty"`
	WGPort       int    `json:"wg_port,omitempty"`
	ControlPlane bool   `json:"control_plane,omitempty"` // join as another master (Raft member)
	CSR          string `json:"csr,omitempty"`           // control plane: CSR for the master cert
}

type joinResponse struct {
	ClusterID  string   `json:"cluster_id"`
	NodeID     string   `json:"node_id"`
	NodeToken  string   `json:"node_token"`
	NodeIP     string   `json:"node_ip"`
	MeshIP     string   `json:"mesh_ip,omitempty"`
	MeshCIDR   string   `json:"mesh_cidr,omitempty"`
	CACert     string   `json:"ca_cert,omitempty"`
	MasterCert string   `json:"master_cert,omitempty"` // control plane only
	Masters    []string `json:"masters,omitempty"`     // API addresses of every master
}

type heartbeatRequest struct {
	Containers  int               `json:"containers"`
	Running     []string          `json:"running"`
	Failed      map[string]string `json:"failed,omitempty"` // container -> start error
	WGPubKey    string            `json:"wg_pubkey,omitempty"`
	WGPort      int               `json:"wg_port,omitempty"`
	MeshError   string            `json:"mesh_error,omitempty"`   // mesh/policy apply failure on the node
	Caps        []string          `json:"caps,omitempty"`         // features this node's ziroctl supports
	RotateToken string            `json:"rotate_token,omitempty"` // a new node token (64 hex), replacing the one this request uses
	Keys        []string          `json:"keys,omitempty"`         // data key IDs held by this node's master
}

// Assignment is one container the master wants running on a node.
type Assignment struct {
	Name      string            `json:"name"`
	App       string            `json:"app"`
	Image     string            `json:"image"`
	Args      []string          `json:"args,omitempty"`
	Port      string            `json:"port"`
	Env       map[string]string `json:"env"`
	SecretEnv map[string]string `json:"secret_env,omitempty"` // written to a 0600 env file, never argv
	Hosts     []string          `json:"hosts,omitempty"`      // --add-host entries (host-port networking only)
	IP        string            `json:"ip,omitempty"`         // pod IP on the ziro-cluster network (pod networking)
	DNS       string            `json:"dns,omitempty"`        // the node's pod DNS responder
	PrivEsc   bool              `json:"priv_esc,omitempty"`   // opt out of no-new-privileges / NET_RAW drop
	Volumes   []string          `json:"volumes,omitempty"`    // host:container[:ro] bind mounts of NFS shares
	Replica   int               `json:"replica"`              // replica index (ZIRO_REPLICA in the container)
	Data      []string          `json:"data,omitempty"`       // container paths backed by node-local dirs
	DataUID   int               `json:"data_uid,omitempty"`   // owner of those dirs (non-root images)
	Resources *Resources        `json:"resources,omitempty"`  // memory/CPU/PID limits
	Network   string            `json:"network,omitempty"`    // local apps: a named network (stacks)
}

// MeshPeer is another node on the WireGuard mesh.
type MeshPeer struct {
	Node     string   `json:"node"`
	PubKey   string   `json:"pubkey"`
	Endpoint string   `json:"endpoint"`
	MeshIP   string   `json:"mesh_ip"`
	Routes   []string `json:"routes,omitempty"` // extra /32s reached through this peer (remote clients behind the hub)
	PodCIDR  string   `json:"pod_cidr,omitempty"`
}

type heartbeatResponse struct {
	Assignments []Assignment        `json:"assignments"`
	MeshIP      string              `json:"mesh_ip,omitempty"`
	MeshPrefix  int                 `json:"mesh_prefix,omitempty"`
	Peers       []MeshPeer          `json:"peers,omitempty"`
	Endpoints   map[string][]string `json:"endpoints,omitempty"` // app -> mesh IPs
	Policy      *MeshPolicy         `json:"policy,omitempty"`
	Gateway     *GatewayConfig      `json:"gateway,omitempty"`      // only for nodes labelled gateway
	CA          string              `json:"ca,omitempty"`           // cluster CA: older agents switch their pin to it
	Masters     []string            `json:"masters,omitempty"`      // every master's API address (failover)
	RotateToken bool                `json:"rotate_token,omitempty"` // the node should send a new token
	PodCIDR     string              `json:"pod_cidr,omitempty"`     // this node's /24 (pod networking on)
	PodNet      string              `json:"pod_net,omitempty"`      // the cluster pod network
	PodDNS      map[string][]string `json:"pod_dns,omitempty"`      // app -> running pod IPs (DNS answers)
	DNSRecords  []DNSRecord         `json:"dns_records,omitempty"`  // cluster-wide records for the host resolver
	Egress      map[string][]string `json:"egress,omitempty"`       // app -> allowed outside destinations
	NFSExports  []clusterExport     `json:"nfs_exports,omitempty"`  // shares this node serves
	NFSMounts   []clusterMount      `json:"nfs_mounts,omitempty"`   // shares its replicas use
	PurgeData   []string            `json:"purge_data,omitempty"`   // apps whose local data to delete
}

// specHash changes whenever a replica must be recreated (image, port, env, secrets).
func specHash(a ClusteredApp) string {
	keys := make([]string, 0, len(a.Env))
	for k := range a.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s", a.Image, a.Port)
	for _, k := range keys {
		fmt.Fprintf(h, "\x00%s=%s", k, a.Env[k])
	}
	if len(a.Secrets) > 0 || a.MeshOnly || len(a.Args) > 0 {
		fmt.Fprintf(h, "\x00secrets=%s\x00mesh=%v\x00args=%q", strings.Join(a.Secrets, ","), a.MeshOnly, a.Args)
	}
	if a.Network != "" { // moving an app onto the pod network recreates its containers (rolling)
		fmt.Fprintf(h, "\x00net=%s", a.Network)
	}
	if a.AllowPrivilegeEscalation { // only when set, so existing apps keep their hash
		h.Write([]byte("\x00privesc"))
	}
	if len(a.Volumes) > 0 || a.VolumeEpoch > 0 {
		fmt.Fprintf(h, "\x00volumes=%q\x00epoch=%d", a.Volumes, a.VolumeEpoch)
	}
	if a.Resources != nil { // only when set, so existing apps keep their hash
		fmt.Fprintf(h, "\x00resources=%+v", *a.Resources)
	}
	if len(a.Data) > 0 {
		fmt.Fprintf(h, "\x00data=%q", a.Data)
	}
	if a.DataUID > 0 { // only when set, so existing apps keep their hash
		fmt.Fprintf(h, "\x00datauid=%d", a.DataUID)
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

func replicaName(app string, index int, hash string) string {
	return fmt.Sprintf("zc-%s-%d-%s", app, index, hash)
}

// containerName embeds the spec hash, so an updated spec yields a new name and
// the agent replaces the old container without having to diff labels.
func containerName(a ClusteredApp, index int) string {
	return replicaName(a.Name, index, specHash(a))
}

// specFor returns the spec a replica runs: the current one, or an older revision mid-rollout.
func (st *ClusterState) specFor(r Replica) (ClusteredApp, bool) {
	cur := st.app(r.App)
	if cur == nil {
		return ClusteredApp{}, false
	}
	if r.Hash == "" || specHash(*cur) == r.Hash {
		return *cur, true
	}
	for _, old := range st.History[r.App] {
		if specHash(old) == r.Hash {
			return old, true
		}
	}
	return *cur, false
}

// scheduleReplicas refreshes node readiness and (re)places replicas:
//   - replicas on Ready nodes stay where they are (no churn),
//   - replicas of removed apps / scaled-down indices are dropped,
//   - a replica that failed to start maxReplicaFails times moves to another node,
//   - unplaced replicas go to the eligible (Ready, not cordoned) node with the fewest replicas,
//   - a host port is held by at most one replica per node, across all apps,
//   - spec changes roll out one replica at a time, only while the app is otherwise healthy,
//   - one replica per pass moves from the busiest to the idlest node when they differ by > 1.
//
// ponytail: least-loaded by replica count, not CPU/memory; add resource-aware scoring when apps declare limits.
func scheduleReplicas(st *ClusterState, now time.Time) {
	if st.History == nil {
		st.History = map[string][]ClusteredApp{}
	}
	ready, eligible := map[string]bool{}, map[string]bool{}
	var gone []string
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if now.Sub(n.LastSeen) > nodeTimeout {
			n.Status = "NotReady"
			if n.Role != "master" && now.Sub(n.LastSeen) > nodeGCAfter {
				gone = append(gone, n.ID)
			}
			continue
		}
		n.Status = "Ready"
		ready[n.ID] = true
		eligible[n.ID] = !n.Cordoned
	}
	for _, id := range gone {
		removeNode(st, id)
	}

	apps := map[string]ClusteredApp{}
	for _, a := range st.Apps {
		apps[a.Name] = a
	}
	load := map[string]int{}
	ports := map[string]map[string]bool{} // node -> host port keys in use
	have := map[string]map[int]bool{}
	portOf := func(r Replica) string {
		spec, _ := st.specFor(r)
		return hostPortKey(spec.Port)
	}
	free := func(node, key string) bool { return key == "" || !ports[node][key] }
	place := func(r Replica) {
		load[r.Node]++
		if k := portOf(r); k != "" {
			if ports[r.Node] == nil {
				ports[r.Node] = map[string]bool{}
			}
			ports[r.Node][k] = true
		}
	}

	var out []Replica
	for _, r := range st.Replicas {
		a, ok := apps[r.App]
		if !ok || r.Index < 1 || r.Index > a.Replicas || have[r.App][r.Index] {
			continue
		}
		if r.Hash == "" {
			r.Hash = specHash(a)
		}
		if r.Fails >= maxReplicaFails && r.Node != "" {
			r.Avoid, r.Node, r.Fails = r.Node, "", 0
		}
		if r.Node != "" && (!ready[r.Node] || !free(r.Node, portOf(r))) {
			r.Node = ""
		}
		if r.Node != "" {
			place(r)
		}
		if have[r.App] == nil {
			have[r.App] = map[int]bool{}
		}
		have[r.App][r.Index] = true
		out = append(out, r)
	}
	for _, a := range st.Apps {
		for i := 1; i <= a.Replicas; i++ {
			if !have[a.Name][i] {
				out = append(out, Replica{App: a.Name, Index: i, Hash: specHash(a)})
			}
		}
	}
	sortReplicas(out)

	pick := func(r Replica, exclude string) string {
		best, fallback := "", ""
		for _, n := range st.Nodes {
			if !eligible[n.ID] || n.ID == exclude || !free(n.ID, portOf(r)) {
				continue
			}
			if n.ID == r.Avoid {
				fallback = n.ID
				continue
			}
			if best == "" || load[n.ID] < load[best] {
				best = n.ID
			}
		}
		if best == "" {
			return fallback // only the node it failed on is left: retry there
		}
		return best
	}
	for i := range out {
		if r := &out[i]; r.Node == "" {
			if r.Node = pick(*r, ""); r.Node != "" {
				place(*r)
			}
		}
	}
	st.Replicas = out

	rollOut(st)
	rebalance(st, eligible, load, free, portOf, pick)
	assignPodIPs(st)
}

// rollOut moves replicas to the current spec. Replicas of an old spec that are not running
// (crashed, failing, unplaced) are replaced at once: that costs no availability and lets a
// rollback replace a broken revision. Running ones go one at a time, only while every
// updated replica runs and none is failing (so a bad image pauses the rollout).
func rollOut(st *ClusterState) {
	for _, a := range st.Apps {
		want := specHash(a)
		healthy, next := true, -1
		for i, r := range st.Replicas {
			if r.App != a.Name {
				continue
			}
			switch {
			case r.Hash == want:
				healthy = healthy && r.Fails == 0 && (r.Node == "" || st.replicaRunning(r))
			case r.Node == "" || !st.replicaRunning(r):
				st.Replicas[i].Hash, st.Replicas[i].Fails, st.Replicas[i].Error = want, 0, ""
			case next < 0:
				next = i
			}
		}
		if next >= 0 && healthy {
			st.Replicas[next].Hash, st.Replicas[next].Fails, st.Replicas[next].Error = want, 0, ""
		}
	}
}

// rebalance moves at most one replica per pass onto an idle node (e.g. one that just joined).
// Only apps with >= 2 replicas that are fully running and not mid-rollout move, so a move
// never takes an app down.
func rebalance(st *ClusterState, eligible map[string]bool, load map[string]int,
	free func(node, key string) bool, portOf func(Replica) string, pick func(Replica, string) string) {
	var busiest, idlest string
	for _, n := range st.Nodes {
		if !eligible[n.ID] {
			continue
		}
		if busiest == "" || load[n.ID] > load[busiest] {
			busiest = n.ID
		}
		if idlest == "" || load[n.ID] < load[idlest] {
			idlest = n.ID
		}
	}
	if busiest == "" || load[busiest]-load[idlest] <= 1 {
		return
	}
	settled := map[string]bool{}
	for _, a := range st.Apps {
		ok := a.Replicas >= 2
		for _, r := range st.Replicas {
			if r.App == a.Name && (r.Hash != specHash(a) || !st.replicaRunning(r)) {
				ok = false
			}
		}
		settled[a.Name] = ok
	}
	for i, r := range st.Replicas {
		if r.Node != busiest || !settled[r.App] || !free(idlest, portOf(r)) {
			continue
		}
		st.Replicas[i].Node = idlest
		return
	}
}

// appEndpoints maps each app to the mesh IPs of nodes where a replica is actually running,
// so discovery never hands out a node whose replica crashed or is stuck on a bad revision.
func appEndpoints(st *ClusterState) map[string][]string {
	out := map[string][]string{}
	for _, r := range st.Replicas {
		n := st.node(r.Node)
		if n == nil || n.MeshIP == "" || !st.replicaRunning(r) {
			continue
		}
		dup := false
		for _, ip := range out[r.App] {
			dup = dup || ip == n.MeshIP
		}
		if !dup {
			out[r.App] = append(out[r.App], n.MeshIP)
		}
	}
	for _, ips := range out {
		sort.Strings(ips)
	}
	return out
}

func assignmentsFor(st *ClusterState, nodeID string, secrets map[string]map[string]string) []Assignment {
	// ponytail: --add-host entries are fixed when a container is created (not part of the spec
	// hash, so endpoint churn never restarts apps); add a DNS responder on the mesh IP if apps
	// need live endpoint updates.
	var hosts []string
	eps := appEndpoints(st)
	for app, ips := range eps {
		for _, ip := range ips {
			hosts = append(hosts, app+"."+meshDomain+":"+ip)
		}
	}
	sort.Strings(hosts)
	n := st.node(nodeID)
	out := []Assignment{}
	for _, r := range st.Replicas {
		if r.Node != nodeID {
			continue
		}
		spec, _ := st.specFor(r)
		port := spec.Port
		if spec.MeshOnly && port != "" && n != nil && n.MeshIP != "" {
			port = n.MeshIP + ":" + port
		}
		var senv map[string]string
		for _, name := range spec.Secrets {
			for k, v := range secrets[name] {
				if senv == nil {
					senv = map[string]string{}
				}
				senv[k] = v
			}
		}
		as := Assignment{Name: replicaName(r.App, r.Index, r.Hash), App: r.App, Image: spec.Image, Args: spec.Args,
			Port: port, Env: spec.Env, SecretEnv: senv, Hosts: hosts, PrivEsc: spec.AllowPrivilegeEscalation,
			Volumes: volumeArgs(spec.Volumes), Replica: r.Index, Data: spec.Data, DataUID: spec.DataUID, Resources: spec.Resources}
		if spec.Network == "pod" && r.IP != "" && n != nil && n.PodCIDR != "" {
			as.IP, as.DNS, as.Hosts = r.IP, podGateway(n.PodCIDR), nil // discovery via DNS instead
		}
		out = append(out, as)
	}
	return out
}

// meshView is what a node needs to join the WireGuard mesh: its address and every other peer.
func meshView(st *ClusterState, self *ClusterNode, cidr string) (string, int, []MeshPeer) {
	prefix := 0
	if p, err := netip.ParsePrefix(cidr); err == nil {
		prefix = p.Bits()
	}
	hub := peerHub(st)
	var remote []string
	for _, rp := range st.Peers {
		remote = append(remote, rp.MeshIP)
	}
	var peers []MeshPeer
	for _, n := range st.Nodes {
		if n.ID == self.ID || n.WGPubKey == "" || n.MeshIP == "" || n.IP == "" {
			continue
		}
		port := n.WGPort
		if port == 0 {
			port = meshPort
		}
		mp := MeshPeer{Node: n.ID, PubKey: n.WGPubKey, MeshIP: n.MeshIP, Endpoint: net.JoinHostPort(n.IP, strconv.Itoa(port))}
		if hub != nil && hub.ID == n.ID {
			mp.Routes = remote // replies to remote clients go back through the hub
		}
		if st.PodCIDR != "" {
			mp.PodCIDR = n.PodCIDR
		}
		peers = append(peers, mp)
	}
	if hub != nil && hub.ID == self.ID {
		for _, rp := range st.Peers { // roaming clients: no endpoint, they dial in
			peers = append(peers, MeshPeer{Node: "peer:" + rp.Name, PubKey: rp.PubKey, MeshIP: rp.MeshIP})
		}
	}
	return self.MeshIP, prefix, peers
}

// ---- master HTTP server ----

type clusterServer struct {
	port    string // cluster API port (for leader redirects)
	limiter *rateLimiter
	mu      sync.Mutex
	denied  map[string]time.Time // ip -> last audited auth failure
}

func newClusterServer() *clusterServer {
	return &clusterServer{limiter: newRateLimiter(120, time.Minute), denied: map[string]time.Time{}}
}

// auditDenied records a rejected credential at most once per IP per 10 minutes, so a
// revoked node that keeps heartbeating cannot flood the audit log.
func (s *clusterServer) auditDenied(ip, path string) {
	s.mu.Lock()
	now := time.Now()
	if now.Sub(s.denied[ip]) < 10*time.Minute {
		s.mu.Unlock()
		return
	}
	for k, t := range s.denied {
		if now.Sub(t) >= 10*time.Minute {
			delete(s.denied, k)
		}
	}
	s.denied[ip] = now
	s.mu.Unlock()
	clusterAudit("ip:"+ip, "cluster auth denied", path, errUnauthorized)
}

// clusterAudit is the control plane's audit hook; a failing log never blocks cluster traffic.
func clusterAudit(actor, action, target string, err error) {
	if e := auditLog(actor, "cluster-master", action, target, err); e != nil {
		fmt.Printf("[cluster] audit log: %v\n", e)
	}
}

func (s *clusterServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/v1/join", s.wrap(s.handleJoin))
	mux.HandleFunc("/cluster/v1/heartbeat", s.wrap(s.handleHeartbeat))
	mux.HandleFunc("/cluster/v1/leave", s.wrap(s.handleLeave))
	return mux
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func (s *clusterServer) wrap(h func(r *http.Request) (interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		var out interface{}
		var err error
		switch {
		case r.Method != http.MethodPost:
			err = httpError{http.StatusMethodNotAllowed, "method not allowed"}
		case !s.limiter.allow(ip):
			err = httpError{http.StatusTooManyRequests, "rate limit exceeded"}
		case localRaft != nil && !localRaft.isLeader():
			// Agents and joiners talk to the leader; tell them where it is.
			leader, lerr := localRaft.leaderAPI(s.port)
			if lerr != nil {
				err = httpError{http.StatusServiceUnavailable, lerr.Error()}
				break
			}
			w.WriteHeader(http.StatusMisdirectedRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "redirect", "leader": leader})
			return
		default:
			r.Body = http.MaxBytesReader(w, r.Body, clusterBodyLimit)
			out, err = h(r)
		}
		if err != nil {
			code := http.StatusInternalServerError
			var he httpError
			if errors.As(err, &he) {
				code = he.code
			}
			if code == http.StatusUnauthorized {
				s.auditDenied(ip, r.URL.Path)
			}
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

var errUnauthorized = httpError{http.StatusUnauthorized, "unauthorized"}

func nodeAuth(cfg *ClusterConfig) string {
	return "Bearer " + cfg.NodeID + "." + cfg.NodeToken
}

// authNode checks "Bearer <node-id>.<token>" against the stored token hash.
func authNode(st *ClusterState, header string) (*ClusterNode, error) {
	n, _, err := authNodeToken(st, header, time.Now())
	return n, err
}

// authNodeToken also accepts a node's previous token for an hour after a rotation (the reply
// carrying the switch may have been lost); prev reports that it was used.
func authNodeToken(st *ClusterState, header string, now time.Time) (n *ClusterNode, prev bool, err error) {
	cred, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return nil, false, errUnauthorized
	}
	id, tok, ok := strings.Cut(cred, ".")
	if !ok {
		return nil, false, errUnauthorized
	}
	h := []byte(hashToken(tok))
	want, known := st.NodeTokens[id]
	switch {
	case known && subtle.ConstantTimeCompare(h, []byte(want)) == 1:
	case st.PrevNodeTokens[id].Hash != "" && now.Before(st.PrevNodeTokens[id].Until) &&
		subtle.ConstantTimeCompare(h, []byte(st.PrevNodeTokens[id].Hash)) == 1:
		prev = true
	default:
		return nil, false, errUnauthorized
	}
	if n = st.node(id); n == nil {
		return nil, false, errUnauthorized
	}
	return n, prev, nil
}

// rotateNodeToken installs a node-generated token; the old one stays valid for an hour.
func rotateNodeToken(st *ClusterState, n *ClusterNode, newTok string, now time.Time) error {
	if !nodeTokenRe.MatchString(newTok) {
		return httpError{http.StatusBadRequest, "invalid rotated token"}
	}
	if st.PrevNodeTokens == nil {
		st.PrevNodeTokens = map[string]prevNodeToken{}
	}
	st.PrevNodeTokens[n.ID] = prevNodeToken{Hash: st.NodeTokens[n.ID], Until: now.Add(time.Hour)}
	st.NodeTokens[n.ID] = hashToken(newTok)
	n.TokenIssued = now
	return nil
}

// needsTokenRotation: tokens live at most 30 days, operators can force a rotation, and a node
// still using its previous token rotates again.
func needsTokenRotation(st *ClusterState, n *ClusterNode, usedPrev bool, now time.Time) bool {
	return usedPrev || now.Sub(n.TokenIssued) > nodeTokenMaxAge || n.TokenIssued.Before(st.RotateTokensBefore)
}

var nodeTokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

const nodeTokenMaxAge = 30 * 24 * time.Hour

func (s *clusterServer) handleJoin(r *http.Request) (interface{}, error) {
	cfg, err := requireMaster()
	if err != nil {
		return nil, err
	}
	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, httpError{http.StatusBadRequest, "invalid body"}
	}
	if req.CPUs < 0 || req.CPUs > 4096 || req.MemTotal > 1<<26 || (req.WGPubKey != "" && !validWGKey(req.WGPubKey)) ||
		req.WGPort < 0 || req.WGPort > 65535 {
		return nil, httpError{http.StatusBadRequest, "invalid node description"}
	}
	req.Hostname = sanitizeLabel(req.Hostname, 64)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	resp := joinResponse{ClusterID: cfg.ClusterID, NodeID: "node-" + randomHex(4), NodeToken: randomHex(32), NodeIP: ip,
		MeshCIDR: meshCIDR(cfg)}
	role := "worker"
	if req.ControlPlane {
		if localRaft == nil {
			return nil, httpError{http.StatusBadRequest, "this master cannot add control-plane members"}
		}
		role, resp.NodeID = "master", "master-"+randomHex(4)
	}

	err = withState(func(st *ClusterState) error {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+st.JoinToken)) != 1 ||
			joinTokenExpired(st, time.Now()) {
			return errUnauthorized
		}
		if req.ControlPlane {
			var err error
			// The master cert names the address the join came from, never a self-reported one.
			if resp.MasterCert, err = signMasterCSR(st, req.CSR, resp.NodeID, []net.IP{net.ParseIP(ip)}); err != nil {
				return httpError{http.StatusBadRequest, "csr: " + err.Error()}
			}
		}
		resp.CACert, resp.Masters = st.CACert, masterAddrs(st, cfg)
		st.NodeTokens[resp.NodeID] = hashToken(resp.NodeToken)
		n := ClusterNode{
			ID: resp.NodeID, Hostname: req.Hostname, IP: ip, Role: role, Status: "Ready", TokenIssued: time.Now(),
			CPUs: req.CPUs, MemTotal: req.MemTotal, LastSeen: time.Now(), WGPubKey: req.WGPubKey, WGPort: req.WGPort,
		}
		if n.WGPubKey != "" {
			mip, err := allocMeshIP(st, meshCIDR(cfg))
			if err != nil {
				return err
			}
			n.MeshIP, resp.MeshIP = mip, mip
		}
		if st.PodCIDR != "" {
			c, err := allocPodCIDR(st)
			if err != nil {
				return err
			}
			n.PodCIDR = c
		}
		st.Nodes = append(st.Nodes, n)
		scheduleReplicas(st, time.Now())
		return nil
	})
	if err != nil {
		return nil, err
	}
	if req.ControlPlane {
		// A non-voter first: it only counts toward quorum once it has caught up (it asks to be
		// promoted), so a joiner that never comes up cannot stall the cluster.
		if err := localRaft.addNonvoter(resp.NodeID, raftAddr(ip, cfg)); err != nil {
			return nil, err
		}
	}
	fmt.Printf("[cluster] %s %s (%s, %s) joined\n", role, resp.NodeID, req.Hostname, ip)
	clusterAudit("ip:"+ip, "cluster node join", resp.NodeID+" ("+req.Hostname+")", nil)
	return resp, nil
}

func meshCIDR(cfg *ClusterConfig) string {
	if cfg.MeshCIDR != "" {
		return cfg.MeshCIDR
	}
	return defaultMeshCIDR
}

func (s *clusterServer) handleHeartbeat(r *http.Request) (interface{}, error) {
	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, httpError{http.StatusBadRequest, "invalid body"}
	}
	if len(req.Running) > 4096 || len(req.Failed) > 4096 || (req.WGPubKey != "" && !validWGKey(req.WGPubKey)) ||
		req.WGPort < 0 || req.WGPort > 65535 {
		return nil, httpError{http.StatusBadRequest, "invalid heartbeat"}
	}
	for k, v := range req.Failed {
		req.Failed[k] = sanitizeLabel(v, 200)
	}
	req.MeshError = sanitizeLabel(req.MeshError, 300)
	if len(req.Caps) > 16 {
		req.Caps = req.Caps[:16]
	}
	for i, c := range req.Caps {
		req.Caps[i] = sanitizeLabel(c, 32)
	}
	cfg, err := requireMaster()
	if err != nil {
		return nil, err
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	var resp heartbeatResponse
	err = withState(func(st *ClusterState) error {
		now := time.Now()
		n, usedPrev, err := authNodeToken(st, r.Header.Get("Authorization"), now)
		if err != nil {
			return err
		}
		for id, p := range st.PrevNodeTokens {
			if !now.Before(p.Until) {
				delete(st.PrevNodeTokens, id)
			}
		}
		if req.RotateToken != "" {
			if err := rotateNodeToken(st, n, req.RotateToken, now); err != nil {
				return err
			}
			usedPrev = false
			clusterAudit("node:"+n.ID, "cluster node token rotate", n.ID, nil)
		}
		resp.RotateToken = needsTokenRotation(st, n, usedPrev, now)
		if n.Status != "Ready" {
			fmt.Printf("[cluster] node %s is Ready again\n", n.ID)
		}
		if st.sealed != nil { // never hand out assignments without their secrets
			return httpError{http.StatusServiceUnavailable, errSecretsLocked.Error()}
		}
		n.LastSeen, n.Containers, n.Running, n.Failed, n.MeshError = time.Now(), req.Containers, req.Running, req.Failed, req.MeshError
		if strings.Join(n.Caps, ",") != strings.Join(req.Caps, ",") {
			n.Caps = req.Caps
		}
		if len(req.Keys) <= 4 && strings.Join(n.Keys, ",") != strings.Join(req.Keys, ",") {
			n.Keys = req.Keys
		}
		if n.Role != "master" {
			n.IP = ip
		}
		if req.WGPubKey != "" {
			n.WGPubKey, n.WGPort = req.WGPubKey, req.WGPort
			if n.MeshIP == "" { // node joined before the mesh existed
				if n.MeshIP, err = allocMeshIP(st, meshCIDR(cfg)); err != nil {
					return err
				}
			}
		}
		if st.PodCIDR != "" && n.PodCIDR == "" {
			if n.PodCIDR, err = allocPodCIDR(st); err != nil {
				return err
			}
		}
		// Failure accounting for this node's replicas: consecutive reported start failures.
		running := map[string]bool{}
		for _, c := range req.Running {
			running[c] = true
		}
		for i := range st.Replicas {
			rp := &st.Replicas[i]
			if rp.Node != n.ID {
				continue
			}
			name := replicaName(rp.App, rp.Index, rp.Hash)
			if msg, bad := req.Failed[name]; bad {
				rp.Fails++
				rp.Error = msg
			} else if running[name] {
				rp.Fails, rp.Error, rp.Avoid = 0, "", ""
			}
		}
		scheduleReplicas(st, time.Now())
		resp.Assignments = assignmentsFor(st, n.ID, st.Secrets)
		resp.MeshIP, resp.MeshPrefix, resp.Peers = meshView(st, n, meshCIDR(cfg))
		resp.Endpoints = appEndpoints(st)
		if st.PodCIDR != "" && n.PodCIDR != "" {
			resp.PodCIDR, resp.PodNet = n.PodCIDR, st.PodCIDR
			resp.PodDNS = podEndpoints(st)
			resp.Endpoints = resp.PodDNS // <app>.cluster.ziro means pod IPs everywhere on a pod network
		}
		resp.Policy = policyFor(st, n.ID)
		resp.DNSRecords = st.DNSRecords
		resp.NFSExports, resp.NFSMounts = storageFor(st, n.ID)
		resp.PurgeData = purgeList(st, time.Now())
		for _, a := range st.Apps {
			if len(a.Egress) > 0 {
				if resp.Egress == nil {
					resp.Egress = map[string][]string{}
				}
				resp.Egress[a.Name] = a.Egress
			}
		}
		resp.CA, resp.Masters = st.CACert, masterAddrs(st, cfg)
		if n.Gateway {
			resp.Gateway = gatewayConfigFor(st)
		}
		return nil
	})
	return resp, err
}

func (s *clusterServer) handleLeave(r *http.Request) (interface{}, error) {
	err := withState(func(st *ClusterState) error {
		n, err := authNode(st, r.Header.Get("Authorization"))
		if err != nil {
			return err
		}
		if n.Role == "master" {
			return httpError{http.StatusBadRequest, "the master cannot leave; use 'cluster leave --force' on it"}
		}
		id := n.ID
		removeNode(st, id)
		scheduleReplicas(st, time.Now())
		fmt.Printf("[cluster] node %s left\n", id)
		clusterAudit("node:"+id, "cluster node leave", id, nil)
		return nil
	})
	return APIMessage{Status: "ok"}, err
}

var clusterServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the cluster master control plane (started by the cluster-master service)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		port := clusterPortOf(cfg)
		if err := ensureTLSCertificates(); err != nil { // served to pre-CA agents (no SNI)
			return err
		}
		legacy, _ := tls.LoadX509KeyPair(apiTLSCert, apiTLSKey)

		// The files hold the last replicated state (or, on a master's first start on this version,
		// the pre-Raft state that becomes the first log entry). Joined masters bring the CA with them.
		// This master's copy of the cluster data key (secrets at rest); a broken provider is fatal.
		if key, err := loadStoredDEK(); err != nil {
			return err
		} else if key != nil {
			setKeyring(key)
		}
		if next, err := loadWrapped(dekNextPath()); err != nil { // restarted mid-rotation
			return err
		} else if next != nil {
			addKey(next)
		}
		st, err := fileState()
		if err != nil {
			return err
		}
		firstStart := !fileExists(filepath.Join(raftDir(), "raft.db"))
		if cfg.RaftJoined || !firstStart {
			// The CA and this master's certificate exist already; the replicated state (not these
			// files) is authoritative from now on, and the renewal loop reissues from it.
			if st.CACert == "" {
				ca, err := os.ReadFile(clusterCAPath())
				if err != nil {
					return fmt.Errorf("cluster CA missing: %w", err)
				}
				st.CACert = string(ca)
			}
		} else { // the founding master's first start on this version: create the CA
			if err := ensureCA(st); err != nil {
				return err
			}
			if err := ensureMasterCert(st, cfg.NodeID, []net.IP{net.ParseIP(cfg.NodeIP)}); err != nil {
				return err
			}
		}
		var importFn func() (*ClusterState, error) // only the founding master seeds a new group
		if !cfg.RaftJoined {
			imported := st
			importFn = func() (*ClusterState, error) { return cloneState(imported), nil }
		}
		rs, err := openRaftStore(cfg, st, importFn)
		if err != nil {
			return fmt.Errorf("raft: %w", err)
		}
		localRaft = rs
		rs.fetchKey = func(id string) error { return fetchDEK(rs, cfg, id) }
		p, _ := strconv.Atoi(port)
		allowFirewall([]FirewallRule{{Port: p + 1, Protocol: "tcp", Comment: "Ziro cluster Raft (mutual TLS)"}}, "")

		local := rs.localHandler(cfg, rs.forwarder(cfg))
		if err := serveLocalSocket(local); err != nil {
			return err
		}
		caPEM := st.CACert
		pool, err := caPool(caPEM)
		if err != nil {
			return err
		}
		cs := newClusterServer()
		cs.port = port
		mux := cs.handler().(*http.ServeMux)
		// Another master asking for the cluster data key (mutual TLS, master certificates only).
		mux.HandleFunc("/cluster/v1/internal/dek", func(w http.ResponseWriter, r *http.Request) {
			key, _ := currentKey()
			if id := r.URL.Query().Get("id"); id != "" {
				key = keyByID(id) // the current key or, during a rotation, the next one
			}
			if !requestFromMaster(r.TLS, caPEM) || key == nil {
				http.Error(w, "unavailable", http.StatusForbidden)
				return
			}
			clusterAudit("master:"+r.TLS.PeerCertificates[0].Subject.CommonName, "cluster data key fetch", cfg.NodeID, nil)
			_ = json.NewEncoder(w).Encode(map[string][]byte{"key": key})
		})
		mux.Handle("/cluster/v1/internal/", http.StripPrefix("/cluster/v1/internal", http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if !requestFromMaster(r.TLS, caPEM) {
					http.Error(w, "master certificate required", http.StatusForbidden)
					return
				}
				local.ServeHTTP(w, r)
			})))

		// Leader-only duties: the periodic scheduling pass (dead nodes lose their replicas even
		// without traffic). Every master: renew its certificate; a joined master asks to become a
		// voter once it has caught up.
		go func() {
			for range time.Tick(agentInterval) {
				if !rs.isLeader() {
					continue
				}
				if err := withState(func(st *ClusterState) error {
					scheduleReplicas(st, time.Now())
					if err := maybeSealSecrets(st); err != nil {
						return err
					}
					return maybeRotateDEK(st)
				}); err != nil && !errors.Is(err, errNotLeader) {
					fmt.Printf("[cluster] schedule: %v\n", err)
				}
			}
		}()
		go func() {
			for ; ; time.Sleep(time.Minute) { // cheap when nothing is due (reads one file)
				if cur, _, err := rs.snapshot(); err == nil && cur.CAKey != "" {
					if err := ensureMasterCert(cur, cfg.NodeID, []net.IP{net.ParseIP(cfg.NodeIP)}); err != nil {
						fmt.Printf("[cluster] certificate renewal: %v\n", err)
					}
				}
			}
		}()
		if cfg.RaftJoined {
			go promoteSelf(rs, cfg)
		}
		// Followers pick up the cluster data key as soon as the state is sealed (or re-keyed), so
		// any master can take over as leader.
		go func() {
			for ; ; time.Sleep(10 * time.Second) {
				if b, _ := rs.fsm.latest(); len(b) > 0 {
					cur, err := decodePayload(b)
					if err == nil && cur.sealed != nil {
						if err := fetchDEK(rs, cfg, cur.DEKID); err != nil {
							fmt.Printf("[cluster] cluster data key: %v\n", err)
						}
					}
					if err == nil && cur.NextDEKID != "" && keyByID(cur.NextDEKID) == nil {
						if err := fetchDEK(rs, cfg, cur.NextDEKID); err != nil {
							fmt.Printf("[cluster] next cluster data key: %v\n", err)
						}
					}
					if err == nil && cur.DEKID != "" {
						promoteRotatedKey(cur.DEKID, cur.NextDEKID)
					}
					if err == nil && cur.DEKID != "" {
						if err := rs.compactAfterSeal(); err != nil {
							fmt.Printf("[cluster] compact after sealing: %v\n", err)
						}
					}
				}
			}
		}()

		srv := &http.Server{
			Addr:    ":" + port,
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if hello.ServerName != clusterSNI && legacy.Certificate != nil && !cfg.RaftJoined {
						return &legacy, nil // agents from before the cluster CA pin this certificate
					}
					return loadMasterTLS()
				},
				ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool, // masters (internal API) present certs
			},
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		fmt.Printf("[cluster] master %s (%s) serving on :%s, raft on :%d\n", cfg.NodeID, cfg.ClusterID, port, p+1)
		return srv.ListenAndServeTLS("", "")
	},
}

// promoteSelf asks the leader to make this master a voter once it has replicated the state.
func promoteSelf(rs *raftStore, cfg *ClusterConfig) {
	fwd := rs.forwarder(cfg)
	for ; ; time.Sleep(2 * time.Second) {
		members, err := rs.members()
		if err == nil {
			for _, m := range members {
				if m.ID == cfg.NodeID && m.Suffrage == "Voter" {
					fmt.Println("[cluster] this master is a voting member")
					return
				}
			}
		}
		_, applied := rs.fsm.latest()
		if applied == 0 {
			continue
		}
		body, _ := json.Marshal(map[string]any{"ID": cfg.NodeID, "Applied": applied})
		if resp, err := fwd("/promote", body); err == nil {
			resp.Body.Close()
		}
	}
}

// fileState reads the state files under a shared lock (no Raft).
func fileState() (*ClusterState, error) {
	lock, err := lockState(syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return loadStateFile()
}

// ---- client side ----

// clusterPost calls the cluster API of a master, trusted by pin (see pinnedTLS). A follower
// answers 421 with the leader's address, which is followed (bounded).
func clusterPost(addr, caHash, path, auth string, body, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	for hop, wait := 0, 0; ; hop++ {
		resp, err := clusterDo(addr, caHash, path, auth, data)
		if err != nil {
			return err
		}
		// 503 while a leader is being elected (startup, failover): wait it out briefly.
		if resp.StatusCode == http.StatusServiceUnavailable && wait < 30 {
			resp.Body.Close()
			wait++
			time.Sleep(time.Second)
			continue
		}
		if resp.StatusCode == http.StatusMisdirectedRequest && hop < 3 {
			var m struct{ Leader string }
			_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&m)
			resp.Body.Close()
			if _, _, err := net.SplitHostPort(m.Leader); err != nil {
				return fmt.Errorf("master redirected to an invalid leader %q", m.Leader)
			}
			addr = m.Leader
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var m APIMessage
			_ = json.NewDecoder(resp.Body).Decode(&m)
			return fmt.Errorf("master returned HTTP %d: %s", resp.StatusCode, m.Message)
		}
		if out == nil {
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
}

// clusterDo sends one request, always with standard chain + hostname verification: against the
// local cluster CA when this node holds the pinned one, otherwise against the trust anchor the pin
// names (see pinnedTLS: first join and pre-CA agents).
func clusterDo(addr, pin, path, auth string, data []byte) (*http.Response, error) {
	tc := caVerifiedTLS(pin)
	if tc == nil {
		var err error
		if tc, err = pinnedTLS(addr, pin); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	return (&http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}).Do(req)
}

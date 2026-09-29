package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Hostname string `json:"hostname"`
	CPUs     int    `json:"cpus"`
	MemTotal uint64 `json:"mem_total_mb"`
	WGPubKey string `json:"wg_pubkey,omitempty"`
	WGPort   int    `json:"wg_port,omitempty"`
}

type joinResponse struct {
	ClusterID string `json:"cluster_id"`
	NodeID    string `json:"node_id"`
	NodeToken string `json:"node_token"`
	NodeIP    string `json:"node_ip"`
	MeshIP    string `json:"mesh_ip,omitempty"`
}

type heartbeatRequest struct {
	Containers int               `json:"containers"`
	Running    []string          `json:"running"`
	Failed     map[string]string `json:"failed,omitempty"` // container -> start error
	WGPubKey   string            `json:"wg_pubkey,omitempty"`
	WGPort     int               `json:"wg_port,omitempty"`
	MeshError  string            `json:"mesh_error,omitempty"` // mesh/policy apply failure on the node
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
	Gateway     *GatewayConfig      `json:"gateway,omitempty"`  // only for nodes labelled gateway
	PodCIDR     string              `json:"pod_cidr,omitempty"` // this node's /24 (pod networking on)
	PodNet      string              `json:"pod_net,omitempty"`  // the cluster pod network
	PodDNS      map[string][]string `json:"pod_dns,omitempty"`  // app -> running pod IPs (DNS answers)
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
			Port: port, Env: spec.Env, SecretEnv: senv, Hosts: hosts}
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
	cred, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return nil, errUnauthorized
	}
	id, tok, ok := strings.Cut(cred, ".")
	want, known := st.NodeTokens[id]
	if !ok || !known || subtle.ConstantTimeCompare([]byte(hashToken(tok)), []byte(want)) != 1 {
		return nil, errUnauthorized
	}
	n := st.node(id)
	if n == nil {
		return nil, errUnauthorized
	}
	return n, nil
}

func (s *clusterServer) handleJoin(r *http.Request) (interface{}, error) {
	cfg, err := requireMaster()
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.JoinToken)) != 1 ||
		joinTokenExpired(cfg, time.Now()) {
		return nil, errUnauthorized
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
	resp := joinResponse{ClusterID: cfg.ClusterID, NodeID: "node-" + randomHex(4), NodeToken: randomHex(32), NodeIP: ip}

	err = withState(func(st *ClusterState) error {
		st.NodeTokens[resp.NodeID] = hashToken(resp.NodeToken)
		n := ClusterNode{
			ID: resp.NodeID, Hostname: req.Hostname, IP: ip, Role: "worker", Status: "Ready",
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
	fmt.Printf("[cluster] node %s (%s, %s) joined\n", resp.NodeID, req.Hostname, ip)
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
	cfg, err := requireMaster()
	if err != nil {
		return nil, err
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	var resp heartbeatResponse
	err = withState(func(st *ClusterState) error {
		n, err := authNode(st, r.Header.Get("Authorization"))
		if err != nil {
			return err
		}
		if n.Status != "Ready" {
			fmt.Printf("[cluster] node %s is Ready again\n", n.ID)
		}
		n.LastSeen, n.Containers, n.Running, n.Failed, n.MeshError = time.Now(), req.Containers, req.Running, req.Failed, req.MeshError
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
		secrets, err := loadSecrets()
		if err != nil {
			return err
		}
		resp.Assignments = assignmentsFor(st, n.ID, secrets)
		resp.MeshIP, resp.MeshPrefix, resp.Peers = meshView(st, n, meshCIDR(cfg))
		resp.Endpoints = appEndpoints(st)
		if st.PodCIDR != "" && n.PodCIDR != "" {
			resp.PodCIDR, resp.PodNet = n.PodCIDR, st.PodCIDR
			resp.PodDNS = podEndpoints(st)
			resp.Endpoints = resp.PodDNS // <app>.cluster.ziro means pod IPs everywhere on a pod network
		}
		resp.Policy = policyFor(st, n.ID)
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
		_, port, err := net.SplitHostPort(cfg.MasterAddr)
		if err != nil {
			return err
		}
		if err := ensureTLSCertificates(); err != nil {
			return err
		}

		// Periodic pass so dead nodes become NotReady and lose their replicas even without traffic.
		go func() {
			for range time.Tick(agentInterval) {
				if err := withState(func(st *ClusterState) error { scheduleReplicas(st, time.Now()); return nil }); err != nil {
					fmt.Printf("[cluster] schedule: %v\n", err)
				}
			}
		}()

		srv := &http.Server{
			Addr:              ":" + port,
			Handler:           newClusterServer().handler(),
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		fmt.Printf("[cluster] master %s serving on :%s\n", cfg.ClusterID, port)
		return srv.ListenAndServeTLS(apiTLSCert, apiTLSKey)
	},
}

// ---- client side ----

func certHash(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s: no PEM certificate", certPath)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// pinnedClient trusts exactly the master certificate whose hash was handed out
// with the join command (same model as kubeadm's --discovery-token-ca-cert-hash).
func pinnedClient(caHash string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Chain/hostname verification is replaced by the certificate pin below.
			InsecureSkipVerify: true, //nolint:gosec
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("master presented no certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if got := "sha256:" + hex.EncodeToString(sum[:]); subtle.ConstantTimeCompare([]byte(got), []byte(caHash)) != 1 {
					return fmt.Errorf("master certificate %s does not match pinned %s", got, caHash)
				}
				return nil
			},
		}},
	}
}

func clusterPost(addr, caHash, path, auth string, body, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := pinnedClient(caHash).Do(req)
	if err != nil {
		return err
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

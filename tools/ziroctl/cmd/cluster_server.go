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
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	nodeTimeout      = 30 * time.Second // a node missing heartbeats this long is NotReady
	clusterBodyLimit = 1 << 20
)

type joinRequest struct {
	Hostname string `json:"hostname"`
	CPUs     int    `json:"cpus"`
	MemTotal uint64 `json:"mem_total_mb"`
}

type joinResponse struct {
	ClusterID string `json:"cluster_id"`
	NodeID    string `json:"node_id"`
	NodeToken string `json:"node_token"`
	NodeIP    string `json:"node_ip"`
}

type heartbeatRequest struct {
	Containers int      `json:"containers"`
	Running    []string `json:"running"`
}

// Assignment is one container the master wants running on a node.
type Assignment struct {
	Name  string            `json:"name"`
	App   string            `json:"app"`
	Image string            `json:"image"`
	Port  string            `json:"port"`
	Env   map[string]string `json:"env"`
}

type heartbeatResponse struct {
	Assignments []Assignment `json:"assignments"`
}

// specHash changes whenever a replica must be recreated (image, port or env change).
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
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// containerName embeds the spec hash, so an updated spec yields a new name and
// the agent replaces the old container without having to diff labels.
func containerName(a ClusteredApp, index int) string {
	return fmt.Sprintf("zc-%s-%d-%s", a.Name, index, specHash(a))
}

// scheduleReplicas refreshes node readiness and (re)places replicas:
//   - replicas on Ready nodes stay where they are (no churn),
//   - replicas of removed apps / scaled-down indices are dropped,
//   - unplaced replicas go to the Ready node with the fewest replicas,
//   - apps with a host port get at most one replica per node (else they stay pending).
//
// ponytail: least-loaded by replica count, not CPU/memory; add resource-aware scoring when apps declare limits.
func scheduleReplicas(st *ClusterState, now time.Time) {
	ready := map[string]bool{}
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if now.Sub(n.LastSeen) > nodeTimeout {
			n.Status = "NotReady"
		} else {
			n.Status = "Ready"
			ready[n.ID] = true
		}
	}

	apps := map[string]ClusteredApp{}
	for _, a := range st.Apps {
		apps[a.Name] = a
	}
	load := map[string]int{}
	hosts := map[string]map[string]bool{} // app -> nodes running it
	have := map[string]map[int]bool{}
	place := func(r Replica) {
		load[r.Node]++
		if hosts[r.App] == nil {
			hosts[r.App] = map[string]bool{}
		}
		hosts[r.App][r.Node] = true
	}

	var out []Replica
	for _, r := range st.Replicas {
		a, ok := apps[r.App]
		if !ok || r.Index < 1 || r.Index > a.Replicas || have[r.App][r.Index] {
			continue
		}
		if r.Node != "" && (!ready[r.Node] || (a.Port != "" && hosts[r.App][r.Node])) {
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
				out = append(out, Replica{App: a.Name, Index: i})
			}
		}
	}
	sortReplicas(out)

	for i := range out {
		r := &out[i]
		if r.Node != "" {
			continue
		}
		a := apps[r.App]
		best := ""
		for _, n := range st.Nodes {
			if !ready[n.ID] || (a.Port != "" && hosts[a.Name][n.ID]) {
				continue
			}
			if best == "" || load[n.ID] < load[best] {
				best = n.ID
			}
		}
		if best != "" {
			r.Node = best
			place(*r)
		}
	}
	st.Replicas = out
}

func assignmentsFor(st *ClusterState, nodeID string) []Assignment {
	apps := map[string]ClusteredApp{}
	for _, a := range st.Apps {
		apps[a.Name] = a
	}
	out := []Assignment{}
	for _, r := range st.Replicas {
		if r.Node != nodeID {
			continue
		}
		a := apps[r.App]
		out = append(out, Assignment{Name: containerName(a, r.Index), App: a.Name, Image: a.Image, Port: a.Port, Env: a.Env})
	}
	return out
}

// ---- master HTTP server ----

type clusterServer struct {
	limiter *rateLimiter
}

func newClusterServer() *clusterServer {
	return &clusterServer{limiter: newRateLimiter(120, time.Minute)}
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
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.JoinToken)) != 1 {
		return nil, errUnauthorized
	}
	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, httpError{http.StatusBadRequest, "invalid body"}
	}
	if len(req.Hostname) > 64 {
		req.Hostname = req.Hostname[:64]
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	resp := joinResponse{ClusterID: cfg.ClusterID, NodeID: "node-" + randomHex(4), NodeToken: randomHex(32), NodeIP: ip}

	err = withState(func(st *ClusterState) error {
		st.NodeTokens[resp.NodeID] = hashToken(resp.NodeToken)
		st.Nodes = append(st.Nodes, ClusterNode{
			ID: resp.NodeID, Hostname: req.Hostname, IP: ip, Role: "worker", Status: "Ready",
			CPUs: req.CPUs, MemTotal: req.MemTotal, LastSeen: time.Now(),
		})
		scheduleReplicas(st, time.Now())
		return nil
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("[cluster] node %s (%s, %s) joined\n", resp.NodeID, req.Hostname, ip)
	return resp, nil
}

func (s *clusterServer) handleHeartbeat(r *http.Request) (interface{}, error) {
	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, httpError{http.StatusBadRequest, "invalid body"}
	}
	if len(req.Running) > 4096 {
		req.Running = req.Running[:4096]
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	var resp heartbeatResponse
	err := withState(func(st *ClusterState) error {
		n, err := authNode(st, r.Header.Get("Authorization"))
		if err != nil {
			return err
		}
		if n.Status != "Ready" {
			fmt.Printf("[cluster] node %s is Ready again\n", n.ID)
		}
		n.LastSeen, n.Containers, n.Running = time.Now(), req.Containers, req.Running
		if n.Role != "master" {
			n.IP = ip
		}
		scheduleReplicas(st, time.Now())
		resp.Assignments = assignmentsFor(st, n.ID)
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
		delete(st.NodeTokens, id)
		var kept []ClusterNode
		for _, x := range st.Nodes {
			if x.ID != id {
				kept = append(kept, x)
			}
		}
		st.Nodes = kept
		scheduleReplicas(st, time.Now())
		fmt.Printf("[cluster] node %s left\n", id)
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

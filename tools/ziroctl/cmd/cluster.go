package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// clusterDir is a var so tests can point it at a temp dir.
var clusterDir = "/etc/ziro/cluster"

func clusterConfigPath() string  { return filepath.Join(clusterDir, "config.json") }
func clusterStatePath() string   { return filepath.Join(clusterDir, "state.json") }
func clusterSecretsPath() string { return filepath.Join(clusterDir, "secrets.json") }

const (
	defaultMeshCIDR = "10.200.0.0/16"
	maxAppHistory   = 5
)

// ClusterConfig is this node's identity and how it reaches the master.
type ClusterConfig struct {
	ClusterID        string `json:"cluster_id"`
	Role             string `json:"role"` // "master" or "worker"
	NodeID           string `json:"node_id"`
	Hostname         string `json:"hostname"`
	NodeIP           string `json:"node_ip"`
	MasterAddr       string `json:"master_addr"` // host:port the local agent talks to
	Advertise        string `json:"advertise,omitempty"`
	JoinToken        string `json:"join_token,omitempty"`         // master only
	JoinTokenExpires string `json:"join_token_expires,omitempty"` // RFC3339; empty = never
	MeshCIDR         string `json:"mesh_cidr,omitempty"`          // master only
	NodeToken        string `json:"node_token"`
	CAHash           string `json:"ca_hash"` // "sha256:<hex>" of the master's TLS certificate
	CreatedAt        string `json:"created_at"`
}

type ClusterNode struct {
	ID         string            `json:"id"`
	Hostname   string            `json:"hostname"`
	IP         string            `json:"ip"`
	Role       string            `json:"role"`
	Status     string            `json:"status"` // Ready, NotReady
	Cordoned   bool              `json:"cordoned,omitempty"`
	CPUs       int               `json:"cpus"`
	MemTotal   uint64            `json:"mem_total_mb"`
	Containers int               `json:"containers"`
	Running    []string          `json:"running"`          // cluster containers the agent reports running
	Failed     map[string]string `json:"failed,omitempty"` // container -> last start error from the agent
	MeshIP     string            `json:"mesh_ip,omitempty"`
	WGPubKey   string            `json:"wg_pubkey,omitempty"`
	WGPort     int               `json:"wg_port,omitempty"`
	MeshError  string            `json:"mesh_error,omitempty"` // last mesh/policy apply error reported by the agent
	LastSeen   time.Time         `json:"last_seen"`
}

type ClusteredApp struct {
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Replicas  int               `json:"replicas"`
	Port      string            `json:"port,omitempty"`       // host:container[/proto]
	Env       map[string]string `json:"env,omitempty"`        // plain config (visible in the spec)
	Args      []string          `json:"args,omitempty"`       // command/arguments after the image
	Secrets   []string          `json:"secrets,omitempty"`    // cluster secrets injected as env files
	MeshOnly  bool              `json:"mesh_only,omitempty"`  // publish Port on the mesh IP only
	AllowFrom []string          `json:"allow_from,omitempty"` // apps (or "*") allowed to reach Port over the mesh
	Revision  int               `json:"revision,omitempty"`
	CreatedAt string            `json:"created_at,omitempty"`
}

// Replica is one placed (or pending, Node == "") instance of an app.
type Replica struct {
	App   string `json:"app"`
	Index int    `json:"index"`
	Node  string `json:"node"`
	Hash  string `json:"hash,omitempty"`  // spec this replica runs; differs from the app's during a rollout
	Fails int    `json:"fails,omitempty"` // consecutive start failures reported by the node
	Error string `json:"error,omitempty"`
	Avoid string `json:"avoid,omitempty"` // node the replica kept failing on
}

// ClusterState is the master's source of truth. Secret values live in secrets.json.
type ClusterState struct {
	Nodes      []ClusterNode             `json:"nodes"`
	Apps       []ClusteredApp            `json:"apps"`
	Replicas   []Replica                 `json:"replicas"`
	History    map[string][]ClusteredApp `json:"history,omitempty"` // previous specs, newest last
	NodeTokens map[string]string         `json:"node_tokens"`       // node id -> sha256(node token)
	// PolicyDefault is "deny" (mesh traffic to app ports needs an allow_from rule) or
	// "allow"/"" (clusters created before policies existed keep working unchanged).
	PolicyDefault string `json:"policy_default,omitempty"`
}

func isClusterMaster() bool {
	cfg, err := loadClusterConfig()
	return err == nil && cfg.Role == "master"
}

func isClusterWorker() bool {
	cfg, err := loadClusterConfig()
	return err == nil && cfg.Role == "worker"
}

func loadClusterConfig() (*ClusterConfig, error) {
	data, err := os.ReadFile(clusterConfigPath())
	if err != nil {
		return nil, err
	}
	var cfg ClusterConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveClusterConfig(cfg *ClusterConfig) error {
	return writeJSONAtomic(clusterConfigPath(), cfg)
}

func writeJSONAtomic(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func lockState(how int) (*os.File, error) {
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(clusterDir, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), how); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

func loadStateFile() (*ClusterState, error) {
	st := &ClusterState{}
	if data, err := os.ReadFile(clusterStatePath()); err == nil {
		if err := json.Unmarshal(data, st); err != nil {
			return nil, fmt.Errorf("corrupt cluster state: %w", err)
		}
	}
	if st.NodeTokens == nil {
		st.NodeTokens = map[string]string{}
	}
	if st.History == nil {
		st.History = map[string][]ClusteredApp{}
	}
	return st, nil
}

// withState runs fn on the master state under an exclusive flock, so the
// cluster server and CLI commands never overwrite each other. The state is
// saved when fn returns nil.
func withState(fn func(st *ClusterState) error) error {
	lock, err := lockState(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer lock.Close()
	st, err := loadStateFile()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	return writeJSONAtomic(clusterStatePath(), st)
}

// readState is a shared-lock snapshot; it never rewrites the file.
func readState() (*ClusterState, error) {
	lock, err := lockState(syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return loadStateFile()
}

// Secrets: name -> KEY -> value, 0600, next to the state (callers hold the state lock).
func loadSecrets() (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	data, err := os.ReadFile(clusterSecretsPath())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(data, &out)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (st *ClusterState) node(id string) *ClusterNode {
	for i := range st.Nodes {
		if st.Nodes[i].ID == id {
			return &st.Nodes[i]
		}
	}
	return nil
}

func (st *ClusterState) app(name string) *ClusteredApp {
	for i := range st.Apps {
		if st.Apps[i].Name == name {
			return &st.Apps[i]
		}
	}
	return nil
}

// replicaRunning: the node the replica is placed on reports its container as running.
func (st *ClusterState) replicaRunning(r Replica) bool {
	n := st.node(r.Node)
	if n == nil || n.Status != "Ready" {
		return false
	}
	name := replicaName(r.App, r.Index, r.Hash)
	for _, c := range n.Running {
		if c == name {
			return true
		}
	}
	return false
}

// appStatus reports "<running>/<replicas> running[, N pending][, updating][, last error]".
func (st *ClusterState) appStatus(app ClusteredApp) string {
	want := specHash(app)
	up, pending, old := 0, 0, 0
	lastErr := ""
	for _, r := range st.Replicas {
		if r.App != app.Name {
			continue
		}
		if r.Hash == "" { // state written before rolling updates existed
			r.Hash = want
		}
		switch {
		case r.Node == "":
			pending++
		case st.replicaRunning(r):
			up++
		}
		if r.Hash != want {
			old++
		}
		if r.Error != "" {
			lastErr = r.Error
		}
	}
	s := fmt.Sprintf("%d/%d running", up, app.Replicas)
	if pending > 0 {
		s += fmt.Sprintf(", %d pending", pending)
	}
	if old > 0 {
		s += fmt.Sprintf(", updating (%d to go)", old)
	}
	if lastErr != "" {
		s += ", error: " + lastErr
	}
	return s
}

func requireMaster() (*ClusterConfig, error) {
	cfg, err := loadClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("not part of a cluster; run 'ziroctl cluster init' first")
	}
	if cfg.Role != "master" {
		return nil, fmt.Errorf("this command must run on the cluster master (%s)", cfg.MasterAddr)
	}
	return cfg, nil
}

// ---- validation (trust boundary for deploy/apply/join input) ----

var (
	envKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	portMapRe = regexp.MustCompile(`^(\d{1,5}):(\d{1,5})(/(tcp|udp))?$`)
)

// hostPortKey returns "8080/tcp" for "8080:80" (the node-level resource a replica holds).
func hostPortKey(port string) string {
	m := portMapRe.FindStringSubmatch(port)
	if m == nil {
		return ""
	}
	proto := m[4]
	if proto == "" {
		proto = "tcp"
	}
	return m[1] + "/" + proto
}

func validPortNum(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

func validateApp(a *ClusteredApp, secrets map[string]map[string]string) error {
	if err := validName(a.Name); err != nil {
		return err
	}
	if a.Image == "" || strings.HasPrefix(a.Image, "-") || strings.ContainsAny(a.Image, " \t\r\n") || len(a.Image) > 512 {
		return fmt.Errorf("invalid image %q", a.Image)
	}
	if a.Replicas < 0 || a.Replicas > 1000 {
		return fmt.Errorf("replicas must be between 0 and 1000")
	}
	if a.Port != "" {
		m := portMapRe.FindStringSubmatch(a.Port)
		if m == nil || !validPortNum(m[1]) || !validPortNum(m[2]) {
			return fmt.Errorf("invalid port %q (want HOST:CONTAINER[/tcp|udp], e.g. 8080:80)", a.Port)
		}
	}
	for _, arg := range a.Args {
		if strings.ContainsRune(arg, 0) || len(arg) > 4096 {
			return fmt.Errorf("invalid argument %q", arg)
		}
	}
	if a.MeshOnly && a.Port == "" {
		return fmt.Errorf("--mesh-only needs --port")
	}
	for k, v := range a.Env {
		if !envKeyRe.MatchString(k) || strings.ContainsAny(v, "\x00\r\n") {
			return fmt.Errorf("invalid env %q", k)
		}
	}
	if len(a.AllowFrom) > 256 {
		return fmt.Errorf("too many allow_from entries")
	}
	for _, from := range a.AllowFrom {
		if from != "*" {
			if err := validName(from); err != nil {
				return fmt.Errorf("allow_from: %w", err)
			}
		}
	}
	for _, s := range a.Secrets {
		if err := validName(s); err != nil {
			return err
		}
		if _, ok := secrets[s]; !ok {
			return fmt.Errorf("secret %q does not exist (create it with 'ziroctl cluster secret set %s KEY=VALUE')", s, s)
		}
	}
	return nil
}

// upsertApp stores a new spec. A changed spec gets a new revision and the old one
// is kept in history (for rollback); the scheduler then rolls replicas over one by one.
func upsertApp(st *ClusterState, app ClusteredApp) (changed bool) {
	cur := st.app(app.Name)
	if cur == nil {
		app.Revision = 1
		if app.CreatedAt == "" {
			app.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		st.Apps = append(st.Apps, app)
		return true
	}
	app.CreatedAt = cur.CreatedAt
	if specHash(*cur) == specHash(app) {
		app.Revision = cur.Revision
		changed = cur.Replicas != app.Replicas
		*cur = app
		return changed
	}
	h := append(st.History[app.Name], *cur)
	if len(h) > maxAppHistory {
		h = h[len(h)-maxAppHistory:]
	}
	st.History[app.Name] = h
	app.Revision = cur.Revision + 1
	*cur = app
	return true
}

// ---- mesh addressing ----

func allocMeshIP(st *ClusterState, cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return "", fmt.Errorf("invalid mesh CIDR %q", cidr)
	}
	used := map[string]bool{}
	for _, n := range st.Nodes {
		used[n.MeshIP] = true
	}
	p = p.Masked()
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		if !p.Contains(a.Next()) { // broadcast
			break
		}
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("mesh subnet %s is full", cidr)
}

// defaultRouteIPv4 is the address on the default-route interface: the one peers can reach,
// not a CNI bridge or a VPN interface that happens to sort first.
func defaultRouteIPv4() string {
	if ifc, err := net.InterfaceByName(defaultRouteIface()); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
					return ipn.IP.String()
				}
			}
		}
	}
	return getFirstNonLoopbackIPv4()
}

// sanitizeLabel strips control characters (log/terminal injection) from peer-supplied text.
func sanitizeLabel(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

var clusterCmd = &cobra.Command{
	Use:     "cluster",
	Aliases: []string{"mesh", "swarm"},
	Short:   "Multi-node container cluster: join nodes, deploy and schedule replicas",
}

var (
	clusterPort      int
	clusterAdvertise string
	clusterMeshCIDR  string
	joinTokenFlag    string
	joinTokenFile    string
	joinCAHashFlag   string
	leaveForce       bool
	tokenTTL         time.Duration
)

func tokenExpiry(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	return time.Now().Add(ttl).UTC().Format(time.RFC3339)
}

var clusterInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this host as the cluster master (it also runs workloads)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadClusterConfig(); err == nil {
			return fmt.Errorf("already part of a cluster; run 'ziroctl cluster leave' first")
		}
		if _, err := netip.ParsePrefix(clusterMeshCIDR); err != nil {
			return fmt.Errorf("invalid --mesh-cidr: %w", err)
		}
		if err := ensureTLSCertificates(); err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		caHash, err := certHash(apiTLSCert)
		if err != nil {
			return err
		}

		host, _ := os.Hostname()
		ip := clusterAdvertise
		if ip == "" {
			ip = defaultRouteIPv4()
		}
		if ip == "" {
			ip = "127.0.0.1"
		}
		_, pub, err := meshKeypair()
		if err != nil {
			return err
		}

		nodeToken := randomHex(32)
		cfg := &ClusterConfig{
			ClusterID:        "ziro-" + randomHex(6),
			Role:             "master",
			NodeID:           "master-1",
			Hostname:         host,
			NodeIP:           ip,
			MasterAddr:       fmt.Sprintf("127.0.0.1:%d", clusterPort),
			Advertise:        fmt.Sprintf("%s:%d", ip, clusterPort),
			JoinToken:        randomHex(16),
			JoinTokenExpires: tokenExpiry(tokenTTL),
			MeshCIDR:         clusterMeshCIDR,
			NodeToken:        nodeToken,
			CAHash:           caHash,
			CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		}

		err = withState(func(st *ClusterState) error {
			*st = ClusterState{NodeTokens: map[string]string{cfg.NodeID: hashToken(nodeToken)}, History: map[string][]ClusteredApp{},
				PolicyDefault: "deny"}
			st.Nodes = []ClusterNode{{
				ID: cfg.NodeID, Hostname: host, IP: ip, Role: "master", Status: "Ready",
				CPUs: runtime.NumCPU(), MemTotal: inspectSystem().TotalMemMB, LastSeen: time.Now(),
				WGPubKey: pub, WGPort: meshPort,
			}}
			mip, err := allocMeshIP(st, cfg.MeshCIDR)
			st.Nodes[0].MeshIP = mip
			return err
		})
		if err != nil {
			return err
		}
		if err := saveClusterConfig(cfg); err != nil {
			return err
		}

		openClusterFirewall(clusterPort)
		startClusterServices("cluster-master", "cluster-agent")

		fmt.Println("================================================================")
		fmt.Println(" 🎉 Ziro-OS cluster initialized — this host is the MASTER")
		fmt.Println("================================================================")
		fmt.Printf(" Cluster ID: %s\n Master:     %s (%s)\n Mesh:       %s (WireGuard, udp/%d)\n\n", cfg.ClusterID, host, cfg.Advertise, cfg.MeshCIDR, meshPort)
		printJoinCommand(cfg)
		return nil
	},
}

func printJoinCommand(cfg *ClusterConfig) {
	fmt.Println("To add a worker, run on it:")
	fmt.Printf("  ZIRO_CLUSTER_TOKEN=%s ziroctl cluster join %s --ca-hash %s\n\n", cfg.JoinToken, cfg.Advertise, cfg.CAHash)
	if cfg.JoinTokenExpires != "" {
		fmt.Printf("The token expires %s. New token: ziroctl cluster token rotate\n", cfg.JoinTokenExpires)
	}
	fmt.Println("Keep the token secret: anyone holding it can join this cluster.")
}

// openClusterFirewall allows the control plane (tcp) and mesh (udp) ports and trusts the
// WireGuard mesh interface (peers are authenticated by their keys); the cluster agent's
// ziro_cluster nft table then narrows ziro0 to the app policy (cluster policy). An admin-disabled
// firewall stays disabled; the boot default (no config file) is enabled.
func openClusterFirewall(port int) {
	fw := loadFirewallConfig()
	have := map[string]bool{}
	for _, r := range fw.AllowedPorts {
		have[fmt.Sprintf("%d/%s", r.Port, r.Protocol)] = true
	}
	if port > 0 && !have[fmt.Sprintf("%d/tcp", port)] {
		fw.AllowedPorts = append(fw.AllowedPorts, FirewallRule{Port: port, Protocol: "tcp", Comment: "Ziro cluster control plane"})
	}
	if !have[fmt.Sprintf("%d/udp", meshPort)] {
		fw.AllowedPorts = append(fw.AllowedPorts, FirewallRule{Port: meshPort, Protocol: "udp", Comment: "Ziro cluster WireGuard mesh"})
	}
	trusted := false
	for _, i := range fw.TrustedInterfaces {
		trusted = trusted || i == meshIface
	}
	if !trusted {
		fw.TrustedInterfaces = append(fw.TrustedInterfaces, meshIface)
	}
	if err := saveFirewallConfig(fw); err != nil {
		fmt.Printf("  ⚠ firewall config: %v\n", err)
		return
	}
	if fw.Enabled {
		_ = applyFirewallRules(fw)
	}
}

func startClusterServices(names ...string) {
	for _, n := range names {
		if err := enableService(n); err != nil {
			fmt.Printf("  ⚠ enable %s: %v\n", n, err)
		}
		if err := startService(n); err != nil && !strings.Contains(err.Error(), "already running") {
			fmt.Printf("  ⚠ start %s: %v\n", n, err)
		}
	}
}

func stopClusterServices(names ...string) {
	for _, n := range names {
		_ = stopService(n)
		_ = disableService(n)
	}
}

// joinToken reads the token from --token-file, ZIRO_CLUSTER_TOKEN or --token (in that order):
// the first two keep it out of argv, shell history and ps.
func joinToken() (string, error) {
	if joinTokenFile != "" {
		b, err := os.ReadFile(joinTokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := os.Getenv("ZIRO_CLUSTER_TOKEN"); t != "" {
		return t, nil
	}
	return joinTokenFlag, nil
}

var clusterJoinCmd = &cobra.Command{
	Use:   "join <master-ip:port>",
	Short: "Join this host to a cluster as a worker",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := joinToken()
		if err != nil {
			return err
		}
		if token == "" || joinCAHashFlag == "" {
			return fmt.Errorf("a join token (ZIRO_CLUSTER_TOKEN, --token-file or --token) and --ca-hash are required (printed by 'ziroctl cluster token' on the master)")
		}
		if _, err := loadClusterConfig(); err == nil {
			return fmt.Errorf("already part of a cluster; run 'ziroctl cluster leave' first")
		}
		_, pub, err := meshKeypair()
		if err != nil {
			return err
		}
		host, _ := os.Hostname()
		req := joinRequest{Hostname: host, CPUs: runtime.NumCPU(), MemTotal: inspectSystem().TotalMemMB, WGPubKey: pub, WGPort: meshPort}
		var resp joinResponse
		if err := clusterPost(args[0], joinCAHashFlag, "/cluster/v1/join", "Bearer "+token, req, &resp); err != nil {
			return fmt.Errorf("join failed: %w", err)
		}

		cfg := &ClusterConfig{
			ClusterID:  resp.ClusterID,
			Role:       "worker",
			NodeID:     resp.NodeID,
			Hostname:   host,
			NodeIP:     resp.NodeIP,
			MasterAddr: args[0],
			NodeToken:  resp.NodeToken,
			CAHash:     joinCAHashFlag,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		if err := saveClusterConfig(cfg); err != nil {
			return err
		}
		openClusterFirewall(0)
		startClusterServices("cluster-agent")
		fmt.Printf("✓ Joined cluster %s as worker %s (%s), mesh IP %s\n", resp.ClusterID, resp.NodeID, host, resp.MeshIP)
		return nil
	},
}

type clusterStatusView struct {
	ClusterID string `json:"cluster_id,omitempty"`
	Role      string `json:"role"`
	NodeID    string `json:"node_id,omitempty"`
	Master    string `json:"master,omitempty"`
	NodesUp   int    `json:"nodes_ready,omitempty"`
	Nodes     int    `json:"nodes,omitempty"`
	Apps      int    `json:"apps,omitempty"`
}

var clusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show this node's cluster role and cluster health",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadClusterConfig()
		if err != nil {
			return printResult(clusterStatusView{Role: "standalone"}, func() {
				fmt.Println("Cluster Status: Standalone (not part of a cluster)")
				fmt.Println("Run 'ziroctl cluster init' to create one, or 'ziroctl cluster join' to join one.")
			})
		}
		v := clusterStatusView{ClusterID: cfg.ClusterID, Role: cfg.Role, NodeID: cfg.NodeID, Master: cfg.MasterAddr}
		if cfg.Role == "master" {
			st, err := readState()
			if err != nil {
				return err
			}
			for _, n := range st.Nodes {
				if n.Status == "Ready" {
					v.NodesUp++
				}
			}
			v.Nodes, v.Apps = len(st.Nodes), len(st.Apps)
		}
		return printResult(v, func() {
			fmt.Println("=== Ziro-OS Cluster Status ===")
			fmt.Printf("Cluster ID:  %s\n", cfg.ClusterID)
			fmt.Printf("Node:        %s (%s, %s)\n", cfg.NodeID, cfg.Hostname, strings.ToUpper(cfg.Role))
			fmt.Printf("Master:      %s\n", cfg.MasterAddr)
			if cfg.Role == "master" {
				fmt.Printf("Nodes:       %d/%d Ready\n", v.NodesUp, v.Nodes)
				fmt.Printf("Apps:        %d deployed\n", v.Apps)
			}
		})
	},
}

var clusterNodesCmd = &cobra.Command{
	Use:   "nodes",
	Short: "List cluster nodes (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		scheduleReplicas(st, time.Now()) // fresh readiness for display only (not saved)
		return printResult(st.Nodes, func() {
			fmt.Printf("%-14s %-16s %-16s %-14s %-7s %-19s %-5s %-8s %s\n", "NODE ID", "HOSTNAME", "IP", "MESH IP", "ROLE", "STATUS", "CPUS", "REPLICAS", "LAST SEEN")
			fmt.Println(strings.Repeat("-", 120))
			for _, n := range st.Nodes {
				count := 0
				for _, r := range st.Replicas {
					if r.Node == n.ID {
						count++
					}
				}
				status := n.Status
				if n.Cordoned {
					status += ",Cordoned"
				}
				if n.MeshError != "" {
					status += ",MeshError"
				}
				fmt.Printf("%-14s %-16s %-16s %-14s %-7s %-19s %-5d %-8d %s ago\n", n.ID, n.Hostname, n.IP, n.MeshIP, n.Role, status, n.CPUs, count,
					time.Since(n.LastSeen).Round(time.Second))
			}
		})
	},
}

var (
	appName     string
	appImage    string
	appReplicas int
	appPort     string
	appEnv      []string
	appSecrets  []string
	appArgs     []string
	appMeshOnly bool
	appAllow    []string
	applyFile   string
)

// deployApp validates and stores app under the state lock, then schedules.
func deployApp(mutate func(st *ClusterState) (*ClusteredApp, error)) error {
	return withState(func(st *ClusterState) error {
		secrets, err := loadSecrets()
		if err != nil {
			return err
		}
		app, err := mutate(st)
		if err != nil {
			return err
		}
		if err := validateApp(app, secrets); err != nil {
			return err
		}
		changed := upsertApp(st, *app)
		scheduleReplicas(st, time.Now())
		if !changed {
			fmt.Printf("= '%s' unchanged (revision %d)\n", app.Name, st.app(app.Name).Revision)
			return nil
		}
		fmt.Printf("✓ '%s' revision %d scheduled; replicas roll over one at a time. Watch: ziroctl cluster services\n",
			app.Name, st.app(app.Name).Revision)
		return nil
	})
}

var clusterDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy an app, or update only the flags given on an existing one (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if appName == "" {
			return fmt.Errorf("--name is required")
		}
		f := cmd.Flags()
		return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
			app := ClusteredApp{Name: appName, Replicas: 1}
			if cur := st.app(appName); cur != nil {
				app = *cur // patch: flags not given keep their current value
			} else if appImage == "" {
				return nil, fmt.Errorf("--image is required for a new app")
			}
			if f.Changed("image") {
				app.Image = appImage
			}
			if f.Changed("replicas") {
				app.Replicas = appReplicas
			}
			if f.Changed("port") {
				app.Port = appPort
			}
			if f.Changed("mesh-only") {
				app.MeshOnly = appMeshOnly
			}
			if f.Changed("arg") {
				app.Args = appArgs
			}
			if f.Changed("allow-from") {
				app.AllowFrom = nil
				for _, a := range appAllow {
					if a = strings.TrimSpace(a); a != "" {
						app.AllowFrom = append(app.AllowFrom, a)
					}
				}
			}
			if f.Changed("secret") {
				app.Secrets = appSecrets
			}
			if f.Changed("env") {
				env := map[string]string{}
				for k, v := range app.Env {
					env[k] = v
				}
				for _, e := range appEnv {
					k, v, ok := strings.Cut(e, "=")
					if !ok || k == "" {
						return nil, fmt.Errorf("invalid --env %q (want KEY=VALUE, or KEY= to remove)", e)
					}
					if v == "" {
						delete(env, k)
					} else {
						env[k] = v
					}
				}
				app.Env = env
			}
			return &app, nil
		})
	},
}

var clusterApplyCmd = &cobra.Command{
	Use:   "apply -f <app.json>",
	Short: "Declaratively create or replace apps from a JSON manifest (one app or a list)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		data, err := os.ReadFile(applyFile)
		if err != nil {
			return err
		}
		var apps []ClusteredApp
		if err := json.Unmarshal(data, &apps); err != nil {
			var one ClusteredApp
			if err2 := json.Unmarshal(data, &one); err2 != nil {
				return fmt.Errorf("%s: want a JSON app object or list: %v", applyFile, err2)
			}
			apps = []ClusteredApp{one}
		}
		for i := range apps {
			a := apps[i]
			if err := deployApp(func(st *ClusterState) (*ClusteredApp, error) {
				a.Revision, a.CreatedAt = 0, ""
				return &a, nil
			}); err != nil {
				return fmt.Errorf("%s: %w", a.Name, err)
			}
		}
		return nil
	},
}

var clusterScaleCmd = &cobra.Command{
	Use:   "scale <app> <replicas>",
	Short: "Change an app's replica count (master only)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		n, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("replicas must be a number")
		}
		return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
			cur := st.app(args[0])
			if cur == nil {
				return nil, fmt.Errorf("app %q not found", args[0])
			}
			a := *cur
			a.Replicas = n
			return &a, nil
		})
	},
}

var clusterRollbackCmd = &cobra.Command{
	Use:   "rollback <app>",
	Short: "Roll an app back to its previous revision (rolling, master only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
			cur := st.app(args[0])
			h := st.History[args[0]]
			if cur == nil || len(h) == 0 {
				return nil, fmt.Errorf("no previous revision of %q", args[0])
			}
			prev := h[len(h)-1]
			st.History[args[0]] = h[:len(h)-1]
			prev.Replicas = cur.Replicas   // rollback restores the spec, not the scale
			prev.AllowFrom = cur.AllowFrom // ... nor an older (possibly looser) network policy
			return &prev, nil
		})
	},
}

var clusterRemoveCmd = &cobra.Command{
	Use:   "remove <app>",
	Short: "Remove an app and all its replicas from the cluster (master only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			var kept []ClusteredApp
			for _, a := range st.Apps {
				if a.Name != args[0] {
					kept = append(kept, a)
				}
			}
			if len(kept) == len(st.Apps) {
				return fmt.Errorf("app %q not found", args[0])
			}
			st.Apps = kept
			delete(st.History, args[0])
			scheduleReplicas(st, time.Now())
			fmt.Printf("✓ Removed '%s'; agents stop its containers within ~%ds\n", args[0], int(agentInterval.Seconds()))
			return nil
		})
	},
}

type appView struct {
	ClusteredApp
	Status string `json:"status"`
}

var clusterServicesCmd = &cobra.Command{
	Use:     "services",
	Aliases: []string{"apps", "ps"},
	Short:   "List cluster apps and replica health (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		views := []appView{}
		for _, a := range st.Apps {
			views = append(views, appView{a, st.appStatus(a)})
		}
		return printResult(views, func() {
			if len(views) == 0 {
				fmt.Println("No cluster apps deployed.")
				return
			}
			fmt.Printf("%-16s %-4s %-28s %-12s %s\n", "NAME", "REV", "IMAGE", "PORT", "STATUS")
			fmt.Println(strings.Repeat("-", 90))
			for _, v := range views {
				p := v.Port
				if p == "" {
					p = "-"
				}
				fmt.Printf("%-16s %-4d %-28s %-12s %s\n", v.Name, v.Revision, v.Image, p, v.Status)
			}
		})
	},
}

var clusterEndpointsCmd = &cobra.Command{
	Use:   "endpoints [app]",
	Short: "Show where each app is reachable on the mesh (<app>.cluster.ziro)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		eps := appEndpoints(st)
		if len(args) == 1 {
			eps = map[string][]string{args[0]: eps[args[0]]}
		}
		return printResult(eps, func() {
			names := make([]string, 0, len(eps))
			for n := range eps {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				port := ""
				if a := st.app(n); a != nil && a.Port != "" {
					port = ":" + strings.SplitN(a.Port, ":", 2)[0]
				}
				fmt.Printf("%s.%s%s -> %s\n", n, meshDomain, port, strings.Join(eps[n], ", "))
			}
		})
	},
}

// ---- node operations ----

func nodeOp(id string, fn func(st *ClusterState, n *ClusterNode) error) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return withState(func(st *ClusterState) error {
		n := st.node(id)
		if n == nil {
			return fmt.Errorf("node %q not found", id)
		}
		if err := fn(st, n); err != nil {
			return err
		}
		scheduleReplicas(st, time.Now())
		return nil
	})
}

var clusterNodeCmd = &cobra.Command{Use: "node", Short: "Cordon, drain or remove cluster nodes (master only)"}

var clusterCordonCmd = &cobra.Command{
	Use: "cordon <node>", Short: "Stop scheduling new replicas on a node", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error { n.Cordoned = true; return nil })
	},
}

var clusterUncordonCmd = &cobra.Command{
	Use: "uncordon <node>", Short: "Allow scheduling on a node again", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error { n.Cordoned = false; return nil })
	},
}

var clusterDrainCmd = &cobra.Command{
	Use: "drain <node>", Short: "Cordon a node and move its replicas to other nodes", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error {
			n.Cordoned = true
			for i := range st.Replicas {
				if st.Replicas[i].Node == n.ID {
					st.Replicas[i].Node = ""
				}
			}
			fmt.Printf("✓ %s cordoned and drained\n", n.ID)
			return nil
		})
	},
}

var clusterNodeRmCmd = &cobra.Command{
	Use: "rm <node>", Short: "Remove a (dead) worker from the cluster and revoke its credentials", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error {
			if n.Role == "master" {
				return fmt.Errorf("the master cannot be removed")
			}
			removeNode(st, n.ID)
			fmt.Printf("✓ %s removed; its token is revoked\n", args[0])
			return nil
		})
	},
}

func removeNode(st *ClusterState, id string) {
	delete(st.NodeTokens, id)
	var kept []ClusterNode
	for _, x := range st.Nodes {
		if x.ID != id {
			kept = append(kept, x)
		}
	}
	st.Nodes = kept
}

var clusterTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print the worker join command (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		if joinTokenExpired(cfg, time.Now()) {
			return fmt.Errorf("the join token expired at %s; create a new one: ziroctl cluster token rotate", cfg.JoinTokenExpires)
		}
		printJoinCommand(cfg)
		return nil
	},
}

var clusterTokenRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the join token (the old one stops working immediately)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		cfg.JoinToken, cfg.JoinTokenExpires = randomHex(16), tokenExpiry(tokenTTL)
		if err := saveClusterConfig(cfg); err != nil {
			return err
		}
		printJoinCommand(cfg)
		return nil
	},
}

func joinTokenExpired(cfg *ClusterConfig, now time.Time) bool {
	if cfg.JoinTokenExpires == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, cfg.JoinTokenExpires)
	return err != nil || now.After(exp)
}

// ---- secrets ----

var clusterSecretCmd = &cobra.Command{Use: "secret", Short: "Manage cluster secrets (injected into apps as env files, never argv)"}

var clusterSecretSetCmd = &cobra.Command{
	Use:   "set <name> KEY=VALUE...",
	Short: "Create or replace a secret",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := validName(args[0]); err != nil {
			return err
		}
		kv := map[string]string{}
		for _, e := range args[1:] {
			k, v, ok := strings.Cut(e, "=")
			if !ok || !envKeyRe.MatchString(k) || strings.ContainsAny(v, "\x00\r\n") {
				return fmt.Errorf("invalid secret entry %q (want KEY=VALUE, single line)", k)
			}
			kv[k] = v
		}
		return withState(func(st *ClusterState) error {
			secrets, err := loadSecrets()
			if err != nil {
				return err
			}
			secrets[args[0]] = kv
			if err := writeJSONAtomic(clusterSecretsPath(), secrets); err != nil {
				return err
			}
			fmt.Printf("✓ secret '%s' saved (%d keys); apps using it pick it up on their next container start\n", args[0], len(kv))
			return nil
		})
	},
}

var clusterSecretRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Delete a secret (refused while an app uses it)", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			for _, a := range st.Apps {
				for _, s := range a.Secrets {
					if s == args[0] {
						return fmt.Errorf("secret %q is used by app %q", s, a.Name)
					}
				}
			}
			secrets, err := loadSecrets()
			if err != nil {
				return err
			}
			if _, ok := secrets[args[0]]; !ok {
				return fmt.Errorf("secret %q not found", args[0])
			}
			delete(secrets, args[0])
			return writeJSONAtomic(clusterSecretsPath(), secrets)
		})
	},
}

var clusterSecretLsCmd = &cobra.Command{
	Use: "ls", Short: "List secret names and keys (never values)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		lock, err := lockState(syscall.LOCK_SH)
		if err != nil {
			return err
		}
		secrets, err := loadSecrets()
		lock.Close()
		if err != nil {
			return err
		}
		view := map[string][]string{}
		for name, kv := range secrets {
			for k := range kv {
				view[name] = append(view[name], k)
			}
			sort.Strings(view[name])
		}
		return printResult(view, func() {
			names := make([]string, 0, len(view))
			for n := range view {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Printf("%-24s %s\n", n, strings.Join(view[n], ", "))
			}
		})
	},
}

var clusterLeaveCmd = &cobra.Command{
	Use:   "leave",
	Short: "Leave the cluster and remove this node's cluster containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadClusterConfig()
		if err != nil {
			return fmt.Errorf("not part of a cluster")
		}
		if cfg.Role == "master" {
			st, err := readState()
			if err == nil && len(st.Nodes) > 1 && !leaveForce {
				return fmt.Errorf("%d worker(s) still joined; use --force to tear down the whole cluster", len(st.Nodes)-1)
			}
			stopClusterServices("cluster-agent", "cluster-master")
			_ = os.Remove(clusterStatePath())
			_ = os.Remove(clusterSecretsPath())
		} else {
			if err := clusterPost(cfg.MasterAddr, cfg.CAHash, "/cluster/v1/leave", nodeAuth(cfg), struct{}{}, nil); err != nil {
				fmt.Printf("⚠ could not notify master (%v); remove it there with: ziroctl cluster node rm %s\n", err, cfg.NodeID)
			}
			stopClusterServices("cluster-agent")
		}
		if err := reconcileContainers(nil); err != nil {
			fmt.Printf("⚠ could not remove cluster containers: %v\n", err)
		}
		teardownMesh()
		if err := os.Remove(clusterConfigPath()); err != nil {
			return err
		}
		fmt.Println("✓ Left the cluster; this node is standalone again.")
		return nil
	},
}

func init() {
	clusterInitCmd.Flags().IntVarP(&clusterPort, "port", "p", 7443, "Cluster control plane listening port")
	clusterInitCmd.Flags().StringVar(&clusterAdvertise, "advertise", "", "IP workers use to reach this master (default: IP of the default-route interface)")
	clusterInitCmd.Flags().StringVar(&clusterMeshCIDR, "mesh-cidr", defaultMeshCIDR, "WireGuard mesh subnet for node-to-node traffic")
	clusterInitCmd.Flags().DurationVar(&tokenTTL, "token-ttl", 24*time.Hour, "Join token lifetime (0 = never expires)")
	clusterTokenRotateCmd.Flags().DurationVar(&tokenTTL, "ttl", 24*time.Hour, "Join token lifetime (0 = never expires)")
	clusterJoinCmd.Flags().StringVarP(&joinTokenFlag, "token", "t", "", "Cluster join token (prefer ZIRO_CLUSTER_TOKEN or --token-file: argv is visible in ps)")
	clusterJoinCmd.Flags().StringVar(&joinTokenFile, "token-file", "", "File containing the join token")
	clusterJoinCmd.Flags().StringVar(&joinCAHashFlag, "ca-hash", "", "Pinned master certificate hash (sha256:...)")
	clusterLeaveCmd.Flags().BoolVar(&leaveForce, "force", false, "On the master: tear down the cluster even if workers remain")

	clusterDeployCmd.Flags().StringVarP(&appName, "name", "n", "", "App name")
	clusterDeployCmd.Flags().StringVarP(&appImage, "image", "i", "", "OCI image")
	clusterDeployCmd.Flags().IntVarP(&appReplicas, "replicas", "r", 1, "Number of replicas (0 scales to zero)")
	clusterDeployCmd.Flags().StringVarP(&appPort, "port", "p", "", "Host port mapping HOST:CONTAINER[/udp]; at most one replica per node")
	clusterDeployCmd.Flags().StringArrayVarP(&appEnv, "env", "e", nil, "Environment variable KEY=VALUE (repeatable; KEY= removes)")
	clusterDeployCmd.Flags().StringArrayVar(&appSecrets, "secret", nil, "Cluster secret to inject as env (repeatable)")
	clusterDeployCmd.Flags().StringArrayVar(&appArgs, "arg", nil, "Command/argument passed after the image (repeatable, in order)")
	clusterDeployCmd.Flags().BoolVar(&appMeshOnly, "mesh-only", false, "Publish --port only on the node's mesh IP (not the public interface)")
	clusterDeployCmd.Flags().StringSliceVar(&appAllow, "allow-from", nil, "Apps allowed to reach --port over the mesh (comma-separated, '*' = any cluster app, '' = none)")
	clusterApplyCmd.Flags().StringVarP(&applyFile, "file", "f", "", "JSON manifest")
	_ = clusterApplyCmd.MarkFlagRequired("file")

	clusterNodeCmd.AddCommand(clusterCordonCmd, clusterUncordonCmd, clusterDrainCmd, clusterNodeRmCmd)
	clusterTokenCmd.AddCommand(clusterTokenRotateCmd)
	clusterSecretCmd.AddCommand(clusterSecretSetCmd, clusterSecretRmCmd, clusterSecretLsCmd)
	clusterCmd.AddCommand(clusterInitCmd, clusterJoinCmd, clusterStatusCmd, clusterNodesCmd, clusterDeployCmd,
		clusterApplyCmd, clusterScaleCmd, clusterRollbackCmd, clusterRemoveCmd, clusterServicesCmd,
		clusterEndpointsCmd, clusterNodeCmd, clusterTokenCmd, clusterSecretCmd, clusterLeaveCmd,
		clusterPolicyCmd, clusterServeCmd, clusterAgentCmd)
	clusterPolicyCmd.AddCommand(clusterPolicyDefaultCmd, clusterPolicyLsCmd)
	rootCmd.AddCommand(clusterCmd)
}

// sortReplicas keeps state output stable.
func sortReplicas(rs []Replica) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].App != rs[j].App {
			return rs[i].App < rs[j].App
		}
		return rs[i].Index < rs[j].Index
	})
}

func getFirstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

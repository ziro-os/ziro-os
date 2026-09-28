package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// clusterDir is a var so tests can point it at a temp dir.
var clusterDir = "/etc/ziro/cluster"

func clusterConfigPath() string { return filepath.Join(clusterDir, "config.json") }
func clusterStatePath() string  { return filepath.Join(clusterDir, "state.json") }

// ClusterConfig is this node's identity and how it reaches the master.
type ClusterConfig struct {
	ClusterID  string `json:"cluster_id"`
	Role       string `json:"role"` // "master" or "worker"
	NodeID     string `json:"node_id"`
	Hostname   string `json:"hostname"`
	NodeIP     string `json:"node_ip"`
	MasterAddr string `json:"master_addr"` // host:port the local agent talks to
	Advertise  string `json:"advertise,omitempty"`
	JoinToken  string `json:"join_token,omitempty"` // master only
	NodeToken  string `json:"node_token"`
	CAHash     string `json:"ca_hash"` // "sha256:<hex>" of the master's TLS certificate
	CreatedAt  string `json:"created_at"`
}

type ClusterNode struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	Role       string    `json:"role"`
	Status     string    `json:"status"` // Ready, NotReady
	CPUs       int       `json:"cpus"`
	MemTotal   uint64    `json:"mem_total_mb"`
	Containers int       `json:"containers"`
	Running    []string  `json:"running"` // cluster containers the agent reports running
	LastSeen   time.Time `json:"last_seen"`
}

type ClusteredApp struct {
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Replicas  int               `json:"replicas"`
	Port      string            `json:"port"`
	Env       map[string]string `json:"env"`
	CreatedAt string            `json:"created_at"`
}

// Replica is one placed (or pending, Node == "") instance of an app.
type Replica struct {
	App   string `json:"app"`
	Index int    `json:"index"`
	Node  string `json:"node"`
}

// ClusterState is the master's source of truth.
type ClusterState struct {
	Nodes      []ClusterNode     `json:"nodes"`
	Apps       []ClusteredApp    `json:"apps"`
	Replicas   []Replica         `json:"replicas"`
	NodeTokens map[string]string `json:"node_tokens"` // node id -> sha256(node token)
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

// withState runs fn on the master state under an exclusive flock, so the
// cluster server and CLI commands never overwrite each other. The state is
// saved when fn returns nil.
func withState(fn func(st *ClusterState) error) error {
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(clusterDir, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	st := &ClusterState{}
	if data, err := os.ReadFile(clusterStatePath()); err == nil {
		if err := json.Unmarshal(data, st); err != nil {
			return fmt.Errorf("corrupt cluster state: %w", err)
		}
	}
	if st.NodeTokens == nil {
		st.NodeTokens = map[string]string{}
	}
	if err := fn(st); err != nil {
		return err
	}
	return writeJSONAtomic(clusterStatePath(), st)
}

func readState() (*ClusterState, error) {
	var out *ClusterState
	err := withState(func(st *ClusterState) error { out = st; return nil })
	return out, err
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

// appStatus reports "<running>/<replicas> running[, N pending]" from agent reports.
func (st *ClusterState) appStatus(app ClusteredApp) string {
	running := map[string]bool{}
	for _, n := range st.Nodes {
		if n.Status == "Ready" {
			for _, c := range n.Running {
				running[c] = true
			}
		}
	}
	up, pending := 0, 0
	for _, r := range st.Replicas {
		if r.App != app.Name {
			continue
		}
		if r.Node == "" {
			pending++
		} else if running[containerName(app, r.Index)] {
			up++
		}
	}
	s := fmt.Sprintf("%d/%d running", up, app.Replicas)
	if pending > 0 {
		s += fmt.Sprintf(", %d pending", pending)
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

var clusterCmd = &cobra.Command{
	Use:     "cluster",
	Aliases: []string{"mesh", "swarm"},
	Short:   "Multi-node container cluster: join nodes, deploy and schedule replicas",
}

var (
	clusterPort      int
	clusterAdvertise string
	joinTokenFlag    string
	joinCAHashFlag   string
	leaveForce       bool
)

var clusterInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this host as the cluster master (it also runs workloads)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadClusterConfig(); err == nil {
			return fmt.Errorf("already part of a cluster; run 'ziroctl cluster leave' first")
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
			ip = getFirstNonLoopbackIPv4()
		}
		if ip == "" {
			ip = "127.0.0.1"
		}

		nodeToken := randomHex(32)
		cfg := &ClusterConfig{
			ClusterID:  "ziro-" + randomHex(6),
			Role:       "master",
			NodeID:     "master-1",
			Hostname:   host,
			NodeIP:     ip,
			MasterAddr: fmt.Sprintf("127.0.0.1:%d", clusterPort),
			Advertise:  fmt.Sprintf("%s:%d", ip, clusterPort),
			JoinToken:  randomHex(16),
			NodeToken:  nodeToken,
			CAHash:     caHash,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}

		err = withState(func(st *ClusterState) error {
			*st = ClusterState{NodeTokens: map[string]string{cfg.NodeID: hashToken(nodeToken)}}
			st.Nodes = []ClusterNode{{
				ID: cfg.NodeID, Hostname: host, IP: ip, Role: "master", Status: "Ready",
				CPUs: runtime.NumCPU(), MemTotal: inspectSystem().TotalMemMB, LastSeen: time.Now(),
			}}
			return nil
		})
		if err != nil {
			return err
		}
		if err := saveClusterConfig(cfg); err != nil {
			return err
		}

		allowClusterPort(clusterPort)
		startClusterServices("cluster-master", "cluster-agent")

		fmt.Println("================================================================")
		fmt.Println(" 🎉 Ziro-OS cluster initialized — this host is the MASTER")
		fmt.Println("================================================================")
		fmt.Printf(" Cluster ID: %s\n Master:     %s (%s)\n\n", cfg.ClusterID, host, cfg.Advertise)
		printJoinCommand(cfg)
		return nil
	},
}

func printJoinCommand(cfg *ClusterConfig) {
	fmt.Println("To add a worker, run on it:")
	fmt.Printf("  ziroctl cluster join %s --token %s --ca-hash %s\n\n", cfg.Advertise, cfg.JoinToken, cfg.CAHash)
	fmt.Println("Keep the token secret: anyone holding it can join this cluster.")
}

func allowClusterPort(port int) {
	fw := loadFirewallConfig()
	for _, r := range fw.AllowedPorts {
		if r.Port == port && r.Protocol == "tcp" {
			return
		}
	}
	fw.AllowedPorts = append(fw.AllowedPorts, FirewallRule{Port: port, Protocol: "tcp", Comment: "Ziro cluster control plane"})
	_ = saveFirewallConfig(fw)
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

var clusterJoinCmd = &cobra.Command{
	Use:   "join <master-ip:port>",
	Short: "Join this host to a cluster as a worker",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if joinTokenFlag == "" || joinCAHashFlag == "" {
			return fmt.Errorf("--token and --ca-hash are required (printed by 'ziroctl cluster token' on the master)")
		}
		if _, err := loadClusterConfig(); err == nil {
			return fmt.Errorf("already part of a cluster; run 'ziroctl cluster leave' first")
		}
		host, _ := os.Hostname()
		req := joinRequest{Hostname: host, CPUs: runtime.NumCPU(), MemTotal: inspectSystem().TotalMemMB}
		var resp joinResponse
		if err := clusterPost(args[0], joinCAHashFlag, "/cluster/v1/join", "Bearer "+joinTokenFlag, req, &resp); err != nil {
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
		startClusterServices("cluster-agent")
		fmt.Printf("✓ Joined cluster %s as worker %s (%s)\n", resp.ClusterID, resp.NodeID, host)
		return nil
	},
}

var clusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show this node's cluster role and cluster health",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadClusterConfig()
		if err != nil {
			fmt.Println("Cluster Status: Standalone (not part of a cluster)")
			fmt.Println("Run 'ziroctl cluster init' to create one, or 'ziroctl cluster join' to join one.")
			return
		}
		fmt.Println("=== Ziro-OS Cluster Status ===")
		fmt.Printf("Cluster ID:  %s\n", cfg.ClusterID)
		fmt.Printf("Node:        %s (%s, %s)\n", cfg.NodeID, cfg.Hostname, strings.ToUpper(cfg.Role))
		fmt.Printf("Master:      %s\n", cfg.MasterAddr)
		if cfg.Role != "master" {
			return
		}
		st, err := readState()
		if err != nil {
			fmt.Printf("State:       error: %v\n", err)
			return
		}
		ready := 0
		for _, n := range st.Nodes {
			if n.Status == "Ready" {
				ready++
			}
		}
		fmt.Printf("Nodes:       %d/%d Ready\n", ready, len(st.Nodes))
		fmt.Printf("Apps:        %d deployed\n", len(st.Apps))
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
		fmt.Printf("%-14s %-16s %-16s %-7s %-9s %-5s %-8s %s\n", "NODE ID", "HOSTNAME", "IP", "ROLE", "STATUS", "CPUS", "REPLICAS", "LAST SEEN")
		fmt.Println(strings.Repeat("-", 96))
		for _, n := range st.Nodes {
			count := 0
			for _, r := range st.Replicas {
				if r.Node == n.ID {
					count++
				}
			}
			fmt.Printf("%-14s %-16s %-16s %-7s %-9s %-5d %-8d %s ago\n", n.ID, n.Hostname, n.IP, n.Role, n.Status, n.CPUs, count,
				time.Since(n.LastSeen).Round(time.Second))
		}
		return nil
	},
}

var (
	appName     string
	appImage    string
	appReplicas int
	appPort     string
	appEnv      []string
)

var clusterDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy or update an app; replicas are scheduled across Ready nodes (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if appName == "" || appImage == "" {
			return fmt.Errorf("--name and --image are required")
		}
		if err := validName(appName); err != nil {
			return err
		}
		if strings.HasPrefix(appImage, "-") || strings.ContainsAny(appImage, " \t\n") {
			return fmt.Errorf("invalid image %q", appImage)
		}
		if appReplicas < 0 {
			return fmt.Errorf("--replicas must be >= 0")
		}
		env := map[string]string{}
		for _, e := range appEnv {
			k, v, ok := strings.Cut(e, "=")
			if !ok || k == "" {
				return fmt.Errorf("invalid --env %q (want KEY=VALUE)", e)
			}
			env[k] = v
		}

		app := ClusteredApp{Name: appName, Image: appImage, Replicas: appReplicas, Port: appPort, Env: env,
			CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		err := withState(func(st *ClusterState) error {
			replaced := false
			for i := range st.Apps {
				if st.Apps[i].Name == app.Name {
					app.CreatedAt = st.Apps[i].CreatedAt
					st.Apps[i] = app
					replaced = true
				}
			}
			if !replaced {
				st.Apps = append(st.Apps, app)
			}
			scheduleReplicas(st, time.Now())
			for _, r := range st.Replicas {
				if r.App != app.Name {
					continue
				}
				where := r.Node
				if where == "" {
					where = "PENDING (no eligible Ready node)"
				}
				fmt.Printf("  %s -> %s\n", containerName(app, r.Index), where)
			}
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("✓ '%s' scheduled; agents converge within ~%ds. Check: ziroctl cluster services\n", app.Name, int(agentInterval.Seconds()))
		return nil
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
			scheduleReplicas(st, time.Now())
			fmt.Printf("✓ Removed '%s'; agents stop its containers within ~%ds\n", args[0], int(agentInterval.Seconds()))
			return nil
		})
	},
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
		if len(st.Apps) == 0 {
			fmt.Println("No cluster apps deployed.")
			return nil
		}
		fmt.Printf("%-16s %-28s %-12s %s\n", "NAME", "IMAGE", "PORT", "STATUS")
		fmt.Println(strings.Repeat("-", 80))
		for _, a := range st.Apps {
			p := a.Port
			if p == "" {
				p = "-"
			}
			fmt.Printf("%-16s %-28s %-12s %s\n", a.Name, a.Image, p, st.appStatus(a))
		}
		return nil
	},
}

var clusterTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print the worker join command (master only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		printJoinCommand(cfg)
		return nil
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
		} else {
			if err := clusterPost(cfg.MasterAddr, cfg.CAHash, "/cluster/v1/leave", nodeAuth(cfg), struct{}{}, nil); err != nil {
				fmt.Printf("⚠ could not notify master (%v); it will mark this node NotReady\n", err)
			}
			stopClusterServices("cluster-agent")
		}
		if err := reconcileContainers(nil); err != nil {
			fmt.Printf("⚠ could not remove cluster containers: %v\n", err)
		}
		if err := os.Remove(clusterConfigPath()); err != nil {
			return err
		}
		fmt.Println("✓ Left the cluster; this node is standalone again.")
		return nil
	},
}

func init() {
	clusterInitCmd.Flags().IntVarP(&clusterPort, "port", "p", 7443, "Cluster control plane listening port")
	clusterInitCmd.Flags().StringVar(&clusterAdvertise, "advertise", "", "IP workers use to reach this master (default: first non-loopback IPv4)")
	clusterJoinCmd.Flags().StringVarP(&joinTokenFlag, "token", "t", "", "Cluster join token")
	clusterJoinCmd.Flags().StringVar(&joinCAHashFlag, "ca-hash", "", "Pinned master certificate hash (sha256:...)")
	clusterLeaveCmd.Flags().BoolVar(&leaveForce, "force", false, "On the master: tear down the cluster even if workers remain")

	clusterDeployCmd.Flags().StringVarP(&appName, "name", "n", "", "App name")
	clusterDeployCmd.Flags().StringVarP(&appImage, "image", "i", "", "OCI image")
	clusterDeployCmd.Flags().IntVarP(&appReplicas, "replicas", "r", 1, "Number of replicas (0 scales to zero)")
	clusterDeployCmd.Flags().StringVarP(&appPort, "port", "p", "", "Host port mapping (e.g. 8080:80); at most one replica per node")
	clusterDeployCmd.Flags().StringArrayVarP(&appEnv, "env", "e", nil, "Environment variable KEY=VALUE (repeatable)")

	clusterCmd.AddCommand(clusterInitCmd, clusterJoinCmd, clusterStatusCmd, clusterNodesCmd, clusterDeployCmd,
		clusterRemoveCmd, clusterServicesCmd, clusterTokenCmd, clusterLeaveCmd, clusterServeCmd, clusterAgentCmd)
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

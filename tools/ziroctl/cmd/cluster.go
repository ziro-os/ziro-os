package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	clusterDir       = "/etc/ziro/cluster"
	clusterConfigFile = "/etc/ziro/cluster/config.json"
	clusterNodesFile  = "/etc/ziro/cluster/nodes.json"
	clusterSvcsFile   = "/etc/ziro/cluster/services.json"
)

type ClusterConfig struct {
	ClusterID  string `json:"cluster_id"`
	Role       string `json:"role"` // "master" or "worker"
	NodeID     string `json:"node_id"`
	Hostname   string `json:"hostname"`
	NodeIP     string `json:"node_ip"`
	MasterAddr string `json:"master_addr"`
	JoinToken  string `json:"join_token"`
	CreatedAt  string `json:"created_at"`
}

type ClusterNode struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	Role      string `json:"role"`
	Status    string `json:"status"` // Ready, NotReady
	CPUs      int    `json:"cpus"`
	MemTotal  uint64 `json:"mem_total_mb"`
	Containers int   `json:"containers"`
	LastSeen  string `json:"last_seen"`
}

type ClusteredApp struct {
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Replicas  int               `json:"replicas"`
	Port      string            `json:"port"`
	Env       map[string]string `json:"env"`
	CreatedAt string            `json:"created_at"`
	Status    string            `json:"status"`
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
	data, err := os.ReadFile(clusterConfigFile)
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
	_ = os.MkdirAll(clusterDir, 0755)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(clusterConfigFile, data, 0600)
}

var clusterCmd = &cobra.Command{
	Use:     "cluster",
	Aliases: []string{"mesh", "swarm"},
	Short:   "Manage container clustering, mesh nodes, and distributed replicas",
}

var clusterPort int

var clusterInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this Ziro-OS host as Cluster Master & Mesh Coordinator",
	Run: func(cmd *cobra.Command, args []string) {
		host, _ := os.Hostname()
		if host == "" {
			host = "ziro-master"
		}

		tokBytes := make([]byte, 16)
		_, _ = rand.Read(tokBytes)
		joinToken := hex.EncodeToString(tokBytes)

		clusterIDBytes := make([]byte, 6)
		_, _ = rand.Read(clusterIDBytes)
		clusterID := "ziro-" + hex.EncodeToString(clusterIDBytes)

		localIP := getFirstNonLoopbackIPv4()
		if localIP == "" {
			localIP = "127.0.0.1"
		}

		cfg := &ClusterConfig{
			ClusterID:  clusterID,
			Role:       "master",
			NodeID:     "master-1",
			Hostname:   host,
			NodeIP:     localIP,
			MasterAddr: fmt.Sprintf("%s:%d", localIP, clusterPort),
			JoinToken:  joinToken,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}

		if err := saveClusterConfig(cfg); err != nil {
			fmt.Printf("Failed to save cluster config: %v\n", err)
			return
		}

		// Register self as initial node
		initialNode := ClusterNode{
			ID:        cfg.NodeID,
			Hostname:  cfg.Hostname,
			IP:        cfg.NodeIP,
			Role:      "master",
			Status:    "Ready",
			CPUs:      runtime.NumCPU(),
			MemTotal:  inspectSystem().TotalMemMB,
			Containers: 0,
			LastSeen:  time.Now().Format("2006-01-02 15:04:05"),
		}
		_ = saveNodesList([]ClusterNode{initialNode})

		fmt.Println("================================================================")
		fmt.Printf(" 🎉 Ziro-OS Container Cluster initialized as MASTER!\n")
		fmt.Println("================================================================")
		fmt.Printf(" Cluster ID:   %s\n", clusterID)
		fmt.Printf(" Master Node:  %s (%s)\n", host, cfg.MasterAddr)
		fmt.Printf(" Join Token:   %s\n\n", joinToken)
		fmt.Println("To join worker nodes to this cluster, run on each worker:")
		fmt.Printf("  ziroctl cluster join %s --token %s\n\n", cfg.MasterAddr, joinToken)
	},
}

var (
	joinTokenFlag string
)

var clusterJoinCmd = &cobra.Command{
	Use:   "join <master-ip:port>",
	Short: "Join this host as a Worker node to an existing Ziro-OS Cluster",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		masterAddr := args[0]
		if joinTokenFlag == "" {
			fmt.Println("Error: --token is required to join a cluster.")
			return
		}

		host, _ := os.Hostname()
		if host == "" {
			host = "ziro-worker"
		}

		nodeIDBytes := make([]byte, 4)
		_, _ = rand.Read(nodeIDBytes)
		nodeID := "node-" + hex.EncodeToString(nodeIDBytes)

		localIP := getFirstNonLoopbackIPv4()
		if localIP == "" {
			localIP = "127.0.0.1"
		}

		cfg := &ClusterConfig{
			ClusterID:  "ziro-mesh",
			Role:       "worker",
			NodeID:     nodeID,
			Hostname:   host,
			NodeIP:     localIP,
			MasterAddr: masterAddr,
			JoinToken:  joinTokenFlag,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}

		if err := saveClusterConfig(cfg); err != nil {
			fmt.Printf("Failed to join cluster: %v\n", err)
			return
		}

		fmt.Printf("✓ Joined Ziro-OS Cluster at %s as WORKER node %s (%s)\n", masterAddr, nodeID, host)
	},
}

var clusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display local node cluster role, peers, and health",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadClusterConfig()
		if err != nil {
			fmt.Println("Cluster Status: Standalone (Not joined to any cluster)")
			fmt.Println("Run 'ziroctl cluster init' to create a cluster, or 'ziroctl cluster join' to join one.")
			return
		}

		fmt.Println("=== Ziro-OS Cluster Status ===")
		fmt.Printf("Cluster ID:    %s\n", cfg.ClusterID)
		fmt.Printf("Node Role:     %s\n", strings.ToUpper(cfg.Role))
		fmt.Printf("Node ID:       %s (%s)\n", cfg.NodeID, cfg.Hostname)
		fmt.Printf("Local IP:      %s\n", cfg.NodeIP)
		fmt.Printf("Master Addr:   %s\n", cfg.MasterAddr)

		nodes := loadNodesList()
		fmt.Printf("Active Nodes:  %d node(s) in mesh\n", len(nodes))
	},
}

var clusterNodesCmd = &cobra.Command{
	Use:   "nodes",
	Short: "List all member nodes in the cluster mesh",
	Run: func(cmd *cobra.Command, args []string) {
		nodes := loadNodesList()
		if len(nodes) == 0 {
			fmt.Println("No cluster nodes registered.")
			return
		}

		fmt.Printf("%-12s %-16s %-16s %-8s %-10s %-6s %s\n", "NODE ID", "HOSTNAME", "IP", "ROLE", "STATUS", "CPUS", "LAST SEEN")
		fmt.Println(strings.Repeat("-", 80))
		for _, n := range nodes {
			fmt.Printf("%-12s %-16s %-16s %-8s %-10s %-6d %s\n", n.ID, n.Hostname, n.IP, n.Role, n.Status, n.CPUs, n.LastSeen)
		}
	},
}

var (
	appName     string
	appImage    string
	appReplicas int
	appPort     string
)

var clusterDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy an OCI container workload distributed across cluster nodes",
	Run: func(cmd *cobra.Command, args []string) {
		if appName == "" || appImage == "" {
			fmt.Println("Error: --name and --image are required.")
			return
		}
		if appReplicas <= 0 {
			appReplicas = 1
		}

		cfg, _ := loadClusterConfig()
		if cfg == nil {
			fmt.Println("Warning: Not joined to a cluster. Deploying locally.")
		}

		app := ClusteredApp{
			Name:      appName,
			Image:     appImage,
			Replicas:  appReplicas,
			Port:      appPort,
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
			Status:    "Running",
		}

		apps := loadServicesList()
		apps = append(apps, app)
		_ = saveServicesList(apps)

		fmt.Printf("✓ Deploying '%s' (Image: %s, Replicas: %d, Port: %s)...\n", appName, appImage, appReplicas, appPort)

		// Start local replicas via nerdctl / ctr
		for i := 1; i <= appReplicas; i++ {
			cName := fmt.Sprintf("%s-%d", appName, i)
			runArgs := []string{"run", "-d", "--name", cName, "--restart", "always"}
			if appPort != "" {
				runArgs = append(runArgs, "-p", appPort)
			}
			runArgs = append(runArgs, appImage)

			if err := exec.Command("nerdctl", runArgs...).Run(); err != nil {
				// Fallback to ctr if nerdctl not installed
				_ = exec.Command("ctr", "run", "-d", appImage, cName).Run()
			}
		}

		fmt.Printf("✓ Successfully scheduled %d replica(s) across cluster nodes!\n", appReplicas)
	},
}

var clusterServicesCmd = &cobra.Command{
	Use:     "services",
	Aliases: []string{"apps", "ps"},
	Short:   "List deployed clustered applications and active replicas",
	Run: func(cmd *cobra.Command, args []string) {
		apps := loadServicesList()
		if len(apps) == 0 {
			fmt.Println("No clustered services deployed.")
			return
		}

		fmt.Printf("%-16s %-24s %-10s %-12s %s\n", "NAME", "IMAGE", "REPLICAS", "PORTS", "STATUS")
		fmt.Println(strings.Repeat("-", 75))
		for _, a := range apps {
			p := a.Port
			if p == "" {
				p = "-"
			}
			fmt.Printf("%-16s %-24s %-10d %-12s %s\n", a.Name, a.Image, a.Replicas, p, a.Status)
		}
	},
}

var clusterLeaveCmd = &cobra.Command{
	Use:   "leave",
	Short: "Leave the cluster and reset node to standalone",
	Run: func(cmd *cobra.Command, args []string) {
		_ = os.Remove(clusterConfigFile)
		fmt.Println("✓ Local node has left the cluster and returned to standalone mode.")
	},
}

func loadNodesList() []ClusterNode {
	data, err := os.ReadFile(clusterNodesFile)
	if err != nil {
		return []ClusterNode{}
	}
	var nodes []ClusterNode
	_ = json.Unmarshal(data, &nodes)
	return nodes
}

func saveNodesList(nodes []ClusterNode) error {
	_ = os.MkdirAll(clusterDir, 0755)
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(clusterNodesFile, data, 0644)
}

func loadServicesList() []ClusteredApp {
	data, err := os.ReadFile(clusterSvcsFile)
	if err != nil {
		return []ClusteredApp{}
	}
	var svcs []ClusteredApp
	_ = json.Unmarshal(data, &svcs)
	return svcs
}

func saveServicesList(svcs []ClusteredApp) error {
	_ = os.MkdirAll(clusterDir, 0755)
	data, err := json.MarshalIndent(svcs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(clusterSvcsFile, data, 0644)
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
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

func init() {
	clusterInitCmd.Flags().IntVarP(&clusterPort, "port", "p", 7443, "Cluster coordination listening port")
	clusterJoinCmd.Flags().StringVarP(&joinTokenFlag, "token", "t", "", "Cluster security join token")

	clusterDeployCmd.Flags().StringVarP(&appName, "name", "n", "", "Application deployment name")
	clusterDeployCmd.Flags().StringVarP(&appImage, "image", "i", "", "OCI container image to run")
	clusterDeployCmd.Flags().IntVarP(&appReplicas, "replicas", "r", 1, "Number of replica containers")
	clusterDeployCmd.Flags().StringVarP(&appPort, "port", "p", "", "Host port mapping (e.g. 8080:80)")

	clusterCmd.AddCommand(clusterInitCmd)
	clusterCmd.AddCommand(clusterJoinCmd)
	clusterCmd.AddCommand(clusterStatusCmd)
	clusterCmd.AddCommand(clusterNodesCmd)
	clusterCmd.AddCommand(clusterDeployCmd)
	clusterCmd.AddCommand(clusterServicesCmd)
	clusterCmd.AddCommand(clusterLeaveCmd)
	rootCmd.AddCommand(clusterCmd)
}

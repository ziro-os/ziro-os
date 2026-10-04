package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prometheus metrics (text exposition format, stdlib only) on the admin API:
// GET /api/v1/metrics with any token (a viewer token is enough). Host metrics on every node;
// cluster metrics on masters (the leader's live view, through the local cluster-master).
//
//	scrape_configs:
//	  - job_name: ziro
//	    scheme: https
//	    tls_config: {insecure_skip_verify: true}   # or ca_file: the node's API certificate
//	    authorization: {credentials_file: /etc/prometheus/ziro-viewer.token}
//	    metrics_path: /api/v1/metrics
//	    static_configs: [{targets: ['10.0.0.10:8443']}]

type hostMetrics struct {
	MemTotal, MemFree      uint64 // bytes
	Load1, Load5, Load15   float64
	Uptime                 float64
	ContainersRunning      int
	ContainerdUp, Cgroups2 bool
	Services               map[string]bool // service -> running
	Router                 *routerStats    // masters: this planet's router
}

type metricsWriter struct{ b strings.Builder }

// family writes HELP/TYPE once per metric name.
func (m *metricsWriter) family(name, typ, help string) {
	fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m *metricsWriter) sample(name string, labels map[string]string, v float64) {
	m.b.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m.b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				m.b.WriteString(",")
			}
			fmt.Fprintf(&m.b, "%s=%q", k, labelEscape(labels[k]))
		}
		m.b.WriteString("}")
	}
	m.b.WriteString(" " + strconv.FormatFloat(v, 'g', -1, 64) + "\n")
}

// labelEscape leaves only what %q then escapes correctly for Prometheus (\\, \", \n).
func labelEscape(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' {
			return -1
		}
		return r
	}, s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// renderMetrics is pure (inputs gathered by collectMetrics) so it can be tested exactly.
func renderMetrics(h hostMetrics, st *ClusterState, members []memberView, selfID string, now time.Time) string {
	var m metricsWriter
	m.family("ziro_up", "gauge", "The Ziro-OS admin API answered.")
	m.sample("ziro_up", nil, 1)
	m.family("ziro_host_memory_bytes", "gauge", "Host memory.")
	m.sample("ziro_host_memory_bytes", map[string]string{"kind": "total"}, float64(h.MemTotal))
	m.sample("ziro_host_memory_bytes", map[string]string{"kind": "free"}, float64(h.MemFree))
	m.family("ziro_host_load", "gauge", "Load average.")
	for w, v := range map[string]float64{"1m": h.Load1, "5m": h.Load5, "15m": h.Load15} {
		m.sample("ziro_host_load", map[string]string{"window": w}, v)
	}
	m.family("ziro_host_uptime_seconds", "gauge", "Seconds since boot.")
	m.sample("ziro_host_uptime_seconds", nil, h.Uptime)
	m.family("ziro_host_containers_running", "gauge", "Running containers on this host.")
	m.sample("ziro_host_containers_running", nil, float64(h.ContainersRunning))
	m.family("ziro_host_containerd_up", "gauge", "containerd socket answers.")
	m.sample("ziro_host_containerd_up", nil, b2f(h.ContainerdUp))
	m.family("ziro_service_up", "gauge", "Ziro service is running (1) or not (0).")
	names := make([]string, 0, len(h.Services))
	for n := range h.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m.sample("ziro_service_up", map[string]string{"service": n}, b2f(h.Services[n]))
	}
	if st == nil {
		return m.b.String()
	}

	// Samples of one family must be contiguous in the text format: one loop per family.
	m.family("ziro_cluster_node_ready", "gauge", "Cluster node is Ready (1) or not (0).")
	for _, n := range st.Nodes {
		m.sample("ziro_cluster_node_ready", map[string]string{"node": n.ID, "role": n.Role}, b2f(n.Status == "Ready"))
	}
	m.family("ziro_cluster_node_token_age_seconds", "gauge", "Age of the node's current token (rotation evidence).")
	for _, n := range st.Nodes {
		if !n.TokenIssued.IsZero() {
			m.sample("ziro_cluster_node_token_age_seconds", map[string]string{"node": n.ID}, now.Sub(n.TokenIssued).Seconds())
		}
	}
	m.family("ziro_cluster_app_replicas", "gauge", "Replicas per app: desired, and running on Ready nodes.")
	running := map[string]int{}
	for _, r := range st.Replicas {
		if st.replicaRunning(r) {
			running[r.App]++
		}
	}
	for _, a := range st.Apps {
		m.sample("ziro_cluster_app_replicas", map[string]string{"app": a.Name, "state": "desired"}, float64(a.Replicas))
		m.sample("ziro_cluster_app_replicas", map[string]string{"app": a.Name, "state": "running"}, float64(running[a.Name]))
	}
	m.family("ziro_cluster_raft_members", "gauge", "Control-plane members by suffrage.")
	suffrage := map[string]int{}
	leaderHere := false
	for _, mv := range members {
		suffrage[mv.Suffrage]++
		leaderHere = leaderHere || (mv.Leader && mv.ID == selfID)
	}
	for s, n := range suffrage {
		m.sample("ziro_cluster_raft_members", map[string]string{"suffrage": s}, float64(n))
	}
	m.family("ziro_cluster_raft_leader", "gauge", "This master is the Raft leader.")
	m.sample("ziro_cluster_raft_leader", nil, b2f(leaderHere))
	m.family("ziro_cluster_security", "gauge", "Security controls in force (1) or not (0).")
	for c, on := range map[string]bool{
		"secrets_sealed":        st.DEKID != "",
		"data_key_rotating":     st.NextDEKID != "",
		"mesh_policy_deny":      st.PolicyDefault == "deny",
		"image_registry_policy": len(st.ImagePolicy.AllowRegistries) > 0,
		"image_signatures":      st.ImagePolicy.RequireSigned,
	} {
		m.sample("ziro_cluster_security", map[string]string{"control": c}, b2f(on))
	}
	m.family("ziro_cluster_objects", "gauge", "Cluster objects by kind.")
	for k, n := range map[string]int{"apps": len(st.Apps), "routes": len(st.Routes), "peers": len(st.Peers), "secrets": len(st.Secrets)} {
		m.sample("ziro_cluster_objects", map[string]string{"kind": k}, float64(n))
	}
	if r := h.Router; r != nil {
		m.family("ziro_router_streams", "gauge", "Router devices streaming their netmap from this planet.")
		m.sample("ziro_router_streams", nil, float64(r.Streams))
		m.family("ziro_router_devices", "gauge", "Router devices: authorized, and online on any planet.")
		m.sample("ziro_router_devices", map[string]string{"state": "authorized"}, float64(r.Devices))
		m.sample("ziro_router_devices", map[string]string{"state": "online"}, float64(r.Online))
		m.family("ziro_router_planet_up", "gauge", "This planet receives the other planet's device state (1) or not (0).")
		ids := make([]string, 0, len(r.Peers))
		for id := range r.Peers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			m.sample("ziro_router_planet_up", map[string]string{"planet": id}, b2f(r.Peers[id]))
		}
	}
	return m.b.String()
}

func collectMetrics() string {
	var h hostMetrics
	sys := inspectSystem()
	h.MemTotal, h.MemFree, h.ContainerdUp, h.Cgroups2 = sys.TotalMemMB<<20, sys.FreeMemMB<<20, sys.ContainerdOK, sys.CgroupsV2
	h.Load1, h.Load5, h.Load15 = readLoadavg()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fmt.Sscanf(string(b), "%f", &h.Uptime)
	}
	if out, err := exec.Command("nerdctl", "ps", "-q").Output(); err == nil {
		h.ContainersRunning = len(strings.Fields(string(out)))
	}
	h.Services = map[string]bool{}
	for _, s := range defaultServices {
		if info, err := getServiceStatus(s.Name); err == nil {
			h.Services[s.Name] = info.Status == "RUNNING"
		}
	}
	var st *ClusterState
	var members []memberView
	selfID := ""
	if cfg, err := loadClusterConfig(); err == nil && cfg.Role == "master" {
		selfID = cfg.NodeID
		if s, err := readState(); err == nil {
			st = s
		}
		if raftMode() {
			_, _ = socketCall(http.MethodGet, "/members", nil, &members)
			var rs routerStats
			if _, err := socketCall(http.MethodGet, "/router/stats", nil, &rs); err == nil {
				h.Router = &rs
			}
		}
	}
	return renderMetrics(h, st, members, selfID, time.Now())
}

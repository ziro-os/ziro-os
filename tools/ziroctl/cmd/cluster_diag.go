package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Diagnosing replicas that do not start. A container runtime reports a failure as one wrapped log
// line; the part that names the cause comes last, behind several layers of boilerplate, so it is
// removed where the error is produced and the master keeps a limit long enough for what is left.

const clusterErrorMax = 600 // characters of a start error kept in the cluster state

var (
	runtimeLogLine = regexp.MustCompile(`^(?:time="[^"]*"\s+level=\w+\s+msg="(.*)"|FATA\[\d+\]\s+(.*))$`)
	runtimeNoise   = []string{
		"failed to create shim task: ", "failed to start shim: ", "OCI runtime create failed: ", "OCI runtime exec failed: ",
		"runc create failed: ", "unable to start container process: ", "error during container init: ",
	}
)

// condenseRuntimeError reduces the last line of a nerdctl failure to its cause.
func condenseRuntimeError(msg string) string {
	msg = strings.TrimSpace(msg)
	if m := runtimeLogLine.FindStringSubmatch(msg); m != nil {
		msg = m[1] + m[2]
		msg = strings.ReplaceAll(msg, `\"`, `"`)
	}
	for stripped := true; stripped; {
		stripped = false
		for _, p := range runtimeNoise {
			if strings.HasPrefix(msg, p) {
				msg, stripped = strings.TrimPrefix(msg, p), true
			}
		}
	}
	return strings.TrimSuffix(msg, ": unknown")
}

// ---- pod network preflight ----

var (
	cniConfPath = podConfPath
	cniBinDir   = "/opt/cni/bin"
	cniLeaseDir = "/var/lib/cni/networks/" + podNetName
)

// podPreflight checks what a pod-network container needs on this node before nerdctl is asked to
// start it, so a node whose network plumbing is broken says so instead of failing inside runc. It
// also frees an address lease left behind by a container that no longer exists, which would
// otherwise make the replica's fixed pod IP unusable.
func podPreflight(a Assignment, containers func() map[string]bool) error {
	if a.IP == "" {
		return nil
	}
	if _, err := os.Stat(cniConfPath); err != nil {
		return fmt.Errorf("pod network not ready on this node: CNI config %s is missing (the agent writes it on the next heartbeat)", cniConfPath)
	}
	plugins := []string{"ptp", "host-local"}
	if a.Port != "" {
		plugins = append(plugins, "portmap")
	}
	for _, p := range plugins {
		if _, err := os.Stat(filepath.Join(cniBinDir, p)); err != nil {
			return fmt.Errorf("pod network not ready on this node: CNI plugin %s is not installed in %s", p, cniBinDir)
		}
	}
	lease := filepath.Join(cniLeaseDir, a.IP)
	if b, err := os.ReadFile(lease); err == nil {
		owner := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if ids := containers(); owner != "" && ids != nil && !ids[owner] {
			_ = os.Remove(lease) // the container that held this address is gone
		}
	}
	return nil
}

// containerIDs lists the ids of every container on the node, running or not (nil when unknown).
func containerIDs() map[string]bool {
	out, err := exec.Command("nerdctl", "ps", "-a", "-q", "--no-trunc").Output()
	if err != nil {
		return nil // unknown: a lease is only removed for an owner that is known to be gone
	}
	ids := map[string]bool{}
	for _, id := range strings.Fields(string(out)) {
		ids[id] = true
	}
	return ids
}

// ---- cluster replicas ----

type replicaView struct {
	App   string `json:"app"`
	Index int    `json:"index"`
	Node  string `json:"node"`
	State string `json:"state"` // running, starting, failing, pending
	Fails int    `json:"fails,omitempty"`
	IP    string `json:"ip,omitempty"`
	Error string `json:"error,omitempty"`
}

// replicaViews lists the replicas of one app (or all), with the node each one is on and why it is
// not running.
func replicaViews(st *ClusterState, app string) []replicaView {
	var out []replicaView
	for _, r := range st.Replicas {
		if app != "" && r.App != app {
			continue
		}
		v := replicaView{App: r.App, Index: r.Index, Node: r.Node, Fails: r.Fails, IP: r.IP, Error: r.Error}
		switch {
		case r.Node == "":
			v.State = "pending"
		case st.replicaRunning(r):
			v.State = "running"
		case r.Error != "":
			v.State = "failing"
		default:
			v.State = "starting"
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		return out[i].Index < out[j].Index
	})
	return out
}

var clusterReplicasCmd = &cobra.Command{
	Use:   "replicas [app]",
	Short: "Show where each replica runs and why one is not running",
	Long: `Lists every replica with its node, state and the last start error the node reported. Use it
when "cluster services" shows fewer replicas running than wanted.`,
	Example: "  ziroctl cluster replicas\n  ziroctl cluster replicas postgres",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		app := ""
		if len(args) == 1 {
			app = args[0]
			if st.app(app) == nil {
				return fmt.Errorf("no cluster app %q", app)
			}
		}
		views := replicaViews(st, app)
		return printResult(views, func() {
			if len(views) == 0 {
				fmt.Println("No replicas.")
				return
			}
			fmt.Printf("%-18s %-4s %-14s %-9s %-5s %s\n", "APP", "IDX", "NODE", "STATE", "FAILS", "ERROR")
			for _, v := range views {
				node := v.Node
				if node == "" {
					node = "-"
				}
				fmt.Printf("%-18s %-4s %-14s %-9s %-5d %s\n", v.App, strconv.Itoa(v.Index), node, v.State, v.Fails, v.Error)
			}
		})
	},
}

func init() {
	clusterCmd.AddCommand(clusterReplicasCmd)
}

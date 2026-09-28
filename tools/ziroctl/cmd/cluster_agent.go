package cmd

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const agentInterval = 10 * time.Second

// listClusterContainers returns cluster-managed containers on this node: name -> running.
func listClusterContainers() (map[string]bool, error) {
	out, err := exec.Command("nerdctl", "ps", "-a", "--filter", "label=ziro.cluster=true",
		"--format", "{{.Names}}\t{{.Status}}").Output()
	if err != nil {
		return nil, err
	}
	actual := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, status, _ := strings.Cut(line, "\t")
		if name = strings.TrimSpace(name); name != "" {
			actual[name] = strings.HasPrefix(strings.TrimSpace(status), "Up")
		}
	}
	return actual, nil
}

// planReconcile diffs desired assignments against local containers.
func planReconcile(desired []Assignment, actual map[string]bool) (start []Assignment, restart, remove []string) {
	want := map[string]bool{}
	for _, a := range desired {
		want[a.Name] = true
		running, exists := actual[a.Name]
		switch {
		case !exists:
			start = append(start, a)
		case !running:
			restart = append(restart, a.Name)
		}
	}
	for name := range actual {
		if !want[name] {
			remove = append(remove, name)
		}
	}
	sort.Strings(remove)
	return start, restart, remove
}

func runArgs(a Assignment) []string {
	args := []string{"run", "-d", "--name", a.Name, "--restart", "always",
		"--label", "ziro.cluster=true", "--label", "ziro.app=" + a.App}
	if a.Port != "" {
		args = append(args, "-p", a.Port)
	}
	keys := make([]string, 0, len(a.Env))
	for k := range a.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+a.Env[k])
	}
	return append(args, "--", a.Image)
}

// reconcileContainers converges local cluster containers to desired.
// Stale containers are removed first so a replaced replica can reuse its host port.
func reconcileContainers(desired []Assignment) error {
	actual, err := listClusterContainers()
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	start, restart, remove := planReconcile(desired, actual)
	for _, name := range remove {
		if nerdctlOnce("rm "+name, "rm", "-f", name) {
			fmt.Printf("[agent] removed %s\n", name)
		}
	}
	for _, name := range restart {
		nerdctlOnce("start "+name, "start", name)
	}
	for _, a := range start {
		if nerdctlOnce("run "+a.Name, runArgs(a)...) {
			fmt.Printf("[agent] started %s (%s)\n", a.Name, a.Image)
		}
	}
	return nil
}

// agentFailing remembers failing actions so a persistently failing container
// (bad image, port clash) is logged once, not every reconcile tick.
var agentFailing = map[string]bool{}

func nerdctlOnce(key string, args ...string) bool {
	out, err := exec.Command("nerdctl", args...).CombinedOutput()
	if err != nil {
		if !agentFailing[key] {
			fmt.Printf("[agent] %s failed (will keep retrying silently): %v %s\n", key, err, strings.TrimSpace(string(out)))
			agentFailing[key] = true
		}
		return false
	}
	if agentFailing[key] {
		fmt.Printf("[agent] %s recovered\n", key)
		delete(agentFailing, key)
	}
	return true
}

var clusterAgentCmd = &cobra.Command{
	Use:    "agent",
	Short:  "Run the node agent: heartbeat to the master and converge assigned containers",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadClusterConfig()
		if err != nil {
			return fmt.Errorf("not part of a cluster")
		}
		fmt.Printf("[agent] node %s reporting to %s every %s\n", cfg.NodeID, cfg.MasterAddr, agentInterval)
		lastErr := ""
		for {
			actual, _ := listClusterContainers()
			running := []string{}
			for name, up := range actual {
				if up {
					running = append(running, name)
				}
			}
			sort.Strings(running)
			total := 0
			if out, err := exec.Command("nerdctl", "ps", "-q").Output(); err == nil {
				total = len(strings.Fields(string(out)))
			}

			var resp heartbeatResponse
			err := clusterPost(cfg.MasterAddr, cfg.CAHash, "/cluster/v1/heartbeat", nodeAuth(cfg),
				heartbeatRequest{Containers: total, Running: running}, &resp)
			// On heartbeat failure the master is unreachable: keep workloads running as they are,
			// never tear down on a network blip.
			if err == nil {
				err = reconcileContainers(resp.Assignments)
			}
			// Log errors only when they change, so a persistent failure cannot flood the log.
			if msg := fmt.Sprint(err); err != nil && msg != lastErr {
				fmt.Printf("[agent] %v\n", err)
				lastErr = msg
			} else if err == nil && lastErr != "" {
				fmt.Println("[agent] healthy again")
				lastErr = ""
			}
			time.Sleep(agentInterval)
		}
	},
}

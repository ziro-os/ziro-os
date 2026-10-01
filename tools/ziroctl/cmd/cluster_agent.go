package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const (
	agentInterval    = 10 * time.Second
	reconcileEvery   = 3 * time.Second
	imagePullTimeout = 10 * time.Minute
)

// secretEnvDir is tmpfs (/run): secret values never touch disk on workers or appear in argv.
var secretEnvDir = "/run/ziro/cluster/secrets"

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

func secretEnvFile(name string) string { return filepath.Join(secretEnvDir, name+".env") }

func runArgs(a Assignment) []string {
	return containerArgs(a, "ziro.cluster=true", "ziro.app="+a.App)
}

// containerArgs is the hardened `nerdctl run` for a cluster replica or a standalone app.
func containerArgs(a Assignment, labels ...string) []string {
	args := []string{"run", "-d", "--name", a.Name, "--restart", "always"}
	for _, l := range labels {
		args = append(args, "--label", l)
	}
	args = append(args, "-e", "ZIRO_REPLICA="+strconv.Itoa(a.Replica))
	if !a.PrivEsc {
		// Secure by default: setuid binaries can't gain privileges, and no raw sockets (spoofing).
		args = append(args, "--security-opt", "no-new-privileges", "--cap-drop", "NET_RAW")
	}
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
	if len(a.SecretEnv) > 0 {
		args = append(args, "--env-file", secretEnvFile(a.Name))
	}
	for _, h := range a.Hosts {
		args = append(args, "--add-host", h)
	}
	if a.IP != "" {
		args = append(args, "--network", podNetName, "--ip", a.IP, "--dns", a.DNS, "--dns-search", meshDomain)
	}
	for _, v := range a.Volumes {
		args = append(args, "-v", v)
	}
	for _, d := range a.Data {
		args = append(args, "-v", dataDir(a.App, a.Replica, d)+":"+d)
	}
	return append(append(args, "--", a.Image), a.Args...)
}

const purgeDataTTL = 7 * 24 * time.Hour

// purgeList is the apps whose data nodes should delete (unexpired entries).
func purgeList(st *ClusterState, now time.Time) []string {
	var out []string
	for app, at := range st.PurgeData {
		if t, err := time.Parse(time.RFC3339, at); err == nil && now.Sub(t) < purgeDataTTL {
			out = append(out, app)
		}
	}
	sort.Strings(out)
	return out
}

// purgeAppData deletes the node-local data of purged apps that have no replica here. The names
// come from the master: they are re-validated, and only appDataRoot/<app> is ever removed.
func purgeAppData(apps []string, desired []Assignment) {
	for _, app := range apps {
		if validName(app) != nil || slices.ContainsFunc(desired, func(a Assignment) bool { return a.App == app }) {
			continue
		}
		dir := filepath.Join(appDataRoot, app)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Printf("[agent] purge %s: %v\n", app, err)
			continue
		}
		fmt.Printf("[agent] purged data of %s\n", app)
	}
}

// appDataRoot holds node-local app data: <app>/<replica>/<container path, "/" -> "_">.
var appDataRoot = "/var/lib/ziro/apps"

func dataDir(app string, replica int, path string) string {
	return filepath.Join(appDataRoot, app, strconv.Itoa(replica), strings.ReplaceAll(strings.Trim(path, "/"), "/", "_"))
}

// ensureDataDirs creates a replica's data dirs (root-only; the image's entrypoint chowns its
// own). The agent re-validates the paths: they come from the master.
func ensureDataDirs(a Assignment) error {
	if err := validName(a.App); err != nil {
		return err
	}
	if err := validateDataPaths(a.Data); err != nil {
		return err
	}
	for _, d := range a.Data {
		if err := os.MkdirAll(dataDir(a.App, a.Replica, d), 0700); err != nil {
			return err
		}
	}
	return nil
}

func writeSecretEnv(a Assignment) error {
	if len(a.SecretEnv) == 0 {
		return nil
	}
	if err := os.MkdirAll(secretEnvDir, 0700); err != nil {
		return err
	}
	keys := make([]string, 0, len(a.SecretEnv))
	for k := range a.SecretEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + a.SecretEnv[k] + "\n")
	}
	return os.WriteFile(secretEnvFile(a.Name), []byte(b.String()), 0600)
}

// setupPods converges the pod network (re-checked every minute in case it was changed under
// us) and keeps the node's DNS responder running with the latest endpoints.
func (ag *agent) setupPods(resp heartbeatResponse) error {
	ip, err := netip.ParseAddr(resp.MeshIP)
	if err != nil || resp.MeshPrefix == 0 {
		return fmt.Errorf("mesh not ready")
	}
	meshNet, err := ip.Prefix(resp.MeshPrefix)
	if err != nil {
		return err
	}
	if time.Since(ag.podAt) > time.Minute {
		podNetApplied.Store("")
		ag.podAt = time.Now()
	}
	if err := applyPodNetwork(resp.PodCIDR, resp.PodNet, meshNet.String()); err != nil {
		return err
	}
	if ag.dns == nil {
		clients, _ := netip.ParsePrefix(resp.PodCIDR)
		gw := podGateway(resp.PodCIDR)
		ag.dns = &podDNS{clients: clients, upstreams: hostResolvers("/etc/resolv.conf", gw),
			egress: &egressLearner{add: nftAddLearned}}
		go func(d *podDNS) {
			for { // the address can briefly be missing while the link is (re)created: retry
				if err := d.serve(net.JoinHostPort(gw, "53")); err != nil {
					fmt.Printf("[agent] pod dns: %v\n", err)
				}
				time.Sleep(5 * time.Second)
			}
		}(ag.dns)
	}
	ag.dns.setEndpoints(resp.PodDNS)
	return nil
}

func uniqueAddrs(first, second string, rest []string) []string {
	var out []string
	seen := map[string]bool{"": true}
	for _, a := range append([]string{first, second}, rest...) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// adoptNodeToken switches to a token the master accepted. If saving fails, the old token still
// works for an hour and using it triggers another rotation, so the node is never locked out.
func adoptNodeToken(cfg *ClusterConfig, tok string) {
	cfg.NodeToken = tok
	if cur, err := loadClusterConfig(); err == nil {
		cur.NodeToken = tok
		if err := saveClusterConfig(cur); err != nil {
			fmt.Printf("[agent] save rotated node token: %v\n", err)
			return
		}
	}
	fmt.Println("[agent] node token rotated")
}

// adoptClusterCA switches this node's pin to the cluster CA the master sent over the channel it
// already trusts (agents from before the CA pinned one master's own certificate), and records
// every master for failover.
func adoptClusterCA(cfg *ClusterConfig, caPEM string, masters []string) {
	changed := false
	if caPEM != "" {
		if h, err := pemHash(caPEM); err == nil && h != cfg.CAHash {
			if c, err := parseCertPEM(caPEM); err == nil && c.IsCA {
				if err := writeFileAtomic(clusterCAPath(), []byte(caPEM), 0644); err == nil {
					cfg.CAHash, changed = h, true
					fmt.Println("[agent] now trusting the cluster CA", h)
				}
			}
		}
	}
	if len(masters) > 0 && strings.Join(masters, ",") != strings.Join(cfg.Masters, ",") {
		cfg.Masters, changed = masters, true
	}
	if changed {
		// Re-read first: the config may have been changed by ziroctl since the agent started.
		if cur, err := loadClusterConfig(); err == nil {
			cur.CAHash, cur.Masters = cfg.CAHash, cfg.Masters
			if err := saveClusterConfig(cur); err != nil {
				fmt.Printf("[agent] save config: %v\n", err)
			}
		}
	}
}

// agent holds what the heartbeat loop learned and what the reconcile loop reports back.
type agent struct {
	dns     *podDNS
	podAt   time.Time
	mu      sync.Mutex
	desired []Assignment
	synced  bool              // at least one successful heartbeat
	failed  map[string]string // container -> last start error
}

func (ag *agent) setFailed(name string, err error) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if err == nil {
		delete(ag.failed, name)
		return
	}
	if ag.failed[name] == "" {
		fmt.Printf("[agent] %s failed (reported to master, retrying): %v\n", name, err)
	}
	ag.failed[name] = err.Error()
}

func nerdctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "nerdctl", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.LastIndex(msg, "\n"); i >= 0 {
			msg = msg[i+1:]
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

// reconcileContainers converges local cluster containers to desired.
// Stale containers are removed first so a replaced replica can reuse its host port.
func reconcileContainers(desired []Assignment) error {
	return (&agent{failed: map[string]string{}}).reconcile(desired)
}

func (ag *agent) reconcile(desired []Assignment) error {
	actual, err := listClusterContainers()
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	start, restart, remove := planReconcile(desired, actual)
	for _, name := range remove {
		if err := nerdctl(context.Background(), "rm", "-f", name); err == nil {
			fmt.Printf("[agent] removed %s\n", name)
			_ = os.Remove(secretEnvFile(name))
		}
		ag.setFailed(name, nil)
	}
	for _, name := range restart {
		ag.setFailed(name, nerdctl(context.Background(), "start", name))
	}
	for _, a := range start {
		ctx, cancel := context.WithTimeout(context.Background(), imagePullTimeout)
		err := nerdctl(ctx, "pull", "-q", a.Image)
		cancel()
		if err == nil {
			err = writeSecretEnv(a)
		}
		if err == nil {
			err = ensureDataDirs(a)
		}
		if err == nil {
			err = nerdctl(context.Background(), runArgs(a)...)
			// a failed run can leave a created container behind; remove it so the retry is clean
			if err != nil {
				_ = nerdctl(context.Background(), "rm", "-f", a.Name)
			}
		}
		if err == nil {
			fmt.Printf("[agent] started %s (%s)\n", a.Name, a.Image)
		}
		ag.setFailed(a.Name, err)
	}
	return nil
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
		_, pub, err := meshKeypair()
		if err != nil {
			return err
		}
		ag := &agent{failed: map[string]string{}}
		fmt.Printf("[agent] node %s reporting to %s every %s\n", cfg.NodeID, cfg.MasterAddr, agentInterval)

		// Reconcile loop: image pulls and container starts can take minutes; they run here so
		// they never delay heartbeats (a late heartbeat would mark this node NotReady).
		go func() {
			for {
				ag.mu.Lock()
				desired, synced := ag.desired, ag.synced
				ag.mu.Unlock()
				// Before the first successful heartbeat the desired set is unknown: never tear down.
				if synced {
					if err := ag.reconcile(desired); err != nil {
						fmt.Printf("[agent] reconcile: %v\n", err)
					}
				}
				time.Sleep(reconcileEvery)
			}
		}()

		lastErr, lastMesh, lastPolicy, active := "", "", "", ""
		wantRotate := false
		var policyAt time.Time
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
			ag.mu.Lock()
			failed := make(map[string]string, len(ag.failed))
			for k, v := range ag.failed {
				failed[k] = v
			}
			ag.mu.Unlock()

			var resp heartbeatResponse
			hb := heartbeatRequest{Containers: total, Running: running, Failed: failed, WGPubKey: pub, WGPort: meshPort, MeshError: lastMesh,
				Caps: nodeCaps, Keys: storedKeyIDs()}
			pending := ""
			if wantRotate { // the new token is generated here and sent once, authenticated by the old one
				pending = randomHex(32)
				hb.RotateToken = pending
			}
			// Last good master first, then the configured one, then every other master (failover).
			var err error
			for _, addr := range uniqueAddrs(active, cfg.MasterAddr, cfg.Masters) {
				if err = clusterPost(addr, cfg.CAHash, "/cluster/v1/heartbeat", nodeAuth(cfg), hb, &resp); err == nil {
					active = addr
					break
				}
			}
			if err == nil {
				if pending != "" {
					adoptNodeToken(cfg, pending)
				}
				wantRotate = resp.RotateToken
				adoptClusterCA(cfg, resp.CA, resp.Masters)
			}
			// On heartbeat failure the master is unreachable: keep workloads running as they are,
			// never tear down on a network blip.
			if err == nil {
				// Policy first, and fail closed: in deny mode the mesh is not (re)configured
				// until its policy is in place. A failed nft transaction leaves the previous
				// table intact. Re-applied every minute in case someone flushed the ruleset.
				var merr error
				if script, _ := buildPolicyScript(resp.Policy); script != lastPolicy || time.Since(policyAt) > time.Minute {
					if merr = applyClusterPolicy(resp.Policy); merr == nil {
						lastPolicy, policyAt = script, time.Now()
					} else {
						lastPolicy = ""
					}
				}
				if merr == nil {
					merr = applyMesh(resp.MeshIP, resp.MeshPrefix, resp.Peers)
				}
				// The pod network must exist before containers join it; while it cannot be set
				// up, the desired set is frozen (running containers are left alone).
				podOK := true
				if merr == nil && resp.PodCIDR != "" {
					if perr := ag.setupPods(resp); perr != nil {
						merr, podOK = fmt.Errorf("pod network: %w", perr), false
					}
				}
				writeClusterDNS(resp)
				// Shares first: a replica whose share can't be mounted here is held back, never
				// started on the empty local mount point.
				if unavailable, serr := applyStorage(resp.NFSExports, resp.NFSMounts); serr != nil || len(unavailable) > 0 {
					resp.Assignments = holdBack(resp.Assignments, unavailable)
					if serr != nil && merr == nil {
						merr = fmt.Errorf("storage: %w", serr)
					}
				}
				if podOK && resp.PodCIDR != "" {
					meshNet := ""
					if ip, err := netip.ParseAddr(resp.MeshIP); err == nil && resp.MeshPrefix > 0 {
						if p, err := ip.Prefix(resp.MeshPrefix); err == nil {
							meshNet = p.String()
						}
					}
					if eerr := applyEgress(resp.Egress, resp.Assignments, resp.PodNet, meshNet); eerr != nil && merr == nil {
						merr = eerr
					}
					if ag.dns != nil {
						ag.dns.egress.set(resp.Egress, resp.Assignments)
					}
				}
				if podOK {
					ag.mu.Lock()
					ag.desired, ag.synced = resp.Assignments, true
					ag.mu.Unlock()
					purgeAppData(resp.PurgeData, resp.Assignments)
				}
				if merr == nil {
					merr = writeHostsBlock(hostsFile, resp.Endpoints)
				}
				if gerr := syncGatewayConfig(resp.Gateway); gerr != nil && merr == nil {
					merr = fmt.Errorf("gateway: %w", gerr)
				}
				if merr != nil && merr.Error() != lastMesh {
					fmt.Printf("[agent] mesh: %v\n", merr)
				}
				lastMesh = ""
				if merr != nil {
					lastMesh = merr.Error()
				}
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

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// Cluster auto-healing, least to most invasive. Everything is leader-driven, conservative,
// rate-limited, audited and alerted:
//
//  1. Node self-heal (nodeHealer, in the agent): restart containerd, prune disk, and report what is
//     still wrong as Conditions in the heartbeat.
//  2. healPass (leader): cordon a node whose condition persists (lifted when it clears, never an
//     admin's cordon); report a master that stays down and the risk of losing Raft quorum; remove a
//     long-dead worker (opt-in).
//  3. scheduleReplicas (the flap guard, the partition brake and the move cap below): replicas leave
//     a NotReady node only after a grace period, never all at once, and not at all while half the
//     cluster looks dead (that is the master's own network, not a mass node failure).
//
// ponytail: a dead master is reported, never demoted: removing a voter on a guess can lose data.
const (
	healGrace         = 20 * time.Second // NotReady this long beyond nodeTimeout before replicas leave (flap guard)
	healMaxMoves      = 5                // replicas taken off dead nodes per scheduling pass
	healBrakeMinNodes = 3                // the partition brake needs a cluster this big to tell a partition from a failure
	healCondGrace     = 30 * time.Second // a condition must persist this long before the node is cordoned
	healMasterWarn    = 3 * time.Minute  // a master NotReady this long is reported
	healReportEvery   = time.Hour        // the same report (kind + node) is recorded once per window
	healHistory       = 20               // actions kept in the state
	healMinRemove     = 10 * time.Minute // shortest accepted --remove-after
)

// Node conditions the agent reports. The master accepts only these.
const (
	CondContainerdDown = "ContainerdDown"
	CondDiskPressure   = "DiskPressure"
	CondMeshError      = "MeshError"
)

var knownConditions = []string{CondContainerdDown, CondDiskPressure, CondMeshError}

// HealConfig is the declarative heal setting; it lives in the cluster state, so it replicates.
type HealConfig struct {
	Disabled    bool         `json:"disabled,omitempty"`     // healing is on unless this is set
	RemoveAfter int          `json:"remove_after,omitempty"` // seconds; a worker NotReady this long is removed (0 = never)
	Next        int          `json:"next,omitempty"`         // sequence number of the next action
	Actions     []HealAction `json:"actions,omitempty"`      // most recent last
}

// HealAction is one thing the heal logic did or found.
type HealAction struct {
	Seq    int    `json:"seq"`
	Time   string `json:"time"`
	Node   string `json:"node,omitempty"`
	Kind   string `json:"kind"` // cordon, uncordon, reschedule, hold, remove, master-down, quorum-risk, quorum-lost
	Detail string `json:"detail"`
}

// healSeverity is the alert severity of an action kind.
var healSeverity = map[string]string{
	"cordon": "medium", "uncordon": "info", "reschedule": "medium", "hold": "high",
	"remove": "high", "master-down": "high", "quorum-risk": "critical", "quorum-lost": "critical",
}

func (c HealConfig) enabled() bool { return !c.Disabled }

// record appends an action. With dedupe, an action of the same kind and node recorded within
// healReportEvery is dropped (repeating reports, not events).
func (c *HealConfig) record(a HealAction, now time.Time, dedupe bool) bool {
	if dedupe {
		for _, p := range c.Actions {
			if t, err := time.Parse(time.RFC3339, p.Time); err == nil && p.Kind == a.Kind && p.Node == a.Node && now.Sub(t) < healReportEvery {
				return false
			}
		}
	}
	c.Next++
	a.Seq, a.Time = c.Next, now.UTC().Format(time.RFC3339)
	c.Actions = append(c.Actions, a)
	if len(c.Actions) > healHistory {
		c.Actions = append([]HealAction(nil), c.Actions[len(c.Actions)-healHistory:]...)
	}
	return true
}

func silentFor(n ClusterNode, now time.Time) time.Duration { return now.Sub(n.LastSeen) }

// partitioned is the safety brake: with at least healBrakeMinNodes nodes, half of them or more
// NotReady looks like the master's own network failing, so nothing is moved, removed or forgotten.
func partitioned(st *ClusterState, now time.Time) bool {
	if len(st.Nodes) < healBrakeMinNodes {
		return false
	}
	dead := 0
	for _, n := range st.Nodes {
		if silentFor(n, now) > nodeTimeout {
			dead++
		}
	}
	return dead*2 >= len(st.Nodes)
}

// healPass is the leader's periodic repair of node state. It mutates st (cordons, removals, the
// action log); the caller commits it and emits the new actions (emitHealActions).
func healPass(st *ClusterState, now time.Time) {
	if !st.Heal.enabled() {
		return
	}
	brake := partitioned(st, now)

	// 1. Cordon a node whose condition persists; lift only what this pass set.
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if silentFor(*n, now) > nodeTimeout {
			continue // a silent node's conditions are stale
		}
		switch {
		case len(n.Conditions) > 0 && !n.Cordoned && !n.CondSince.IsZero() && now.Sub(n.CondSince) >= healCondGrace:
			n.Cordoned, n.AutoCordon = true, true
			st.Heal.record(HealAction{Node: n.ID, Kind: "cordon",
				Detail: "cordoned until it recovers: " + strings.Join(n.Conditions, ", ")}, now, false)
		case len(n.Conditions) == 0 && n.AutoCordon:
			n.Cordoned, n.AutoCordon = false, false
			st.Heal.record(HealAction{Node: n.ID, Kind: "uncordon", Detail: "recovered: scheduling allowed again"}, now, false)
		}
	}

	// 2. Optional removal of a long-dead worker (its replicas are rescheduled by the next pass).
	if after := time.Duration(st.Heal.RemoveAfter) * time.Second; after > 0 && !brake {
		var gone []string
		for _, n := range st.Nodes {
			if n.Role != "master" && silentFor(n, now) > after {
				gone = append(gone, n.ID)
			}
		}
		for _, id := range gone {
			removeNode(st, id)
			st.Heal.record(HealAction{Node: id, Kind: "remove",
				Detail: fmt.Sprintf("NotReady for more than %s: removed, credentials revoked", after)}, now, false)
		}
	}

	// 3. Masters: report, never demote. Raft quorum is ceil((n+1)/2) voters.
	var masters, ready int
	for _, n := range st.Nodes {
		if n.Role != "master" {
			continue
		}
		masters++
		if silentFor(n, now) <= nodeTimeout {
			ready++
		} else if silentFor(n, now) > healMasterWarn {
			st.Heal.record(HealAction{Node: n.ID, Kind: "master-down",
				Detail: fmt.Sprintf("master NotReady for %s", silentFor(n, now).Round(time.Second))}, now, true)
		}
	}
	if quorum := masters/2 + 1; masters >= 2 && ready < masters && ready <= quorum {
		kind, detail := "quorum-risk", "one more master down loses quorum"
		if ready < quorum {
			kind, detail = "quorum-lost", "quorum is lost, the cluster cannot change state"
		}
		st.Heal.record(HealAction{Kind: kind, Detail: fmt.Sprintf("%d of %d masters are up; Raft needs %d: %s", ready, masters, quorum, detail)}, now, true)
	}
}

// emitHealActions alerts and audits the actions recorded after seq and returns the new high-water
// mark. Only the leader's loop calls it, so every action is announced once (a new leader starts
// from the log it inherited).
func emitHealActions(c HealConfig, seq int) int {
	for _, a := range c.Actions {
		if a.Seq <= seq {
			continue
		}
		seq = a.Seq
		title := "Cluster heal: " + a.Kind
		if a.Node != "" {
			title += " " + a.Node
		}
		fmt.Printf("[cluster] heal: %s %s: %s\n", a.Kind, a.Node, a.Detail)
		alertf(healSeverity[a.Kind], "heal", title, map[string]any{"node": a.Node, "detail": a.Detail})
		clusterAudit("cluster-master", "cluster heal "+a.Kind, a.Node, nil)
	}
	return seq
}

// ---- node self-heal (agent) ----

// Cooldowns keep the agent from fighting a service that cannot start or a disk that cannot be freed.
const (
	healRestartCooldown = 2 * time.Minute
	healPruneCooldown   = 30 * time.Minute
	diskPressureOn      = 85 // % used that raises DiskPressure (after a prune)
	diskPressureOff     = 80 // and the level it must fall below to clear (hysteresis)
)

// nodeHealer repairs what the host can repair by itself and reports what is still wrong. Its
// effects are injectable so the policy is testable.
type nodeHealer struct {
	containerdUp      func() bool
	restartContainerd func() error
	diskPercent       func() (int, bool)
	prune             func() error

	mu                     sync.Mutex
	lastRestart, lastPrune time.Time
	diskHigh               bool
}

func newNodeHealer() *nodeHealer {
	return &nodeHealer{
		containerdUp:      func() bool { return containerdResponds() == nil },
		restartContainerd: func() error { return restartDown("containerd") },
		diskPercent:       hostDiskPercent,
		prune:             pruneHostDisk,
	}
}

// check runs one pass and returns the conditions that remain, plus what it did. meshErr is the
// agent's last mesh/policy apply error.
func (h *nodeHealer) check(now time.Time, meshErr string) (conds, did []string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.containerdUp() {
		if now.Sub(h.lastRestart) >= healRestartCooldown {
			h.lastRestart = now
			if err := h.restartContainerd(); err != nil {
				did = append(did, "restart containerd failed: "+err.Error())
			} else {
				did = append(did, "restarted containerd")
			}
		}
		conds = append(conds, CondContainerdDown) // until a later pass sees it answer
	}

	if pct, ok := h.diskPercent(); ok {
		if pct >= diskPressureOn && now.Sub(h.lastPrune) >= healPruneCooldown {
			h.lastPrune = now
			if err := h.prune(); err != nil {
				did = append(did, "prune failed: "+err.Error())
			} else {
				did = append(did, fmt.Sprintf("pruned logs, temp files and caches at %d%% disk", pct))
			}
			if again, ok := h.diskPercent(); ok {
				pct = again
			}
		}
		h.diskHigh = pct >= diskPressureOn || (h.diskHigh && pct >= diskPressureOff)
		if h.diskHigh {
			conds = append(conds, CondDiskPressure)
		}
	}

	if meshErr != "" {
		conds = append(conds, CondMeshError)
	}
	return conds, did
}

// hostDiskPercent is the fullest of / and /var.
func hostDiskPercent() (int, bool) {
	worst, any := 0, false
	for _, p := range []string{"/", "/var"} {
		if used, total, ok := diskUsage(p); ok && (p == "/" || !sameFilesystem(p, "/")) {
			worst, any = max(worst, int(used*100/max(total, 1))), true
		}
	}
	return worst, any
}

// pruneHostDisk removes rotated logs, stale temp files and caches (never images or data).
func pruneHostDisk() error {
	_, errs := applyPrune(planPrune(map[string]bool{"logs": true, "tmp": true, "cache": true}, time.Now()))
	return errors.Join(errs...)
}

// cleanConditions keeps only known conditions, once each, in a fixed order (the master never
// stores what an agent merely claims).
func cleanConditions(in []string) []string {
	var out []string
	for _, k := range knownConditions {
		if slices.Contains(in, k) {
			out = append(out, k)
		}
	}
	return out
}

// ---- agent status file (read by doctor) ----

var agentStatusFile = "/run/ziro/cluster/agent.json"

type agentStatus struct {
	LastOK    string `json:"last_ok,omitempty"` // last successful heartbeat (RFC3339)
	LastError string `json:"last_error,omitempty"`
	Updated   string `json:"updated"`
}

func writeAgentStatus(lastOK time.Time, err error) {
	s := agentStatus{Updated: time.Now().UTC().Format(time.RFC3339)}
	if !lastOK.IsZero() {
		s.LastOK = lastOK.UTC().Format(time.RFC3339)
	}
	if err != nil {
		s.LastError = sanitizeLabel(err.Error(), 200)
	}
	if b, e := json.Marshal(s); e == nil {
		_ = os.MkdirAll(strings.TrimSuffix(agentStatusFile, "/agent.json"), 0755)
		_ = writeFileAtomic(agentStatusFile, b, 0644)
	}
}

func readAgentStatus() (agentStatus, bool) {
	var s agentStatus
	b, err := os.ReadFile(agentStatusFile)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return s, false
	}
	return s, true
}

// ---- operations: CLI and API ----

// HealNodeView is a node that is not fully healthy.
type HealNodeView struct {
	ID         string   `json:"id"`
	Hostname   string   `json:"hostname,omitempty"`
	Role       string   `json:"role"`
	Status     string   `json:"status"`
	SilentFor  string   `json:"silent_for,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
	Cordoned   bool     `json:"cordoned,omitempty"`
	AutoCordon bool     `json:"auto_cordoned,omitempty"`
}

// HealView is what `cluster heal status` and GET /api/v1/cluster/heal show.
type HealView struct {
	Enabled     bool           `json:"enabled"`
	RemoveAfter string         `json:"remove_after,omitempty"`
	Partitioned bool           `json:"partition_brake"` // half the cluster looks dead: nothing is moved
	Unhealthy   []HealNodeView `json:"unhealthy"`
	Actions     []HealAction   `json:"actions"`
}

func healView(st *ClusterState, now time.Time) HealView {
	v := HealView{Enabled: st.Heal.enabled(), Partitioned: partitioned(st, now), Unhealthy: []HealNodeView{},
		Actions: append([]HealAction{}, st.Heal.Actions...)}
	if st.Heal.RemoveAfter > 0 {
		v.RemoveAfter = (time.Duration(st.Heal.RemoveAfter) * time.Second).String()
	}
	for _, n := range st.Nodes {
		dead := silentFor(n, now) > nodeTimeout
		if !dead && len(n.Conditions) == 0 && !n.AutoCordon {
			continue
		}
		hv := HealNodeView{ID: n.ID, Hostname: n.Hostname, Role: n.Role, Status: "Ready", Conditions: n.Conditions,
			Cordoned: n.Cordoned, AutoCordon: n.AutoCordon}
		if dead {
			hv.Status, hv.SilentFor = "NotReady", silentFor(n, now).Round(time.Second).String()
		}
		v.Unhealthy = append(v.Unhealthy, hv)
	}
	sort.Slice(v.Unhealthy, func(i, j int) bool { return v.Unhealthy[i].ID < v.Unhealthy[j].ID })
	return v
}

func clusterHealStatus() (HealView, error) {
	if _, err := requireMaster(); err != nil {
		return HealView{}, err
	}
	st, err := readState()
	if err != nil {
		return HealView{}, err
	}
	return healView(st, time.Now()), nil
}

// clusterHealSet turns healing on or off and sets the auto-removal threshold (nil: unchanged,
// 0: off).
func clusterHealSet(enabled bool, removeAfter *time.Duration) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	if removeAfter != nil && *removeAfter != 0 && *removeAfter < healMinRemove {
		return fmt.Errorf("--remove-after must be at least %s (or 0 to turn it off)", healMinRemove)
	}
	return withState(func(st *ClusterState) error {
		st.Heal.Disabled = !enabled
		if removeAfter != nil {
			st.Heal.RemoveAfter = int(*removeAfter / time.Second)
		}
		return nil
	})
}

var (
	healRemoveAfter time.Duration
)

var clusterHealCmd = &cobra.Command{
	Use:     "heal",
	Short:   "Cluster auto-healing: cordon, reschedule, report",
	Example: "  ziroctl cluster heal status\n  ziroctl cluster heal enable --remove-after 2h",
	Long: `The leader repairs the cluster on its own, conservatively:

  - a node whose condition persists (ContainerdDown, DiskPressure, MeshError) is cordoned until it
    recovers; a cordon you set yourself is never lifted automatically;
  - replicas leave a NotReady node only after a short grace period, a few at a time;
  - when half the nodes (of at least three) are NotReady, nothing is moved: that is the master's own
    network, not a mass failure;
  - a master that stays down is reported, and so is the risk of losing Raft quorum (never demoted);
  - with --remove-after, a worker dead that long is removed and its credentials revoked.

Every action is audited and raised as a "heal" alert. Healing is on by default.`,
}

var clusterHealStatusCmd = &cobra.Command{
	Use: "status", Short: "Show what the heal logic sees and did", Args: cobra.NoArgs,
	Example: "  ziroctl cluster heal status",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := clusterHealStatus()
		if err != nil {
			return err
		}
		return printResult(v, func() {
			state := "enabled"
			if !v.Enabled {
				state = "disabled"
			}
			fmt.Printf("Auto-healing: %s", state)
			if v.RemoveAfter != "" {
				fmt.Printf(" (removes workers NotReady for %s)", v.RemoveAfter)
			}
			fmt.Println()
			if v.Partitioned {
				fmt.Println("Safety brake: ON (half the nodes are NotReady; replicas stay where they are)")
			}
			if len(v.Unhealthy) == 0 {
				fmt.Println("Nodes: all healthy")
			}
			for _, n := range v.Unhealthy {
				detail := n.Status
				if n.SilentFor != "" {
					detail += " " + n.SilentFor
				}
				if len(n.Conditions) > 0 {
					detail += ", " + strings.Join(n.Conditions, ",")
				}
				if n.AutoCordon {
					detail += ", cordoned by heal"
				}
				fmt.Printf("  %-14s %-7s %s\n", n.ID, n.Role, detail)
			}
			if len(v.Actions) > 0 {
				fmt.Println("Recent actions:")
				for _, a := range v.Actions {
					fmt.Printf("  %s  %-11s %-14s %s\n", a.Time, a.Kind, a.Node, a.Detail)
				}
			}
		})
	},
}

func healSetCmd(name string, on bool) *cobra.Command {
	c := &cobra.Command{
		Use: name, Short: strings.ToUpper(name[:1]) + name[1:] + " cluster auto-healing", Args: cobra.NoArgs,
		Example: "  ziroctl cluster heal " + name,
		RunE: func(cmd *cobra.Command, args []string) error {
			var after *time.Duration
			if cmd.Flags().Changed("remove-after") {
				after = &healRemoveAfter
			}
			if err := clusterHealSet(on, after); err != nil {
				return err
			}
			clusterAudit("cli", "cluster heal "+name, "", nil)
			fmt.Printf("✓ auto-healing %sd\n", name)
			return nil
		},
	}
	if on {
		c.Flags().DurationVar(&healRemoveAfter, "remove-after", 0, "Also remove workers NotReady this long, e.g. 2h (0 turns it off)")
	}
	return c
}

func init() {
	clusterHealCmd.AddCommand(clusterHealStatusCmd, healSetCmd("enable", true), healSetCmd("disable", false))
	clusterCmd.AddCommand(clusterHealCmd)
}

// recordMoves logs what scheduleReplicas did about dead nodes: replicas moved off them, and
// replicas deliberately left on them while the partition brake holds. The leader loop announces
// them (display-only copies of the state never reach it).
func recordMoves(st *ClusterState, now time.Time, brake bool, moved, held map[string]int) {
	for _, id := range sortedKeys(moved) {
		st.Heal.record(HealAction{Node: id, Kind: "reschedule",
			Detail: fmt.Sprintf("%d replica(s) moved off the NotReady node", moved[id])}, now, false)
	}
	if brake && len(held) > 0 {
		dead := 0
		for _, n := range st.Nodes {
			if silentFor(n, now) > nodeTimeout {
				dead++
			}
		}
		st.Heal.record(HealAction{Kind: "hold", Detail: fmt.Sprintf(
			"%d of %d nodes are NotReady: assuming a network partition on the master's side; replicas stay where they are", dead, len(st.Nodes))}, now, true)
	}
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- doctor ----

// agentFresh is how recent the agent's last good heartbeat must be (three missed beats).
const agentFresh = 3 * agentInterval

// healOnce runs one heal and scheduling pass now instead of waiting for the leader's next tick.
func healOnce() error {
	return withState(func(st *ClusterState) error {
		now := time.Now()
		healPass(st, now)
		scheduleReplicas(st, now)
		return nil
	})
}

// clusterDoctorChecks are the master's cluster rows: a summary with a fix, then one row per node
// that is not healthy. A remote node's agent cannot be restarted from here; its row names the
// host to run `doctor --fix` on.
func clusterDoctorChecks(cfg *ClusterConfig, st *ClusterState, now time.Time) []doctorCheck {
	v := healView(st, now)
	ready := 0
	for _, n := range st.Nodes {
		if silentFor(n, now) <= nodeTimeout {
			ready++
		}
	}
	localDown := false
	var rows []doctorCheck
	for _, n := range v.Unhealthy {
		name := n.Hostname
		if name == "" {
			name = n.ID
		}
		var parts []string
		if n.Status == "NotReady" {
			parts = append(parts, "NotReady "+n.SilentFor)
		}
		parts = append(parts, n.Conditions...)
		if n.AutoCordon {
			parts = append(parts, "cordoned by heal until it recovers")
		}
		row := doctorCheck{Name: "Node " + name, Details: strings.Join(parts, ", "), Passed: n.Status == "Ready" && len(n.Conditions) == 0}
		if n.ID == cfg.NodeID {
			localDown = !row.Passed
			row.Fix = "restart cluster-agent"
			row.fix = func() error { return restartService("cluster-agent") }
		} else {
			row.Fix = "run 'ziroctl doctor --fix' on " + name
		}
		if !row.Passed || n.AutoCordon {
			rows = append(rows, row)
		}
	}
	summary := doctorCheck{Name: "Cluster nodes ready", Passed: ready == len(st.Nodes) && len(rows) == 0,
		Details: fmt.Sprintf("%d/%d ready", ready, len(st.Nodes)),
		Fix:     "run a heal pass (cordon, reschedule), restart this node's agent if it is down",
		fix: func() error {
			err := healOnce()
			if localDown {
				err = errors.Join(err, restartService("cluster-agent"))
			}
			return err
		}}
	if v.Partitioned {
		summary.Details += "; safety brake on: half the nodes are NotReady, nothing is moved"
	}
	if !v.Enabled {
		summary.Details += "; auto-healing is disabled (ziroctl cluster heal enable)"
	}
	return append([]doctorCheck{summary}, rows...)
}

// agentDoctorCheck reports the node agent's heartbeat from the status file it keeps.
func agentDoctorCheck(now time.Time) (doctorCheck, bool) {
	s, ok := readAgentStatus()
	if !ok {
		return doctorCheck{}, false
	}
	c := doctorCheck{Name: "Cluster heartbeat", Fix: "restart cluster-agent", fix: func() error { return restartService("cluster-agent") }}
	last, _ := time.Parse(time.RFC3339, s.LastOK)
	updated, _ := time.Parse(time.RFC3339, s.Updated)
	switch {
	case now.Sub(updated) > agentFresh: // the agent itself is not looping
		c.Details = fmt.Sprintf("agent silent for %s", now.Sub(updated).Round(time.Second))
	case s.LastError != "":
		c.Details = "heartbeat failing: " + s.LastError
		if !last.IsZero() {
			c.Details += fmt.Sprintf(" (last ok %s ago)", now.Sub(last).Round(time.Second))
		}
	default:
		c.Passed, c.Details = true, fmt.Sprintf("last heartbeat %s ago", now.Sub(last).Round(time.Second))
	}
	return c, true
}

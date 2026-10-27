package cmd

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The Postgres controller (RFC 0005). pgPass runs on the cluster leader beside the scheduler, over
// the Raft-replicated state, and is a pure function of that state and the time: it never talks to a
// node. It renders every member as a pinned cluster app, ingests what the agents reported (probes and
// command results) and decides roles: failover, switchover, replicas joining and leaving, the
// synchronous standbys. What it decides is carried out by orders in the heartbeat response
// (pg_agent.go). A new leader continues from the state alone.

// pgDynamic returns the files the agent keeps current for a Postgres member's container (nil for any
// other app).
func pgDynamic(st *ClusterState, app string) map[string]string {
	if !strings.HasPrefix(app, pgAppPrefix) {
		return nil
	}
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			for mi := range g.Members {
				if m := &g.Members[mi]; c.memberApp(g.Name, m.ID) == app {
					return map[string]string{"role": pgRoleFile(m, g)}
				}
			}
		}
	}
	return nil
}

// ---- commands ----

// The orders the master may give an agent: a closed list, each with a validated argument. Nothing
// else is ever executed in a member's container.
const (
	opPromote  = "promote"  // pg_ctl promote, then clear read-only
	opDemote   = "demote"   // make read-only, end sessions, stop: the container restarts as a replica
	opReadonly = "readonly" // default_transaction_read_only = on, end sessions (switchover, fencing)
	opWritable = "writable" // undo opReadonly
	opSetSync  = "setsync"  // synchronous_standby_names; argument is the value ("" = asynchronous)
	opSlots    = "slots"    // create the named physical replication slots if missing
	opDropSlot = "dropslot" // drop one replication slot
)

var pgSyncValueRe = regexp.MustCompile(`^(ANY [12] \(m[0-9]{1,3}(, m[0-9]{1,3})*\))?$`)

// validPGCommand checks an order and its argument.
func validPGCommand(op, arg string) error {
	switch op {
	case opPromote, opDemote, opReadonly, opWritable:
		if arg != "" {
			return fmt.Errorf("%s takes no argument", op)
		}
	case opSetSync:
		if !pgSyncValueRe.MatchString(arg) {
			return fmt.Errorf("invalid synchronous standby list %q", arg)
		}
	case opSlots:
		for _, s := range strings.Split(arg, ",") {
			if s != "" && !pgSlotRe.MatchString(s) {
				return fmt.Errorf("invalid slot name %q", s)
			}
		}
	case opDropSlot:
		if !pgSlotRe.MatchString(arg) {
			return fmt.Errorf("invalid slot name %q", arg)
		}
	default:
		if err := validCitusCommand(op, arg); err != nil {
			return err
		}
	}
	return nil
}

// newPGCommand makes an order with an ID no other order has: agents run an ID once, so two orders
// issued in the same instant (a promotion and the demotion of the old primary) must differ.
func newPGCommand(op, arg string, epoch int64, now time.Time) *PGCommand {
	return &PGCommand{ID: strconv.FormatInt(now.UnixNano(), 36) + "-" + randomHex(4), Op: op, Arg: arg, Epoch: epoch, At: now}
}

// issue gives a member an order unless one is still outstanding.
func (m *PGMember) issue(op, arg string, epoch int64, now time.Time) bool {
	if m.Cmd != nil {
		return false
	}
	m.Cmd = newPGCommand(op, arg, epoch, now)
	return true
}

// ---- events ----

func (g *PGGroup) note(now time.Time, format string, a ...any) { g.record(now, "", format, a...) }

// alert records an event that also raises an alert (category "database") once it is committed.
func (g *PGGroup) alert(now time.Time, severity, format string, a ...any) {
	g.record(now, severity, format, a...)
}

func (g *PGGroup) record(now time.Time, severity, format string, a ...any) {
	g.Events = append(g.Events, PGEvent{At: now, Msg: fmt.Sprintf(format, a...), Alert: severity})
	if len(g.Events) > 20 {
		g.Events = g.Events[len(g.Events)-20:]
	}
}

type pgAlert struct {
	Severity, Cluster, Group, Msg string
}

// pgTakeAlerts returns the alerts not yet raised and marks them raised. The caller raises them
// after the state is committed.
func pgTakeAlerts(st *ClusterState) []pgAlert {
	var out []pgAlert
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			for i := range g.Events {
				if e := &g.Events[i]; e.Alert != "" && !e.Sent {
					e.Sent = true
					out = append(out, pgAlert{e.Alert, c.Name, g.Name, e.Msg})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Cluster+out[i].Group+out[i].Msg < out[j].Cluster+out[j].Group+out[j].Msg
	})
	return out
}

// ---- what the agents report ----

// PGReport is one member's probe, as an agent sends it.
type PGReport struct {
	App      string `json:"app"`
	OK       bool   `json:"ok"`
	Recovery bool   `json:"recovery,omitempty"`
	LSN      string `json:"lsn,omitempty"`
	Timeline int    `json:"timeline,omitempty"`
	LagMs    int64  `json:"lag_ms,omitempty"`
	Epoch    int64  `json:"epoch,omitempty"`
	// Streaming: a replica's WAL receiver is connected to a primary.
	Streaming bool `json:"streaming,omitempty"`
	// AgeMs is how long ago the agent took the probe: an agent that is alive but whose probes hang
	// must not look healthy.
	AgeMs int64 `json:"age_ms,omitempty"`
}

// PGResult is the outcome of an order.
type PGResult struct {
	ID  string `json:"id"`
	OK  bool   `json:"ok"`
	Msg string `json:"msg,omitempty"`
}

// PGOrder is an order in a heartbeat response.
type PGOrder struct {
	ID        string `json:"id"`
	App       string `json:"app"`
	Container string `json:"container"`
	Op        string `json:"op"`
	Arg       string `json:"arg,omitempty"`
	Epoch     int64  `json:"epoch"`
	DB        string `json:"db,omitempty"`
}

// pgFind locates the member that runs app.
func pgFind(st *ClusterState, app string) (*PGCluster, *PGGroup, *PGMember) {
	if !strings.HasPrefix(app, pgAppPrefix) {
		return nil, nil, nil
	}
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			for mi := range g.Members {
				if c.memberApp(g.Name, g.Members[mi].ID) == app {
					return c, g, &g.Members[mi]
				}
			}
		}
	}
	return nil, nil, nil
}

// pgIngest records what a node reported. Only the node a member is pinned to may report for it.
func pgIngest(st *ClusterState, nodeID string, reports []PGReport, results []PGResult, now time.Time) {
	for _, r := range reports {
		_, _, m := pgFind(st, r.App)
		if m == nil || m.Node != nodeID {
			continue
		}
		if !r.OK {
			m.Probe.OK = false // the time of the last good probe stays: failure is judged by its age
			continue
		}
		lsn, err := parseLSN(r.LSN)
		if err != nil || r.LagMs < 0 || r.Timeline < 0 {
			continue
		}
		at := now.Add(-time.Duration(max(r.AgeMs, 0)) * time.Millisecond)
		if at.Before(m.Probe.At) {
			continue // an older report than the one we have
		}
		m.Probe = PGProbe{At: at, OK: true, Recovery: r.Recovery, Streaming: r.Streaming, LSN: lsn, Timeline: r.Timeline, LagMs: r.LagMs, Epoch: r.Epoch}
	}
	if len(results) == 0 {
		return
	}
	byID := map[string]PGResult{}
	for _, r := range results {
		byID[r.ID] = r
	}
	for _, c := range st.PG {
		for gi := range c.Groups {
			for mi := range c.Groups[gi].Members {
				m := &c.Groups[gi].Members[mi]
				if m.Node != nodeID || m.Cmd == nil || m.Cmd.Done {
					continue
				}
				if r, ok := byID[m.Cmd.ID]; ok {
					m.Cmd.Done, m.Cmd.OK, m.Cmd.Msg = true, r.OK, sanitizeLabel(r.Msg, 300)
				}
			}
		}
	}
}

// pgOrdersFor lists the orders for the members pinned to a node.
func pgOrdersFor(st *ClusterState, nodeID string) []PGOrder {
	var out []PGOrder
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			for mi := range g.Members {
				m := &g.Members[mi]
				if m.Node != nodeID || m.Cmd == nil || m.Cmd.Done {
					continue
				}
				app := c.memberApp(g.Name, m.ID)
				for _, r := range st.Replicas {
					if r.App == app && r.Node == nodeID {
						out = append(out, PGOrder{ID: m.Cmd.ID, App: app, Container: replicaName(app, r.Index, r.Hash),
							Op: m.Cmd.Op, Arg: m.Cmd.Arg, Epoch: m.Cmd.Epoch, DB: m.Cmd.DB})
					}
				}
			}
		}
	}
	return out
}

// ---- the pass ----

// pgPass reconciles every Postgres cluster. The caller commits st.
func pgPass(st *ClusterState, now time.Time) {
	names := make([]string, 0, len(st.PG))
	for n := range st.PG {
		names = append(names, n)
	}
	sort.Strings(names)
	braked := partitioned(st, now)
	for _, n := range names {
		c := st.PG[n]
		if !c.Paused {
			for gi := range c.Groups {
				pgGroupPass(st, c, &c.Groups[gi], now, braked)
			}
			pgCitusPass(st, c, now)
		}
		pgEnsureApps(st, c)
	}
	pgRemoveOrphans(st)
}

// pgGroupPass settles commands, then lets the group's state machine take one step.
func pgGroupPass(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time, braked bool) {
	for i := range g.Members {
		pgSettle(c, g, &g.Members[i], now)
	}
	// Joined: a replica that has been ready counts toward the synchronous standbys from then on.
	for i := range g.Members {
		if m := &g.Members[i]; m.ready(now) && !m.Joined {
			m.Joined = true
			g.note(now, "%s joined as a replica", m.ID)
		}
	}

	switch {
	case g.promoting() != nil:
		pgFinishPromotion(c, g, now)
	case g.Switch != nil:
		pgSwitchover(c, g, now)
	default:
		if p := g.primary(); p == nil || pgPrimaryFailed(p, now) {
			if !braked {
				pgFailover(c, g, now)
			} else if g.last(now, 60*time.Second, "braked") {
				g.alert(now, "high", "primary is down, but too many nodes are unreachable to tell a failure from a partition; not promoting")
			}
		}
	}
	pgFence(c, g, now)
	if g.primary() != nil && g.promoting() == nil && g.Switch == nil {
		pgAdjustMembers(st, c, g, now)
		pgSyncAndSlots(c, g, now)
	}
}

func (g *PGGroup) promoting() *PGMember {
	for i := range g.Members {
		if g.Members[i].Role == pgPromoting {
			return &g.Members[i]
		}
	}
	return nil
}

// Probes are soft state: they change on every heartbeat, so they are kept out of the Raft
// commits (hardKey) and a new leader starts from what the last commit happened to carry.

// pgWithoutProbes copies the Postgres clusters with every member's probe blanked.
func pgWithoutProbes(pg map[string]*PGCluster) map[string]*PGCluster {
	if len(pg) == 0 {
		return pg
	}
	out := make(map[string]*PGCluster, len(pg))
	for name, c := range pg {
		cc := *c
		cc.Groups = make([]PGGroup, len(c.Groups))
		for i, g := range c.Groups {
			g.Members = append([]PGMember(nil), g.Members...)
			for j := range g.Members {
				g.Members[j].Probe = PGProbe{}
			}
			cc.Groups[i] = g
		}
		out[name] = &cc
	}
	return out
}

// pgProbesUnknown is a new leader's view of probes it hasn't received: not OK (nothing is fresh,
// ready or a promotion candidate until its agent reports), last heard now (a primary that never
// reports is failed over one grace period from now), and older reports are ignored by pgIngest.
func pgProbesUnknown(st *ClusterState, now time.Time) {
	for _, c := range st.PG {
		for gi := range c.Groups {
			for mi := range c.Groups[gi].Members {
				p := &c.Groups[gi].Members[mi].Probe
				if !p.At.IsZero() {
					p.OK, p.At = false, now
				}
			}
		}
	}
}

// pgPrimaryFailed: a primary that has been up before and has not answered for the grace period.
func pgPrimaryFailed(p *PGMember, now time.Time) bool {
	return !p.Probe.At.IsZero() && now.Sub(p.Probe.At) > pgGrace
}

// pgSettle consumes the outcome of a member's order, or gives up on one that never answered.
func pgSettle(c *PGCluster, g *PGGroup, m *PGMember, now time.Time) {
	cmd := m.Cmd
	if cmd == nil {
		return
	}
	if !cmd.Done {
		if now.Sub(cmd.At) <= pgCommandTimeout {
			return
		}
		cmd.Done, cmd.OK, cmd.Msg = true, false, "no answer from the node"
	}
	switch cmd.Op {
	case opSetSync:
		if cmd.OK {
			g.Sync = cmd.Arg
		}
	case opSlots:
		if cmd.OK {
			g.Slots = cmd.Epoch
		}
	case opPromote:
		if m.Role == pgPromoting {
			return // pgFinishPromotion reads the result
		}
	case opDemote, opReadonly, opWritable, opDropSlot:
		if g.Switch != nil && cmd.Op == opReadonly {
			return // pgSwitchover reads the result
		}
	default:
		pgCitusSettle(c, g, m, cmd, now)
	}
	if !cmd.OK {
		g.alert(now, "medium", "%s on %s failed: %s", cmd.Op, m.ID, cmd.Msg)
	}
	m.Cmd = nil
}

// ---- failover ----

// pgCandidate picks the replica to promote: reachable, in recovery, joined, the furthest ahead.
// reachable and total count the replicas that could hold acknowledged commits.
func pgCandidate(g *PGGroup, now time.Time) (best *PGMember, reachable, total int) {
	for i := range g.Members {
		m := &g.Members[i]
		if m.Role != pgReplica || !m.Joined || m.Draining {
			continue
		}
		total++
		if !m.fresh(now) || !m.Probe.Recovery {
			continue
		}
		reachable++
		if best == nil || m.Probe.LSN > best.Probe.LSN ||
			m.Probe.LSN == best.Probe.LSN && m.ID < best.ID {
			best = m
		}
	}
	return best, reachable, total
}

// pgSafeToPromote: with k acknowledgements required of n synchronous replicas, a commit is on at least k
// of them, so it is certain to be visible on a reachable one when at most k-1 are unreachable.
func pgSafeToPromote(reachable, total, k int) bool {
	if k == 0 {
		return reachable > 0 // asynchronous: the replication lag may be lost
	}
	return reachable >= total-k+1
}

func pgFailover(c *PGCluster, g *PGGroup, now time.Time) {
	best, reachable, total := pgCandidate(g, now)
	if best == nil {
		// Replicas answer a beat after a leader change or a long step: only a lasting silence is news.
		if g.Notes == nil {
			g.Notes = map[string]time.Time{}
		}
		since, ok := g.Notes["nocandidate-since"]
		if !ok {
			g.Notes["nocandidate-since"] = now
		} else if now.Sub(since) > pgGrace && g.last(now, 60*time.Second, "nocandidate") {
			g.alert(now, "high", "primary is down and no joined replica answers; nothing can be promoted")
		}
		return
	}
	delete(g.Notes, "nocandidate-since")
	k := 0
	if c.Sync == pgSyncQuorum {
		k = pgQuorum(total)
	}
	if !pgSafeToPromote(reachable, total, k) {
		if g.last(now, 60*time.Second, "waiting") {
			g.alert(now, "high", "primary is down, but only %d of %d replicas answer; promoting could lose acknowledged writes", reachable, total)
		}
		return
	}
	pgPromote(c, g, best, now, "primary is down")
}

// last rate-limits a repeated event: it reports whether msg-kind key has not been recorded in d.
func (g *PGGroup) last(now time.Time, d time.Duration, key string) bool {
	if g.Notes == nil {
		g.Notes = map[string]time.Time{}
	}
	if t, ok := g.Notes[key]; ok && now.Sub(t) < d {
		return false
	}
	g.Notes[key] = now
	return true
}

// pgPromote starts a promotion: the old primary (if any) is fenced and the epoch moves.
func pgPromote(c *PGCluster, g *PGGroup, target *PGMember, now time.Time, why string) {
	if old := g.primary(); old != nil {
		old.Role = pgFenced
		old.Cmd = nil
	}
	g.Epoch++
	if g.Notes == nil {
		g.Notes = map[string]time.Time{}
	}
	g.Notes["promoting"] = now
	target.Role = pgPromoting
	target.Cmd = newPGCommand(opPromote, "", g.Epoch, now)
	g.Sync = "" // the new primary starts without synchronous standbys; pgSyncAndSlots sets them
	g.alert(now, "high", "promoting %s (%s), epoch %d", target.ID, why, g.Epoch)
}

func pgFinishPromotion(c *PGCluster, g *PGGroup, now time.Time) {
	m := g.promoting()
	confirmed := m.Probe.OK && m.fresh(now) && !m.Probe.Recovery && m.Probe.Timeline > 0
	cmd := m.Cmd
	switch {
	case cmd != nil && cmd.Done && cmd.OK, confirmed && cmd == nil:
		m.Role = pgPrimary
		m.Cmd = nil
		m.Draining = false
		g.note(now, "%s is the primary (epoch %d)", m.ID, g.Epoch)
	case cmd != nil && cmd.Done:
		// The promotion failed, or the node never answered. If the member is out of recovery anyway,
		// it did promote.
		if confirmed {
			m.Role = pgPrimary
			m.Cmd = nil
			g.note(now, "%s is the primary (epoch %d)", m.ID, g.Epoch)
			return
		}
		// Not confirmed yet: pg_ctl may have timed out on a slow promotion that still completes, and
		// reverting now would leave a writable replica nobody fences. Wait for a probe.
		m.Cmd = nil
		g.alert(now, "high", "promoting %s failed: %s", m.ID, cmd.Msg)
	case cmd == nil && now.Sub(g.Notes["promoting"]) > pgCommandTimeout+pgGrace:
		// No answer and no probe that shows it out of recovery: give the group back to the failover.
		m.Role = pgReplica
		g.alert(now, "high", "promoting %s did not complete; trying again", m.ID)
	}
}

// pgFence makes sure a former primary does not serve: while it still answers as a primary it is told
// to demote (which stops it, and its restart rejoins as a replica); once it answers in recovery it is
// a replica again.
func pgFence(c *PGCluster, g *PGGroup, now time.Time) {
	for i := range g.Members {
		m := &g.Members[i]
		if m.Role != pgFenced || !m.fresh(now) {
			continue
		}
		if m.Probe.Recovery {
			m.Role = pgReplica
			m.Joined = false
			g.note(now, "%s rejoined as a replica", m.ID)
			continue
		}
		if m.Cmd == nil {
			m.issue(opDemote, "", g.Epoch, now)
		}
	}
}

// ---- switchover ----

// pgStartSwitchover begins a planned switchover to the named replica.
func pgStartSwitchover(c *PGCluster, g *PGGroup, to string, now time.Time) error {
	p := g.primary()
	t := g.member(to)
	switch {
	case g.Switch != nil || g.promoting() != nil:
		return fmt.Errorf("group %s is already changing primary", g.Name)
	case p == nil || !p.fresh(now):
		return fmt.Errorf("group %s has no healthy primary", g.Name)
	case t == nil || t.Role != pgReplica || t.Draining:
		return fmt.Errorf("%s is not a replica of group %s", to, g.Name)
	case !t.fresh(now) || !t.Probe.Recovery:
		return fmt.Errorf("%s is not answering", to)
	}
	g.Switch = &PGSwitch{To: to, At: now, Step: "readonly"}
	g.note(now, "switchover from %s to %s", p.ID, to)
	return nil
}

func pgAbortSwitch(g *PGGroup, p *PGMember, now time.Time, why string) {
	g.alert(now, "medium", "switchover aborted: %s", why)
	g.Switch = nil
	if p != nil && p.Cmd == nil {
		p.issue(opWritable, "", g.Epoch, now)
	}
}

func pgSwitchover(c *PGCluster, g *PGGroup, now time.Time) {
	sw := g.Switch
	p, t := g.primary(), g.member(sw.To)
	if p == nil || t == nil || t.Role != pgReplica {
		pgAbortSwitch(g, p, now, "the primary or the target changed")
		return
	}
	if now.Sub(sw.At) > 2*time.Minute {
		pgAbortSwitch(g, p, now, "timed out")
		return
	}
	switch sw.Step {
	case "readonly":
		if p.Cmd == nil {
			p.issue(opReadonly, "", g.Epoch, now)
			return
		}
		if p.Cmd.Op != opReadonly || !p.Cmd.Done {
			return
		}
		ok := p.Cmd.OK
		p.Cmd = nil
		if !ok {
			pgAbortSwitch(g, p, now, "could not make the primary read-only")
			return
		}
		sw.Step, sw.ReadOnlyAt = "catchup", now
	case "catchup":
		// The primary is read-only: its position no longer moves in a way that matters. The target
		// must have replayed it, as seen by probes taken after the primary stopped accepting writes.
		if p.Probe.OK && t.Probe.OK && p.Probe.At.After(sw.ReadOnlyAt) && !t.Probe.At.Before(p.Probe.At) && t.Probe.Recovery && t.Probe.LSN >= p.Probe.LSN {
			pgPromote(c, g, t, now, "planned switchover")
			g.Switch = nil
		}
	}
}

// ---- members ----

// pgPickNode chooses the node for a new member: ready and not cordoned, not already holding a member
// of the group unless colocation is allowed, and the one with the fewest replicas.
func pgPickNode(st *ClusterState, c *PGCluster, g *PGGroup, exclude ...string) string {
	used := map[string]bool{}
	for _, m := range g.Members {
		used[m.Node] = true
	}
	load := map[string]int{}
	for _, r := range st.Replicas {
		load[r.Node]++
	}
	best := ""
	for _, n := range st.Nodes {
		if n.Status != "Ready" || n.Cordoned || n.Labels["runner"] == "false" || slices.Contains(exclude, n.ID) {
			continue
		}
		if used[n.ID] && !c.Colocate {
			continue
		}
		if best == "" || load[n.ID] < load[best] || load[n.ID] == load[best] && n.ID < best {
			best = n.ID
		}
	}
	return best
}

// pgNodeGone: the node was removed, or has not been seen for pgNodeGoneAfter.
func pgNodeGone(st *ClusterState, id string, now time.Time) bool {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n.Status != "Ready" && now.Sub(n.LastSeen) > pgNodeGoneAfter
		}
	}
	return true
}

// pgAdjustMembers adds or drains replicas until the group has the declared number, and finishes the
// removal of drained ones.
func pgAdjustMembers(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time) {
	var replicas []*PGMember
	for i := range g.Members {
		if m := &g.Members[i]; m.Role != pgPrimary && !m.Draining {
			replicas = append(replicas, m)
		}
	}
	// A member whose node has been gone a long time is replaced: drained (its data is a copy), which
	// makes room for a new replica on a live node. Only when there is such a node, and one at a time.
	for i := range g.Members {
		m := &g.Members[i]
		if m.Role != pgPrimary && !m.Draining && pgNodeGone(st, m.Node, now) && pgPickNode(st, c, g) != "" {
			m.Draining = true
			g.note(now, "replacing %s: node %s is gone", m.ID, m.Node)
			return
		}
	}
	switch {
	case len(replicas) < c.Replicas:
		node := pgPickNode(st, c, g)
		if node == "" {
			if g.last(now, 5*time.Minute, "nonode") {
				g.alert(now, "medium", "no node is free for another replica (members of a group are spread over nodes)")
			}
			return
		}
		g.Next++
		id := "m" + strconv.Itoa(g.Next)
		g.Members = append(g.Members, PGMember{ID: id, Node: node, Role: pgReplica, Init: pgReplica})
		g.note(now, "adding replica %s on %s", id, node)
	case len(replicas) > c.Replicas:
		// Drain the replica that is furthest behind (or the newest).
		sort.Slice(replicas, func(i, j int) bool {
			if replicas[i].Probe.LSN != replicas[j].Probe.LSN {
				return replicas[i].Probe.LSN < replicas[j].Probe.LSN
			}
			return replicas[i].ID > replicas[j].ID
		})
		replicas[0].Draining = true
		g.note(now, "removing replica %s", replicas[0].ID)
	}
	// A drained replica leaves once the primary no longer counts it as a synchronous standby and
	// its slot is dropped.
	p := g.primary()
	for i := range g.Members {
		m := &g.Members[i]
		if !m.Draining || m.Role == pgPrimary {
			continue
		}
		if g.Sync != pgSyncSpec(c, g) {
			continue // the synchronous list still names it
		}
		if m.DropSlot == "" {
			if p != nil && p.fresh(now) {
				if p.Cmd == nil {
					p.issue(opDropSlot, pgSlot(m.ID), g.Epoch, now)
					m.DropSlot = now.Format(time.RFC3339)
				}
				continue
			}
		} else if p != nil && p.Cmd != nil {
			continue
		}
		g.note(now, "replica %s removed", m.ID)
		markPurge(st, c.memberApp(g.Name, m.ID))
		g.Members = slices.Delete(g.Members, i, i+1)
		return
	}
}

// pgSyncAndSlots keeps the primary's synchronous standbys and the replicas' slots right.
func pgSyncAndSlots(c *PGCluster, g *PGGroup, now time.Time) {
	p := g.primary()
	if p == nil || !p.fresh(now) || p.Cmd != nil {
		return
	}
	// After a promotion the new primary has none of the old one's slots.
	if g.Slots != g.Epoch {
		var slots []string
		for _, m := range g.Members {
			if m.Role != pgPrimary && !m.Draining {
				slots = append(slots, pgSlot(m.ID))
			}
		}
		sort.Strings(slots)
		p.issue(opSlots, strings.Join(slots, ","), g.Epoch, now)
		return
	}
	if want := pgSyncSpec(c, g); g.Sync != want {
		p.issue(opSetSync, want, g.Epoch, now)
	}
}

// ---- apps ----

// pgEnsureApps makes the cluster apps match the members: one pinned app per member, and no others.
func pgEnsureApps(st *ClusterState, c *PGCluster) {
	want := map[string]bool{}
	for gi := range c.Groups {
		g := &c.Groups[gi]
		for mi := range g.Members {
			m := &g.Members[mi]
			if m.Node == "" {
				m.Node = pgPickNode(st, c, g)
				if m.Node == "" {
					continue
				}
			}
			app := withPodNetwork(st, pgMemberApp(st, c, g, m))
			want[app.Name] = true
			upsertApp(st, app)
		}
	}
	prefix := pgAppPrefix + c.Name + "-"
	var kept []ClusteredApp
	for _, a := range st.Apps {
		if strings.HasPrefix(a.Name, prefix) && !want[a.Name] {
			delete(st.History, a.Name)
			continue
		}
		kept = append(kept, a)
	}
	st.Apps = kept
}

// pgRemoveOrphans deletes the apps of clusters that no longer exist.
func pgRemoveOrphans(st *ClusterState) {
	var kept []ClusteredApp
	for _, a := range st.Apps {
		if strings.HasPrefix(a.Name, pgAppPrefix) {
			name, _, _ := strings.Cut(strings.TrimPrefix(a.Name, pgAppPrefix), "-")
			if st.PG[name] == nil {
				delete(st.History, a.Name)
				continue
			}
		}
		kept = append(kept, a)
	}
	st.Apps = kept
}

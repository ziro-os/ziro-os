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
					params, _ := pgReloadParams(c)
					return map[string]string{"role": pgRoleFile(c, m, g), "lease": pgLeaseFile(g, m, pgNow()), "params.conf": params}
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
	opReinit   = "reinit"   // a replica discards its data directory and takes a new base backup (pg reinit)
	opFollow   = "follow"   // a replica follows the named primary (primary_conninfo, reload); argument is the conninfo
	opReload   = "reload"   // reload the configuration once params.conf has the given hash (pg set)
	opStanza   = "stanza"   // create the group's pgBackRest stanza (pg_backup.go); argument is the stanza
	opBackup   = "backup"   // start a pgBackRest backup in the background; argument is full, diff or incr
)

// pgFenceName is the synchronous standby no member is ever called: a primary with it waits for ever on
// each commit, so nothing is acknowledged (switchover, and the lease watchdog in pg_entry.sh).
const pgFenceName = "ziro_fenced"

// pgConninfoRe is the only primary_conninfo an opFollow may set: a member host, the replication user, the
// member's own name and, with TLS, the cluster CA.
var pgConninfoRe = regexp.MustCompile(`^host=[0-9a-z][0-9a-z.-]{0,200} port=5432 user=replicator application_name=m[0-9]{1,3}( sslmode=verify-ca sslrootcert=/var/lib/postgresql/data/ziro-tls/ca\.crt)?$`)

var pgSyncValueRe = regexp.MustCompile(`^(ANY [12] \(m[0-9]{1,3}(, m[0-9]{1,3})*\))?$`)

// validPGCommand checks an order and its argument.
func validPGCommand(op, arg string) error {
	switch op {
	case opPromote, opDemote, opReadonly, opReinit:
		if arg != "" {
			return fmt.Errorf("%s takes no argument", op)
		}
	case opPassword:
		return validPasswordArg(arg)
	case opRole:
		return validRoleArg(arg)
	case opRoleOff:
		if !pgIdentRe.MatchString(arg) || pgReservedRoleRe.MatchString(arg) {
			return fmt.Errorf("invalid role %q", arg)
		}
	case opDatabase:
		return validDatabaseArg(arg)
	case opStanza:
		if !pgGroupRe.MatchString(arg) {
			return fmt.Errorf("invalid stanza %q", arg)
		}
	case opBackup:
		if arg != "full" && arg != "diff" && arg != "incr" {
			return fmt.Errorf("invalid backup type %q", arg)
		}
	case opReload:
		if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(arg) {
			return fmt.Errorf("invalid parameters hash %q", arg)
		}
	case opFollow:
		if !pgConninfoRe.MatchString(arg) {
			return fmt.Errorf("invalid primary connection %q", arg)
		}
	case opSetSync, opWritable: // writable restores the synchronous standbys the switchover fence replaced
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
	if len(g.Events) > pgEventsKept {
		g.Events = g.Events[len(g.Events)-pgEventsKept:]
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
	// ReadOnly: default_transaction_read_only is on (a primary left read-only by an aborted switchover).
	ReadOnly bool `json:"ro,omitempty"`
	// Received: a replica's WAL received and flushed; SyncNames: its synchronous_standby_names.
	Received  string `json:"received,omitempty"`
	SyncNames string `json:"sync_names,omitempty"`
	// DiskPct: how full the member's data volume is (0 = unknown).
	DiskPct int `json:"disk_pct,omitempty"`
	// ArchiveFailed and ArchivedAgo: pg_stat_archiver; Backup: what pgbackrest info said (a primary, every minute).
	// Conns, MaxConns, Commits, XIDAge: see PGProbe.
	ArchiveFailed int64         `json:"archive_failed,omitempty"`
	ArchivedAgo   int64         `json:"archived_ago,omitempty"`
	Backup        *PGBackupInfo `json:"backup,omitempty"`
	// For metrics and alerts: client connections, max_connections, commits so far, oldest XID age.
	Conns    int64 `json:"conns,omitempty"`
	MaxConns int64 `json:"max_conns,omitempty"`
	Commits  int64 `json:"commits,omitempty"`
	XIDAge   int64 `json:"xid_age,omitempty"`
	// UpSecs is how long the server has been running (0 = not reported): a member that restarted for a new
	// spec is told from the old container, which answers until the node stops it, by when its server started.
	UpSecs int64 `json:"up_secs,omitempty"`
	// Detail says what the node sees of a member that does not answer (container state, the entry
	// script's last error); Busy: a base backup or rewind is running in it, so it is not stuck.
	Detail string `json:"detail,omitempty"`
	Busy   bool   `json:"busy,omitempty"`
	// Starting: the container is up and Postgres is starting or recovering, so it refuses connections.
	Starting bool `json:"starting,omitempty"`
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
	Index     int    `json:"index,omitempty"` // the replica index of the member's app on this node (its data directory)
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
		m.Detail, m.Busy, m.Starting = sanitizeLabel(r.Detail, 200), r.Busy, r.Starting
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
		received, _ := parseLSN(r.Received)
		m.Probe = PGProbe{At: at, OK: true, Recovery: r.Recovery, Streaming: r.Streaming, LSN: lsn, Timeline: r.Timeline, LagMs: r.LagMs, Epoch: r.Epoch,
			ReadOnly: r.ReadOnly, Received: received, SyncNames: sanitizeLabel(r.SyncNames, 200), DiskPct: min(max(r.DiskPct, 0), 100),
			Conns: max(r.Conns, 0), MaxConns: max(r.MaxConns, 0), Commits: max(r.Commits, 0), XIDAge: max(r.XIDAge, 0),
			ArchiveFailed: max(r.ArchiveFailed, 0), ArchivedAgo: max(r.ArchivedAgo, -1)}
		if r.UpSecs > 0 {
			m.Probe.Started = at.Add(-time.Duration(r.UpSecs) * time.Second)
		}
		if r.Backup != nil && !r.Recovery {
			if c, g, _ := pgFind(st, r.App); c != nil && c.backupsOn() {
				if g.Backup == nil {
					g.Backup = &PGGroupBackup{}
				}
				info := *r.Backup
				info.At, info.Status, info.LastLog = at, sanitizeLabel(info.Status, 120), sanitizeLabel(info.LastLog, 300)
				if len(info.Backups) > 50 {
					info.Backups = info.Backups[len(info.Backups)-50:]
				}
				g.Backup.Info = &info
			}
		}
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
							Op: m.Cmd.Op, Arg: m.Cmd.Arg, Epoch: m.Cmd.Epoch, DB: m.Cmd.DB, Index: r.Index})
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
	held := now.Before(st.PGHold)
	for _, n := range names {
		c := st.PG[n]
		if !c.Paused {
			for gi := range c.Groups {
				pgGroupPass(st, c, &c.Groups[gi], now, braked, held)
			}
			pgCitusPass(st, c, now)
			pgRotationPass(st, c, now)
			pgRolesPass(st, c, now)
		}
		pgEnsureApps(st, c, now)
		pgEnsureRoleSecrets(st, c)
	}
	pgRemoveOrphans(st)
}

// pgGroupPass settles commands, then lets the group's state machine take one step.
func pgGroupPass(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time, braked, held bool) {
	for i := range g.Members {
		pgSettle(c, g, &g.Members[i], now)
	}
	// A replica on an older timeline than the primary still follows a former primary: no reads, no vote.
	tl := 0
	if p := g.primary(); p != nil && p.fresh(now) && !p.Probe.Recovery {
		tl = p.Probe.Timeline
	}
	for i := range g.Members {
		m := &g.Members[i]
		m.OffTimeline = tl > 0 && m.Role == pgReplica && m.Probe.Timeline > 0 && m.Probe.Timeline < tl
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
	case g.Force != nil:
		pgForcedFailover(c, g, now)
	default:
		if p := g.primary(); p == nil || pgPrimaryFailed(p, now) {
			switch {
			case held:
				// A new cluster leader has not heard from the members yet: a primary that is merely
				// slow to report (a reboot, a long crash recovery) must not lose its place to a replica.
			case !braked:
				pgFailover(c, g, now)
			case g.last(now, 60*time.Second, "braked"):
				g.alert(now, "high", "primary is down, but too many nodes are unreachable to tell a failure from a partition; not promoting")
			}
		}
	}
	pgFence(c, g, now)
	pgSelfHeal(st, c, g, now)
	if g.primary() != nil && g.promoting() == nil && g.Switch == nil {
		pgAdjustMembers(st, c, g, now)
		pgSyncAndSlots(c, g, now)
		pgFollowPrimary(st, c, g, now)
		pgReloadPass(c, g, now)
		pgBackupPass(c, g, now)
	}
}

// pgConninfo is the primary_conninfo of member m following primary p.
func pgConninfo(st *ClusterState, c *PGCluster, g *PGGroup, p, m *PGMember) string {
	s := "host=1." + c.memberApp(g.Name, p.ID) + "." + meshDomain + " port=5432 user=replicator application_name=" + m.ID
	if pgTLSEnabled(st, c) {
		s += " sslmode=verify-ca sslrootcert=" + pgTLSDir + "/ca.crt"
	}
	return s
}

// pgFollowPrimary points every replica at the primary by its member name. A replica that still streams
// from a former primary (alive, but no longer the primary) would not move by itself: the read-write
// name it connected through has moved, its connection has not.
func pgFollowPrimary(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time) {
	p := g.primary()
	if p == nil || !p.fresh(now) || p.Probe.Recovery {
		return
	}
	for i := range g.Members {
		m := &g.Members[i]
		if m.Role != pgReplica || m.Draining || m.Cmd != nil || !m.fresh(now) || !m.Probe.Recovery {
			continue
		}
		if want := pgConninfo(st, c, g, p, m); m.Following != want {
			m.issue(opFollow, want, g.Epoch, now)
		}
	}
}

// pgSelfHeal is the controller acting on its own for what would otherwise wait for an operator: it
// remembers a member that has held a database, makes a primary left read-only writable again, rebuilds
// a replica that answers but cannot follow, and says so when a primary never reports.
func pgSelfHeal(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time) {
	p := g.primary()
	if p != nil && p.fresh(now) && !p.Probe.Recovery && p.Probe.Timeline > 0 && !p.Initialised {
		// From now on an empty data directory on this member is a loss, not a new cluster: the entry
		// script refuses to initialise one and the controller fails over instead.
		p.Initialised = true
	}
	if p != nil && p.Probe.At.IsZero() {
		key := "noprobe-" + p.ID
		if g.Notes == nil {
			g.Notes = map[string]time.Time{}
		}
		if _, ok := g.Notes[key]; !ok {
			g.Notes[key] = now
		} else if now.Sub(g.Notes[key]) > 5*time.Minute && g.last(now, 30*time.Minute, key) {
			g.alert(now, "medium", "primary %s has not reported since the controller started watching it: check its node and container", p.ID)
		}
	} else if p != nil {
		delete(g.Notes, "noprobe-"+p.ID)
	}
	if g.Switch != nil || g.promoting() != nil || g.Force != nil {
		return
	}
	// A primary left read-only (an aborted switchover, a failed writable order) refuses every write
	// and nothing else would ever change it back.
	if p != nil && p.fresh(now) && !p.Probe.Recovery && (p.Probe.ReadOnly || pgFenceLeftOver(g, p, now)) && p.Cmd == nil {
		p.issue(opWritable, pgSyncSpec(c, g), g.Epoch, now)
		if g.last(now, 10*time.Minute, "readonly") {
			g.alert(now, "medium", "primary %s is read-only and no switchover is running: making it writable", p.ID)
		}
	}
	pgTrackProgress(st, g, now)
	pgAutoRebuild(c, g, now)
	pgDiskAlerts(g, now)
	pgLoadAlerts(c, g, now)
}

// pgLoadAlerts warns of connections running out and of transaction ID wraparound coming (Postgres stops
// accepting writes when the oldest unfrozen XID is about 2^31 old: vacuum must freeze before that).
func pgLoadAlerts(c *PGCluster, g *PGGroup, now time.Time) {
	for i := range g.Members {
		m := &g.Members[i]
		if !m.fresh(now) {
			continue
		}
		if p := m.Probe; p.MaxConns > 0 && p.Conns*10 >= p.MaxConns*9 && g.last(now, 30*time.Minute, "conns-"+m.ID) {
			hint := "turn the pooler on (ziroctl pg pool " + c.Name + " --enable)"
			if c.poolerOn() {
				hint = "raise max_connections or lower the pool size"
			}
			g.alert(now, "medium", "%s has %d of %d connections in use: %s", m.ID, p.Conns, p.MaxConns, hint)
		}
		if m.Probe.XIDAge > 1_500_000_000 && g.last(now, time.Hour, "xid-"+m.ID) {
			g.alert(now, "high", "%s: the oldest unfrozen transaction is %d transactions old; Postgres stops writes near 2.1 billion: check long transactions and vacuum", m.ID, m.Probe.XIDAge)
		}
	}
}

// pgDiskAlerts warns before a data volume fills up: a primary with a full disk stops (PANIC on WAL
// write), and a replica that falls behind makes the primary keep WAL for it.
func pgDiskAlerts(g *PGGroup, now time.Time) {
	for i := range g.Members {
		m := &g.Members[i]
		if !m.fresh(now) {
			continue
		}
		switch pct := m.Probe.DiskPct; {
		case pct >= 90 && g.last(now, 30*time.Minute, "disk90-"+m.ID):
			g.alert(now, "high", "the data volume of %s (%s) is %d%% full: add space or remove data before Postgres stops", m.ID, m.Role, pct)
		case pct >= 80 && pct < 90 && g.last(now, 6*time.Hour, "disk80-"+m.ID):
			g.alert(now, "medium", "the data volume of %s (%s) is %d%% full", m.ID, m.Role, pct)
		}
	}
}

// pgFenceLeftOver: the primary has waited on the fence standby for longer than its lease watchdog
// would keep it there while the master grants it a lease (an aborted switchover, or a fence the
// watchdog could not lift).
func pgFenceLeftOver(g *PGGroup, p *PGMember, now time.Time) bool {
	key := "fenced-" + p.ID
	if g.Notes == nil {
		g.Notes = map[string]time.Time{}
	}
	if p.Probe.SyncNames != pgFenceName || !pgLeaseGrant(p, now) {
		delete(g.Notes, key)
		return false
	}
	since, ok := g.Notes[key]
	if !ok {
		g.Notes[key] = now
		return false
	}
	return now.Sub(since) > pgLeaseTTL+10*time.Second
}

// pgTrackProgress keeps UnreadySince honest. It runs while a replica does not follow the primary and
// starts over whenever its WAL position moves (a long catch-up is progress) or the node says a base
// backup is running in it. A replica that is silent while its node is up (its container crash-loops or
// never started) is counted too: that is a container problem a rebuild can cure, and nothing else
// would ever look at it. A silent replica on a node that is down is the node's problem (pgAdjustMembers).
func pgTrackProgress(st *ClusterState, g *PGGroup, now time.Time) {
	for i := range g.Members {
		m := &g.Members[i]
		silent := !m.fresh(now)
		switch {
		case m.Role != pgReplica || m.Draining || m.ready(now) || m.Busy:
			m.UnreadySince = time.Time{}
		case silent && !pgNodeReady(st, m.Node):
			m.UnreadySince = time.Time{}
		case m.UnreadySince.IsZero() || m.Probe.LSN > m.UnreadyLSN:
			m.UnreadySince, m.UnreadyLSN = now, m.Probe.LSN
		}
	}
}

// pgNodeReady: the node is known and Ready.
func pgNodeReady(st *ClusterState, id string) bool {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n.Status == "Ready"
		}
	}
	return false
}

// pgAutoRebuild rebuilds a replica that has made no progress for pgRebuildAfter (twice that for one that
// has never reported: its first image pull and base backup take time), one at a time and only while the
// primary answers (it is the copy source). A member that still does not work between pgRebuildCooldown and
// pgReplaceWindow after its rebuild is replaced by a new one: the cause is then not its data, and the same
// rebuild again would fail the same way. The replacement waits, and says what for, when it is not safe or not
// its turn (see pgReplaceBlock); it is never turned into one more identical rebuild. Later than the window it
// is a new problem and is rebuilt again.
func pgAutoRebuild(c *PGCluster, g *PGGroup, now time.Time) {
	p := g.primary()
	if p == nil || !p.fresh(now) {
		return
	}
	for i := range g.Members {
		if m := &g.Members[i]; m.Cmd != nil && m.Cmd.Op == opReinit {
			return // one at a time
		}
	}
	var worst *PGMember
	for i := range g.Members {
		m := &g.Members[i]
		wait := pgRebuildAfter
		if m.Probe.At.IsZero() {
			wait *= 2
		}
		if m.Starting {
			wait = max(wait, pgStartingGrace) // Postgres is up and replaying WAL to a consistent state: a rebuild would throw that work away
		}
		if !m.RolledAt.IsZero() && now.Sub(m.RolledAt) < pgRollGrace {
			continue // it restarted for a new spec a moment ago: crash recovery after a stop is not "no progress"
		}
		if m.Role == pgReplica && !m.Draining && m.Cmd == nil && !m.UnreadySince.IsZero() && now.Sub(m.UnreadySince) >= wait &&
			(worst == nil || m.UnreadySince.Before(worst.UnreadySince)) {
			worst = m
		}
	}
	if worst == nil {
		return
	}
	if !worst.RebuiltAt.IsZero() && now.Sub(worst.RebuiltAt) < pgRebuildCooldown {
		if g.last(now, 30*time.Minute, "rebuilt-"+worst.ID) {
			g.alert(now, "high", "%s was rebuilt less than an hour ago and still does not follow the primary: after the hour it is replaced by a new member (when another replica is healthy and the group has not just replaced one); until then it is left alone (ziroctl pg status %s)", worst.ID, c.Name)
		}
		return
	}
	if !worst.RebuiltAt.IsZero() && now.Sub(worst.RebuiltAt) < pgReplaceWindow {
		why := pgReplaceBlock(g, worst, now)
		if why == "" && !g.last(now, pgReplaceEvery, "autoreplace") {
			why = fmt.Sprintf("the group replaced a member at %s and replaces one at a time (next from %s)", g.Notes["autoreplace"].Format("15:04"), g.Notes["autoreplace"].Add(pgReplaceEvery).Format("15:04"))
		}
		if why != "" {
			if g.last(now, 30*time.Minute, "replace-wait-"+worst.ID) {
				g.alert(now, "high", "%s still does not work after a rebuild and is not replaced yet: %s (ziroctl pg status %s)", worst.ID, why, c.Name)
			}
			return
		}
		worst.Draining = true
		g.alert(now, "high", "%s still does not work after a rebuild: replacing it with a new member", worst.ID)
		return
	}
	worst.From = "" // the copy comes from the primary: whatever member it was taken from before may be the problem
	worst.issue(opReinit, "", g.Epoch, now)
	worst.RebuiltAt, worst.UnreadySince = now, time.Time{}
	g.alert(now, "medium", "%s has not followed the primary for %s: rebuilding it from the primary", worst.ID, pgRebuildAfter)
}

// pgReplaceBlock says why a member that a rebuild did not mend is not replaced now ("" = it may be). When
// every other replica is broken too, the fault is the primary's, the network's or the cluster's and not this
// member's, and replacing members one after another would not help.
func pgReplaceBlock(g *PGGroup, m *PGMember, now time.Time) string {
	others, ready := 0, 0
	for i := range g.Members {
		if o := &g.Members[i]; o.ID != m.ID && o.Role == pgReplica && !o.Draining {
			others++
			if o.ready(now) {
				ready++
			}
		}
	}
	if others > 0 && ready == 0 {
		return "no other replica is healthy, so the fault may be the primary's or the network's and not this member's"
	}
	return ""
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
				g.Members[j].Detail, g.Members[j].Busy, g.Members[j].Starting = "", false, false
				// The progress timer moves with every probe of a replica that is catching up: soft too.
				g.Members[j].UnreadySince, g.Members[j].UnreadyLSN = time.Time{}, 0
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
	if len(st.PG) > 0 {
		st.PGHold = now.Add(pgHoldAfterElection) // and nothing is failed over until the members have had time to report
	}
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
	case opFollow:
		if cmd.OK {
			m.Following = cmd.Arg
		}
	case opReload:
		if cmd.OK {
			m.Params = cmd.Arg
		}
	case opStanza, opBackup:
		pgBackupSettle(g, cmd, now)
	case opRole, opRoleOff, opDatabase:
		pgRolesSettle(c, g, cmd, now)
	case opPassword:
		if cmd.OK && c.Rotation != nil {
			if g.Notes == nil {
				g.Notes = map[string]time.Time{}
			}
			g.Notes["rotated-"+c.Rotation.Key] = now
		}
	case opPromote:
		if m.Role == pgPromoting {
			return // pgFinishPromotion reads the result
		}
	case opReinit:
		if cmd.OK {
			// It restarts with an empty data directory and rebuilds from the primary: not a standby
			// (nor a promotion candidate) until it has caught up again.
			m.Joined = false
			g.note(now, "%s is rebuilding from the primary", m.ID)
		}
	case opDemote, opReadonly, opWritable, opDropSlot:
		if g.Switch != nil && cmd.Op == opReadonly {
			return // pgSwitchover reads the result
		}
	default:
		pgCitusSettle(c, g, m, cmd, now)
	}
	if !cmd.OK {
		m.LastFail, m.LastFailAt = cmd.Op+": "+cmd.Msg, now
		// A command that keeps failing is re-issued every pass: one alert per quarter hour, not one per try.
		if g.last(now, 15*time.Minute, "cmdfail-"+cmd.Op+"-"+m.ID) {
			g.alert(now, "medium", "%s on %s failed: %s", cmd.Op, m.ID, cmd.Msg)
		} else {
			g.note(now, "%s on %s failed again: %s", cmd.Op, m.ID, cmd.Msg)
		}
	} else if strings.HasPrefix(m.LastFail, cmd.Op+": ") {
		m.LastFail, m.LastFailAt = "", time.Time{} // the same order worked since
	}
	m.Cmd = nil
}

// ---- failover ----

// pgCandidate picks the replica to promote: reachable, in recovery, joined, the furthest ahead.
// reachable and total count the replicas that could hold acknowledged commits.
func pgCandidate(g *PGGroup, now time.Time) (best *PGMember, reachable, total int) {
	tl := 0 // the timeline the group was last known to be on: a replica behind it never followed
	if p := g.primary(); p != nil {
		tl = p.Probe.Timeline
	}
	for i := range g.Members {
		m := &g.Members[i]
		if m.Role != pgReplica || !m.Joined || m.Draining {
			continue
		}
		total++
		if !m.fresh(now) || !m.Probe.Recovery {
			continue
		}
		if tl > 0 && m.Probe.Timeline > 0 && m.Probe.Timeline < tl {
			continue // its WAL position is on an older timeline: not comparable, and it lacks the newer writes
		}
		reachable++
		if best == nil || m.pos() > best.pos() || m.pos() == best.pos() && m.ID < best.ID {
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
	if why := pgPromotionBlock(c, g, best, reachable, total); why != "" {
		if g.last(now, 60*time.Second, "waiting") {
			g.alert(now, "high", "primary is down, but %s; `ziroctl pg failover %s --force` promotes anyway and accepts the loss", why, c.Name)
		}
		return
	}
	pgPromote(c, g, best, now, "primary is down")
}

// pgPromotionBlock says why promoting best could lose acknowledged writes ("" = it cannot). With
// synchronous replication a commit is on k replicas, so enough reachable ones make it safe; without it
// the writes the replica has not received are lost, so a replica further behind the primary's last
// known position than pgMaxLagBytes is not promoted automatically.
func pgPromotionBlock(c *PGCluster, g *PGGroup, best *PGMember, reachable, total int) string {
	k := 0
	if c.Sync == pgSyncQuorum {
		k = pgQuorum(total)
	}
	if !pgSafeToPromote(reachable, total, k) {
		return fmt.Sprintf("only %d of %d replicas answer; promoting could lose acknowledged writes", reachable, total)
	}
	if k == 0 {
		if p := g.primary(); p != nil && p.Probe.LSN > best.pos() && p.Probe.LSN-best.pos() > pgMaxLagBytes {
			return fmt.Sprintf("%s is %d MiB behind the primary's last known position; promoting it would lose those writes",
				best.ID, (p.Probe.LSN-best.pos())>>20)
		}
	}
	return ""
}

// pgForcedFailover carries out an operator's failover request: promote the named replica (or the one
// furthest ahead) now, without the grace period or the partition brake. Unless the request is forced it
// keeps the safety checks of an automatic failover. It waits for a replica that can be promoted, up to
// two minutes.
func pgForcedFailover(c *PGCluster, g *PGGroup, now time.Time) {
	f := g.Force
	if now.Sub(f.At) > 2*time.Minute {
		g.Force = nil
		g.alert(now, "medium", "the failover request expired: no replica could be promoted")
		return
	}
	var target *PGMember
	switch {
	case f.To != "":
		t := g.member(f.To)
		if t != nil && t.Role == pgReplica && !t.Draining && t.fresh(now) && t.Probe.Recovery {
			target = t
		}
		if target != nil && !f.Unsafe {
			_, reachable, total := pgCandidate(g, now)
			if why := pgPromotionBlock(c, g, target, reachable, total); why != "" {
				g.Force = nil
				g.alert(now, "high", "failover to %s refused: %s; add --force to accept the loss", target.ID, why)
				return
			}
		}
	case f.Unsafe:
		for i := range g.Members {
			m := &g.Members[i]
			if m.Role == pgReplica && !m.Draining && m.fresh(now) && m.Probe.Recovery && (target == nil || m.pos() > target.pos()) {
				target = m
			}
		}
	default:
		best, reachable, total := pgCandidate(g, now)
		if best != nil {
			if why := pgPromotionBlock(c, g, best, reachable, total); why != "" {
				g.Force = nil
				g.alert(now, "high", "failover refused: %s; add --force to accept the loss", why)
				return
			}
			target = best
		}
	}
	if target == nil {
		return // wait for a replica to answer
	}
	g.Force = nil
	why := "operator failover"
	if f.Unsafe {
		why += ", forced: acknowledged writes may be lost"
	}
	pgPromote(c, g, target, now, why)
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
	// The new primary may carry the synchronous list of the one before it (it was a primary once, or was
	// copied from one), so the list is unknown, not empty: pgSyncAndSlots always sends it, even as "".
	g.Sync = pgSyncUnknown
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
	// The primary is fenced for as long as the switchover lasts: do not start one that cannot finish.
	if why := pgTakeoverBlock(p, t, now); why != "" {
		return fmt.Errorf("%s %s, so it cannot take over now (ziroctl pg status %s)", to, why, c.Name)
	}
	g.Switch = &PGSwitch{To: to, At: now, Step: "readonly"}
	g.note(now, "switchover from %s to %s", p.ID, to)
	return nil
}

// pgTakeoverBlock says why a replica cannot take over from the primary now ("" = it can): it follows the
// primary's timeline, streams from it and is not far behind.
func pgTakeoverBlock(p, t *PGMember, now time.Time) string {
	switch {
	case !t.fresh(now) || !t.Probe.Recovery:
		return "is not answering"
	case t.OffTimeline:
		return "is on an older timeline than the primary"
	case !t.Probe.Streaming:
		return "is not streaming from the primary"
	case t.Probe.LagMs > pgReadyLagMillis:
		return fmt.Sprintf("is %dms behind the primary", t.Probe.LagMs)
	case p.Probe.LSN > t.pos() && p.Probe.LSN-t.pos() > pgMaxLagBytes:
		return fmt.Sprintf("is %s behind the primary", humanBytes(p.Probe.LSN-t.pos()))
	}
	return ""
}

// pgSwitchAbortedKey records when a switchover was last given up: a rolling restart does not start the
// next one at once, which would fence the primary again for as long.
const pgSwitchAbortedKey = "switch-aborted"

func pgAbortSwitch(c *PGCluster, g *PGGroup, p *PGMember, now time.Time, why string) {
	if g.Notes == nil {
		g.Notes = map[string]time.Time{}
	}
	g.Notes[pgSwitchAbortedKey] = now
	g.alert(now, "medium", "switchover aborted: %s", why)
	g.Switch = nil
	// A primary whose order slot is busy is made writable by pgSelfHeal as soon as it is free.
	if p != nil && p.Cmd == nil {
		p.issue(opWritable, pgSyncSpec(c, g), g.Epoch, now)
	}
}

// pgReportedLSN reads the WAL position a readonly order reports ("lsn=0/B000168").
func pgReportedLSN(msg string) uint64 {
	v, ok := strings.CutPrefix(strings.TrimSpace(msg), "lsn=")
	if !ok {
		return 0
	}
	n, err := parseLSN(v)
	if err != nil {
		return 0
	}
	return n
}

func pgSwitchover(c *PGCluster, g *PGGroup, now time.Time) {
	sw := g.Switch
	p, t := g.primary(), g.member(sw.To)
	if p == nil || t == nil || t.Role != pgReplica {
		pgAbortSwitch(c, g, p, now, "the primary or the target changed")
		return
	}
	if elapsed := now.Sub(sw.At); elapsed > pgSwitchTimeout {
		pgAbortSwitch(c, g, p, now, fmt.Sprintf("timed out after %s in step %s: %s", elapsed.Round(time.Second), sw.Step, sw.Wait))
		return
	}
	switch sw.Step {
	case "readonly":
		if p.Cmd == nil {
			p.issue(opReadonly, "", g.Epoch, now)
			sw.Wait = fmt.Sprintf("making %s read-only", p.ID)
			return
		}
		if p.Cmd.Op != opReadonly || !p.Cmd.Done {
			if p.Cmd.Op != opReadonly {
				sw.Wait = fmt.Sprintf("%s is still busy with %s", p.ID, p.Cmd.Op)
			} else {
				sw.Wait = fmt.Sprintf("making %s read-only: the order has been out for %s", p.ID, now.Sub(p.Cmd.At).Round(time.Second))
			}
			return
		}
		ok, msg := p.Cmd.OK, p.Cmd.Msg
		p.Cmd = nil
		if !ok {
			pgAbortSwitch(c, g, p, now, "could not make the primary read-only: "+msg)
			return
		}
		sw.Step, sw.ReadOnlyAt, sw.LSN = "catchup", now, pgReportedLSN(msg)
		sw.Best, sw.BestAt = t.pos(), now
	case "catchup":
		// The primary is fenced: no commit is acknowledged from here on, so its WAL position cannot move
		// in a way that matters. The target must hold everything up to it. Any probe of the target will
		// do (positions only grow), so the two members' probes need not be taken at the same time. The
		// readonly order reports the position (read a second after the fence); a probe of the primary taken
		// after the fence is a later reading and raises it when there is one, but is not waited for.
		need, have := sw.LSN, sw.LSN != 0
		if p.Probe.OK && p.Probe.At.After(sw.ReadOnlyAt) {
			need, have = max(need, p.Probe.LSN), true
		}
		if !have {
			sw.Wait = fmt.Sprintf("waiting for a probe of %s taken after it became read-only (its last is %s old)", p.ID, now.Sub(p.Probe.At).Round(time.Second))
			return
		}
		if !t.fresh(now) || !t.Probe.Recovery {
			sw.Wait = fmt.Sprintf("%s is not answering (its last probe is %s old)", t.ID, now.Sub(t.Probe.At).Round(time.Second))
		} else if t.pos() >= need {
			pgPromote(c, g, t, now, "planned switchover")
			g.Switch = nil
			return
		} else {
			sw.Wait = fmt.Sprintf("waiting for %s to receive up to %s: it is at %s (%s behind), streaming=%t", t.ID, formatLSN(need), formatLSN(t.pos()), humanBytes(need-t.pos()), t.Probe.Streaming)
		}
		// A target that makes no progress will not get there: give up now instead of keeping commits blocked
		// until the time is out.
		if t.fresh(now) && t.pos() > sw.Best {
			sw.Best, sw.BestAt = t.pos(), now
		}
		if stalled := now.Sub(sw.BestAt); stalled > pgSwitchStall {
			pgAbortSwitch(c, g, p, now, fmt.Sprintf("%s made no progress for %s in step catchup: %s", t.ID, stalled.Round(time.Second), sw.Wait))
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
		if m.Role != pgPrimary && !m.Draining && pgNodeGone(st, m.Node, now) {
			if pgPickNode(st, c, g) == "" {
				if g.last(now, 30*time.Minute, "nonode-replace") {
					g.alert(now, "medium", "node %s of %s is gone and no other node is free to rebuild it on (the members of a group are spread over nodes): add a node", m.Node, m.ID)
				}
				continue
			}
			m.Draining = true
			g.note(now, "replacing %s: node %s is gone", m.ID, m.Node)
			return
		}
	}
	switch {
	case len(replicas) < c.Replicas:
		// With no free node the drained members below must still be removed: one of them may be what
		// holds the node the new replica needs.
		if node := pgPickNode(st, c, g); node != "" {
			g.Next++
			id := "m" + strconv.Itoa(g.Next)
			g.Members = append(g.Members, PGMember{ID: id, Node: node, Role: pgReplica, Init: pgReplica})
			g.note(now, "adding replica %s on %s", id, node)
		} else if !pgDraining(g) && g.last(now, 5*time.Minute, "nonode") {
			g.alert(now, "medium", "no node is free for another replica (members of a group are spread over nodes)")
		}
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
			// The synchronous list still names it: wait for the primary to drop it, but not forever (a
			// setsync that keeps failing must not keep a removed member in the group).
			key := "drain-" + m.ID
			if g.Notes == nil {
				g.Notes = map[string]time.Time{}
			}
			if _, ok := g.Notes[key]; !ok {
				g.Notes[key] = now
			}
			if now.Sub(g.Notes[key]) < pgRebuildAfter {
				continue
			}
			g.alert(now, "medium", "removing %s although the synchronous standby list could not be updated for %s", m.ID, pgRebuildAfter)
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
		delete(g.Notes, "drain-"+m.ID)
		g.note(now, "replica %s removed", m.ID)
		markPurge(st, c.memberApp(g.Name, m.ID))
		g.Members = slices.Delete(g.Members, i, i+1)
		return
	}
}

// pgDraining: a member of the group is being removed.
func pgDraining(g *PGGroup) bool {
	for i := range g.Members {
		if g.Members[i].Draining {
			return true
		}
	}
	return false
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
	// The primary says what it has: a list it lost (a restart from an older postgresql.auto.conf) is sent again.
	if got := p.Probe.SyncNames; p.fresh(now) && got != "" && got != pgFenceName && got != g.Sync {
		g.Sync = pgSyncUnknown
	}
	if want := pgSyncSpec(c, g); g.Sync != want {
		p.issue(opSetSync, want, g.Epoch, now)
	}
}

// ---- apps ----

// pgEnsureApps makes the cluster apps match the members: one pinned app per member, and no others. A
// member whose app would change takes the new spec when pgMayRoll says it is its turn.
func pgEnsureApps(st *ClusterState, c *PGCluster, now time.Time) {
	want := map[string]bool{}
	for gi := range c.Groups {
		g := &c.Groups[gi]
		apps := make([]*ClusteredApp, len(g.Members))
		pending := map[string]bool{} // members whose running app is not the one they should run
		urgent := map[string]bool{}  // ... for a password change: it does not wait for the maintenance window
		for mi := range g.Members {
			m := &g.Members[mi]
			if m.Node == "" {
				m.Node = pgPickNode(st, c, g)
				if m.Node == "" {
					continue
				}
			}
			app := withPodNetwork(st, pgMemberApp(st, c, g, m))
			apps[mi] = &app
			want[app.Name] = true
			if cur := st.app(app.Name); cur != nil && specHash(*cur) != specHash(app) {
				pending[m.ID] = true
				urgent[m.ID] = cur.Env["ZIRO_PG_SECRET_EPOCH"] != app.Env["ZIRO_PG_SECRET_EPOCH"]
			}
		}
		for mi := range g.Members {
			m, app := &g.Members[mi], apps[mi]
			if app == nil {
				continue
			}
			if pending[m.ID] && !pgMayRoll(c, g, m, pending, urgent[m.ID], now.Before(st.PGHold), now) {
				continue
			}
			if upsertApp(st, *app) && pending[m.ID] {
				m.RolledAt = now
				delete(pending, m.ID)
			}
		}
		pgNoteWaiting(c, g, pending, urgent, now)
	}
	pgEnsurePooler(st, c, want, now)
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

// pgNoteWaiting records the members whose new spec waits for the maintenance window, and says so once
// when they start waiting.
func pgNoteWaiting(c *PGCluster, g *PGGroup, pending, urgent map[string]bool, now time.Time) {
	var waiting []string
	if !pgWindowOpen(c, now) {
		for _, m := range g.Members {
			if pending[m.ID] && !urgent[m.ID] {
				waiting = append(waiting, m.ID)
			}
		}
	}
	if len(waiting) > 0 && len(g.Waiting) == 0 {
		g.note(now, "%d member(s) have a new configuration and restart in the maintenance window (%s)", len(waiting), pgWindowLabel(c, now))
	}
	g.Waiting = waiting
}

// pgRollTimeout is how long a member that took a new spec may take to come back before the next one goes.
const pgRollTimeout = 10 * time.Minute

// pgRestarted: a member that took a new spec has been restarted since. A probe taken after the spec was set
// can still come from the old container, which keeps answering until the node stops it (a heartbeat later,
// then up to its stop timeout), so a server that reports when it started is believed only if that was after
// the spec was set. One that does not report it (an agent not upgraded yet) is judged by the probe's time.
func pgRestarted(m *PGMember, now time.Time) bool {
	if m.RolledAt.IsZero() || now.Sub(m.RolledAt) > pgRollTimeout {
		return true
	}
	if !m.Probe.At.After(m.RolledAt) {
		return false
	}
	return m.Probe.Started.IsZero() || m.Probe.Started.After(m.RolledAt)
}

// pgBack: a member that took a new spec has restarted and answers as what it should be: a primary that
// serves, a replica that streams and is within pgMaxLagBytes of the primary. "Streaming" alone is not caught
// up, and the next replica must not go while this one still has a lot of WAL to replay.
func pgBack(m, p *PGMember, now time.Time) bool {
	if m.RolledAt.IsZero() || now.Sub(m.RolledAt) > pgRollTimeout {
		return true
	}
	if !pgRestarted(m, now) {
		return false
	}
	if m.Role == pgPrimary {
		return m.fresh(now) && !m.Probe.Recovery
	}
	if !m.ready(now) {
		return false
	}
	return p == nil || p == m || !p.fresh(now) || p.Probe.LSN <= m.pos() || p.Probe.LSN-m.pos() <= pgMaxLagBytes
}

// pgMayRoll decides whether a member may take a new spec now (a ziroctl upgrade changed the entry script,
// new tuning, a new image): replicas one at a time, each back and caught up before the next, and the
// primary last, after a switchover to a replica that already runs the new spec. A member that is not
// serving anyway (down, rebuilding) is not waited for. Without a replica to hand over to, the primary
// restarts in place. pending lists the members whose app is out of date.
func pgMayRoll(c *PGCluster, g *PGGroup, m *PGMember, pending map[string]bool, urgent, held bool, now time.Time) bool {
	if c.Paused || g.Switch != nil || g.promoting() != nil {
		return false // paused: the operator decides when members restart (pg resume)
	}
	if held {
		// A new cluster leader has no probes yet: every member looks down, and a "member that is not serving
		// anyway" restarts at once, the primary in place and outside the maintenance window. It waits until the
		// members have reported, as a failover does.
		return false
	}
	if !urgent && !pgWindowOpen(c, now) && m.fresh(now) {
		return false // a serving member restarts in the maintenance window (one that is down takes it now)
	}
	prim := g.primary()
	for i := range g.Members {
		o := &g.Members[i]
		if o.ID != m.ID && !pgBack(o, prim, now) {
			return false // another member is still coming back
		}
	}
	serving := m.fresh(now) && (m.Role == pgPrimary && !m.Probe.Recovery || m.ready(now))
	if !serving || m.Role != pgPrimary {
		return true
	}
	// The primary: every serving replica first, then hand over to one on the new spec.
	var target *PGMember
	for i := range g.Members {
		o := &g.Members[i]
		if o.Role != pgReplica || o.Draining || !o.ready(now) {
			continue
		}
		if pending[o.ID] {
			return false // it goes first
		}
		if target == nil || o.pos() > target.pos() {
			target = o
		}
	}
	if target == nil {
		return true // nothing to hand over to: a restart in place
	}
	if at, ok := g.Notes[pgSwitchAbortedKey]; ok && now.Sub(at) < pgSwitchRetryAfter {
		return false // a switchover was just given up: not again at once (the primary was fenced for all that time)
	}
	if err := pgStartSwitchover(c, g, target.ID, now); err == nil {
		g.note(now, "%s takes a new configuration: switching over to %s first", m.ID, target.ID)
	}
	return false
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

package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Postgres clusters (RFC 0005). A PGCluster is declared with `ziroctl pg create` and kept in
// ClusterState.PG, replicated by Raft like the rest of the cluster state. The controller (pg_controller.go)
// turns each member into a one-replica ClusteredApp pinned to its node, and keeps the roles: it
// reads the probes the agents report (pg_agent.go), promotes and fences, and decides which member
// the read-write name points at.

// Member roles.
const (
	pgPrimary   = "primary"
	pgReplica   = "replica"
	pgPromoting = "promoting" // told to promote, not yet confirmed
	pgFenced    = "fenced"    // a former primary: must rejoin as a replica before it serves again
)

// Sync policies.
const (
	pgSyncQuorum = "quorum" // synchronous_standby_names = 'ANY 1 (*)'
	pgSyncOff    = "off"    // asynchronous
)

var (
	pgNameRe   = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`) // cluster name: no dashes, the app names join parts with them
	pgSlotRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	pgMemberRe = regexp.MustCompile(`^m[0-9]{1,3}$`)
	pgGroupRe  = regexp.MustCompile(`^(main|coord|w[0-9]{1,2})$`)
	pgVersions = map[string]bool{"16": true, "17": true, "18": true}
)

const (
	pgMaxReplicas = 15 // per group
	pgMaxShards   = 32 // worker groups
	// A healthy member's last probe is at most about 15 s old when the master looks (probes every 5 s,
	// heartbeats every 10 s), so a member that has been silent for pgGrace is gone. The same limit
	// decides whether a replica counts as reachable, which keeps the two judgements consistent: a
	// replica is never reachable while the primary it would replace is already declared dead for
	// the same silence.
	pgGrace            = 30 * time.Second
	pgReadyAge         = 20 * time.Second // a probe older than this does not make a replica serve reads
	pgMaxLagBytes      = 16 << 20         // a replica further behind is not promoted without --force, and is not served reads
	pgReadyLagMillis   = 5000             // a replica serves reads when it replays within this many ms
	pgCommandTimeout   = 60 * time.Second
	pgNodeGoneAfter    = 10 * time.Minute // a node unseen this long no longer holds a member: it is replaced
	pgStopTimeout      = 120              // seconds Postgres gets to shut down cleanly
	pgDataPath         = "/var/lib/postgresql/data"
	pgDataUID          = 999 // the postgres user of the official image
	pgSecretPrefix     = "pg-"
	pgAppPrefix        = "pgc-"
	pgConfigMountPoint = "/etc/ziro-config"
)

// PGCluster is one declared cluster.
type PGCluster struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Image     string     `json:"image"`                // the member image (digest-pinned)
	Sync      string     `json:"sync"`                 // pgSyncQuorum or pgSyncOff
	Replicas  int        `json:"replicas"`             // replicas per group (members are replicas + 1)
	Resources *Resources `json:"resources,omitempty"`  // per member
	Database  string     `json:"database"`             // created on the first primary
	User      string     `json:"user"`                 // its owner
	AllowFrom []string   `json:"allow_from,omitempty"` // apps allowed to connect
	Citus     string     `json:"citus,omitempty"`      // Citus member image; set for a sharded cluster
	Groups    []PGGroup  `json:"groups"`
	CreatedAt string     `json:"created_at"`
	Paused    bool       `json:"paused,omitempty"`   // the controller leaves roles alone (maintenance)
	Colocate  bool       `json:"colocate,omitempty"` // allow members of a group on the same node (development)
	// Citus registration progress (pg_citus.go).
	CitusReady       bool `json:"citus_ready,omitempty"`       // the coordinator is registered under its DNS name
	MetaSynced       bool `json:"meta_synced,omitempty"`       // the metadata reached every node
	RebalancePending bool `json:"rebalance_pending,omitempty"` // a worker joined: shards should move
}

// PGGroup is one primary and its replicas: a plain cluster has one group ("main"); a sharded one has a
// coordinator ("coord") and one group per shard ("w1", "w2", ...).
type PGGroup struct {
	Name       string               `json:"name"`
	Epoch      int64                `json:"epoch"`           // bumped on every promotion; commands carry it
	Next       int                  `json:"next"`            // numbering of the next member
	Members    []PGMember           `json:"members"`         // the primary first
	Sync       string               `json:"sync,omitempty"`  // synchronous_standby_names last applied on the primary
	Slots      int64                `json:"slots,omitempty"` // the epoch for which the primary's replication slots were created
	Notes      map[string]time.Time `json:"notes,omitempty"` // when a repeated event was last recorded
	Switch     *PGSwitch            `json:"switch,omitempty"`
	Force      *PGForce             `json:"force,omitempty"`      // an operator's request to promote now (pg failover)
	Registered bool                 `json:"registered,omitempty"` // Citus: the coordinator knows this worker group
	Events     []PGEvent            `json:"events,omitempty"`     // the last few role changes, newest last
}

// PGForce is an operator's request to promote now. It is read once by the controller and expires if
// no replica can be promoted in time.
type PGForce struct {
	To     string    `json:"to,omitempty"`     // the replica to promote ("" = the one furthest ahead)
	Unsafe bool      `json:"unsafe,omitempty"` // --force: skip the Joined, quorum and lag checks, accepting that acknowledged writes may be lost
	At     time.Time `json:"at"`
}

// PGMember is one Postgres container.
type PGMember struct {
	ID       string     `json:"id"`
	Node     string     `json:"node"`
	Role     string     `json:"role"`
	Init     string     `json:"init"`                // pgPrimary or pgReplica: how an empty data directory is initialised
	From     string     `json:"from,omitempty"`      // member to take the base backup from ("" = the primary)
	Joined   bool       `json:"joined,omitempty"`    // has been a ready replica: counted in the synchronous standbys
	Draining bool       `json:"draining,omitempty"`  // being removed: out of the read-only name
	DropSlot string     `json:"drop_slot,omitempty"` // set when the member's replication slot was ordered dropped
	Probe    PGProbe    `json:"probe"`
	Cmd      *PGCommand `json:"cmd,omitempty"`
}

// PGProbe is what the member's agent last read from Postgres.
type PGProbe struct {
	At        time.Time `json:"at"`
	OK        bool      `json:"ok"`
	Recovery  bool      `json:"recovery"`            // in recovery: a replica
	Streaming bool      `json:"streaming,omitempty"` // a replica's WAL receiver is connected
	LSN       uint64    `json:"lsn"`                 // WAL position: received or replayed on a replica, written on a primary
	Timeline  int       `json:"timeline"`
	LagMs     int64     `json:"lag_ms"`
	Epoch     int64     `json:"epoch"` // the epoch of the role file the container has seen
}

// PGCommand is an order for one member's agent, taken from a closed list (pg_agent.go).
type PGCommand struct {
	ID    string    `json:"id"`
	Op    string    `json:"op"`
	Arg   string    `json:"arg,omitempty"`
	Epoch int64     `json:"epoch"`
	DB    string    `json:"db,omitempty"` // the database an order runs in (Citus); empty = postgres
	At    time.Time `json:"at"`
	Done  bool      `json:"done,omitempty"`
	OK    bool      `json:"ok,omitempty"`
	Msg   string    `json:"msg,omitempty"`
}

// PGSwitch is a planned switchover in progress.
type PGSwitch struct {
	To         string    `json:"to"`
	At         time.Time `json:"at"`
	Step       string    `json:"step"`                  // readonly, catchup
	ReadOnlyAt time.Time `json:"readonly_at,omitempty"` // when the primary became read-only
}

// PGEvent records a role change for `pg status`.
type PGEvent struct {
	At    time.Time `json:"at"`
	Msg   string    `json:"msg"`
	Alert string    `json:"alert,omitempty"` // severity of the alert this event raises ("" = none)
	Sent  bool      `json:"sent,omitempty"`  // the alert was raised
}

// ---- names ----

func (c *PGCluster) secretName() string { return pgSecretPrefix + c.Name }

// memberApp is the cluster app that runs the member.
func (c *PGCluster) memberApp(group, member string) string {
	return pgAppPrefix + c.Name + "-" + group + "-" + member
}

// dnsRW and dnsROName are the role-following names (without the cluster domain).
func (c *PGCluster) dnsRW(group string) string { return c.Name + "-" + group + "-rw" }
func (c *PGCluster) dnsRO(group string) string { return c.Name + "-" + group + "-ro" }

// entryGroup is the group clients use by default: the only one, or the Citus coordinator.
func (c *PGCluster) entryGroup() string {
	if c.Citus != "" {
		return "coord"
	}
	return "main"
}

func (c *PGCluster) group(name string) *PGGroup {
	for i := range c.Groups {
		if c.Groups[i].Name == name {
			return &c.Groups[i]
		}
	}
	return nil
}

func (g *PGGroup) member(id string) *PGMember {
	for i := range g.Members {
		if g.Members[i].ID == id {
			return &g.Members[i]
		}
	}
	return nil
}

func (g *PGGroup) primary() *PGMember {
	for i := range g.Members {
		if g.Members[i].Role == pgPrimary {
			return &g.Members[i]
		}
	}
	return nil
}

// slot is the replication slot the member's replica uses on whichever member is primary.
func pgSlot(member string) string { return "ziro_" + member }

func (m *PGMember) fresh(now time.Time) bool {
	return m.Probe.OK && now.Sub(m.Probe.At) <= pgGrace
}

// ready reports whether a replica may serve reads: it answers, replays close to the primary and is not
// being removed.
func (m *PGMember) ready(now time.Time) bool {
	return m.Role == pgReplica && !m.Draining && m.fresh(now) && now.Sub(m.Probe.At) <= pgReadyAge && m.Probe.Recovery && m.Probe.Streaming && m.Probe.LagMs <= pgReadyLagMillis
}

// ---- LSN ----

// parseLSN reads a Postgres WAL position such as "0/3000060".
func parseLSN(s string) (uint64, error) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("invalid LSN %q", s)
	}
	return h<<32 | l, nil
}

func formatLSN(v uint64) string { return fmt.Sprintf("%X/%X", v>>32, v&0xffffffff) }

// ---- validation ----

// Validate checks a declared cluster (CLI, API and the controller re-check before acting).
func (c *PGCluster) Validate() error {
	if !pgNameRe.MatchString(c.Name) {
		return fmt.Errorf("cluster name must be 1-16 lower-case letters and digits, starting with a letter")
	}
	if !pgVersions[c.Version] {
		return fmt.Errorf("version must be 16, 17 or 18")
	}
	if c.Image == "" || strings.ContainsAny(c.Image, " \t\r\n") || len(c.Image) > 512 {
		return fmt.Errorf("invalid image")
	}
	if c.Sync != pgSyncQuorum && c.Sync != pgSyncOff {
		return fmt.Errorf("sync must be %q or %q", pgSyncQuorum, pgSyncOff)
	}
	if c.Replicas < 0 || c.Replicas > pgMaxReplicas {
		return fmt.Errorf("replicas must be 0-%d", pgMaxReplicas)
	}
	if err := c.Resources.Validate(); err != nil {
		return err
	}
	for _, n := range []string{c.Database, c.User} {
		if !pgIdentRe.MatchString(n) {
			return fmt.Errorf("database and user names must be lower-case identifiers (%s)", pgIdentRe)
		}
	}
	if len(c.Groups) == 0 || len(c.Groups) > pgMaxShards+1 {
		return fmt.Errorf("a cluster has 1-%d groups", pgMaxShards+1)
	}
	seen := map[string]bool{}
	for _, g := range c.Groups {
		if !pgGroupRe.MatchString(g.Name) || seen[g.Name] {
			return fmt.Errorf("invalid or repeated group %q", g.Name)
		}
		seen[g.Name] = true
		if len(g.Members) == 0 || len(g.Members) > pgMaxReplicas+1 {
			return fmt.Errorf("group %s: 1-%d members", g.Name, pgMaxReplicas+1)
		}
		ids := map[string]bool{}
		for _, m := range g.Members {
			if !pgMemberRe.MatchString(m.ID) || ids[m.ID] {
				return fmt.Errorf("group %s: invalid or repeated member %q", g.Name, m.ID)
			}
			ids[m.ID] = true
			if m.Init != pgPrimary && m.Init != pgReplica {
				return fmt.Errorf("group %s member %s: invalid init", g.Name, m.ID)
			}
		}
	}
	if c.Citus != "" && c.group("coord") == nil || c.Citus == "" && (len(c.Groups) != 1 || c.Groups[0].Name != "main") {
		return fmt.Errorf("a cluster is either one main group or a Citus coordinator with worker groups")
	}
	return nil
}

var pgIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

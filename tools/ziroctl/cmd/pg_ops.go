package cmd

import (
	"fmt"
	"sort"
	"time"
)

// The edits the CLI and the API make to ClusterState.PG, each inside one withState. They only declare;
// the controller (pg_controller.go) does the work on its next pass.

// pgImages are the member images, pinned by digest (the same references the catalog's postgres app
// uses). A sharded cluster needs a Citus image, which is given explicitly until one is pinned here.
var pgImages = map[string]string{
	"16": "docker.io/library/postgres:16.15@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54",
	"17": "docker.io/library/postgres:17.11@sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f",
	"18": "docker.io/library/postgres:18.6@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
}

type pgCreateOpts struct {
	Name      string
	Version   string
	Image     string // overrides the built-in image
	Replicas  int
	Sync      string
	Shards    int // worker groups; 0 = a plain cluster
	Citus     string
	Resources *Resources
	Database  string
	User      string
	AllowFrom []string
	Colocate  bool
}

// pgCreate declares a cluster: its groups and members, spread over the cluster's nodes, and its
// secret.
func pgCreate(st *ClusterState, o pgCreateOpts, now time.Time) (*PGCluster, error) {
	if st.PodCIDR == "" {
		return nil, fmt.Errorf("postgres clusters need the pod network (ziroctl cluster network enable)")
	}
	if st.PG[o.Name] != nil {
		return nil, fmt.Errorf("postgres cluster %q exists", o.Name)
	}
	if st.app(pgAppPrefix+o.Name+"-main-m1") != nil {
		return nil, fmt.Errorf("%q is in use", o.Name)
	}
	if o.Version == "" {
		o.Version = "17"
	}
	image := o.Image
	if image == "" {
		image = pgImages[o.Version]
	}
	if o.Sync == "" {
		o.Sync = pgSyncQuorum
	}
	if o.Database == "" {
		o.Database = "app"
	}
	if o.User == "" {
		o.User = "app"
	}
	if o.Shards < 0 || o.Shards > pgMaxShards {
		return nil, fmt.Errorf("shards must be 0-%d", pgMaxShards)
	}
	if o.Shards > 0 && o.Citus == "" {
		return nil, fmt.Errorf("a sharded cluster needs a Citus image: --citus-image <image@sha256:...>")
	}
	c := &PGCluster{Name: o.Name, Version: o.Version, Image: image, Sync: o.Sync, Replicas: o.Replicas, Resources: o.Resources,
		Database: o.Database, User: o.User, AllowFrom: o.AllowFrom, Colocate: o.Colocate,
		CreatedAt: now.UTC().Format(time.RFC3339)}
	groups := []string{"main"}
	if o.Shards > 0 {
		c.Citus = o.Citus
		groups = []string{"coord"}
		for i := 1; i <= o.Shards; i++ {
			groups = append(groups, fmt.Sprintf("w%d", i))
		}
	}
	for _, name := range groups {
		g := PGGroup{Name: name}
		for i := 0; i <= o.Replicas; i++ {
			node := pgPickNode(st, c, &g)
			if node == "" {
				return nil, fmt.Errorf("group %s needs %d nodes, one per member, so a node failure cannot take the data; the cluster has fewer ready nodes (--colocate allows sharing a node, for development)", name, o.Replicas+1)
			}
			g.Next++
			m := PGMember{ID: fmt.Sprintf("m%d", g.Next), Node: node, Role: pgReplica, Init: pgReplica}
			if i == 0 {
				m.Role, m.Init = pgPrimary, pgPrimary
			}
			g.Members = append(g.Members, m)
		}
		c.Groups = append(c.Groups, g)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	secrets := map[string]string{}
	for _, k := range []string{"POSTGRES_PASSWORD", "PG_REPL_PASSWORD", "PG_SUPERUSER_PASSWORD"} {
		v, err := genSecret("alnum:32")
		if err != nil {
			return nil, err
		}
		secrets[k] = v
	}
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]string{}
	}
	st.Secrets[c.secretName()] = secrets
	if st.PG == nil {
		st.PG = map[string]*PGCluster{}
	}
	st.PG[c.Name] = c
	return c, nil
}

// pgCluster finds a cluster or says so.
func pgCluster(st *ClusterState, name string) (*PGCluster, error) {
	if c := st.PG[name]; c != nil {
		return c, nil
	}
	return nil, errNotFound(fmt.Sprintf("Postgres cluster %q not found", name))
}

// pgDelete removes a cluster; the controller deletes its apps. With purge the data on every node goes
// too, and the credentials with it.
func pgDelete(st *ClusterState, name string, purge bool) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if purge {
		var apps []string
		for _, g := range c.Groups {
			for _, m := range g.Members {
				apps = append(apps, c.memberApp(g.Name, m.ID))
			}
		}
		markPurge(st, apps...)
		delete(st.Secrets, c.secretName())
	}
	delete(st.PG, name)
	return nil
}

// pgSetReplicas changes how many replicas every group has; the controller adds or drains members
// without touching the primary.
func pgSetReplicas(st *ClusterState, name string, n int) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if n < 0 || n > pgMaxReplicas {
		return fmt.Errorf("replicas must be 0-%d", pgMaxReplicas)
	}
	c.Replicas = n
	return nil
}

// pgAddReplica adds one replica to every group's count, on a chosen node and copying from a chosen
// member when given (group "" = the cluster's default group).
func pgAddReplica(st *ClusterState, name, groupName, node, from string) (string, error) {
	c, err := pgCluster(st, name)
	if err != nil {
		return "", err
	}
	if groupName == "" {
		groupName = c.entryGroup()
	}
	g := c.group(groupName)
	if g == nil {
		return "", errNotFound(fmt.Sprintf("group %q not found", groupName))
	}
	if len(g.Members) > pgMaxReplicas {
		return "", fmt.Errorf("group %s has the most members it can", g.Name)
	}
	if node == "" {
		node = pgPickNode(st, c, g)
	} else if n := st.node(node); n == nil || n.Status != "Ready" || n.Cordoned {
		return "", fmt.Errorf("node %q is not available", node)
	}
	if node == "" {
		return "", fmt.Errorf("no node is free for another member of group %s", g.Name)
	}
	if from != "" && g.member(from) == nil {
		return "", errNotFound(fmt.Sprintf("member %q not found", from))
	}
	g.Next++
	id := fmt.Sprintf("m%d", g.Next)
	g.Members = append(g.Members, PGMember{ID: id, Node: node, Role: pgReplica, Init: pgReplica, From: from})
	g.note(time.Now(), "adding replica %s on %s", id, node)
	// Keep the declared count in step so the controller does not drain it again.
	c.Replicas = max(c.Replicas, len(g.Members)-1)
	return id, nil
}

// pgRemoveReplica drains one replica; the controller removes it once the primary no longer counts it.
func pgRemoveReplica(st *ClusterState, name, groupName, member string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if groupName == "" {
		groupName = c.entryGroup()
	}
	g := c.group(groupName)
	if g == nil {
		return errNotFound(fmt.Sprintf("group %q not found", groupName))
	}
	m := g.member(member)
	switch {
	case m == nil:
		return errNotFound(fmt.Sprintf("member %q not found", member))
	case m.Role == pgPrimary || m.Role == pgPromoting:
		return fmt.Errorf("%s is the primary: switch over first (ziroctl pg switchover %s)", member, name)
	}
	m.Draining = true
	c.Replicas = max(0, min(c.Replicas, len(g.Members)-1-countDraining(g)))
	g.note(time.Now(), "removing replica %s", m.ID)
	return nil
}

func countDraining(g *PGGroup) int {
	n := 0
	for _, m := range g.Members {
		if m.Draining {
			n++
		}
	}
	return n
}

// pgRequestSwitchover starts a planned switchover (the default group unless one is named).
func pgRequestSwitchover(st *ClusterState, name, groupName, to string, now time.Time) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if groupName == "" {
		groupName = c.entryGroup()
	}
	g := c.group(groupName)
	if g == nil {
		return errNotFound(fmt.Sprintf("group %q not found", groupName))
	}
	if to == "" { // the replica furthest ahead
		best, _, _ := pgCandidate(g, now)
		if best == nil {
			return fmt.Errorf("group %s has no replica that is ready to take over", g.Name)
		}
		to = best.ID
	}
	return pgStartSwitchover(c, g, to, now)
}

// pgGroupFor finds a group by name (the entry group when empty).
func pgGroupFor(c *PGCluster, groupName string) (*PGGroup, error) {
	if groupName == "" {
		groupName = c.entryGroup()
	}
	g := c.group(groupName)
	if g == nil {
		return nil, errNotFound(fmt.Sprintf("group %q not found", groupName))
	}
	return g, nil
}

// pgRequestFailover is `pg failover`: promote a replica now because the primary is gone. It is refused
// while the primary answers (use a switchover); unless unsafe it keeps the checks of an automatic
// failover (enough replicas reachable, a replica not too far behind) and only skips the grace period
// and the partition brake. unsafe promotes any replica that answers and accepts losing writes.
func pgRequestFailover(st *ClusterState, name, groupName, to string, unsafe bool, now time.Time) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	g, err := pgGroupFor(c, groupName)
	if err != nil {
		return err
	}
	switch p := g.primary(); {
	case c.Paused:
		return fmt.Errorf("the controller of %s is paused: `ziroctl pg resume %s` first", name, name)
	case g.Switch != nil || g.promoting() != nil:
		return fmt.Errorf("group %s is already changing primary", g.Name)
	case g.Force != nil:
		return fmt.Errorf("a failover of group %s is already requested", g.Name)
	case p != nil && p.fresh(now):
		return fmt.Errorf("the primary %s of group %s is answering: use `ziroctl pg switchover %s` for a planned change", p.ID, g.Name, name)
	}
	if to != "" {
		if t := g.member(to); t == nil || t.Role != pgReplica || t.Draining {
			return fmt.Errorf("%s is not a replica of group %s", to, g.Name)
		}
	}
	g.Force = &PGForce{To: to, Unsafe: unsafe, At: now}
	if unsafe {
		g.alert(now, "high", "operator requested a forced failover: acknowledged writes may be lost")
	} else {
		g.note(now, "operator requested a failover")
	}
	return nil
}

// pgRequestReinit is `pg reinit`: a replica discards its data directory and takes a new base backup from
// the primary. The agent refuses a member that is not in recovery, so a primary is never wiped.
func pgRequestReinit(st *ClusterState, name, groupName, member string, now time.Time) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	g, err := pgGroupFor(c, groupName)
	if err != nil {
		return err
	}
	m := g.member(member)
	p := g.primary()
	switch {
	case m == nil:
		return errNotFound(fmt.Sprintf("member %q not found in group %s", member, g.Name))
	case c.Paused:
		return fmt.Errorf("the controller of %s is paused: `ziroctl pg resume %s` first", name, name)
	case m.Role != pgReplica:
		return fmt.Errorf("only a replica can be rebuilt: %s is %s", m.ID, m.Role)
	case m.Draining:
		return fmt.Errorf("%s is being removed", m.ID)
	case g.Switch != nil || g.promoting() != nil || g.Force != nil:
		return fmt.Errorf("group %s is changing primary", g.Name)
	case m.Cmd != nil:
		return fmt.Errorf("%s has an order in progress (%s)", m.ID, m.Cmd.Op)
	case p == nil || !p.fresh(now):
		return fmt.Errorf("group %s has no answering primary to copy from", g.Name)
	case !m.fresh(now):
		return fmt.Errorf("%s is not answering: reinit needs its container running", m.ID)
	}
	m.issue(opReinit, "", g.Epoch, now)
	g.note(now, "operator requested a rebuild of %s", m.ID)
	return nil
}

// pgGroupReasons says, in words, why a group is not simply healthy: the same predicates the controller
// acts on, so `pg status` explains a stall instead of leaving the operator to read the code.
func pgGroupReasons(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time) []string {
	var r []string
	if c.Paused {
		r = append(r, fmt.Sprintf("the controller is paused: it changes no roles (ziroctl pg resume %s)", c.Name))
	}
	if sw := g.Switch; sw != nil {
		r = append(r, fmt.Sprintf("switchover to %s in progress (%s)", sw.To, sw.Step))
	}
	if f := g.Force; f != nil {
		r = append(r, fmt.Sprintf("an operator failover is waiting for a replica that can be promoted (%s left)", (2*time.Minute-now.Sub(f.At)).Round(time.Second)))
	}
	if m := g.promoting(); m != nil {
		r = append(r, fmt.Sprintf("promoting %s since %s", m.ID, now.Sub(g.Notes["promoting"]).Round(time.Second)))
	}
	if hold := st.PGHold; now.Before(hold) {
		r = append(r, fmt.Sprintf("the cluster leader changed recently: the controller waits %s for the members to report before it fails anything over", hold.Sub(now).Round(time.Second)))
	}
	p := g.primary()
	switch {
	case p == nil:
		r = append(r, "the group has no primary")
	case pgPrimaryFailed(p, now):
		r = append(r, fmt.Sprintf("primary %s has not answered for %s", p.ID, now.Sub(p.Probe.At).Round(time.Second)))
	case !p.fresh(now) && p.Probe.At.IsZero():
		r = append(r, fmt.Sprintf("primary %s has not reported yet", p.ID))
	}
	if (p == nil || pgPrimaryFailed(p, now)) && g.promoting() == nil && g.Switch == nil {
		if partitioned(st, now) {
			r = append(r, "too many nodes are unreachable to tell a failure from a partition, so the controller does not fail over")
		}
		best, reachable, total := pgCandidate(g, now)
		switch {
		case best == nil:
			r = append(r, fmt.Sprintf("no joined replica answers, so nothing can be promoted (ziroctl pg failover %s --force promotes any replica that answers)", c.Name))
		default:
			if why := pgPromotionBlock(c, g, best, reachable, total); why != "" {
				r = append(r, why+fmt.Sprintf(" (ziroctl pg failover %s --force accepts the loss)", c.Name))
			}
		}
	}
	for i := range g.Members {
		m := &g.Members[i]
		if m.Cmd != nil {
			switch {
			case m.Cmd.Done && !m.Cmd.OK:
				r = append(r, fmt.Sprintf("%s: %s failed: %s", m.ID, m.Cmd.Op, m.Cmd.Msg))
			case !m.Cmd.Done && now.Sub(m.Cmd.At) > 30*time.Second:
				r = append(r, fmt.Sprintf("%s: %s has not completed after %s", m.ID, m.Cmd.Op, now.Sub(m.Cmd.At).Round(time.Second)))
			}
		}
		if !m.UnreadySince.IsZero() {
			if left := pgRebuildAfter - now.Sub(m.UnreadySince); left > 0 {
				r = append(r, fmt.Sprintf("%s makes no progress; the controller rebuilds it from the primary in %s", m.ID, left.Round(time.Second)))
			}
		}
		if m.Role == pgReplica && !m.Draining && !m.ready(now) {
			switch {
			case !m.fresh(now) && m.Probe.At.IsZero():
				r = append(r, fmt.Sprintf("%s has not reported yet", m.ID))
			case !m.fresh(now):
				r = append(r, fmt.Sprintf("%s is not answering", m.ID))
			case !m.Probe.Streaming:
				r = append(r, fmt.Sprintf("%s is not streaming from the primary (ziroctl pg reinit %s %s rebuilds it)", m.ID, c.Name, m.ID))
			case m.Probe.LagMs > pgReadyLagMillis:
				r = append(r, fmt.Sprintf("%s is catching up (%dms behind)", m.ID, m.Probe.LagMs))
			}
		}
	}
	return r
}

// pgView is one cluster for `pg status` and the API.
type pgView struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Sync      string        `json:"sync"`
	Replicas  int           `json:"replicas"`
	Paused    bool          `json:"paused,omitempty"`
	Database  string        `json:"database"`
	User      string        `json:"user"`
	Sharded   bool          `json:"sharded"`
	Endpoints pgEndpointsV  `json:"endpoints"`
	Groups    []pgGroupView `json:"groups"`
}

type pgEndpointsV struct {
	RW string `json:"rw"`
	RO string `json:"ro"`
}

type pgGroupView struct {
	Name    string         `json:"name"`
	Epoch   int64          `json:"epoch"`
	Sync    string         `json:"sync,omitempty"`
	Primary string         `json:"primary,omitempty"`
	Members []pgMemberView `json:"members"`
	Reasons []string       `json:"reasons,omitempty"` // why the group is not healthy, if it is not
	Events  []string       `json:"events,omitempty"`
}

type pgMemberView struct {
	ID       string `json:"id"`
	Node     string `json:"node"`
	Role     string `json:"role"`
	State    string `json:"state"` // ready, catching-up, down, draining
	LSN      string `json:"lsn,omitempty"`
	Timeline int    `json:"timeline,omitempty"`
	LagMs    int64  `json:"lag_ms,omitempty"`
	Joined   bool   `json:"joined,omitempty"` // counts toward the synchronous standbys and is a promotion candidate
}

func pgViewOf(st *ClusterState, c *PGCluster, now time.Time) pgView {
	v := pgView{Name: c.Name, Version: c.Version, Sync: c.Sync, Replicas: c.Replicas, Paused: c.Paused, Database: c.Database, User: c.User,
		Sharded:   c.Citus != "",
		Endpoints: pgEndpointsV{RW: c.Name + "-rw." + meshDomain + ":" + pgPort, RO: c.Name + "-ro." + meshDomain + ":" + pgPort}}
	for gi := range c.Groups {
		g := &c.Groups[gi]
		gv := pgGroupView{Name: g.Name, Epoch: g.Epoch, Sync: g.Sync}
		if g.Sync == pgSyncUnknown {
			gv.Sync = ""
		}
		for _, m := range g.Members {
			mv := pgMemberView{ID: m.ID, Node: m.Node, Role: m.Role, Timeline: m.Probe.Timeline, LagMs: m.Probe.LagMs, Joined: m.Joined}
			if m.Probe.OK {
				mv.LSN = formatLSN(m.Probe.LSN)
			}
			switch {
			case m.Draining:
				mv.State = "draining"
			case !m.fresh(now):
				mv.State = "down"
				if m.Probe.At.IsZero() {
					mv.State = "starting"
				}
			case m.Role == pgPrimary:
				mv.State = "ready"
			case m.ready(now):
				mv.State = "ready"
			default:
				mv.State = "catching-up"
			}
			if m.Role == pgPrimary {
				gv.Primary = m.ID
			}
			gv.Members = append(gv.Members, mv)
		}
		gv.Reasons = pgGroupReasons(st, c, g, now)
		for _, e := range g.Events {
			gv.Events = append(gv.Events, e.At.UTC().Format("15:04:05")+" "+e.Msg)
		}
		v.Groups = append(v.Groups, gv)
	}
	return v
}

func pgViews(st *ClusterState, now time.Time) []pgView {
	names := make([]string, 0, len(st.PG))
	for n := range st.PG {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []pgView{}
	for _, n := range names {
		out = append(out, pgViewOf(st, st.PG[n], now))
	}
	return out
}

// pgConnString is the connection string for a cluster's default read-write name.
func pgConnString(st *ClusterState, c *PGCluster, ro bool) string {
	pw := st.Secrets[c.secretName()]["POSTGRES_PASSWORD"]
	host := c.Name + "-rw"
	if ro {
		host = c.Name + "-ro"
	}
	return fmt.Sprintf("postgres://%s:%s@%s.%s:%s/%s", c.User, pw, host, meshDomain, pgPort, c.Database)
}

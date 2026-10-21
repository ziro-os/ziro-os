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
		return nil, fmt.Errorf("Postgres clusters need the pod network (ziroctl cluster network enable)")
	}
	if st.PG[o.Name] != nil {
		return nil, fmt.Errorf("Postgres cluster %q exists", o.Name)
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

// pgView is one cluster for `pg status` and the API.
type pgView struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Sync      string        `json:"sync"`
	Replicas  int           `json:"replicas"`
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
}

func pgViewOf(st *ClusterState, c *PGCluster, now time.Time) pgView {
	v := pgView{Name: c.Name, Version: c.Version, Sync: c.Sync, Replicas: c.Replicas, Database: c.Database, User: c.User,
		Sharded:   c.Citus != "",
		Endpoints: pgEndpointsV{RW: c.Name + "-rw." + meshDomain + ":" + pgPort, RO: c.Name + "-ro." + meshDomain + ":" + pgPort}}
	for gi := range c.Groups {
		g := &c.Groups[gi]
		gv := pgGroupView{Name: g.Name, Epoch: g.Epoch, Sync: g.Sync}
		for _, m := range g.Members {
			mv := pgMemberView{ID: m.ID, Node: m.Node, Role: m.Role, Timeline: m.Probe.Timeline, LagMs: m.Probe.LagMs}
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

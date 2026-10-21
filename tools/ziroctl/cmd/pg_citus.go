package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Citus sharding (RFC 0005). A sharded cluster is a coordinator group plus worker groups, each a
// primary with replicas. The controller registers every worker with the coordinator by the worker's
// read-write DNS name, so a worker failover changes no Citus metadata; it enables metadata sync so any
// node can take writes, and starts Citus's online shard rebalance when a worker joins. Citus runs the
// orders on the coordinator's primary, in the application database. The orders are fixed templates
// with one validated argument.

const (
	opCitusCoordinator = "citus-coordinator" // register the coordinator under its own DNS name
	opCitusAddNode     = "citus-add-node"    // register a worker
	opCitusMetaSync    = "citus-metadata-sync"
	opCitusRebalance   = "citus-rebalance" // start the non-blocking shard rebalance
)

var citusHostRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,100}$`)

func validCitusCommand(op, arg string) error {
	switch op {
	case opCitusCoordinator, opCitusAddNode:
		if !citusHostRe.MatchString(arg) {
			return fmt.Errorf("invalid host %q", arg)
		}
	case opCitusMetaSync, opCitusRebalance:
		if arg != "" {
			return fmt.Errorf("%s takes no argument", op)
		}
	default:
		return fmt.Errorf("unknown order %q", op)
	}
	return nil
}

// citusSteps are the statements of a Citus order, run in the order's database.
func citusSteps(o PGOrder) ([][]string, error) {
	if err := validCitusCommand(o.Op, o.Arg); err != nil {
		return nil, err
	}
	if !pgIdentRe.MatchString(o.DB) {
		return nil, fmt.Errorf("invalid database %q", o.DB)
	}
	var sql string
	switch o.Op {
	case opCitusCoordinator:
		sql = "select citus_set_coordinator_host('" + o.Arg + "', " + pgPort + ") where not exists (select from pg_dist_node where groupid = 0)"
	case opCitusAddNode:
		sql = "select citus_add_node('" + o.Arg + "', " + pgPort + ") where not exists (select from pg_dist_node where nodename = '" + o.Arg + "' and nodeport = " + pgPort + ")"
	case opCitusMetaSync:
		sql = "select start_metadata_sync_to_all_nodes()"
	case opCitusRebalance:
		sql = "select citus_rebalance_start(shard_transfer_mode := 'force_logical') where exists (select from pg_dist_shard)"
	}
	return [][]string{psqlDB(o.Container, o.DB, sql)}, nil
}

// citusHost is the name a group is registered under.
func citusHost(c *PGCluster, g *PGGroup) string { return c.dnsRW(g.Name) + "." + meshDomain }

// pgCitusPass walks the coordinator through the registration steps, one order at a time.
func pgCitusPass(st *ClusterState, c *PGCluster, now time.Time) {
	if c.Citus == "" {
		return
	}
	coord := c.group("coord")
	if coord == nil || coord.Switch != nil || coord.promoting() != nil {
		return
	}
	p := coord.primary()
	if p == nil || !p.fresh(now) || p.Cmd != nil {
		return
	}
	issue := func(key, op, arg string) {
		if !coord.last(now, 30*time.Second, key) { // do not hammer a step that keeps failing
			return
		}
		if p.issue(op, arg, coord.Epoch, now) {
			p.Cmd.DB = c.Database
		}
	}
	if !c.CitusReady {
		issue(opCitusCoordinator, opCitusCoordinator, citusHost(c, coord))
		return
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Name == "coord" || g.Registered {
			continue
		}
		if wp := g.primary(); wp == nil || !wp.fresh(now) {
			continue // the worker is not up yet
		}
		issue(opCitusAddNode+g.Name, opCitusAddNode, citusHost(c, g))
		return
	}
	if !c.MetaSynced {
		issue(opCitusMetaSync, opCitusMetaSync, "")
		return
	}
	if c.RebalancePending {
		issue(opCitusRebalance, opCitusRebalance, "")
	}
}

// pgCitusSettle records the outcome of a Citus order.
func pgCitusSettle(c *PGCluster, g *PGGroup, m *PGMember, cmd *PGCommand, now time.Time) {
	if !cmd.OK {
		return
	}
	switch cmd.Op {
	case opCitusCoordinator:
		c.CitusReady = true
	case opCitusAddNode:
		for i := range c.Groups {
			if citusHost(c, &c.Groups[i]) == cmd.Arg {
				c.Groups[i].Registered = true
				c.MetaSynced = false // a new node needs the metadata
				c.RebalancePending = true
				c.Groups[i].note(now, "registered with the coordinator")
			}
		}
	case opCitusMetaSync:
		c.MetaSynced = true
	case opCitusRebalance:
		c.RebalancePending = false
		g.note(now, "shard rebalance started")
	}
}

// pgAddShard adds a worker group to a sharded cluster; the controller registers it and rebalances.
func pgAddShard(st *ClusterState, name string, now time.Time) (string, error) {
	c, err := pgCluster(st, name)
	if err != nil {
		return "", err
	}
	if c.Citus == "" {
		return "", fmt.Errorf("%s is not a sharded cluster", name)
	}
	n := 0
	for _, g := range c.Groups {
		if g.Name != "coord" {
			n++
		}
	}
	if n >= pgMaxShards {
		return "", fmt.Errorf("a cluster has at most %d shard groups", pgMaxShards)
	}
	g := PGGroup{Name: "w" + strconv.Itoa(n+1)}
	for i := 0; i <= c.Replicas; i++ {
		node := pgPickNode(st, c, &g)
		if node == "" {
			return "", fmt.Errorf("the new group needs %d nodes, one per member", c.Replicas+1)
		}
		g.Next++
		m := PGMember{ID: fmt.Sprintf("m%d", g.Next), Node: node, Role: pgReplica, Init: pgReplica}
		if i == 0 {
			m.Role, m.Init = pgPrimary, pgPrimary
		}
		g.Members = append(g.Members, m)
	}
	g.note(now, "shard group added")
	c.Groups = append(c.Groups, g)
	return g.Name, nil
}

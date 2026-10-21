package cmd

import (
	"slices"
	"sort"
	"strings"
	"time"
)

// Role-following names (RFC 0005). The pod DNS answers <cluster>-<group>-rw with the primary and
// <cluster>-<group>-ro with the replicas that are ready to serve reads; the cluster's default group
// (the only group, or the Citus coordinator) is also <cluster>-rw and <cluster>-ro. The names are
// computed from ClusterState.PG, so a failover changes the answer without restarting anything:
// replicas reconnect to the read-write name and clients re-resolve it.

const pgPort = "5432"

// pgNow is the clock of the endpoint computation (tests replace it).
var pgNow = time.Now

// memberIP is the pod IP of a member that is running.
func memberIP(st *ClusterState, app string) string {
	for _, r := range st.Replicas {
		if r.App == app && r.IP != "" && st.replicaRunning(r) {
			return r.IP
		}
	}
	return ""
}

// pgGroupEndpoints returns the addresses behind a group's read-write and read-only names.
func pgGroupEndpoints(st *ClusterState, c *PGCluster, g *PGGroup, now time.Time) (rw, ro []string) {
	for _, m := range g.Members {
		ip := memberIP(st, c.memberApp(g.Name, m.ID))
		if ip == "" {
			continue
		}
		switch {
		case m.Role == pgPrimary:
			rw = append(rw, ip)
		case m.ready(now):
			ro = append(ro, ip)
		}
	}
	sort.Strings(ro)
	if len(ro) == 0 {
		ro = slices.Clone(rw) // no replica is ready: reads go to the primary
	}
	return rw, ro
}

// pgEndpoints adds the Postgres names to a map of app -> pod IPs.
func pgEndpoints(st *ClusterState, out map[string][]string, now time.Time) {
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			rw, ro := pgGroupEndpoints(st, c, g, now)
			out[c.dnsRW(g.Name)], out[c.dnsRO(g.Name)] = rw, ro
			if g.Name == c.entryGroup() {
				out[c.Name+"-rw"], out[c.Name+"-ro"] = rw, ro
			}
		}
	}
}

// pgAliasMembers returns the member apps behind a role-following name ("" prefix: not one).
func pgAliasMembers(st *ClusterState, alias string) []string {
	var out []string
	for _, c := range st.PG {
		for gi := range c.Groups {
			g := &c.Groups[gi]
			names := []string{c.dnsRW(g.Name), c.dnsRO(g.Name)}
			if g.Name == c.entryGroup() {
				names = append(names, c.Name+"-rw", c.Name+"-ro")
			}
			if slices.Contains(names, alias) {
				for _, m := range g.Members {
					out = append(out, c.memberApp(g.Name, m.ID))
				}
			}
		}
	}
	return out
}

// pgAliasTargets are the gateway addresses behind a role-following name.
func pgAliasTargets(pods map[string][]string, st *ClusterState, alias string) []string {
	if len(pgAliasMembers(st, alias)) == 0 {
		return nil
	}
	var out []string
	for _, ip := range pods[alias] {
		out = append(out, ip+":"+pgPort)
	}
	return out
}

// isPGAlias reports whether name is one of the role-following names.
func isPGAlias(st *ClusterState, name string) bool {
	return strings.Contains(name, "-") && len(pgAliasMembers(st, name)) > 0
}

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
		if c.poolerOn() {
			out[c.Name+"-pool"] = pgPoolerIPs(st, c)
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

// pgMetrics adds the Postgres clusters to the master's metrics.
func pgMetrics(m *metricsWriter, st *ClusterState, now time.Time) {
	if len(st.PG) == 0 {
		return
	}
	m.family("ziro_pg_primary", "gauge", "The member that is the primary of a group (1).")
	m.family("ziro_pg_members", "gauge", "Members of a group by state.")
	m.family("ziro_pg_epoch", "gauge", "Promotions of a group so far (the failover epoch).")
	m.family("ziro_pg_replication_lag_milliseconds", "gauge", "How far a replica's replay is behind.")
	m.family("ziro_pg_connections", "gauge", "Client connections of a member.")
	m.family("ziro_pg_max_connections", "gauge", "max_connections of a member.")
	m.family("ziro_pg_commits_total", "counter", "Committed transactions of a member (per second: rate()).")
	m.family("ziro_pg_xid_age", "gauge", "Age of a member's oldest unfrozen transaction ID (wraparound at about 2.1e9).")
	m.family("ziro_pg_disk_used_percent", "gauge", "How full a member's data volume is.")
	m.family("ziro_pg_backup_last_seconds", "gauge", "Seconds since the newest finished backup of a group, by type.")
	m.family("ziro_pg_backup_repository_bytes", "gauge", "Size of a group's backups in the repository (compressed, without the WAL).")
	m.family("ziro_pg_archive_failed_total", "counter", "Failed WAL archive attempts of a primary since it started.")
	m.family("ziro_pg_archive_last_seconds", "gauge", "Seconds since a primary last archived a WAL segment.")
	for _, v := range pgViews(st, now) {
		for _, g := range v.Groups {
			base := map[string]string{"cluster": v.Name, "group": g.Name}
			with := func(extra map[string]string) map[string]string {
				l := map[string]string{"cluster": v.Name, "group": g.Name}
				for k, x := range extra {
					l[k] = x
				}
				return l
			}
			m.sample("ziro_pg_epoch", base, float64(g.Epoch))
			if c := st.PG[v.Name]; c != nil {
				if gr := c.group(g.Name); gr != nil {
					pgBackupMetrics(m, c, gr, with, now)
					for _, mm := range gr.Members {
						if !mm.Probe.OK {
							continue
						}
						l := with(map[string]string{"member": mm.ID})
						m.sample("ziro_pg_connections", l, float64(mm.Probe.Conns))
						m.sample("ziro_pg_max_connections", l, float64(mm.Probe.MaxConns))
						m.sample("ziro_pg_commits_total", l, float64(mm.Probe.Commits))
						m.sample("ziro_pg_xid_age", l, float64(mm.Probe.XIDAge))
						m.sample("ziro_pg_disk_used_percent", l, float64(mm.Probe.DiskPct))
					}
				}
			}
			states := map[string]int{}
			for _, mv := range g.Members {
				states[mv.State]++
				if mv.Role == pgPrimary {
					m.sample("ziro_pg_primary", with(map[string]string{"member": mv.ID}), 1)
				} else {
					m.sample("ziro_pg_replication_lag_milliseconds", with(map[string]string{"member": mv.ID}), float64(mv.LagMs))
				}
			}
			for _, s := range []string{"ready", "catching-up", "starting", "down", "draining"} {
				m.sample("ziro_pg_members", with(map[string]string{"state": s}), float64(states[s]))
			}
		}
	}
}

// pgBackupMetrics adds a group's backups: the age of the newest of each type, the repository's size and,
// from the primary, archiving.
func pgBackupMetrics(m *metricsWriter, c *PGCluster, g *PGGroup, with func(map[string]string) map[string]string, now time.Time) {
	if !c.backupsOn() {
		return
	}
	if g.Backup != nil && g.Backup.Info != nil {
		newest := map[string]time.Time{}
		var size int64
		for _, b := range g.Backup.Info.Backups {
			if b.Stop.After(newest[b.Type]) {
				newest[b.Type] = b.Stop
			}
			size += b.Repo
		}
		for _, typ := range []string{"full", "diff", "incr"} {
			if t := newest[typ]; !t.IsZero() {
				m.sample("ziro_pg_backup_last_seconds", with(map[string]string{"type": typ}), now.Sub(t).Seconds())
			}
		}
		m.sample("ziro_pg_backup_repository_bytes", with(nil), float64(size))
	}
	if p := g.primary(); p != nil && p.Probe.OK {
		l := with(map[string]string{"member": p.ID})
		m.sample("ziro_pg_archive_failed_total", l, float64(p.Probe.ArchiveFailed))
		if p.Probe.ArchivedAgo >= 0 {
			m.sample("ziro_pg_archive_last_seconds", l, float64(p.Probe.ArchivedAgo))
		}
	}
}

package cmd

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// The fleet overview: every Postgres cluster on one screen, with what needs an operator's attention
// (`ziroctl pg overview`, GET /api/v1/pg-overview, and the dashboard's front page).

// pgOverviewRow is one cluster in the overview.
type pgOverviewRow struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Health     string   `json:"health"`  // healthy, degraded, down or paused
	Primary    string   `json:"primary"` // member@node of the entry group's primary
	Groups     int      `json:"groups"`
	Members    int      `json:"members"`
	Ready      int      `json:"ready"`
	MaxLagMs   int64    `json:"max_lag_ms"`
	ConnPct    int      `json:"conn_pct"` // the fullest member's connections against max_connections
	DiskPct    int      `json:"disk_pct"` // the fullest data volume
	Backups    bool     `json:"backups"`
	LastBackup string   `json:"last_backup,omitempty"` // RFC 3339: the oldest group's newest finished backup
	Window     string   `json:"window,omitempty"`      // maintenance window
	Alerts24h  int      `json:"alerts_24h"`
	Attention  []string `json:"attention,omitempty"` // what needs an operator, worst first
}

// pgOverviewOf summarizes one cluster.
func pgOverviewOf(st *ClusterState, c *PGCluster, now time.Time) pgOverviewRow {
	v := pgViewOf(st, c, now)
	row := pgOverviewRow{Name: c.Name, Version: c.Version, Groups: len(c.Groups), Backups: c.backupsOn(), Window: pgWindowLabel(c, now)}
	down := false
	var lastBackup time.Time
	for gi := range c.Groups {
		g := &c.Groups[gi]
		gv := v.Groups[gi]
		prefix := ""
		if len(c.Groups) > 1 {
			prefix = g.Name + ": "
		}
		for _, r := range gv.Reasons {
			row.Attention = append(row.Attention, prefix+r)
		}
		p := g.primary()
		if p == nil || !p.fresh(now) {
			down = true
		} else if g.Name == c.entryGroup() {
			row.Primary = p.ID + "@" + p.Node
		}
		for _, mv := range gv.Members {
			row.Members++
			if mv.State == "ready" {
				row.Ready++
			}
			if mv.Role != pgPrimary {
				row.MaxLagMs = max(row.MaxLagMs, mv.LagMs)
			}
		}
		for _, m := range g.Members {
			if !m.Probe.OK {
				continue
			}
			row.DiskPct = max(row.DiskPct, m.Probe.DiskPct)
			if m.Probe.MaxConns > 0 {
				row.ConnPct = max(row.ConnPct, int(m.Probe.Conns*100/m.Probe.MaxConns))
			}
		}
		if len(g.Waiting) > 0 {
			row.Attention = append(row.Attention, fmt.Sprintf("%s%s wait for the maintenance window to take a new configuration", prefix, strings.Join(g.Waiting, ", ")))
		}
		if c.backupsOn() {
			var newest time.Time
			if g.Backup != nil && g.Backup.Info != nil {
				for _, b := range g.Backup.Info.Backups {
					if b.Stop.After(newest) {
						newest = b.Stop
					}
				}
			}
			switch {
			case newest.IsZero():
				row.Attention = append(row.Attention, prefix+"no backup has finished yet")
			case lastBackup.IsZero() || newest.Before(lastBackup):
				lastBackup = newest
			}
		}
		for _, e := range g.Events {
			if e.Alert != "" && now.Sub(e.At) < 24*time.Hour {
				row.Alerts24h++
			}
		}
	}
	if !lastBackup.IsZero() {
		row.LastBackup = lastBackup.UTC().Format(time.RFC3339)
		if now.Sub(lastBackup) > 26*time.Hour {
			row.Attention = append(row.Attention, "the newest backup is "+dockerHumanDuration(now.Sub(lastBackup))+" old")
		}
	}
	if row.DiskPct >= 80 {
		row.Attention = append(row.Attention, fmt.Sprintf("a data volume is %d%% full", row.DiskPct))
	}
	if row.ConnPct >= 90 {
		row.Attention = append(row.Attention, fmt.Sprintf("%d%% of the connections are in use", row.ConnPct))
	}
	switch {
	case c.Paused:
		row.Health = "paused"
	case down:
		row.Health = "down"
	case len(row.Attention) > 0 || row.Ready < row.Members:
		row.Health = "degraded"
	default:
		row.Health = "healthy"
	}
	return row
}

// pgOverview is every cluster, the ones that need attention first.
func pgOverview(st *ClusterState, now time.Time) []pgOverviewRow {
	rank := map[string]int{"down": 0, "degraded": 1, "paused": 2, "healthy": 3}
	out := []pgOverviewRow{}
	for _, c := range st.PG {
		out = append(out, pgOverviewOf(st, c, now))
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Health] != rank[out[j].Health] {
			return rank[out[i].Health] < rank[out[j].Health]
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var pgOverviewCmd = &cobra.Command{
	Use:   "overview",
	Short: "Show every cluster's health on one screen",
	Long: `Lists every Postgres cluster with its health (healthy, degraded, down or paused), primary, ready members, the
largest replication lag, the fullest connection pool and data volume, the last backup and recent alerts, then
what needs attention. Clusters that are down or degraded come first. With --json it prints the same as
GET /api/v1/pg-overview.`,
	Example: "  ziroctl pg overview\n  ziroctl pg overview --json",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		now := time.Now()
		rows := pgOverview(st, now)
		return printResult(rows, func() { printPGOverview(rows, now) })
	},
}

func printPGOverview(rows []pgOverviewRow, now time.Time) {
	if len(rows) == 0 {
		fmt.Println("no postgres clusters (ziroctl pg create <name>)")
		return
	}
	fmt.Printf("%-16s %-3s %-9s %-12s %-7s %-8s %-5s %-5s %-11s %s\n", "NAME", "PG", "HEALTH", "PRIMARY", "READY", "LAG", "CONN", "DISK", "BACKUP", "ALERTS")
	for _, r := range rows {
		backup := "off"
		if r.Backups {
			backup = "none yet"
			if t, err := time.Parse(time.RFC3339, r.LastBackup); err == nil {
				backup = dockerHumanDuration(now.Sub(t)) + " ago"
			}
		}
		primary := r.Primary
		if primary == "" {
			primary = "-"
		}
		fmt.Printf("%-16s %-3s %-9s %-12s %-7s %-8s %-5s %-5s %-11s %d\n", r.Name, r.Version, r.Health, primary,
			fmt.Sprintf("%d/%d", r.Ready, r.Members), (time.Duration(r.MaxLagMs) * time.Millisecond).String(),
			fmt.Sprintf("%d%%", r.ConnPct), fmt.Sprintf("%d%%", r.DiskPct), backup, r.Alerts24h)
	}
	first := true
	for _, r := range rows {
		for _, a := range r.Attention {
			if first {
				fmt.Println("\nNeeds attention:")
				first = false
			}
			fmt.Printf("  %s: %s\n", r.Name, a)
		}
	}
}

func registerPGOverviewRoutes(a *apiRouter) {
	a.get("/api/v1/pg-overview", "viewer", func(w http.ResponseWriter, r *http.Request) {
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, pgOverview(st, time.Now()))
	})
}

func init() {
	pgCmd.AddCommand(pgOverviewCmd)
}

package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// Maintenance windows. A change that restarts members (a new image, restart-only parameters, a resize,
// a ziroctl upgrade that changes the entry script, pg restart) rolls out only while the cluster's window
// is open: it opens on a cron schedule (UTC) and stays open for its duration. Outside it, the members
// keep running the old spec and `pg status` lists them as waiting. A cluster without a window rolls at
// once, as before.
//
// Never held back: failover, switchover by hand, repairs (rebuilding a replica, replacing a member on a
// gone node), members that are not serving anyway, and restarts for a password change (a replica must
// not reconnect with a password the primary no longer takes).

// PGMaintenance is a cluster's maintenance window.
type PGMaintenance struct {
	Window   string `json:"window"`   // cron, UTC: when it opens
	Duration string `json:"duration"` // how long it stays open
}

func (m *PGMaintenance) validate() error {
	if _, err := pgParseCron(m.Window); err != nil {
		return fmt.Errorf("maintenance window: %v", err)
	}
	d, err := time.ParseDuration(m.Duration)
	if err != nil || d < 30*time.Minute || d > 24*time.Hour {
		return fmt.Errorf("maintenance duration: 30m to 24h (2h)")
	}
	return nil
}

// pgWindowOpen reports whether members may restart for a new spec now.
func pgWindowOpen(c *PGCluster, now time.Time) bool {
	if c.Maintenance == nil || now.Before(c.WindowUntil) {
		return true
	}
	s, err := pgParseCron(c.Maintenance.Window)
	d, err2 := time.ParseDuration(c.Maintenance.Duration)
	if err != nil || err2 != nil {
		return true // validated when set; a bad value never blocks changes for ever
	}
	start := s.prev(now)
	return !start.IsZero() && now.Sub(start) < d
}

// pgNextWindow is when the window next opens (zero: open now, or no window).
func pgNextWindow(c *PGCluster, now time.Time) time.Time {
	if c.Maintenance == nil || pgWindowOpen(c, now) {
		return time.Time{}
	}
	s, err := pgParseCron(c.Maintenance.Window)
	if err != nil {
		return time.Time{}
	}
	return s.next(now)
}

// pgSetMaintenance sets (or with an empty window, removes) the cluster's window.
func pgSetMaintenance(st *ClusterState, name, window, duration string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if window == "" {
		c.Maintenance = nil
		return nil
	}
	if duration == "" {
		duration = "2h"
	}
	m := &PGMaintenance{Window: window, Duration: duration}
	if err := m.validate(); err != nil {
		return err
	}
	c.Maintenance = m
	return nil
}

// pgOpenWindow keeps the window open for d from now (0 closes a window opened by hand).
func pgOpenWindow(st *ClusterState, name string, d time.Duration, now time.Time) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if d < 0 || d > 24*time.Hour {
		return fmt.Errorf("--for: up to 24h")
	}
	if d == 0 {
		c.WindowUntil = time.Time{}
		return nil
	}
	if c.Maintenance == nil {
		return fmt.Errorf("%s has no maintenance window: changes already roll out at once", name)
	}
	c.WindowUntil = now.Add(d)
	return nil
}

// pgWindowLabel describes the window for pg status: "0 2 * * 0 for 2h (open)", "... (next 2026-11-08 02:00)".
func pgWindowLabel(c *PGCluster, now time.Time) string {
	if c.Maintenance == nil {
		return ""
	}
	l := c.Maintenance.Window + " for " + c.Maintenance.Duration
	switch {
	case now.Before(c.WindowUntil):
		return l + " (open by hand until " + c.WindowUntil.UTC().Format("2006-01-02 15:04") + " UTC)"
	case pgWindowOpen(c, now):
		return l + " (open)"
	}
	if n := pgNextWindow(c, now); !n.IsZero() {
		return l + " (next " + n.Format("2006-01-02 15:04") + " UTC)"
	}
	return l
}

// ---- commands ----

var pgMaintFlags struct {
	window, duration, open string
	clear                  bool
}

var pgMaintenanceCmd = &cobra.Command{
	Use:   "maintenance <name>",
	Short: "Set when members may restart for changes",
	Long: `Sets the cluster's maintenance window: changes that restart members (a new image, restart-only parameters, a
resize, pg restart, a ziroctl upgrade that changes the members) roll out only while it is open. --window is a
cron expression in UTC for when it opens, --duration how long it stays open. Failover, repairs and password
changes never wait. --open keeps it open by hand for a while (--open 0 closes it again); --clear removes it.`,
	Example: "  ziroctl pg maintenance shop --window '0 2 * * 0' --duration 2h\n  ziroctl pg maintenance shop --open 1h\n  ziroctl pg maintenance shop --clear",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f := pgMaintFlags
		set := f.window != "" || f.clear
		if !set && f.open == "" {
			return fmt.Errorf("give --window, --open or --clear")
		}
		if f.clear && f.window != "" {
			return fmt.Errorf("--clear and --window exclude each other")
		}
		var open time.Duration
		if f.open != "" {
			d, err := time.ParseDuration(f.open)
			if err != nil {
				return fmt.Errorf("--open: a duration such as 1h")
			}
			open = d
		}
		var label string
		if err := pgEdit("pg maintenance", args[0], func(st *ClusterState, now time.Time) error {
			if set {
				if err := pgSetMaintenance(st, args[0], f.window, f.duration); err != nil {
					return err
				}
			}
			if f.open != "" {
				if err := pgOpenWindow(st, args[0], open, now); err != nil {
					return err
				}
			}
			label = pgWindowLabel(st.PG[args[0]], now)
			return nil
		}); err != nil {
			return err
		}
		if label == "" {
			fmt.Printf("✓ %s has no maintenance window: changes roll out at once\n", args[0])
		} else {
			fmt.Printf("✓ %s: maintenance window %s\n", args[0], label)
		}
		return nil
	},
}

func init() {
	f := pgMaintenanceCmd.Flags()
	f.StringVar(&pgMaintFlags.window, "window", "", "When the window opens: cron, UTC ('0 2 * * 0' = Sundays 02:00)")
	f.StringVar(&pgMaintFlags.duration, "duration", "2h", "How long it stays open (30m-24h)")
	f.StringVar(&pgMaintFlags.open, "open", "", "Keep it open by hand for this long (1h); 0 closes it")
	f.BoolVar(&pgMaintFlags.clear, "clear", false, "Remove the window: changes roll out at once")
	pgCmd.AddCommand(pgMaintenanceCmd)
}

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// `ziroctl pg top`: a live view of the Postgres clusters in the terminal. The fleet first (pg overview,
// one line per cluster); Enter opens a cluster: its members with role, state, lag, transactions per
// second, connections and disk, what needs attention, and the latest events. Actions go through the
// same operations as the pg commands, and each asks for confirmation (y).

const pgTopInterval = 2 * time.Second

// pgTopAction is an action waiting for its confirmation.
type pgTopAction struct {
	label string
	run   func() error
}

type pgTopView struct {
	sel     int    // the selected cluster (fleet) or member (cluster view)
	cluster string // the open cluster ("" = the fleet)
	confirm *pgTopAction
	status  string
	help    bool
	// transactions per second, from the commit counters of two samples
	commits map[string]int64
	at      time.Time
	tps     map[string]float64
	// act runs an operation on the cluster state (pgEdit on the master; tests replace it).
	act func(audit, cluster string, fn func(st *ClusterState, now time.Time) error) error
}

func newPGTopView() *pgTopView {
	return &pgTopView{commits: map[string]int64{}, tps: map[string]float64{},
		act: func(audit, cluster string, fn func(*ClusterState, time.Time) error) error {
			return pgEdit(audit, cluster, fn)
		}}
}

// sample updates the transaction rates from a new state.
func (v *pgTopView) sample(st *ClusterState, now time.Time) {
	dt := now.Sub(v.at).Seconds()
	for _, c := range st.PG {
		for _, g := range c.Groups {
			for _, m := range g.Members {
				if !m.Probe.OK {
					continue
				}
				k := c.Name + "/" + g.Name + "/" + m.ID
				if prev, ok := v.commits[k]; ok && dt > 0 && m.Probe.Commits >= prev {
					v.tps[k] = float64(m.Probe.Commits-prev) / dt
				}
				v.commits[k] = m.Probe.Commits
			}
		}
	}
	v.at = now
}

// pgTopMember is one member line of the cluster view.
type pgTopMember struct {
	group, id string
	member    *PGMember
	view      pgMemberView
}

func pgTopMembers(st *ClusterState, c *PGCluster, now time.Time) []pgTopMember {
	v := pgViewOf(st, c, now)
	var out []pgTopMember
	for gi := range c.Groups {
		g := &c.Groups[gi]
		for mi := range g.Members {
			out = append(out, pgTopMember{group: g.Name, id: g.Members[mi].ID, member: &g.Members[mi], view: v.Groups[gi].Members[mi]})
		}
	}
	return out
}

// key handles one key press; it reports whether to quit.
func (v *pgTopView) key(k string, st *ClusterState, now time.Time) bool {
	if v.confirm != nil {
		if k == "y" || k == "Y" {
			if err := v.confirm.run(); err != nil {
				v.status = v.confirm.label + " failed: " + err.Error()
			} else {
				v.status = v.confirm.label + ": requested"
			}
		} else {
			v.status = "cancelled"
		}
		v.confirm = nil
		return false
	}
	if v.help {
		v.help = false
		return false
	}
	rows := pgOverview(st, now)
	var c *PGCluster
	var members []pgTopMember
	if v.cluster != "" {
		if c = st.PG[v.cluster]; c == nil {
			v.cluster, v.sel = "", 0
		} else {
			members = pgTopMembers(st, c, now)
		}
	}
	n := len(rows)
	if c != nil {
		n = len(members)
	}
	switch k {
	case "q", "\x03":
		return true
	case "?":
		v.help = true
	case "up", "k":
		if v.sel > 0 {
			v.sel--
		}
	case "down", "j":
		if v.sel < n-1 {
			v.sel++
		}
	case "enter", "right":
		if c == nil && v.sel < len(rows) {
			v.cluster, v.sel = rows[v.sel].Name, 0
		}
	case "esc", "left":
		if c != nil {
			v.cluster, v.sel = "", 0
			for i, r := range rows {
				if r.Name == c.Name {
					v.sel = i
				}
			}
		}
	}
	if c == nil {
		return false
	}
	name := c.Name
	var m *pgTopMember
	if v.sel < len(members) {
		m = &members[v.sel]
	}
	ask := func(label string, fn func(st *ClusterState, now time.Time) error) {
		v.confirm = &pgTopAction{label: label, run: func() error { return v.act("pg top: "+label, name, fn) }}
	}
	switch k {
	case "s":
		to, group := "", ""
		if m != nil {
			group = m.group
			if m.member.Role == pgReplica {
				to = m.id
			}
		}
		label := "switchover"
		if to != "" {
			label += " to " + to
		}
		ask(label, func(st *ClusterState, now time.Time) error { return pgRequestSwitchover(st, name, group, to, now) })
	case "r":
		if m == nil || m.member.Role != pgReplica {
			v.status = "select a replica to rebuild"
			return false
		}
		group, id := m.group, m.id
		ask("rebuild "+id, func(st *ClusterState, now time.Time) error { return pgRequestReinit(st, name, group, id, now) })
	case "a":
		group := ""
		if m != nil {
			group = m.group
		}
		ask("add a replica", func(st *ClusterState, now time.Time) error {
			_, err := pgAddReplica(st, name, group, "", "")
			return err
		})
	case "b":
		if !c.backupsOn() {
			v.status = "backups are off (ziroctl pg backup enable " + name + ")"
			return false
		}
		ask("incremental backup", func(st *ClusterState, now time.Time) error { return pgBackupNow(st, name, "", "incr") })
	case "p":
		paused := !c.Paused
		label := map[bool]string{true: "pause the controller", false: "resume the controller"}[paused]
		ask(label, func(st *ClusterState, now time.Time) error {
			cc, err := pgCluster(st, name)
			if err == nil {
				cc.Paused = paused
			}
			return err
		})
	}
	return false
}

var pgTopHealth = map[string]string{"healthy": "\033[32m", "degraded": "\033[33m", "down": "\033[31m", "paused": "\033[35m"}

// render draws one frame for a terminal of w×h.
func (v *pgTopView) render(buf *bytes.Buffer, st *ClusterState, now time.Time, w, h int) {
	buf.Reset()
	lines := 0
	line := func(format string, a ...any) {
		if lines >= h-1 {
			return
		}
		buf.WriteString(clip(fmt.Sprintf(format, a...), w) + "\033[K\r\n")
		lines++
	}
	buf.WriteString("\033[H")
	title := "ziroctl pg top — " + now.UTC().Format("15:04:05") + " UTC"
	if v.cluster != "" {
		title += " — " + v.cluster
	}
	line("\033[1m%s\033[0m", title)
	switch {
	case v.help:
		for _, l := range []string{"",
			"  ↑/↓ or j/k   select          Enter/→   open a cluster       Esc/←   back to the fleet",
			"  s   switchover (to the selected replica, or the best one)",
			"  r   rebuild the selected replica from the primary",
			"  a   add a replica           b   take an incremental backup now",
			"  p   pause or resume the controller",
			"  q   quit                    every action asks for confirmation (y)", "", "  press any key"} {
			line("%s", l)
		}
	case v.cluster == "" || st.PG[v.cluster] == nil:
		v.renderFleet(line, st, now)
	default:
		v.renderCluster(line, st, st.PG[v.cluster], now)
	}
	for lines < h-1 {
		buf.WriteString("\033[K\r\n")
		lines++
	}
	foot := "? help  q quit"
	switch {
	case v.confirm != nil:
		foot = "\033[1;33m" + v.confirm.label + "? press y to confirm, any other key cancels\033[0m"
	case v.status != "":
		foot = v.status + "   (" + foot + ")"
	}
	buf.WriteString(clip(foot, w) + "\033[K")
}

func (v *pgTopView) renderFleet(line func(string, ...any), st *ClusterState, now time.Time) {
	rows := pgOverview(st, now)
	if len(rows) == 0 {
		line("")
		line("  no postgres clusters (ziroctl pg create <name>)")
		return
	}
	line("")
	line("\033[7m  %-16s %-3s %-9s %-12s %-6s %-8s %-8s %-5s %-5s %-14s %s\033[0m", "NAME", "PG", "HEALTH", "PRIMARY", "READY", "LAG", "TPS", "CONN", "DISK", "BACKUP", "ALERTS")
	for i, r := range rows {
		tps := 0.0
		for k, x := range v.tps {
			if strings.HasPrefix(k, r.Name+"/") {
				tps += x
			}
		}
		backup := "off"
		if r.Backups {
			backup = "none yet"
			if t, err := time.Parse(time.RFC3339, r.LastBackup); err == nil {
				backup = strings.TrimSuffix(dockerHumanDuration(now.Sub(t)), " ago") + " ago"
			}
		}
		mark := "  "
		if i == v.sel {
			mark = "\033[1m> "
		}
		line("%s%-16s %-3s %s%-9s\033[0m %-12s %-6s %-8s %-8.1f %-5s %-5s %-14s %d\033[0m", mark, r.Name, r.Version, pgTopHealth[r.Health], r.Health,
			r.Primary, fmt.Sprintf("%d/%d", r.Ready, r.Members), (time.Duration(r.MaxLagMs) * time.Millisecond).String(), tps,
			fmt.Sprintf("%d%%", r.ConnPct), fmt.Sprintf("%d%%", r.DiskPct), clip(backup, 14), r.Alerts24h)
	}
	first := true
	for _, r := range rows {
		for _, a := range r.Attention {
			if first {
				line("")
				line("\033[1mNeeds attention\033[0m")
				first = false
			}
			line("  \033[33m!\033[0m %s: %s", r.Name, a)
		}
	}
}

func (v *pgTopView) renderCluster(line func(string, ...any), st *ClusterState, c *PGCluster, now time.Time) {
	o := pgOverviewOf(st, c, now)
	line("PostgreSQL %s, %s replication, health %s%s\033[0m, %d alert(s) in 24h", c.Version, c.Sync, pgTopHealth[o.Health], o.Health, o.Alerts24h)
	if w := pgWindowLabel(c, now); w != "" {
		line("maintenance window: %s", w)
	}
	line("")
	line("\033[7m  %-5s %-5s %-14s %-9s %-12s %-9s %-8s %-11s %-5s %s\033[0m", "GROUP", "ID", "NODE", "ROLE", "STATE", "LAG", "TPS", "CONN", "DISK", "TIMELINE")
	for i, m := range pgTopMembers(st, c, now) {
		mark := "  "
		if i == v.sel {
			mark = "\033[1m> "
		}
		lag := "-"
		if m.member.Role != pgPrimary && m.view.LSN != "" {
			lag = (time.Duration(m.view.LagMs) * time.Millisecond).String()
		}
		conn := "-"
		if p := m.member.Probe; p.OK && p.MaxConns > 0 {
			conn = fmt.Sprintf("%d/%d", p.Conns, p.MaxConns)
		}
		state := m.view.State
		color := map[string]string{"ready": "\033[32m", "catching-up": "\033[33m", "down": "\033[31m"}[state]
		line("%s%-5s %-5s %-14s %-9s %s%-12s\033[0m %-9s %-8.1f %-11s %-5s %d\033[0m", mark, m.group, m.id, m.member.Node, m.member.Role, color, state, lag,
			v.tps[c.Name+"/"+m.group+"/"+m.id], conn, fmt.Sprintf("%d%%", m.member.Probe.DiskPct), m.member.Probe.Timeline)
	}
	if len(o.Attention) > 0 {
		line("")
		line("\033[1mNeeds attention\033[0m")
		for _, a := range o.Attention {
			line("  \033[33m!\033[0m %s", a)
		}
	}
	events := pgEventsOf(c, "", time.Time{})
	if len(events) > 8 {
		events = events[len(events)-8:]
	}
	line("")
	line("\033[1mEvents\033[0m")
	for _, e := range events {
		line("  %s", pgEventLine(e))
	}
}

// pgTopKeys turns raw terminal bytes into key names (arrows are escape sequences).
func pgTopKeys(in <-chan byte, out chan<- string) {
	defer close(out)
	for b := range in {
		if b != 27 {
			switch b {
			case '\r', '\n':
				out <- "enter"
			default:
				out <- string(rune(b))
			}
			continue
		}
		select {
		case b2, ok := <-in:
			if !ok {
				out <- "esc"
				return
			}
			if b2 != '[' {
				out <- "esc"
				continue
			}
			b3, ok := <-in
			if !ok {
				return
			}
			if k, known := map[byte]string{'A': "up", 'B': "down", 'C': "right", 'D': "left"}[b3]; known {
				out <- k
			}
		case <-time.After(50 * time.Millisecond):
			out <- "esc"
		}
	}
}

var pgTopCmd = &cobra.Command{
	Use:   "top [name]",
	Short: "Live view of the clusters in the terminal",
	Long: `A live view, refreshed every 2 seconds: the fleet (as pg overview, with transactions per second), and with
Enter a cluster's members, what needs attention and its latest events. Keys: ↑/↓ select, Enter open, Esc back,
s switchover, r rebuild a replica, a add a replica, b back up now, p pause or resume, ? help, q quit. Every action
asks for confirmation. Without a terminal it prints pg overview once.`,
	Example: "  ziroctl pg top\n  ziroctl pg top shop",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		fd := int(os.Stdin.Fd())
		if jsonOutput || !term.IsTerminal(fd) || !term.IsTerminal(int(os.Stdout.Fd())) {
			return pgOverviewCmd.RunE(cmd, nil)
		}
		v := newPGTopView()
		st, err := readState()
		if err != nil {
			return err
		}
		if len(args) == 1 {
			if _, err := pgCluster(st, args[0]); err != nil {
				return err
			}
			v.cluster = args[0]
		}
		v.sample(st, time.Now())
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, old)
		fmt.Print("\033[?1049h\033[?25l") // alternate screen, hide cursor
		defer fmt.Print("\033[?25h\033[?1049l")
		raw := make(chan byte, 16)
		go func() {
			b := make([]byte, 1)
			for {
				if n, err := os.Stdin.Read(b); err != nil || n == 0 {
					close(raw)
					return
				}
				raw <- b[0]
			}
		}()
		keys := make(chan string, 16)
		go pgTopKeys(raw, keys)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(sig)
		tick := time.NewTicker(pgTopInterval)
		defer tick.Stop()
		var buf bytes.Buffer
		draw := func() {
			w, h, err := term.GetSize(fd)
			if err != nil {
				w, h = 120, 40
			}
			v.render(&buf, st, time.Now(), w, h)
			os.Stdout.Write(buf.Bytes())
		}
		draw()
		for {
			select {
			case <-sig:
				return nil
			case <-tick.C:
				if next, err := readState(); err == nil {
					st = next
					v.sample(st, time.Now())
				} else {
					v.status = "reading the cluster state: " + err.Error()
				}
			case k, ok := <-keys:
				if !ok || v.key(k, st, time.Now()) {
					return nil
				}
				if next, err := readState(); err == nil {
					st = next
				}
			}
			draw()
		}
	},
}

func init() {
	pgCmd.AddCommand(pgTopCmd)
}

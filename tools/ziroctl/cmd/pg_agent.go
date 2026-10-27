package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The agent side of the Postgres controller (RFC 0005): probe the member containers on this node and
// carry out the master's orders. The orders are a closed list (pg_controller.go); every argument has
// been validated by the master and is validated again here, and the SQL is built from fixed
// templates, never from free text.

const (
	pgProbeEvery = 5 * time.Second
	pgPgCtl      = "pg_ctl"
	pgDataDirIn  = pgDataPath + "/pgdata" // PGDATA inside the member container
)

// pgRunner runs nerdctl; tests replace it.
type pgRunner func(ctx context.Context, argv ...string) (string, error)

var pgNerdctl pgRunner = func(ctx context.Context, argv ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "nerdctl", argv...).CombinedOutput()
	return string(out), err
}

// psqlArgs is `nerdctl exec` of psql in a member, one -c per statement.
func psqlArgs(container string, sqls ...string) []string {
	return psqlDB(container, "postgres", sqls...)
}

// psqlDB is psqlArgs in a named database.
func psqlDB(container, db string, sqls ...string) []string {
	args := []string{"exec", "-u", "postgres", container, "psql", "-X", "-U", "postgres", "-d", db,
		"-v", "ON_ERROR_STOP=1", "-A", "-t", "-q", "-F", "|"}
	for _, s := range sqls {
		args = append(args, "-c", s)
	}
	return args
}

// pgProbeSQL reads, in one row: recovery state, WAL position, timeline, whether a WAL receiver is
// streaming, and how far behind the replay is.
const pgProbeSQL = `select pg_is_in_recovery()::int,
  case when pg_is_in_recovery() then coalesce(pg_last_wal_replay_lsn(), pg_last_wal_receive_lsn()) else pg_current_wal_lsn() end,
  case when pg_is_in_recovery() then coalesce((select received_tli from pg_stat_wal_receiver), 0)
       else ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::int end,
  exists (select from pg_stat_wal_receiver where status = 'streaming')::int,
  case when pg_is_in_recovery() and pg_last_wal_receive_lsn() is distinct from pg_last_wal_replay_lsn()
       then coalesce((extract(epoch from now() - pg_last_xact_replay_timestamp()) * 1000)::bigint, 0) else 0 end,
  (current_setting('default_transaction_read_only') = 'on')::int`

// parseProbe reads the row pgProbeSQL returns.
func parseProbe(out string) (PGReport, error) {
	line := strings.TrimSpace(out)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	f := strings.Split(line, "|")
	if len(f) == 5 { // an older probe without the read-only column
		f = append(f, "0")
	}
	if len(f) != 6 {
		return PGReport{}, fmt.Errorf("unexpected probe output %q", line)
	}
	tli, err1 := strconv.Atoi(f[2])
	lag, err2 := strconv.ParseInt(f[4], 10, 64)
	if _, err := parseLSN(f[1]); err != nil || err1 != nil || err2 != nil || (f[0] != "0" && f[0] != "1") || (f[5] != "0" && f[5] != "1") {
		return PGReport{}, fmt.Errorf("unexpected probe output %q", line)
	}
	return PGReport{OK: true, Recovery: f[0] == "1", LSN: f[1], Timeline: tli, Streaming: f[3] == "1", LagMs: lag, ReadOnly: f[5] == "1"}, nil
}

// pgProbe asks one member how it is.
func pgProbe(ctx context.Context, run pgRunner, container string) (PGReport, error) {
	out, err := run(ctx, psqlArgs(container, pgProbeSQL)...)
	if err != nil {
		return PGReport{}, fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return parseProbe(out)
}

// ---- orders ----

const (
	sqlReload    = "select pg_reload_conf()"
	sqlResetRO   = "alter system reset default_transaction_read_only"
	sqlSetRO     = "alter system set default_transaction_read_only = on"
	sqlEndClient = "select pg_terminate_backend(pid) from pg_stat_activity where backend_type = 'client backend' and pid <> pg_backend_pid()"
)

// pgSteps turns an order into the nerdctl invocations that carry it out.
func pgSteps(o PGOrder) ([][]string, error) {
	if err := validPGCommand(o.Op, o.Arg); err != nil {
		return nil, err
	}
	c := o.Container
	ctl := func(args ...string) []string {
		return append([]string{"exec", "-u", "postgres", c, pgPgCtl}, args...)
	}
	switch o.Op {
	case opPromote:
		return [][]string{ctl("promote", "-D", pgDataDirIn, "-w", "-t", "60"), psqlArgs(c, sqlResetRO, sqlReload)}, nil
	case opReinit:
		// Only a replica is rebuilt: the first statement divides by zero on a member that is not in
		// recovery, and ON_ERROR_STOP ends the order before anything is touched. The marker makes the
		// entry script take a new base backup when the container comes back.
		return [][]string{psqlArgs(c, "select 1 / (select pg_is_in_recovery()::int)"),
			{"exec", "-u", "postgres", c, "touch", pgDataDirIn + "/ziro-reinit"},
			ctl("stop", "-m", "fast", "-D", pgDataDirIn, "-w", "-t", "60")}, nil
	case opReadonly:
		return [][]string{psqlArgs(c, sqlSetRO, sqlReload, sqlEndClient)}, nil
	case opWritable:
		return [][]string{psqlArgs(c, sqlResetRO, sqlReload)}, nil
	case opDemote:
		// Read-only first, so nothing more is accepted while it stops; the runtime restarts the
		// container, and the entry script brings it back as a replica.
		return [][]string{psqlArgs(c, sqlSetRO, sqlReload, sqlEndClient), ctl("stop", "-m", "fast", "-D", pgDataDirIn, "-w", "-t", "60")}, nil
	case opSetSync:
		set := "alter system reset synchronous_standby_names"
		if o.Arg != "" {
			set = "alter system set synchronous_standby_names = '" + o.Arg + "'"
		}
		return [][]string{psqlArgs(c, set, sqlReload)}, nil
	case opSlots:
		var sqls []string
		for _, s := range strings.Split(o.Arg, ",") {
			if s != "" {
				sqls = append(sqls, "select pg_create_physical_replication_slot('"+s+"') where not exists (select from pg_replication_slots where slot_name = '"+s+"')")
			}
		}
		if len(sqls) == 0 {
			return nil, nil
		}
		return [][]string{psqlArgs(c, sqls...)}, nil
	case opDropSlot:
		return [][]string{psqlArgs(c, "select pg_drop_replication_slot(slot_name) from pg_replication_slots where slot_name = '"+o.Arg+"' and not active")}, nil
	}
	return citusSteps(o)
}

// pgExecute runs an order. The container name comes from the master: it must be a cluster container
// of this node's own naming scheme.
func pgExecute(ctx context.Context, run pgRunner, o PGOrder) error {
	if !strings.HasPrefix(o.Container, "zc-"+pgAppPrefix) || strings.ContainsAny(o.Container, " /\t\n") {
		return fmt.Errorf("not a Postgres member container")
	}
	steps, err := pgSteps(o)
	if err != nil {
		return err
	}
	if o.Op == opReinit {
		// The first step proves the member is a replica. When the container does not answer at all (it is
		// crash-looping, or never started) there is nothing to ask: leave the marker on the data directory
		// instead, which is what a rebuild is for.
		out, err := run(ctx, steps[0]...)
		switch {
		case err == nil:
			steps = steps[1:]
		case strings.Contains(out, "division by zero"):
			return fmt.Errorf("reinit: not a replica: a primary is never rebuilt")
		default:
			return pgReinitOffline(ctx, run, o)
		}
	}
	for _, argv := range steps {
		if out, err := run(ctx, argv...); err != nil {
			// Stopping Postgres ends the container's exec session: that is the order succeeding.
			if (o.Op == opDemote || o.Op == opReinit) && len(argv) > 4 && argv[4] == pgPgCtl {
				continue
			}
			return fmt.Errorf("%s: %v: %s", o.Op, err, condenseRuntimeError(lastOutputLine(out)))
		}
	}
	return nil
}

// pgReinitOffline asks for a rebuild of a member whose container cannot be asked: the entry script finds
// the marker when the container next starts, and a container that is up but stuck is restarted to do so.
func pgReinitOffline(ctx context.Context, run pgRunner, o PGOrder) error {
	if err := validName(o.App); err != nil || !strings.HasPrefix(o.App, pgAppPrefix) || o.Index < 0 || o.Index > 99 {
		return fmt.Errorf("reinit: not a Postgres member")
	}
	dir := filepath.Join(dataDir(o.App, o.Index, pgDataPath), "pgdata")
	if _, err := os.Stat(dir); err != nil {
		return nil // never had a data directory: the first start takes a base backup anyway
	}
	if err := os.WriteFile(filepath.Join(dir, "ziro-reinit"), nil, 0600); err != nil {
		return fmt.Errorf("reinit: %v", err)
	}
	run(ctx, "restart", "-t", "20", o.Container) // best effort: a container that does not exist yet starts with the marker in place
	return nil
}

// pgWhy is what this node can say about a member that does not answer: whether a copy is running (so it
// is not stuck), the container's state, and the entry script's last error or the last line of its log.
func pgWhy(ctx context.Context, run pgRunner, a Assignment, now time.Time) (detail string, busy bool) {
	dir := dataDir(a.App, a.Replica, pgDataPath)
	if fi, err := os.Stat(filepath.Join(dir, "ziro-busy")); err == nil && now.Sub(fi.ModTime()) < 45*time.Second {
		busy = true
	}
	state, err := run(ctx, "inspect", "-f", "{{.State.Status}} (exit {{.State.ExitCode}})", a.Name)
	if err != nil {
		return "the container does not exist yet", busy
	}
	detail = "container " + strings.TrimSpace(lastOutputLine(state))
	if b, err := os.ReadFile(filepath.Join(dir, "ziro-last-error")); err == nil && len(b) > 0 {
		return detail + ": " + strings.TrimSpace(string(b)), busy
	}
	if out, err := run(ctx, "logs", "--tail", "1", a.Name); err == nil {
		if l := strings.TrimSpace(lastOutputLine(out)); l != "" {
			detail += ": " + l
		}
	}
	return detail, busy
}

func lastOutputLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// ---- the agent's part ----

type pgAgent struct {
	mu      sync.Mutex
	reports map[string]pgStamped // member app -> last probe
	results map[string]pgDone    // order id -> outcome, resent until the master stops sending the order
	seen    map[string]time.Time // orders already started
	run     pgRunner
	exec    sync.Mutex // one order at a time on this node
}

type pgStamped struct {
	r      PGReport
	at     time.Time
	detail string
	busy   bool
}

type pgDone struct {
	r  PGResult
	at time.Time
}

func newPGAgent() *pgAgent {
	return &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: pgNerdctl}
}

// probeAll probes the member containers this node should run.
func (p *pgAgent) probeAll(ctx context.Context, desired []Assignment, now time.Time) {
	for _, a := range desired {
		if !a.PG {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		r, err := pgProbe(cctx, p.run, a.Name)
		cancel()
		r.App = a.App
		if err != nil {
			r = PGReport{App: a.App}
		}
		p.mu.Lock()
		if cur, ok := p.reports[a.App]; err != nil && ok {
			// A failed probe keeps the last good one (with its age): the master judges by age.
			r = cur.r
			p.reports[a.App] = pgStamped{r: r, at: cur.at}
		} else {
			p.reports[a.App] = pgStamped{r: r, at: now}
		}
		p.mu.Unlock()
	}
}

// report is what goes into a heartbeat: each member's last good probe with its age, and the order
// outcomes.
func (p *pgAgent) report(now time.Time) ([]PGReport, []PGResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var reps []PGReport
	for app, s := range p.reports {
		r := s.r
		r.App, r.AgeMs, r.Detail, r.Busy = app, now.Sub(s.at).Milliseconds(), s.detail, s.busy
		reps = append(reps, r)
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].App < reps[j].App })
	var res []PGResult
	for id, d := range p.results {
		if now.Sub(d.at) > 10*time.Minute {
			delete(p.results, id)
			continue
		}
		res = append(res, d.r)
	}
	for id, t := range p.seen {
		if now.Sub(t) > 10*time.Minute {
			delete(p.seen, id)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return reps, res
}

// submit starts the orders this agent has not seen yet.
func (p *pgAgent) submit(ctx context.Context, orders []PGOrder, now time.Time) {
	for _, o := range orders {
		p.mu.Lock()
		_, dup := p.seen[o.ID]
		if !dup {
			p.seen[o.ID] = now
		}
		p.mu.Unlock()
		if dup {
			continue
		}
		go func(o PGOrder) {
			p.exec.Lock()
			defer p.exec.Unlock()
			octx, cancel := context.WithTimeout(ctx, pgCommandTimeout-5*time.Second)
			defer cancel()
			err := pgExecute(octx, p.run, o)
			res := PGResult{ID: o.ID, OK: err == nil}
			if err != nil {
				res.Msg = err.Error()
			}
			p.mu.Lock()
			p.results[o.ID] = pgDone{r: res, at: time.Now()}
			p.mu.Unlock()
		}(o)
	}
}

// loop probes until ctx ends. desired reads the node's current assignments.
func (p *pgAgent) loop(ctx context.Context, desired func() []Assignment) {
	t := time.NewTicker(pgProbeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.probeAll(ctx, desired(), now)
		}
	}
}

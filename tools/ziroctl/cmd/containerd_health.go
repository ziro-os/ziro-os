package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// containerd health and recovery.
//
// containerd can be alive and still not serve: its accept queue fills (a descriptor limit reached, a
// flood of clients, a stalled disk), so a client's connect() fails with EAGAIN ("resource temporarily
// unavailable"), or it accepts and never answers. ziro-init restarts a daemon only when it exits, so
// such a daemon used to stay wedged for good. This file tells the states apart with a real request,
// and restarts a wedged containerd (keeping the evidence). Workloads are not touched: every container
// has its own shim, and a restarted containerd re-attaches to them.

type ctrdState string

const (
	ctrdOK      ctrdState = "ok"      // answers requests
	ctrdLoading ctrdState = "loading" // started moments ago, not serving yet
	ctrdBusy    ctrdState = "busy"    // listening, but the accept queue is full (EAGAIN)
	ctrdHung    ctrdState = "hung"    // accepts connections and never answers
	ctrdDown    ctrdState = "down"    // nothing is listening
)

type ctrdStatus struct {
	State  ctrdState
	Reason string
	PID    int           // the containerd process, 0 if none was found
	Age    time.Duration // how long it has been running (the pidfile init writes at spawn)
}

func (s ctrdStatus) ok() bool { return s.State == ctrdOK }

// Variables so tests can point them at a fixture.
var (
	containerdSock    = containerdSocket
	containerdPIDFile = "/run/containerd/containerd.pid"
	containerdLogFile = "/var/log/containerd.log"
	ctrdLoadingGrace  = 60 * time.Second
	ctrdDialTimeout   = 2 * time.Second
	ctrdCallTimeout   = 3 * time.Second
)

// probeContainerdSocket makes one real request: connect (a full accept queue is EAGAIN, a dead daemon
// ECONNREFUSED or ENOENT), then containerd's Version call, so a daemon that accepts and never answers
// is not mistaken for a healthy one.
func probeContainerdSocket(sock string) (ctrdState, string) {
	conn, err := net.DialTimeout("unix", sock, ctrdDialTimeout)
	if err != nil {
		var ne net.Error
		switch {
		case errors.Is(err, syscall.EAGAIN):
			return ctrdBusy, "it is running but not accepting connections (its accept queue is full)"
		case errors.As(err, &ne) && ne.Timeout():
			return ctrdBusy, "connecting timed out"
		case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, os.ErrNotExist):
			return ctrdDown, "nothing is listening on " + sock
		}
		return ctrdDown, err.Error()
	}
	_ = conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), ctrdCallTimeout)
	defer cancel()
	c := newCtrdClient(sock, containerdNamespace())
	defer c.http.CloseIdleConnections()
	if _, err := c.call(ctx, "/containerd.services.version.v1.Version/Version", nil); err != nil {
		var ce *ctrdError
		if errors.As(err, &ce) { // it answered, with an error status: it is serving
			return ctrdOK, ""
		}
		return ctrdHung, "it accepts connections but does not answer requests"
	}
	return ctrdOK, ""
}

// containerdProc finds the containerd process and how long it has run. Init writes the pidfile when it
// spawns the daemon, so the file's age is the daemon's age; without it the age is unknown and never
// treated as "just started".
func containerdProc() (pid int, age time.Duration) {
	def, err := loadServiceDef("containerd")
	if err != nil {
		return 0, 0
	}
	pid = getServicePID(def)
	if pid <= 0 {
		return 0, 0
	}
	age = ctrdLoadingGrace
	if fi, err := os.Stat(containerdPIDFile); err == nil {
		age = time.Since(fi.ModTime())
	}
	return pid, age
}

// containerdStatus is the one place that says whether containerd works.
func containerdStatus() ctrdStatus {
	st, why := probeContainerdSocket(containerdSock)
	s := ctrdStatus{State: st, Reason: why}
	s.PID, s.Age = containerdProc()
	if s.State != ctrdOK && s.PID > 0 && s.Age < ctrdLoadingGrace {
		s.State = ctrdLoading
		s.Reason = fmt.Sprintf("started %s ago and is not serving yet", s.Age.Round(time.Second))
	}
	return s
}

// containerdResponds is the node agent's and doctor's yes/no.
func containerdResponds() error {
	if s := containerdStatus(); !s.ok() {
		return fmt.Errorf("containerd is %s: %s", s.State, s.Reason)
	}
	return nil
}

// ctrdWedged: a daemon that is running but serves nobody. A down socket with a live process counts
// too (a process that never created its socket, or lost it), once it has had time to start.
func ctrdWedged(s ctrdStatus) bool {
	switch s.State {
	case ctrdBusy, ctrdHung:
		return true
	case ctrdDown:
		return s.PID > 0
	}
	return false
}

// ---- recovery policy ----

const (
	ctrdRecoveriesPerHour = 3
	ctrdStopGrace         = 8 * time.Second // SIGTERM, then SIGQUIT (every goroutine's stack into the log), then SIGKILL
	ctrdQuitGrace         = 3 * time.Second
	ctrdKillGrace         = 5 * time.Second
)

// Variables so tests can shorten them.
var (
	ctrdRestartWait  = 60 // polls, waiting for init to bring it back
	ctrdRestartPoll  = time.Second
	ctrdRecoveryFile = "/run/ziro/containerd-recovery.json"
	ctrdLockFile     = "/run/ziro/containerd-recovery.lock"
	ctrdProbes       = 3 // consecutive wedged probes before acting
	ctrdProbeGap     = 7 * time.Second
)

// ctrdRecoveryHold says how long to wait before another recovery, and why: at most three an hour,
// spaced further apart each time, so a daemon that wedges again at once is reported, not restarted
// in a loop.
func ctrdRecoveryHold(times []time.Time, now time.Time) (time.Duration, string) {
	var recent []time.Time
	for _, t := range times {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		return 0, ""
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].Before(recent[j]) })
	last := recent[len(recent)-1]
	if len(recent) >= ctrdRecoveriesPerHour {
		return recent[0].Add(time.Hour).Sub(now), fmt.Sprintf("it was already restarted %d times in the last hour", len(recent))
	}
	gap := map[int]time.Duration{1: 5 * time.Minute, 2: 15 * time.Minute}[len(recent)]
	if wait := last.Add(gap).Sub(now); wait > 0 {
		return wait, fmt.Sprintf("it was restarted %s ago", now.Sub(last).Round(time.Second))
	}
	return 0, ""
}

type ctrdRecoveries struct {
	Times []time.Time `json:"times"`
}

func loadCtrdRecoveries(path string) ctrdRecoveries {
	var r ctrdRecoveries
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &r)
	}
	return r
}

// ctrdDeps are the effects of a recovery, injectable for tests.
type ctrdDeps struct {
	now      func() time.Time
	sleep    func(time.Duration)
	status   func() ctrdStatus
	stopped  func() bool // stopped on purpose (ziroctl service stop containerd)
	signal   func(pid int, sig syscall.Signal) error
	gone     func(pid int, d time.Duration) bool
	incident func(st ctrdStatus) (after func()) // saves the evidence; after() saves the log once it has exited
	lock     func() (unlock func(), err error)
	note     func(ctrdState)
	recFile  string
	probes   int // consecutive wedged probes before acting
	gap      time.Duration
}

func realCtrdDeps() ctrdDeps {
	return ctrdDeps{
		now:      time.Now,
		sleep:    time.Sleep,
		status:   containerdStatus,
		stopped:  func() bool { return fileExists(filepath.Join(stopMarkerDir, "containerd")) },
		signal:   func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) },
		gone:     waitGone,
		incident: captureCtrdIncident,
		lock:     lockCtrdRecovery,
		note:     noteContainerdState,
		recFile:  ctrdRecoveryFile,
		probes:   ctrdProbes,
		gap:      ctrdProbeGap,
	}
}

func lockCtrdRecovery() (func(), error) {
	_ = os.MkdirAll(filepath.Dir(ctrdLockFile), 0o755)
	f, err := os.OpenFile(ctrdLockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another containerd recovery is running")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// ensureContainerd restarts containerd when it is running but wedged. It returns what it did ("" when
// there was nothing to do) or why it did not. force (doctor --fix) acts after two probes and ignores
// the hourly limit.
func ensureContainerd(force bool) (string, error) {
	d := realCtrdDeps()
	if force {
		d.probes, d.gap = 2, 2*time.Second
	}
	return ctrdEnsure(d, force)
}

func ctrdEnsure(d ctrdDeps, force bool) (string, error) {
	st := d.status()
	d.note(st.State)
	if !ctrdWedged(st) || d.stopped() {
		return "", nil
	}
	for i := 1; i < d.probes; i++ { // a busy moment is not a wedge: it has to stay wedged
		d.sleep(d.gap)
		if st = d.status(); !ctrdWedged(st) {
			d.note(st.State)
			return "", nil
		}
	}
	if st.PID <= 1 {
		return "", fmt.Errorf("containerd is %s (%s) but no containerd process was found to restart", st.State, st.Reason)
	}
	unlock, err := d.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	rec := loadCtrdRecoveries(d.recFile)
	now := d.now()
	if wait, why := ctrdRecoveryHold(rec.Times, now); wait > 0 && !force {
		return "", fmt.Errorf("containerd is %s (%s); not restarted again for %s: %s", st.State, st.Reason, wait.Round(time.Second), why)
	}
	var keep []time.Time
	for _, t := range rec.Times {
		if now.Sub(t) < 24*time.Hour {
			keep = append(keep, t)
		}
	}
	rec.Times = append(keep, now)
	if b, err := json.Marshal(rec); err == nil {
		_ = writeFileAtomic(d.recFile, b, 0o600) // recorded before the kill: a crash here still counts
	}

	after := d.incident(st)
	_ = d.signal(st.PID, syscall.SIGTERM)
	if !d.gone(st.PID, ctrdStopGrace) {
		_ = d.signal(st.PID, syscall.SIGQUIT) // a Go program prints every goroutine's stack to stderr: containerd's log
		if !d.gone(st.PID, ctrdQuitGrace) {
			_ = d.signal(st.PID, syscall.SIGKILL)
			if !d.gone(st.PID, ctrdKillGrace) {
				after()
				return "", fmt.Errorf("containerd (PID %d) did not exit", st.PID)
			}
		}
	}
	after()
	for i := 0; i < ctrdRestartWait; i++ { // ziro-init restarts it as soon as it exits
		d.sleep(ctrdRestartPoll)
		if s := d.status(); s.ok() {
			d.note(ctrdOK)
			return fmt.Sprintf("restarted containerd (it was %s: %s)", st.State, st.Reason), nil
		}
	}
	return fmt.Sprintf("restarted containerd (it was %s); it is not answering yet", st.State), nil
}

// ---- state file the pollers read ----

var ctrdStateFile = "/run/ziro/containerd.state"

const ctrdStateTTL = 90 * time.Second

func noteContainerdState(s ctrdState) {
	_ = os.MkdirAll(filepath.Dir(ctrdStateFile), 0o755)
	_ = writeFileAtomic(ctrdStateFile, []byte(string(s)+"\n"), 0o644)
}

var errContainerdSick = errors.New("the container runtime is not accepting connections and is being recovered")

// containerdSick reports a recent verdict that containerd is busy or hung. Platform pollers (health
// checks, Postgres probes, the cluster agent) skip their containerd calls then, instead of adding
// connections to a daemon that is not accepting them. A missing or old verdict is "not sick".
func containerdSick() bool {
	fi, err := os.Stat(ctrdStateFile)
	if err != nil || time.Since(fi.ModTime()) > ctrdStateTTL {
		return false
	}
	b, _ := os.ReadFile(ctrdStateFile)
	s := ctrdState(strings.TrimSpace(string(b)))
	return s == ctrdBusy || s == ctrdHung
}

// ---- incident bundles ----

var ctrdIncidentDir = "/var/log/ziro/containerd-incidents"

const ctrdIncidentKeep = 10

// captureCtrdIncident saves what is needed to find out why containerd wedged, before it is restarted:
// limits, descriptor use by kind, kernel pressure, the socket's queue. The returned function saves the
// tail of containerd's own log (which holds the goroutine dump when SIGQUIT was needed). Nothing here
// reads the environment or the memory of any process.
func captureCtrdIncident(st ctrdStatus) func() {
	dir := filepath.Join(ctrdIncidentDir, time.Now().UTC().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}
	}
	pruneCtrdIncidents(ctrdIncidentDir, ctrdIncidentKeep)
	write := func(name string, data []byte) { _ = os.WriteFile(filepath.Join(dir, name), data, 0o600) }
	proc := fmt.Sprintf("/proc/%d", st.PID)
	limits, _ := os.ReadFile(proc + "/limits")
	var targets []string
	if ents, err := os.ReadDir(proc + "/fd"); err == nil {
		for _, e := range ents {
			if t, err := os.Readlink(filepath.Join(proc, "fd", e.Name())); err == nil {
				targets = append(targets, t)
			}
		}
	}
	summary := fmt.Sprintf("state: %s\nreason: %s\npid: %d\nuptime: %s\nopen files: %d\n", st.State, st.Reason, st.PID, st.Age.Round(time.Second), len(targets))
	if hint := ctrdFDHint(string(limits), len(targets)); hint != "" {
		summary += "cause: " + hint + "\n"
	}
	write("summary.txt", []byte(summary))
	write("proc-limits", limits)
	write("fds.txt", []byte(summariseFDTargets(targets)))
	for _, f := range []string{"status", "io", "stat"} {
		if b, err := os.ReadFile(proc + "/" + f); err == nil {
			write("proc-"+f, b)
		}
	}
	var sys strings.Builder
	for _, f := range []string{"/proc/pressure/memory", "/proc/pressure/io", "/proc/pressure/cpu", "/proc/loadavg", "/proc/sys/fs/file-nr"} {
		if b, err := os.ReadFile(f); err == nil {
			fmt.Fprintf(&sys, "== %s\n%s\n", f, b)
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.SplitN(string(b), "\n", 9)
		fmt.Fprintf(&sys, "== /proc/meminfo\n%s\n", strings.Join(lines[:min(len(lines), 8)], "\n"))
	}
	write("system.txt", []byte(sys.String()))
	if ss, err := exec.LookPath("ss"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, _ := exec.CommandContext(ctx, ss, "-xl").CombinedOutput() // Recv-Q is the accept queue
		cancel()
		write("socket-queue.txt", out)
	}
	return func() {
		if b, err := os.ReadFile(containerdLogFile); err == nil {
			if len(b) > 256<<10 {
				b = b[len(b)-256<<10:]
			}
			write("containerd.log.tail", b)
		}
	}
}

// ctrdFDHint names the cause when the descriptor count is at the limit.
func ctrdFDHint(limits string, open int) string {
	if soft, ok := ctrdOpenFilesLimit(limits); ok && soft > 0 && open*10 >= soft*9 {
		return fmt.Sprintf("open files %d of %d: the descriptor limit is reached, so accept() fails and the queue fills", open, soft)
	}
	return ""
}

// ctrdOpenFilesLimit reads the soft "Max open files" from /proc/<pid>/limits.
func ctrdOpenFilesLimit(limits string) (int, bool) {
	for _, l := range strings.Split(limits, "\n") {
		if strings.HasPrefix(l, "Max open files") {
			f := strings.Fields(strings.TrimPrefix(l, "Max open files"))
			if len(f) >= 1 {
				if f[0] == "unlimited" {
					return 1 << 30, true
				}
				if n, err := strconv.Atoi(f[0]); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// summariseFDTargets counts descriptors by kind (sockets, pipes, anonymous inodes, files by directory).
func summariseFDTargets(targets []string) string {
	count := map[string]int{}
	for _, t := range targets {
		k := t
		switch {
		case strings.HasPrefix(t, "socket:"):
			k = "socket"
		case strings.HasPrefix(t, "pipe:"):
			k = "pipe"
		case strings.HasPrefix(t, "/"):
			parts := strings.Split(strings.TrimPrefix(t, "/"), "/")
			k = "/" + strings.Join(parts[:min(len(parts)-1, 4)], "/")
		}
		count[k]++
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var b strings.Builder
	fmt.Fprintf(&b, "total %d\n", len(targets))
	for _, k := range keys[:min(len(keys), 25)] {
		fmt.Fprintf(&b, "%6d  %s\n", count[k], k)
	}
	return b.String()
}

func pruneCtrdIncidents(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) <= keep {
		return
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // timestamps sort by age
	for len(names) > keep-1 {
		_ = os.RemoveAll(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

// ctrdIncident is one saved recovery.
type ctrdIncident struct {
	Time   time.Time
	State  string
	Reason string
	Cause  string
}

// recentCtrdIncidents lists the recoveries since the given time, oldest first.
func recentCtrdIncidents(dir string, since time.Time) []ctrdIncident {
	ents, _ := os.ReadDir(dir)
	var out []ctrdIncident
	for _, e := range ents {
		t, err := time.Parse("20060102-150405", e.Name())
		if err != nil || t.Before(since) {
			continue
		}
		in := ctrdIncident{Time: t}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name(), "summary.txt")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				switch k, v, _ := strings.Cut(l, ": "); k {
				case "state":
					in.State = v
				case "reason":
					in.Reason = v
				case "cause":
					in.Cause = v
				}
			}
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// ---- doctor ----

// containerdChecks is doctor's view of the container runtime: whether it answers, how often it had to
// be restarted lately and why, and whether its descriptor limit leaves room.
func containerdChecks() []doctorCheck {
	st := containerdStatus()
	noteContainerdState(st.State)
	c := doctorCheck{Name: "containerd responds", Fix: "restart the stuck containerd (running containers keep running)",
		fix: func() error { return restartDown("containerd") }}
	switch {
	case st.ok():
		c.Passed, c.Details, c.Fix = true, containerdSock, ""
	case st.State == ctrdLoading:
		c.Details, c.Fix, c.fix = "containerd is starting: "+st.Reason, "wait a minute and run doctor again", nil
	case st.State == ctrdDown && st.PID == 0:
		c.Details, c.Fix = "containerd is not running: "+st.Reason, "start containerd"
	default:
		c.Details = fmt.Sprintf("containerd is %s: %s", st.State, st.Reason)
	}
	checks := []doctorCheck{c}
	if n := len(recentCtrdIncidents(ctrdIncidentDir, time.Now().Add(-24*time.Hour))); n > 0 {
		last := recentCtrdIncidents(ctrdIncidentDir, time.Now().Add(-24*time.Hour))[n-1]
		d := fmt.Sprintf("restarted %d time(s) in 24 h; last at %s, it was %s", n, last.Time.Format("15:04:05"), last.State)
		if last.Cause != "" {
			d += " (" + last.Cause + ")"
		}
		checks = append(checks, doctorCheck{Name: "containerd restarts", Passed: false, Details: d + "; evidence in " + ctrdIncidentDir})
	}
	if st.PID > 0 {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", st.PID)); err == nil {
			if soft, ok := ctrdOpenFilesLimit(string(b)); ok {
				fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", st.PID))
				lim := doctorCheck{Name: "containerd open files", Passed: soft >= 65536, Details: fmt.Sprintf("%d of %d in use", len(fds), soft)}
				if !lim.Passed {
					lim.Details += " (low: it can stop accepting connections; reboot onto the current ziro-init, which raises the limit)"
				}
				checks = append(checks, lim)
			}
		}
	}
	return checks
}

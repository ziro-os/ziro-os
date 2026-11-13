package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// shortSock returns a socket path short enough for sun_path.
func shortSock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ctrd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "c.sock")
}

// saturate listens with a backlog of 1 and never accepts, then fills the queue: the state a containerd
// that has stopped accepting is in (connect fails with EAGAIN).
func saturate(t *testing.T, sock string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if err != nil {
			return
		}
		held = append(held, c)
	}
	t.Fatal("the accept queue did not fill")
}

func TestProbeClassifiesWhatContainerdIsDoing(t *testing.T) {
	// Not listening: down (a missing socket and a stale one alike).
	sock := shortSock(t)
	if st, _ := probeContainerdSocket(sock); st != ctrdDown {
		t.Fatalf("no socket: %s", st)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close() // the file stays: a stale socket
	if st, _ := probeContainerdSocket(sock); st != ctrdDown {
		t.Fatalf("stale socket: %s", st)
	}

	// Listening with a full queue: busy, the user's "resource temporarily unavailable".
	full := shortSock(t)
	saturate(t, full)
	st, why := probeContainerdSocket(full)
	if st != ctrdBusy || !strings.Contains(why, "accept queue is full") {
		t.Fatalf("full accept queue: %s %q", st, why)
	}

	// Accepts and never answers: hung.
	hung := shortSock(t)
	hl, err := net.Listen("unix", hung)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hl.Close() })
	go func() {
		for {
			c, err := hl.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	old := ctrdCallTimeout
	ctrdCallTimeout = 300 * time.Millisecond
	defer func() { ctrdCallTimeout = old }()
	if st, _ := probeContainerdSocket(hung); st != ctrdHung {
		t.Fatalf("accepts, never answers: %s", st)
	}

	// Answers (any gRPC status, even an error one, means it is serving): ok.
	f, sockOK := startFakeContainerd(t)
	_ = f
	if st, why := probeContainerdSocket(sockOK); st != ctrdOK {
		t.Fatalf("a serving containerd (unknown method is still an answer): %s %q", st, why)
	}
}

func TestProbeDoesNotMistakeAnotherServerForContainerd(t *testing.T) {
	// A listener that speaks HTTP/2 but not gRPC answers with a non-200 status: not "ok".
	sock := shortSock(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: &protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if st, _ := probeContainerdSocket(sock); st != ctrdHung {
		t.Fatalf("a non-gRPC answer is not a working containerd: %s", st)
	}
}

func TestWedgedMeansRunningButNotServing(t *testing.T) {
	cases := []struct {
		s    ctrdStatus
		want bool
	}{
		{ctrdStatus{State: ctrdOK, PID: 5}, false},
		{ctrdStatus{State: ctrdLoading, PID: 5}, false},
		{ctrdStatus{State: ctrdBusy, PID: 5}, true},
		{ctrdStatus{State: ctrdHung, PID: 5}, true},
		{ctrdStatus{State: ctrdDown}, false},        // not running: init and the start path handle it
		{ctrdStatus{State: ctrdDown, PID: 5}, true}, // running without a socket
	}
	for _, c := range cases {
		if got := ctrdWedged(c.s); got != c.want {
			t.Errorf("%+v: wedged %v, want %v", c.s, got, c.want)
		}
	}
}

func TestRecoveryHoldLimitsRestarts(t *testing.T) {
	now := time.Now()
	if w, _ := ctrdRecoveryHold(nil, now); w != 0 {
		t.Fatal("the first recovery is never held")
	}
	if w, _ := ctrdRecoveryHold([]time.Time{now.Add(-2 * time.Hour)}, now); w != 0 {
		t.Fatal("an old one does not count")
	}
	if w, why := ctrdRecoveryHold([]time.Time{now.Add(-time.Minute)}, now); w != 4*time.Minute || !strings.Contains(why, "restarted") {
		t.Fatalf("after one, 5 minutes apart: %v %q", w, why)
	}
	if w, _ := ctrdRecoveryHold([]time.Time{now.Add(-6 * time.Minute)}, now); w != 0 {
		t.Fatal("5 minutes after the first it may restart again")
	}
	two := []time.Time{now.Add(-30 * time.Minute), now.Add(-10 * time.Minute)}
	if w, _ := ctrdRecoveryHold(two, now); w != 5*time.Minute {
		t.Fatalf("after two, 15 minutes apart: %v", w)
	}
	three := []time.Time{now.Add(-50 * time.Minute), now.Add(-30 * time.Minute), now.Add(-20 * time.Minute)}
	w, why := ctrdRecoveryHold(three, now)
	if w != 10*time.Minute || !strings.Contains(why, "3 times in the last hour") {
		t.Fatalf("three an hour is the limit: %v %q", w, why)
	}
}

// fakeCtrd drives ctrdEnsure: a script of statuses and a record of what was done to the process.
type fakeCtrd struct {
	statuses []ctrdStatus // returned in turn, the last one repeated
	calls    int
	signals  []syscall.Signal
	exitOn   syscall.Signal // the signal that makes it exit (0: SIGTERM)
	slept    time.Duration
	notes    []ctrdState
	stopped  bool
	lockErr  error
	incident int
	after    int
	now      time.Time
	rec      string
}

func (f *fakeCtrd) deps(t *testing.T) ctrdDeps {
	if f.now.IsZero() {
		f.now = time.Unix(1_700_000_000, 0)
	}
	f.rec = filepath.Join(t.TempDir(), "rec.json")
	if f.exitOn == 0 {
		f.exitOn = syscall.SIGTERM
	}
	exited := false
	return ctrdDeps{
		now:   func() time.Time { return f.now },
		sleep: func(d time.Duration) { f.slept += d; f.now = f.now.Add(d) },
		status: func() ctrdStatus {
			i := f.calls
			f.calls++
			if exited && i < len(f.statuses)-1 {
				i = len(f.statuses) - 1 // after the restart it is the last scripted state
			}
			return f.statuses[min(i, len(f.statuses)-1)]
		},
		stopped: func() bool { return f.stopped },
		signal: func(pid int, sig syscall.Signal) error {
			f.signals = append(f.signals, sig)
			if sig == f.exitOn || sig == syscall.SIGKILL {
				exited = true
			}
			return nil
		},
		gone:     func(pid int, d time.Duration) bool { return exited },
		incident: func(ctrdStatus) func() { f.incident++; return func() { f.after++ } },
		lock: func() (func(), error) {
			if f.lockErr != nil {
				return nil, f.lockErr
			}
			return func() {}, nil
		},
		note:    func(s ctrdState) { f.notes = append(f.notes, s) },
		recFile: f.rec,
		probes:  3,
		gap:     7 * time.Second,
	}
}

var (
	stOK     = ctrdStatus{State: ctrdOK, PID: 42}
	stBusy   = ctrdStatus{State: ctrdBusy, PID: 42, Reason: "it is running but not accepting connections"}
	stHung   = ctrdStatus{State: ctrdHung, PID: 42, Reason: "it accepts connections but does not answer requests"}
	stLoad   = ctrdStatus{State: ctrdLoading, PID: 42}
	stNoProc = ctrdStatus{State: ctrdBusy}
)

func TestEnsureRestartsAContainerdThatStaysWedged(t *testing.T) {
	f := &fakeCtrd{statuses: []ctrdStatus{stBusy, stBusy, stBusy, stBusy, stOK}}
	act, err := ctrdEnsure(f.deps(t), false)
	if err != nil || !strings.Contains(act, "restarted containerd (it was busy") {
		t.Fatalf("%q %v", act, err)
	}
	if len(f.signals) != 1 || f.signals[0] != syscall.SIGTERM {
		t.Fatalf("a daemon that exits on SIGTERM is not killed harder: %v", f.signals)
	}
	if f.incident != 1 || f.after != 1 {
		t.Fatalf("the evidence is saved before and after: %d %d", f.incident, f.after)
	}
	if f.slept < 14*time.Second {
		t.Fatalf("three probes 7 s apart before acting: waited %s", f.slept)
	}
	if rec := loadCtrdRecoveries(f.rec); len(rec.Times) != 1 {
		t.Fatalf("the restart is recorded: %+v", rec)
	}
}

func TestEnsureEscalatesSIGTERMToSIGQUITToSIGKILL(t *testing.T) {
	f := &fakeCtrd{statuses: []ctrdStatus{stHung, stHung, stHung, stOK}, exitOn: syscall.SIGKILL}
	if _, err := ctrdEnsure(f.deps(t), false); err != nil {
		t.Fatal(err)
	}
	want := []syscall.Signal{syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL}
	if len(f.signals) != 3 || f.signals[0] != want[0] || f.signals[1] != want[1] || f.signals[2] != want[2] {
		t.Fatalf("SIGTERM, then SIGQUIT (its stacks reach the log), then SIGKILL: %v", f.signals)
	}
	f = &fakeCtrd{statuses: []ctrdStatus{stHung}, exitOn: syscall.SIGQUIT}
	if _, err := ctrdEnsure(f.deps(t), false); err != nil {
		t.Fatal(err)
	}
	if len(f.signals) != 2 {
		t.Fatalf("SIGQUIT was enough: %v", f.signals)
	}
}

func TestEnsureLeavesAHealthyOrBusyMomentAlone(t *testing.T) {
	for name, statuses := range map[string][]ctrdStatus{
		"healthy":               {stOK},
		"loading":               {stLoad},
		"not running":           {{State: ctrdDown}},
		"busy once, then fine":  {stBusy, stOK},
		"busy twice, then fine": {stBusy, stBusy, stOK},
		"hung, then loading":    {stHung, stLoad},
	} {
		f := &fakeCtrd{statuses: statuses}
		act, err := ctrdEnsure(f.deps(t), false)
		if act != "" || err != nil || len(f.signals) != 0 || f.incident != 0 {
			t.Errorf("%s: acted: %q %v %v", name, act, err, f.signals)
		}
	}
	f := &fakeCtrd{statuses: []ctrdStatus{stBusy}, stopped: true}
	if act, err := ctrdEnsure(f.deps(t), false); act != "" || err != nil || len(f.signals) != 0 {
		t.Fatalf("stopped on purpose: %q %v %v", act, err, f.signals)
	}
}

func TestEnsureIsHeldBackFromRestartLoops(t *testing.T) {
	f := &fakeCtrd{statuses: []ctrdStatus{stBusy}}
	d := f.deps(t)
	// Three restarts in the last hour are already on record.
	rec := ctrdRecoveries{Times: []time.Time{f.now.Add(-50 * time.Minute), f.now.Add(-30 * time.Minute), f.now.Add(-20 * time.Minute)}}
	writeJSON(t, f.rec, rec)
	act, err := ctrdEnsure(d, false)
	if act != "" || err == nil || !strings.Contains(err.Error(), "already restarted 3 times in the last hour") || len(f.signals) != 0 {
		t.Fatalf("a daemon that wedges again and again is reported, not restarted in a loop: %q %v %v", act, err, f.signals)
	}
	// An administrator running doctor --fix overrides the limit.
	f2 := &fakeCtrd{statuses: []ctrdStatus{stBusy, stBusy, stOK}}
	d2 := f2.deps(t)
	writeJSON(t, f2.rec, ctrdRecoveries{Times: []time.Time{f2.now.Add(-time.Minute), f2.now.Add(-2 * time.Minute), f2.now.Add(-3 * time.Minute)}})
	d2.probes = 2
	if act, err := ctrdEnsure(d2, true); err != nil || act == "" {
		t.Fatalf("force restarts: %q %v", act, err)
	}
}

func TestEnsureOneRecoveryAtATimeAndNeverWithoutAProcess(t *testing.T) {
	f := &fakeCtrd{statuses: []ctrdStatus{stBusy}, lockErr: errors.New("another containerd recovery is running")}
	if _, err := ctrdEnsure(f.deps(t), false); err == nil || len(f.signals) != 0 {
		t.Fatalf("a second recovery waits: %v %v", err, f.signals)
	}
	f = &fakeCtrd{statuses: []ctrdStatus{stNoProc}}
	if _, err := ctrdEnsure(f.deps(t), false); err == nil || !strings.Contains(err.Error(), "no containerd process was found") || len(f.signals) != 0 {
		t.Fatalf("nothing is signalled without a process: %v %v", err, f.signals)
	}
	f = &fakeCtrd{statuses: []ctrdStatus{{State: ctrdBusy, PID: 1}}}
	if _, err := ctrdEnsure(f.deps(t), false); err == nil || len(f.signals) != 0 {
		t.Fatalf("PID 1 is never signalled: %v %v", err, f.signals)
	}
}

func TestEnsureReportsAProcessThatWillNotDie(t *testing.T) {
	f := &fakeCtrd{statuses: []ctrdStatus{stBusy}, exitOn: syscall.Signal(99)}
	d := f.deps(t)
	d.gone = func(int, time.Duration) bool { return false }
	if _, err := ctrdEnsure(d, false); err == nil || !strings.Contains(err.Error(), "did not exit") {
		t.Fatalf("%v", err)
	}
	if f.after != 1 {
		t.Fatal("the log is still saved")
	}
}

func TestSickStateIsSharedAndExpires(t *testing.T) {
	ctrdStateFile = filepath.Join(t.TempDir(), "state")
	defer func(p string) { ctrdStateFile = p }("/run/ziro/containerd.state")
	if containerdSick() {
		t.Fatal("no verdict is not sick")
	}
	for s, sick := range map[ctrdState]bool{ctrdBusy: true, ctrdHung: true, ctrdOK: false, ctrdLoading: false, ctrdDown: false} {
		noteContainerdState(s)
		if containerdSick() != sick {
			t.Errorf("%s: sick %v", s, !sick)
		}
	}
	noteContainerdState(ctrdHung)
	old := time.Now().Add(-ctrdStateTTL - time.Second)
	if err := os.Chtimes(ctrdStateFile, old, old); err != nil {
		t.Fatal(err)
	}
	if containerdSick() {
		t.Fatal("an old verdict must not keep the pollers away")
	}
}

func TestIncidentEvidenceNamesTheDescriptorLimit(t *testing.T) {
	limits := "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 4096                 files\n"
	if soft, ok := ctrdOpenFilesLimit(limits); !ok || soft != 1024 {
		t.Fatalf("%d %v", soft, ok)
	}
	if h := ctrdFDHint(limits, 1000); !strings.Contains(h, "open files 1000 of 1024") {
		t.Fatalf("at the limit the cause is named: %q", h)
	}
	if h := ctrdFDHint(limits, 200); h != "" {
		t.Fatalf("far from the limit it is not blamed: %q", h)
	}
	sum := summariseFDTargets([]string{"socket:[1]", "socket:[2]", "socket:[3]", "pipe:[4]", "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", "anon_inode:[eventpoll]"})
	if !strings.HasPrefix(sum, "total 6\n") || !strings.Contains(sum, "     3  socket") || strings.Contains(sum, "[1]") {
		t.Fatalf("descriptors are counted by kind: %q", sum)
	}
}

func TestIncidentBundlesAreSavedPrunedAndListed(t *testing.T) {
	dir := t.TempDir()
	ctrdIncidentDir = dir
	defer func() { ctrdIncidentDir = "/var/log/ziro/containerd-incidents" }()
	logf := filepath.Join(t.TempDir(), "containerd.log")
	os.WriteFile(logf, []byte(strings.Repeat("x", 300<<10)+"goroutine 1 [running]:\n"), 0o644)
	containerdLogFile = logf
	defer func() { containerdLogFile = "/var/log/containerd.log" }()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	after := captureCtrdIncident(ctrdStatus{State: ctrdBusy, Reason: "full", PID: cmd.Process.Pid, Age: time.Hour})
	after()
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("one bundle: %v", ents)
	}
	b := filepath.Join(dir, ents[0].Name())
	if fi, _ := os.Stat(b); fi.Mode().Perm() != 0o700 {
		t.Fatalf("the bundle is private: %v", fi.Mode())
	}
	for _, f := range []string{"summary.txt", "proc-limits", "fds.txt", "system.txt", "containerd.log.tail"} {
		if _, err := os.Stat(filepath.Join(b, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	tail, _ := os.ReadFile(filepath.Join(b, "containerd.log.tail"))
	if len(tail) != 256<<10 || !strings.HasSuffix(string(tail), "[running]:\n") {
		t.Fatalf("the end of the log is kept, bounded: %d", len(tail))
	}
	got := recentCtrdIncidents(dir, time.Now().Add(-time.Hour))
	if len(got) != 1 || got[0].State != "busy" || got[0].Reason != "full" {
		t.Fatalf("%+v", got)
	}
	if len(recentCtrdIncidents(dir, time.Now().Add(time.Hour))) != 0 {
		t.Fatal("only recent ones")
	}
	for i := 0; i < 15; i++ {
		os.MkdirAll(filepath.Join(dir, "2020010"+strconv.Itoa(i%10)+"-0000"+strconv.Itoa(i/10)+"00"), 0o700)
	}
	pruneCtrdIncidents(dir, 10)
	if ents, _ := os.ReadDir(dir); len(ents) != 9 { // room for the one about to be written
		t.Fatalf("pruned to leave room: %d", len(ents))
	}
}

// The reported bug end to end: a containerd process that is alive and listening but not accepting is
// restarted by the heal pass and by doctor --fix's path, where it used to be reported as running.
func TestHealRestartsALiveButWedgedContainerd(t *testing.T) {
	dir := t.TempDir()
	old := map[string]any{"servicesDir": servicesDir, "stopMarkerDir": stopMarkerDir, "sock": containerdSock, "pidfile": containerdPIDFile,
		"state": ctrdStateFile, "rec": ctrdRecoveryFile, "lock": ctrdLockFile, "inc": ctrdIncidentDir, "probes": ctrdProbes, "gap": ctrdProbeGap,
		"wait": ctrdRestartWait, "poll": ctrdRestartPoll, "log": containerdLogFile}
	defer func() {
		servicesDir, stopMarkerDir, containerdSock = old["servicesDir"].(string), old["stopMarkerDir"].(string), old["sock"].(string)
		containerdPIDFile, ctrdStateFile, ctrdRecoveryFile = old["pidfile"].(string), old["state"].(string), old["rec"].(string)
		ctrdLockFile, ctrdIncidentDir, ctrdProbes = old["lock"].(string), old["inc"].(string), old["probes"].(int)
		ctrdProbeGap, ctrdRestartWait, ctrdRestartPoll = old["gap"].(time.Duration), old["wait"].(int), old["poll"].(time.Duration)
		containerdLogFile = old["log"].(string)
	}()
	servicesDir = filepath.Join(dir, "services")
	stopMarkerDir = filepath.Join(dir, "stopped")
	containerdPIDFile = filepath.Join(dir, "containerd.pid")
	ctrdStateFile = filepath.Join(dir, "state")
	ctrdRecoveryFile = filepath.Join(dir, "rec.json")
	ctrdLockFile = filepath.Join(dir, "lock")
	ctrdIncidentDir = filepath.Join(dir, "incidents")
	containerdLogFile = filepath.Join(dir, "containerd.log")
	ctrdProbes, ctrdProbeGap, ctrdRestartWait, ctrdRestartPoll = 2, 10*time.Millisecond, 3, 10*time.Millisecond
	os.MkdirAll(servicesDir, 0o755)
	os.MkdirAll(stopMarkerDir, 0o755)
	for _, svc := range defaultServices { // the built-in services are not under test: stopped on purpose
		if svc.Name != "containerd" {
			os.WriteFile(filepath.Join(stopMarkerDir, svc.Name), nil, 0o644)
		}
	}
	// The "containerd" is a long-running sleep that init would restart; the listener is not accepting.
	arg := strconv.Itoa(600000 + os.Getpid()%100000) // a command line only this test has
	proc := exec.Command("sleep", arg)
	if err := proc.Start(); err != nil {
		t.Skip("cannot start a process: ", err)
	}
	reaped := make(chan struct{})
	var mu sync.Mutex
	var respawned *exec.Cmd
	defer func() {
		proc.Process.Kill()
		<-reaped // init has finished its respawn
		mu.Lock()
		defer mu.Unlock()
		if respawned != nil {
			respawned.Process.Kill()
			respawned.Wait()
		}
	}()
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	conf := "name=containerd\nexec=" + sleepPath + "\nargs=" + arg + "\n"
	os.WriteFile(filepath.Join(servicesDir, "containerd.conf"), []byte(conf), 0o644)
	os.WriteFile(containerdPIDFile, []byte(strconv.Itoa(proc.Process.Pid)), 0o644)
	old2 := time.Now().Add(-time.Hour) // it has been running for an hour: not "loading"
	os.Chtimes(containerdPIDFile, old2, old2)
	// ziro-init: when the daemon exits it starts another one and writes the pidfile.
	go func() {
		proc.Wait()
		mu.Lock()
		respawned = exec.Command("sleep", arg)
		if respawned.Start() == nil {
			os.WriteFile(containerdPIDFile, []byte(strconv.Itoa(respawned.Process.Pid)), 0o644)
		}
		mu.Unlock()
		close(reaped)
	}()
	containerdSock = shortSock(t)
	saturate(t, containerdSock)

	if s := containerdStatus(); s.State != ctrdBusy || s.PID != proc.Process.Pid {
		t.Fatalf("precondition: alive but not accepting: %+v", s)
	}
	fixes := healServices(true)
	var got *ServiceFix
	for i := range fixes {
		if fixes[i].Name == "containerd" {
			got = &fixes[i]
		}
	}
	if got == nil || !strings.Contains(got.Action+got.Error, "containerd") {
		t.Fatalf("the heal pass must deal with it: %+v", fixes)
	}
	select {
	case <-reaped:
	case <-time.After(5 * time.Second):
		t.Fatalf("the wedged process was not restarted (stopped): %+v", fixes)
	}
	ents, _ := os.ReadDir(ctrdIncidentDir)
	if len(ents) != 1 {
		t.Fatalf("the evidence was saved: %v", ents)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// While containerd is stuck the platform's pollers add no connections to it, and resume by themselves.
func TestPollersStandDownWhileContainerdIsStuck(t *testing.T) {
	ctrdStateFile = filepath.Join(t.TempDir(), "state")
	defer func(p string) { ctrdStateFile = p }("/run/ziro/containerd.state")

	calls := 0
	run := func(_ context.Context, argv ...string) (string, error) { calls++; return "", errors.New("no") }
	ag := &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: run}
	now := time.Now()
	a := []Assignment{{Name: "zc-pgc-db-main-m1-abc", App: "pgc-db-main-m1", PG: true}}
	ag.reports["pgc-db-main-m1"] = pgStamped{r: PGReport{App: "pgc-db-main-m1"}, at: now.Add(-time.Second)}

	noteContainerdState(ctrdHung)
	ag.probeAll(context.Background(), a, now)
	if calls != 0 {
		t.Fatalf("Postgres probes ran %d runtime calls against a stuck containerd", calls)
	}
	if got := ag.reports["pgc-db-main-m1"]; !strings.Contains(got.detail, "being recovered") || !got.at.Equal(now.Add(-time.Second)) || got.busy {
		t.Fatalf("the last probe keeps its age (the master judges by it), and the reason is shown: %+v", got)
	}

	listed := 0
	old := listNodeContainers
	listNodeContainers = func() (map[string]bool, int, error) { listed++; return map[string]bool{}, 0, nil }
	defer func() { listNodeContainers = old }()
	var l containerList
	if _, _, err := l.get(0); !errors.Is(err, errContainerdSick) || listed != 0 {
		t.Fatalf("the cluster agent does not list containers through a stuck containerd: %v %d", err, listed)
	}

	noteContainerdState(ctrdOK)
	ag.probeAll(context.Background(), a, now)
	if calls == 0 {
		t.Fatal("probes resume once containerd answers")
	}
	if _, _, err := l.get(0); err != nil || listed != 1 {
		t.Fatalf("listing resumes: %v %d", err, listed)
	}
}

func TestDoctorSaysWhatIsWrongWithContainerd(t *testing.T) {
	dir := t.TempDir()
	defer func(a, b, c, d string) { ctrdStateFile, containerdSock, ctrdIncidentDir, servicesDir = a, b, c, d }(ctrdStateFile, containerdSock, ctrdIncidentDir, servicesDir)
	ctrdStateFile, ctrdIncidentDir, servicesDir = filepath.Join(dir, "state"), filepath.Join(dir, "inc"), filepath.Join(dir, "none")

	containerdSock = shortSock(t)
	checks := containerdChecks()
	if c := checks[0]; c.Passed || !strings.Contains(c.Details, "containerd is not running") || c.Fix != "start containerd" {
		t.Fatalf("not running: %+v", c)
	}
	containerdSock = shortSock(t)
	saturate(t, containerdSock)
	c := containerdChecks()[0]
	if c.Passed || !strings.Contains(c.Details, "not accepting connections") || !strings.Contains(c.Fix, "restart the stuck containerd") || c.fix == nil {
		t.Fatalf("the user's case is a stuck daemon, not a missing one: %+v", c)
	}
	if containerdSick() == false {
		t.Fatal("doctor shares its verdict with the pollers")
	}

	f, sock := startFakeContainerd(t)
	_ = f
	containerdSock = sock
	if c := containerdChecks()[0]; !c.Passed {
		t.Fatalf("serving: %+v", c)
	}

	os.MkdirAll(filepath.Join(ctrdIncidentDir, time.Now().UTC().Format("20060102-150405")), 0o700)
	os.WriteFile(filepath.Join(ctrdIncidentDir, time.Now().UTC().Format("20060102-150405"), "summary.txt"),
		[]byte("state: busy\nreason: full\ncause: open files 4090 of 4096: the descriptor limit is reached\n"), 0o600)
	var got *doctorCheck
	for _, c := range containerdChecks() {
		if c.Name == "containerd restarts" {
			got = &c
		}
	}
	if got == nil || got.Passed || !strings.Contains(got.Details, "restarted 1 time(s) in 24 h") || !strings.Contains(got.Details, "descriptor limit") {
		t.Fatalf("a recent restart and its cause are shown: %+v", got)
	}
}

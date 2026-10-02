package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// `system top`: live resource use of containers (read from their cgroups, like `docker stats`)
// and processes (from /proc), in one small, interactive view. Everything is read directly from
// the kernel; the only subprocess is an occasional `nerdctl ps` for container names.

type ContainerStat struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	CPU      float64 `json:"cpu_percent"` // of one CPU, like docker stats
	Mem      uint64  `json:"mem_bytes"`
	MemLimit uint64  `json:"mem_limit_bytes,omitempty"`
	NetRx    uint64  `json:"net_rx_bps"`
	NetTx    uint64  `json:"net_tx_bps"`
	BlkRead  uint64  `json:"blk_read_bps"`
	BlkWrite uint64  `json:"blk_write_bps"`
	PIDs     int     `json:"pids"`
}

type ProcStat struct {
	PID   int     `json:"pid"`
	User  string  `json:"user"`
	Name  string  `json:"name"`
	Unit  string  `json:"unit,omitempty"` // service or container it belongs to
	CPU   float64 `json:"cpu_percent"`
	RSS   uint64  `json:"rss_bytes"`
	State string  `json:"state"`
}

type TopSnapshot struct {
	Time        time.Time       `json:"time"`
	CPU         float64         `json:"cpu_percent"` // whole host, 0-100
	CPUs        int             `json:"cpus"`
	Load1       float64         `json:"load1"`
	MemTotal    uint64          `json:"mem_total"`
	MemUsed     uint64          `json:"mem_used"`
	SwapUsed    uint64          `json:"swap_used"`
	MemPressure float64         `json:"mem_pressure"` // PSI some avg10, %
	Containers  []ContainerStat `json:"containers"`
	Processes   []ProcStat      `json:"processes"`
}

var containerIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type cgPrev struct{ cpuUsec, rd, wr, rx, tx uint64 }

// topCollector keeps the previous counters to turn them into rates; reused between refreshes.
type topCollector struct {
	at        time.Time
	cpuTotal  uint64
	cpuIdle   uint64
	cgs       map[string]cgPrev // container id -> counters
	procs     map[int]uint64    // pid -> utime+stime ticks
	names     map[string]string // container id -> name
	namesAt   time.Time
	users     map[int]string
	pageSize  uint64
	clockTick float64
}

func newTopCollector() *topCollector {
	c := &topCollector{cgs: map[string]cgPrev{}, procs: map[int]uint64{}, names: map[string]string{},
		users: readPasswd(), pageSize: uint64(os.Getpagesize()), clockTick: 100} // USER_HZ is 100 on Linux
	return c
}

func readPasswd() map[int]string {
	out := map[int]string{}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) > 2 {
			if uid, err := strconv.Atoi(p[2]); err == nil {
				out[uid] = p[0]
			}
		}
	}
	return out
}

func readUint(p string) uint64 {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// kv reads "key value" lines (cpu.stat, memory.stat) for one key.
func kv(p, key string) uint64 {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if v, ok := bytes.CutPrefix(line, []byte(key+" ")); ok {
			n, _ := strconv.ParseUint(string(v), 10, 64)
			return n
		}
	}
	return 0
}

// ioBytes sums rbytes/wbytes over all devices in io.stat.
func ioBytes(p string) (rd, wr uint64) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	for _, f := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(f, "rbytes="); ok {
			n, _ := strconv.ParseUint(v, 10, 64)
			rd += n
		} else if v, ok := strings.CutPrefix(f, "wbytes="); ok {
			n, _ := strconv.ParseUint(v, 10, 64)
			wr += n
		}
	}
	return
}

// netBytes reads a process's network namespace counters (all interfaces but lo).
func netBytes(pid string) (rx, tx uint64) {
	b, err := os.ReadFile(filepath.Join(procRoot, pid, "net", "dev"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n")[2:] {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) > 8 {
			r, _ := strconv.ParseUint(f[0], 10, 64)
			t, _ := strconv.ParseUint(f[8], 10, 64)
			rx, tx = rx+r, tx+t
		}
	}
	return
}

// containerCgroups finds container cgroups (directories named by a 64-hex container id) two
// levels under the cgroup root, wherever the runtime's namespace put them.
func containerCgroups() map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		depth := strings.Count(strings.TrimPrefix(p, cgroupRoot), "/")
		if containerIDRe.MatchString(d.Name()) {
			out[d.Name()] = p
			return fs.SkipDir
		}
		if depth >= 3 || d.Name() == "ziro" {
			return fs.SkipDir
		}
		return nil
	})
	return out
}

func (c *topCollector) refreshNames() {
	if time.Since(c.namesAt) < 10*time.Second {
		return
	}
	c.namesAt = time.Now()
	if out, err := runNerdctl("ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if id, name, ok := strings.Cut(line, "\t"); ok {
				c.names[id] = name
			}
		}
	}
}

func (c *topCollector) sample() TopSnapshot {
	now := time.Now()
	dt := now.Sub(c.at).Seconds()
	first := c.at.IsZero()
	c.at = now
	s := TopSnapshot{Time: now, CPUs: max(1, numCPU())}
	s.Load1, _, _ = readLoadavg()
	mi := readMeminfo()
	s.MemTotal, s.MemUsed = mi["MemTotal"], mi["MemTotal"]-min(mi["MemAvailable"], mi["MemTotal"])
	s.SwapUsed = mi["SwapTotal"] - min(mi["SwapFree"], mi["SwapTotal"])
	s.MemPressure, _, _ = readPressure("memory")
	if b, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i, v := range f[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		if !first && total > c.cpuTotal {
			s.CPU = 100 * (1 - float64(idle-c.cpuIdle)/float64(total-c.cpuTotal))
		}
		c.cpuTotal, c.cpuIdle = total, idle
	}

	c.refreshNames()
	seen := map[string]bool{}
	for id, dir := range containerCgroups() {
		seen[id] = true
		cs := ContainerStat{ID: id[:12], Name: c.names[id], Mem: readUint(filepath.Join(dir, "memory.current")),
			PIDs: int(readUint(filepath.Join(dir, "pids.current")))}
		if cs.Name == "" {
			cs.Name = cs.ID
		}
		if l := readUint(filepath.Join(dir, "memory.max")); l > 0 && l < s.MemTotal {
			cs.MemLimit = l
		}
		cur := cgPrev{cpuUsec: kv(filepath.Join(dir, "cpu.stat"), "usage_usec")}
		cur.rd, cur.wr = ioBytes(filepath.Join(dir, "io.stat"))
		if procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")); err == nil {
			if pid, _, _ := strings.Cut(string(procs), "\n"); pid != "" {
				cur.rx, cur.tx = netBytes(pid)
			}
		}
		if p, ok := c.cgs[id]; ok && dt > 0 {
			rate := func(a, b uint64) uint64 {
				if a < b {
					return 0
				}
				return uint64(float64(a-b) / dt)
			}
			cs.CPU = float64(cur.cpuUsec-min(p.cpuUsec, cur.cpuUsec)) / (dt * 1e4)
			cs.BlkRead, cs.BlkWrite = rate(cur.rd, p.rd), rate(cur.wr, p.wr)
			cs.NetRx, cs.NetTx = rate(cur.rx, p.rx), rate(cur.tx, p.tx)
		}
		c.cgs[id] = cur
		s.Containers = append(s.Containers, cs)
	}
	for id := range c.cgs {
		if !seen[id] {
			delete(c.cgs, id)
		}
	}

	pids, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	alive := make(map[int]bool, len(pids))
	for _, pd := range pids {
		ps, ok := c.readProc(pd, dt)
		if !ok {
			continue
		}
		alive[ps.PID] = true
		s.Processes = append(s.Processes, ps)
	}
	for pid := range c.procs {
		if !alive[pid] {
			delete(c.procs, pid)
		}
	}
	return s
}

func numCPU() int {
	n := 0
	if b, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
				n++
			}
		}
	}
	return n
}

// readProc reads one /proc/<pid> (stat for CPU and state, statm for RSS, cgroup for the unit).
func (c *topCollector) readProc(dir string, dt float64) (ProcStat, bool) {
	pid, err := strconv.Atoi(filepath.Base(dir))
	if err != nil {
		return ProcStat{}, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ProcStat{}, false
	}
	// comm is in parentheses and may contain spaces; fields follow the last ')'.
	lp, rp := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if lp < 0 || rp < lp {
		return ProcStat{}, false
	}
	f := strings.Fields(string(b[rp+1:]))
	if len(f) < 13 {
		return ProcStat{}, false
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	if f[0] == "Z" || (ut+st == 0 && f[0] != "R" && strings.HasPrefix(string(b[lp+1:rp]), "kworker")) {
		return ProcStat{}, false
	}
	ps := ProcStat{PID: pid, Name: string(b[lp+1 : rp]), State: f[0]}
	if prev, ok := c.procs[pid]; ok && dt > 0 && ut+st >= prev {
		ps.CPU = float64(ut+st-prev) / c.clockTick / dt * 100
	}
	c.procs[pid] = ut + st
	if m, err := os.ReadFile(filepath.Join(dir, "statm")); err == nil {
		if fs := strings.Fields(string(m)); len(fs) > 1 {
			pages, _ := strconv.ParseUint(fs[1], 10, 64)
			ps.RSS = pages * c.pageSize
		}
	}
	if fi, err := os.Stat(dir); err == nil {
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			ps.User = c.users[int(sys.Uid)]
			if ps.User == "" {
				ps.User = strconv.Itoa(int(sys.Uid))
			}
		}
	}
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		path := strings.TrimSpace(string(cg))
		if i := strings.LastIndex(path, "::"); i >= 0 {
			path = path[i+2:]
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		last := parts[len(parts)-1]
		switch {
		case len(parts) == 3 && parts[0] == "ziro":
			ps.Unit = last
		case containerIDRe.MatchString(last):
			if n := c.names[last]; n != "" {
				ps.Unit = n
			} else {
				ps.Unit = last[:12]
			}
		}
	}
	return ps, true
}

// ---- view ----

type topView struct {
	pane    string // containers, processes
	sortBy  string // cpu, mem, name
	filter  string
	editing bool   // typing a filter
	confirm string // pending stop/kill target
	status  string
}

func (v *topView) sortSnapshot(s *TopSnapshot) {
	sort.Slice(s.Containers, func(i, j int) bool {
		a, b := s.Containers[i], s.Containers[j]
		switch v.sortBy {
		case "mem":
			return a.Mem > b.Mem
		case "name":
			return a.Name < b.Name
		}
		return a.CPU > b.CPU
	})
	sort.Slice(s.Processes, func(i, j int) bool {
		a, b := s.Processes[i], s.Processes[j]
		switch v.sortBy {
		case "mem":
			return a.RSS > b.RSS
		case "name":
			return a.Name < b.Name
		}
		return a.CPU > b.CPU
	})
}

func shortBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%dB", b)
}

func bar(pct float64, width int) string {
	n := int(pct / 100 * float64(width))
	n = max(0, min(n, width))
	return strings.Repeat("█", n) + strings.Repeat("·", width-n)
}

// render draws one frame into buf (reused) for a terminal of w×h.
func (v *topView) render(buf *bytes.Buffer, s TopSnapshot, w, h int) {
	buf.Reset()
	buf.WriteString("\033[H")
	line := func(format string, a ...any) {
		l := fmt.Sprintf(format, a...)
		if len([]rune(l)) > w {
			l = string([]rune(l)[:w])
		}
		buf.WriteString(l + "\033[K\r\n")
	}
	memPct := float64(s.MemUsed) * 100 / float64(max(s.MemTotal, 1))
	host, _ := os.Hostname()
	line("\033[1m%s\033[0m  %s  load %.2f  %d CPU", host, s.Time.Format("15:04:05"), s.Load1, s.CPUs)
	line("cpu %s %5.1f%%   mem %s %5.1f%% %s/%s   swap %s   pressure %.0f%%",
		bar(s.CPU, 12), s.CPU, bar(memPct, 12), memPct, shortBytes(s.MemUsed), shortBytes(s.MemTotal), shortBytes(s.SwapUsed), s.MemPressure)
	tab := func(name, key string) string {
		if v.pane == name {
			return "\033[7m " + key + " " + name + " \033[0m"
		}
		return " " + key + " " + name + " "
	}
	line("%s%s  sort:%s%s", tab("containers", "c"), tab("processes", "p"), v.sortBy, map[bool]string{true: "  filter:" + v.filter, false: ""}[v.filter != ""])
	rows := max(1, h-6)
	match := func(s string) bool {
		return v.filter == "" || strings.Contains(strings.ToLower(s), strings.ToLower(v.filter))
	}
	if v.pane == "containers" {
		line("\033[1m%-24s %6s %15s %17s %15s %5s\033[0m", "NAME", "CPU%", "MEM / LIMIT", "NET rx/tx /s", "BLOCK r/w /s", "PIDS")
		n := 0
		for _, c := range s.Containers {
			if !match(c.Name) || n >= rows {
				continue
			}
			n++
			limit := "-"
			if c.MemLimit > 0 {
				limit = shortBytes(c.MemLimit)
			}
			line("%-24.24s %6.1f %15s %17s %15s %5d", c.Name, c.CPU, shortBytes(c.Mem)+" / "+limit,
				shortBytes(c.NetRx)+" / "+shortBytes(c.NetTx), shortBytes(c.BlkRead)+" / "+shortBytes(c.BlkWrite), c.PIDs)
		}
		if len(s.Containers) == 0 {
			line("no running containers")
		}
	} else {
		line("\033[1m%7s %-10s %6s %8s %2s %-18s %s\033[0m", "PID", "USER", "CPU%", "RSS", "S", "UNIT", "COMMAND")
		n := 0
		for _, p := range s.Processes {
			if !match(p.Name+" "+p.Unit+" "+p.User) || n >= rows {
				continue
			}
			n++
			line("%7d %-10.10s %6.1f %8s %2s %-18.18s %s", p.PID, p.User, p.CPU, shortBytes(p.RSS), p.State, p.Unit, p.Name)
		}
	}
	buf.WriteString("\033[J")
	foot := "q quit  c/p pane  s sort  / filter  k stop"
	switch {
	case v.editing:
		foot = "filter: " + v.filter + "█  (enter apply, esc clear)"
	case v.confirm != "":
		foot = "\033[1;33mstop " + v.confirm + "? y/N\033[0m"
	case v.status != "":
		foot = v.status
	}
	fmt.Fprintf(buf, "\033[%d;1H%s\033[K", h, foot)
}

// first visible item in the current pane (the target of k).
func (v *topView) selected(s TopSnapshot) string {
	match := func(x string) bool {
		return v.filter == "" || strings.Contains(strings.ToLower(x), strings.ToLower(v.filter))
	}
	if v.pane == "containers" {
		for _, c := range s.Containers {
			if match(c.Name) {
				return "container " + c.Name
			}
		}
	} else {
		for _, p := range s.Processes {
			if match(p.Name + " " + p.Unit + " " + p.User) {
				return fmt.Sprintf("process %d (%s)", p.PID, p.Name)
			}
		}
	}
	return ""
}

func stopTarget(t string) error {
	if name, ok := strings.CutPrefix(t, "container "); ok {
		_, err := runNerdctl("stop", name)
		return err
	}
	var pid int
	if _, err := fmt.Sscanf(t, "process %d", &pid); err != nil || pid <= 1 {
		return errors.New("refusing to signal that process")
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

var (
	topOnce     bool
	topInterval time.Duration
	topPane     string
)

func takeSnapshot(interval time.Duration) TopSnapshot {
	c := newTopCollector()
	c.sample()
	time.Sleep(interval)
	return c.sample()
}

var systemTopCmd = &cobra.Command{
	Use:   "top",
	Short: "Live CPU, memory, network and disk use of containers and processes",
	Long: `An interactive view of what uses the host, like docker stats and top in one:
containers (from their cgroups: CPU, memory against its limit, network and block I/O rates,
PIDs) and processes (CPU, RSS, the service or container they belong to).

Keys: c/p switch pane, s cycle sort (cpu, mem, name), / filter, k stop the top row (asks
first), q quit. --once (or --json) prints one snapshot for scripts.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := &topView{pane: topPane, sortBy: "cpu"}
		if v.pane != "containers" && v.pane != "processes" {
			return fmt.Errorf("--pane must be containers or processes")
		}
		fd := int(os.Stdin.Fd())
		if topOnce || jsonOutput || !term.IsTerminal(fd) || !term.IsTerminal(int(os.Stdout.Fd())) {
			s := takeSnapshot(time.Second)
			v.sortSnapshot(&s)
			return printResult(s, func() {
				var buf bytes.Buffer
				v.render(&buf, s, 160, 40)
				// Strip cursor control for plain output.
				out := regexp.MustCompile(`\033\[[0-9;]*[HJK]`).ReplaceAllString(buf.String(), "")
				fmt.Print(strings.ReplaceAll(out, "\r", ""), "\n")
			})
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, old)
		fmt.Print("\033[?1049h\033[?25l") // alternate screen, hide cursor
		defer fmt.Print("\033[?25h\033[?1049l")

		keys := make(chan byte, 16)
		go func() {
			b := make([]byte, 1)
			for {
				if n, err := os.Stdin.Read(b); err != nil || n == 0 {
					close(keys)
					return
				} else {
					keys <- b[0]
				}
			}
		}()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(sig)

		c := newTopCollector()
		snap := c.sample()
		var buf bytes.Buffer
		tick := time.NewTicker(topInterval)
		defer tick.Stop()
		draw := func() {
			w, h, err := term.GetSize(fd)
			if err != nil {
				w, h = 120, 40
			}
			v.sortSnapshot(&snap)
			v.render(&buf, snap, w, h)
			os.Stdout.Write(buf.Bytes())
		}
		draw()
		for {
			select {
			case <-sig:
				return nil
			case <-tick.C:
				snap = c.sample()
				v.status = ""
			case k, ok := <-keys:
				if !ok {
					return nil
				}
				switch {
				case v.editing:
					switch k {
					case '\r', '\n':
						v.editing = false
					case 27: // esc
						v.editing, v.filter = false, ""
					case 127, 8:
						if len(v.filter) > 0 {
							v.filter = v.filter[:len(v.filter)-1]
						}
					default:
						if k >= 32 && k < 127 && len(v.filter) < 40 {
							v.filter += string(k)
						}
					}
				case v.confirm != "":
					if k == 'y' || k == 'Y' {
						if err := stopTarget(v.confirm); err != nil {
							v.status = "stop failed: " + err.Error()
						} else {
							v.status = "stopped " + v.confirm
						}
					}
					v.confirm = ""
				default:
					switch k {
					case 'q', 3: // q, Ctrl-C
						return nil
					case 'c':
						v.pane = "containers"
					case 'p':
						v.pane = "processes"
					case '\t':
						v.pane = map[string]string{"containers": "processes", "processes": "containers"}[v.pane]
					case 's':
						v.sortBy = map[string]string{"cpu": "mem", "mem": "name", "name": "cpu"}[v.sortBy]
					case '/':
						v.editing = true
					case 'k':
						v.confirm = v.selected(snap)
					}
				}
			}
			draw()
		}
	},
}

func init() {
	f := systemTopCmd.Flags()
	f.BoolVar(&topOnce, "once", false, "Print one snapshot and exit")
	f.DurationVar(&topInterval, "interval", 2*time.Second, "Refresh interval")
	f.StringVar(&topPane, "pane", "containers", "Start on: containers or processes")
	systemCmd.AddCommand(systemTopCmd)
}

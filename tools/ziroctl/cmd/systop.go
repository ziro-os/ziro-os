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
	"runtime/debug"
	"slices"
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
	Uptime      uint64          `json:"uptime_seconds"`
	Containers  []ContainerStat `json:"containers"`
	Processes   []ProcStat      `json:"processes"`
	Network     *NetSnapshot    `json:"network,omitempty"`
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
	only      string // collect only this pane ("" = everything, for snapshots)
	contAt    time.Time
	procAt    time.Time
	netAt     time.Time
	net       *netCollector
	buf       []byte // reused for /proc reads
	cont      []ContainerStat
	proc      []ProcStat
}

func newTopCollector() *topCollector {
	c := &topCollector{cgs: map[string]cgPrev{}, procs: map[int]uint64{}, names: map[string]string{},
		users: readPasswd(), pageSize: uint64(os.Getpagesize()), clockTick: 100, // USER_HZ is 100 on Linux
		net: newNetCollector(), buf: make([]byte, 64<<10)}
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
		c.names = map[string]string{} // rebuilt, so removed containers don't accumulate
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if id, name, ok := strings.Cut(line, "\t"); ok {
				c.names[id] = name
			}
		}
	}
}

func (c *topCollector) sample() TopSnapshot {
	now := time.Now()
	first := c.at.IsZero()
	c.at = now
	s := TopSnapshot{Time: now, CPUs: max(1, numCPU())}
	s.Load1, _, _ = readLoadavg()
	if b := readInto(c.buf, filepath.Join(procRoot, "uptime")); len(b) > 0 {
		var up float64
		fmt.Sscanf(string(b), "%f", &up)
		s.Uptime = uint64(up)
	}
	mi := readMeminfo()
	s.MemTotal, s.MemUsed = mi["MemTotal"], mi["MemTotal"]-min(mi["MemAvailable"], mi["MemTotal"])
	s.SwapUsed = mi["SwapTotal"] - min(mi["SwapFree"], mi["SwapTotal"])
	s.MemPressure, _, _ = readPressure("memory")
	if b := readInto(c.buf, filepath.Join(procRoot, "stat")); len(b) > 0 {
		line, _, _ := bytes.Cut(b, []byte("\n"))
		f := strings.Fields(string(line))
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

	// Each pane's rates are over the time since that pane was last sampled (it may have been
	// hidden in between).
	since := func(at *time.Time) float64 {
		d := 0.0
		if !at.IsZero() {
			d = now.Sub(*at).Seconds()
		}
		*at = now
		return d
	}
	if c.only == "" || c.only == "network" {
		n := c.net.sample(since(&c.netAt), c.buf)
		s.Network = &n
	}
	if c.only == "" || c.only == "containers" {
		c.sampleContainers(&s, since(&c.contAt))
	}
	if c.only == "" || c.only == "processes" {
		c.sampleProcesses(&s, since(&c.procAt))
	}
	return s
}

func (c *topCollector) sampleContainers(s *TopSnapshot, dt float64) {
	c.refreshNames()
	c.cont = c.cont[:0]
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
		c.cont = append(c.cont, cs)
	}
	for id := range c.cgs {
		if !seen[id] {
			delete(c.cgs, id)
		}
	}
	s.Containers = c.cont
}

func (c *topCollector) sampleProcesses(s *TopSnapshot, dt float64) {
	c.proc = c.proc[:0]
	pids, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	alive := make(map[int]bool, len(pids))
	for _, pd := range pids {
		ps, ok := c.readProc(pd, dt)
		if !ok {
			continue
		}
		alive[ps.PID] = true
		c.proc = append(c.proc, ps)
	}
	for pid := range c.procs {
		if !alive[pid] {
			delete(c.procs, pid)
		}
	}
	s.Processes = c.proc
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
	b := readInto(c.buf, filepath.Join(dir, "stat"))
	if len(b) == 0 {
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
	if m := readInto(c.buf, filepath.Join(dir, "statm")); len(m) > 0 {
		if _, rest, ok := bytes.Cut(m, []byte(" ")); ok {
			rss, _, _ := bytes.Cut(rest, []byte(" "))
			pages, _ := strconv.ParseUint(string(rss), 10, 64)
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
	if cg := readInto(c.buf, filepath.Join(dir, "cgroup")); len(cg) > 0 {
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

var topPanes = []string{"containers", "processes", "network"}

type topView struct {
	pane    string // containers, processes, network
	sortBy  string // cpu, mem, name; network: rate, total, remote
	filter  string
	editing bool   // typing a filter
	confirm string // pending stop/kill target
	status  string
	style   termStyle
}

func (v *topView) setPane(p string) {
	if (p == "network") != (v.pane == "network") {
		v.sortBy = map[bool]string{true: "rate", false: "cpu"}[p == "network"]
	}
	v.pane = p
}

func (v *topView) cycleSort() {
	next := map[string]string{"cpu": "mem", "mem": "name", "name": "cpu", "rate": "total", "total": "remote", "remote": "rate"}
	v.sortBy = next[v.sortBy]
}

func (v *topView) match(s string) bool {
	return v.filter == "" || strings.Contains(strings.ToLower(s), strings.ToLower(v.filter))
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
	if n := s.Network; n != nil {
		sort.Slice(n.Flows, func(i, j int) bool {
			a, b := n.Flows[i], n.Flows[j]
			switch v.sortBy {
			case "total":
				return a.Bytes > b.Bytes
			case "remote":
				return a.Remote < b.Remote
			}
			if a.RxBps+a.TxBps != b.RxBps+b.TxBps {
				return a.RxBps+a.TxBps > b.RxBps+b.TxBps
			}
			return a.Bytes > b.Bytes
		})
	}
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

// clip cuts l to w visible cells, keeping escape sequences intact.
func clip(l string, w int) string {
	n, esc := 0, false
	for i, r := range l {
		switch {
		case esc:
			esc = r < '@' || r > '~'
			continue
		case r == '\033':
			esc = true
			continue
		}
		if n++; n > w {
			return l[:i] + "\033[0m"
		}
	}
	return l
}

var ansiCursorRe = regexp.MustCompile(`\033\[[0-9;?]*[A-Za-z]`)

// render draws one frame into buf (reused) for a terminal of w×h.
func (v *topView) render(buf *bytes.Buffer, s TopSnapshot, w, h int) {
	st := v.style
	buf.Reset()
	buf.WriteString("\033[H")
	used := 0
	line := func(format string, a ...any) {
		buf.WriteString(clip(fmt.Sprintf(format, a...), w) + "\033[K\r\n")
		used++
	}
	memPct := float64(s.MemUsed) * 100 / float64(max(s.MemTotal, 1))
	host, _ := os.Hostname()
	up := ""
	if s.Uptime > 0 {
		up = "  up " + humanDuration(s.Uptime)
	}
	line(" %s  %s%s  load %.2f  %d CPU", st.bold(host), s.Time.Format("15:04:05"), up, s.Load1, s.CPUs)
	head := fmt.Sprintf(" %s %s %5.1f%%   %s %s %5.1f%% %s/%s   %s %s   %s %.0f%%",
		st.dim("CPU"), st.meter(s.CPU, 12), s.CPU, st.dim("MEM"), st.meter(memPct, 12), memPct, shortBytes(s.MemUsed), shortBytes(s.MemTotal),
		st.dim("SWAP"), shortBytes(s.SwapUsed), st.dim("PSI"), s.MemPressure)
	if n := s.Network; n != nil && len(n.Ifaces) > 0 && n.Ifaces[0].Name == n.Primary {
		head += fmt.Sprintf("   %s %s rx %s/s tx %s/s", st.dim("NET"), n.Primary, shortBytes(n.Ifaces[0].RxBps), shortBytes(n.Ifaces[0].TxBps))
	}
	line("%s", head)
	var tabs []string
	for _, p := range topPanes {
		t := " " + p[:1] + " " + p + " "
		if p == v.pane {
			t = st.paint(t, "7;1;94", "1;48;5;69;38;5;231", "1;48;2;79;107;255;38;2;255;255;255")
			if st.depth == 0 {
				t = "[" + strings.TrimSpace(t) + "]"
			}
		}
		tabs = append(tabs, t)
	}
	extra := "  sort " + v.sortBy
	if v.filter != "" {
		extra += "  filter " + v.filter
	}
	line(" %s%s", strings.Join(tabs, " "), st.dim(extra))
	rows := max(1, h-used-2)
	hdr := func(format string, a ...any) { line("%s", st.bold(fmt.Sprintf(format, a...))) }

	switch v.pane {
	case "containers":
		hdr(" %-24s %6s %15s %17s %15s %5s", "NAME", "CPU%", "MEM / LIMIT", "NET rx/tx /s", "BLOCK r/w /s", "PIDS")
		n := 0
		for _, c := range s.Containers {
			if !v.match(c.Name) || n >= rows {
				continue
			}
			n++
			limit := "-"
			if c.MemLimit > 0 {
				limit = shortBytes(c.MemLimit)
			}
			line(" %-24.24s %s %15s %17s %15s %5d", c.Name, st.level(fmt.Sprintf("%6.1f", c.CPU), c.CPU), shortBytes(c.Mem)+" / "+limit,
				shortBytes(c.NetRx)+" / "+shortBytes(c.NetTx), shortBytes(c.BlkRead)+" / "+shortBytes(c.BlkWrite), c.PIDs)
		}
		if len(s.Containers) == 0 {
			line(" %s", st.dim("no running containers"))
		}
	case "processes":
		hdr(" %7s %-10s %6s %8s %2s %-18s %s", "PID", "USER", "CPU%", "RSS", "S", "UNIT", "COMMAND")
		n := 0
		for _, p := range s.Processes {
			if !v.match(p.Name+" "+p.Unit+" "+p.User) || n >= rows {
				continue
			}
			n++
			line(" %7d %-10.10s %s %8s %2s %-18.18s %s", p.PID, p.User, st.level(fmt.Sprintf("%6.1f", p.CPU), p.CPU), shortBytes(p.RSS), p.State, p.Unit, p.Name)
		}
	case "network":
		v.renderNetwork(line, hdr, s.Network, rows, w)
	}
	buf.WriteString("\033[J")
	foot := " q quit  tab/c/p/n pane  s sort  / filter"
	if v.pane != "network" {
		foot += "  k stop"
	}
	switch {
	case v.editing:
		foot = " filter: " + v.filter + "_  (enter apply, esc clear)"
	case v.confirm != "":
		foot = st.warn(" stop " + v.confirm + "? y/N")
	case v.status != "":
		foot = " " + v.status
	default:
		foot = st.dim(foot)
	}
	fmt.Fprintf(buf, "\033[%d;1H%s\033[K", h, clip(foot, w))
}

func (v *topView) renderNetwork(line func(string, ...any), hdr func(string, ...any), n *NetSnapshot, rows, w int) {
	st := v.style
	if n == nil {
		line(" %s", st.dim("collecting..."))
		return
	}
	hdr(" %-14s %9s %9s %9s %9s %7s %7s", "INTERFACE", "RX/s", "TX/s", "RX pkt/s", "TX pkt/s", "ERRORS", "DROPS")
	shown := 0
	for _, i := range n.Ifaces {
		if shown >= 4 {
			break
		}
		if i.Name != n.Primary && i.RxBps+i.TxBps == 0 && shown > 0 {
			continue
		}
		shown++
		line(" %-14.14s %9s %9s %9d %9d %7d %7d", i.Name, shortBytes(i.RxBps), shortBytes(i.TxBps), i.RxPps, i.TxPps, i.Errors, i.Drops)
	}
	sw := max(10, min(60, w-30))
	var rx, tx uint64
	if len(n.RxHist) > 0 {
		rx, tx = n.RxHist[len(n.RxHist)-1], n.TxHist[len(n.TxHist)-1]
	}
	line(" %s %s %s/s", st.dim("rx"), st.cyan(fmt.Sprintf("%-*s", sw, sparkline(n.RxHist, sw, st.unicode))), shortBytes(rx))
	line(" %s %s %s/s", st.dim("tx"), st.blue(fmt.Sprintf("%-*s", sw, sparkline(n.TxHist, sw, st.unicode))), shortBytes(tx))

	states := make([]string, 0, len(n.States))
	for k, c := range n.States {
		states = append(states, fmt.Sprintf("%s %d", strings.ToLower(k), c))
	}
	sort.Strings(states)
	line(" %s %d in · %d out   %s   %s", st.bold("CONNECTIONS"), n.In, n.Out, strings.Join(states, "  "), st.dim("from "+n.Source))
	left := rows - shown - 5
	flowRows := max(1, left*2/3)
	hdr(" %-5s %-3s %-26s %-26s %-12s %8s %8s %8s", "PROTO", "DIR", "LOCAL", "REMOTE", "STATE", "RX/s", "TX/s", "TOTAL")
	k := 0
	for _, f := range n.Flows {
		if k >= flowRows || !v.match(f.Proto+" "+f.Local+" "+f.Remote+" "+f.State) {
			continue
		}
		k++
		dir := st.cyan("in ")
		if f.Dir == "out" {
			dir = st.blue("out")
		}
		total := "-"
		if f.Bytes > 0 {
			total = shortBytes(f.Bytes)
		}
		line(" %-5s %s %-26.26s %-26.26s %-12.12s %8s %8s %8s", f.Proto, dir, f.Local, f.Remote, strings.ToLower(f.State),
			shortBytes(f.RxBps), shortBytes(f.TxBps), total)
	}
	if len(n.Flows) == 0 {
		line(" %s", st.dim("no connections"))
	}
	hdr(" %-42s  %s", "TOP PEERS", "LISTENING")
	var peers, lis []string
	for _, p := range n.Peers {
		if v.match(p.IP) {
			peers = append(peers, fmt.Sprintf("%-22.22s %4d flows %8s/s", p.IP, p.Flows, shortBytes(p.Bps)))
		}
	}
	for _, l := range n.Listeners {
		if v.match(l.Addr + " " + l.Process) {
			lis = append(lis, fmt.Sprintf("%-4s %-24.24s %s", l.Proto, l.Addr, l.Process))
		}
	}
	for i := 0; i < max(1, left-flowRows-2) && (i < len(peers) || i < len(lis)); i++ {
		var a, b string
		if i < len(peers) {
			a = peers[i]
		}
		if i < len(lis) {
			b = lis[i]
		}
		line(" %-42s  %s", a, b)
	}
}

// first visible item in the current pane (the target of k).
func (v *topView) selected(s TopSnapshot) string {
	switch v.pane {
	case "containers":
		for _, c := range s.Containers {
			if v.match(c.Name) {
				return "container " + c.Name
			}
		}
	case "processes":
		for _, p := range s.Processes {
			if v.match(p.Name + " " + p.Unit + " " + p.User) {
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
	Short: "Watch CPU, memory, disk and network use live",
	Long: `A live view of what uses the host, in three panes:

  containers  CPU, memory against its limit, network and block I/O, PIDs (from cgroups)
  processes   CPU, RSS, state, and the service or container each belongs to
  network     interface rates with a history graph; every connection with its direction
              (in/out), state and traffic; the busiest remote peers; listening ports and
              the process behind each

Connection traffic comes from conntrack, so it includes NAT'd container traffic. Without
conntrack the pane lists sockets and states only.

Keys: tab or c/p/n switch pane, s cycle sort, / filter, k stop the top row (asks first),
q quit. --once or --json prints one snapshot of every pane.`,
	Example: `  ziroctl system top
  ziroctl system top --pane network
  ziroctl system top --once
  ziroctl system top --json | jq '.network.peers[:5]'`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := &topView{style: detectStyle(os.Stdout)}
		if !slices.Contains(topPanes, topPane) {
			return fmt.Errorf("--pane must be one of %s", strings.Join(topPanes, ", "))
		}
		v.setPane(topPane)
		v.sortBy = map[bool]string{true: "rate", false: "cpu"}[topPane == "network"]
		fd := int(os.Stdin.Fd())
		if topOnce || jsonOutput || !term.IsTerminal(fd) || !term.IsTerminal(int(os.Stdout.Fd())) {
			s := takeSnapshot(time.Second)
			v.sortSnapshot(&s)
			v.style.depth = 0
			return printResult(s, func() {
				var buf bytes.Buffer
				for _, p := range topPanes {
					v.setPane(p)
					v.sortSnapshot(&s)
					v.render(&buf, s, 160, 30)
					fmt.Print(strings.ReplaceAll(ansiCursorRe.ReplaceAllString(buf.String(), ""), "\r", ""), "\n\n")
				}
			})
		}
		// A viewer should stay small: cap the heap, the GC works harder instead.
		debug.SetMemoryLimit(24 << 20)
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
		c.only = v.pane
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
					pane := v.pane
					switch k {
					case 'q', 3: // q, Ctrl-C
						return nil
					case 'c':
						pane = "containers"
					case 'p':
						pane = "processes"
					case 'n':
						pane = "network"
					case '\t':
						pane = topPanes[(slices.Index(topPanes, v.pane)+1)%len(topPanes)]
					case 's':
						v.cycleSort()
					case '/':
						v.editing = true
					case 'k':
						v.confirm = v.selected(snap)
					}
					if pane != v.pane {
						v.setPane(pane)
						c.only = pane
						snap = c.sample() // the new pane's first rates come on the next tick
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
	f.StringVar(&topPane, "pane", "containers", "Start on: containers, processes or network")
	systemCmd.AddCommand(systemTopCmd)
}

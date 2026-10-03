package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTopCollector(t *testing.T) {
	proc, cg := t.TempDir(), t.TempDir()
	oldProc, oldCg, oldN := procRoot, cgroupRoot, runNerdctl
	procRoot, cgroupRoot = proc, cg
	defer func() { procRoot, cgroupRoot, runNerdctl = oldProc, oldCg, oldN }()
	id := strings.Repeat("ab", 32)
	runNerdctl = func(args ...string) ([]byte, error) { return []byte(id + "\tweb\n"), nil }

	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(s), 0644)
	}
	w(filepath.Join(proc, "meminfo"), "MemTotal: 4000000 kB\nMemAvailable: 1000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	w(filepath.Join(proc, "loadavg"), "0.50 0.40 0.30 1/100 42\n")
	w(filepath.Join(proc, "stat"), "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0\ncpu1 50 0 50 400 0 0 0\n")
	w(filepath.Join(proc, "42", "stat"), "42 (my (odd) proc) S 1 42 42 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0\n")
	w(filepath.Join(proc, "42", "statm"), "1000 256 10 1 0 100 0\n")
	w(filepath.Join(proc, "42", "cgroup"), "0::/ziro/workloads/clamav\n")
	dir := filepath.Join(cg, "default", id)
	w(filepath.Join(dir, "memory.current"), "104857600\n")
	w(filepath.Join(dir, "memory.max"), "209715200\n")
	w(filepath.Join(dir, "pids.current"), "3\n")
	w(filepath.Join(dir, "cpu.stat"), "usage_usec 1000000\n")
	w(filepath.Join(dir, "io.stat"), "8:0 rbytes=1000 wbytes=2000 rios=1\n")

	c := newTopCollector()
	c.sample()
	// One second later: the container used 0.5 s of CPU, the process 50 ticks, the host 50% busy.
	c.at, c.contAt, c.procAt = c.at.Add(-time.Second), c.contAt.Add(-time.Second), c.procAt.Add(-time.Second)
	w(filepath.Join(dir, "cpu.stat"), "usage_usec 1500000\n")
	w(filepath.Join(proc, "42", "stat"), "42 (my (odd) proc) S 1 42 42 0 -1 0 0 0 0 0 125 75 0 0 20 0 1 0\n")
	w(filepath.Join(proc, "stat"), "cpu  200 0 200 1000 0 0 0 0 0 0\ncpu0 1\ncpu1 1\n")
	s := c.sample()

	if len(s.Containers) != 1 || s.Containers[0].Name != "web" || s.Containers[0].MemLimit != 200<<20 || s.Containers[0].PIDs != 3 {
		t.Fatalf("containers %+v", s.Containers)
	}
	if cpu := s.Containers[0].CPU; cpu < 45 || cpu > 55 {
		t.Errorf("container cpu %.1f", cpu)
	}
	if len(s.Processes) != 1 || s.Processes[0].Name != "my (odd) proc" || s.Processes[0].Unit != "clamav" || s.Processes[0].RSS != 256*uint64(os.Getpagesize()) {
		t.Fatalf("processes %+v", s.Processes)
	}
	if cpu := s.Processes[0].CPU; cpu < 45 || cpu > 55 {
		t.Errorf("process cpu %.1f", cpu)
	}
	if s.CPU < 49 || s.CPU > 51 || s.MemUsed != 3000000<<10 || s.CPUs != 2 {
		t.Errorf("host %+v", s)
	}
	var buf bytes.Buffer
	(&topView{pane: "containers", sortBy: "cpu"}).render(&buf, s, 100, 20)
	if !strings.Contains(buf.String(), "web") || !strings.Contains(buf.String(), "200.0M") {
		t.Errorf("render:\n%s", buf.String())
	}
}

func TestTopNetwork(t *testing.T) {
	proc := t.TempDir()
	old := procRoot
	procRoot = proc
	defer func() { procRoot = old }()
	w := func(p, s string) {
		os.MkdirAll(filepath.Join(proc, filepath.Dir(p)), 0755)
		os.WriteFile(filepath.Join(proc, p), []byte(s), 0644)
	}
	// 127.0.0.1 is local on every host: an inbound flow to its port 22, an outbound one from it.
	ct := func(in, out uint64) string {
		return fmt.Sprintf("ipv4     2 tcp      6 431999 ESTABLISHED src=203.0.113.9 dst=127.0.0.1 sport=50000 dport=22 packets=10 bytes=%d src=127.0.0.1 dst=203.0.113.9 sport=22 dport=50000 packets=8 bytes=%d [ASSURED] mark=0 use=1\n", in, out) +
			"ipv4     2 udp      17 29 src=127.0.0.1 dst=1.1.1.1 sport=40000 dport=53 packets=1 bytes=60 src=1.1.1.1 dst=127.0.0.1 sport=53 dport=40000 packets=1 bytes=120 mark=0 use=1\n"
	}
	w("net/dev", "Inter-|   Receive\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
		"  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n")
	w("net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0 100 0 0 10 0\n")
	w("net/nf_conntrack", ct(1000, 5000))
	n := newNetCollector()
	n.sample(0, make([]byte, 64))
	w("net/dev", "  eth0: 3000 30 1 0 0 0 0 0 6000 60 0 2 0 0 0 0\n")
	w("net/nf_conntrack", ct(3000, 15000))
	s := n.sample(2, make([]byte, 64)) // a small buffer exercises the large-file path

	if s.Source != "conntrack" || s.In != 1 || s.Out != 1 || len(s.Listeners) != 1 || s.Listeners[0].Addr != "0.0.0.0:22" {
		t.Fatalf("snapshot %+v", s)
	}
	var in Flow
	for _, f := range s.Flows {
		if f.Dir == "in" {
			in = f
		}
	}
	// Inbound: the peer sent 2000 B (rx) and we replied 10000 B (tx) over 2 s.
	if in.Remote != "203.0.113.9:50000" || in.Local != "127.0.0.1:22" || in.RxBps != 1000 || in.TxBps != 5000 || in.Bytes != 18000 {
		t.Errorf("inbound flow %+v", in)
	}
	if len(s.Ifaces) != 1 || s.Ifaces[0].RxBps != 1000 || s.Ifaces[0].TxBps != 2000 || s.Ifaces[0].Errors != 1 || s.Ifaces[0].Drops != 2 {
		t.Errorf("iface %+v", s.Ifaces)
	}
	if len(s.Peers) == 0 || s.Peers[0].IP != "203.0.113.9" {
		t.Errorf("peers %+v", s.Peers)
	}
	if a, p := hexAddr("0100007F:0016"); a != "127.0.0.1" || p != "22" {
		t.Errorf("hexAddr v4 = %s %s", a, p)
	}
	if a, _ := hexAddr("00000000000000000000000001000000:0050"); a != "::1" {
		t.Errorf("hexAddr v6 = %s", a)
	}
	var buf bytes.Buffer
	v := &topView{}
	v.setPane("network")
	snap := TopSnapshot{Network: &s}
	v.sortSnapshot(&snap)
	v.render(&buf, snap, 140, 30)
	if out := buf.String(); !strings.Contains(out, "203.0.113.9:50000") || !strings.Contains(out, "CONNECTIONS 1 in · 1 out") {
		t.Errorf("render:\n%s", out)
	}
}

func BenchmarkTopSample(b *testing.B) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		b.Skip("needs /proc")
	}
	c := newTopCollector()
	c.only = "processes"
	for b.Loop() {
		c.sample()
	}
}

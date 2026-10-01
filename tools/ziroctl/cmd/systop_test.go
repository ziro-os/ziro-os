package cmd

import (
	"bytes"
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
	c.at = c.at.Add(-time.Second)
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

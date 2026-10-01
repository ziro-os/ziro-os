package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchdogMemoryStep(t *testing.T) {
	c := watchdogConf{MemoryFullPercent: 10, MemoryForSeconds: 15}
	var w watchdogState
	now := time.Now()
	for i, full := range []float64{20, 20} { // 10 s of stalling: not yet
		if w.memoryStep(c, full, now.Add(time.Duration(i)*watchdogTick)) {
			t.Fatal("acted too early")
		}
	}
	if !w.memoryStep(c, 30, now.Add(10*time.Second)) {
		t.Fatal("no action after 15 s")
	}
	for i := 0; i < 5; i++ { // still stalling, but within the cool-off
		if w.memoryStep(c, 30, now.Add(time.Duration(15+5*i)*time.Second)) {
			t.Fatal("acted during cool-off")
		}
	}
	w.memoryStep(c, 1, now.Add(time.Minute)) // recovered: counter resets
	if w.stalledFor != 0 {
		t.Error("counter not reset")
	}
}

func TestLargestWorkloads(t *testing.T) {
	old := cgroupRoot
	cgroupRoot = t.TempDir()
	defer func() { cgroupRoot = old }()
	for name, mem := range map[string]string{"clamav": "900000000", "hello": "1000", "minio": "300000000"} {
		d := filepath.Join(cgroupRoot, "ziro", "workloads", name)
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, "memory.current"), []byte(mem+"\n"), 0644)
	}
	got := largestWorkloads()
	if len(got) != 3 || got[0].Name != "clamav" || got[1].Name != "minio" || got[2].Name != "hello" {
		t.Errorf("%+v", got)
	}
}

package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestServiceCgroup(t *testing.T) {
	old := cgroupRoot
	cgroupRoot = t.TempDir()
	defer func() { cgroupRoot = old }()
	if _, err := serviceCgroup(&ServiceDef{Name: "x"}); err != errNoCgroup {
		t.Fatalf("no cgroup2: %v", err)
	}
	os.WriteFile(filepath.Join(cgroupRoot, "cgroup.controllers"), []byte("cpu memory pids"), 0644)

	dir, err := serviceCgroup(&ServiceDef{Name: "clamd", Resources: &Resources{Memory: "1Gi", CPUs: 1.5, PIDs: 64}})
	if err != nil || dir != filepath.Join(cgroupRoot, "ziro", "workloads", "clamd") {
		t.Fatalf("%s %v", dir, err)
	}
	read := func(f string) string { b, _ := os.ReadFile(filepath.Join(dir, f)); return string(b) }
	if read("memory.max") != "1073741824" || read("memory.high") != "966367638" || read("cpu.max") != "150000 100000" ||
		read("pids.max") != "64" || read("memory.oom.group") != "1" {
		t.Errorf("limits: %q %q %q %q", read("memory.max"), read("memory.high"), read("cpu.max"), read("pids.max"))
	}
	// Removing the limits resets them to max.
	if _, err := serviceCgroup(&ServiceDef{Name: "clamd"}); err != nil || read("memory.max") != "max" || read("cpu.max") != "max 100000" {
		t.Errorf("reset: %v %q", err, read("memory.max"))
	}
	if serviceClass("sshd") != "system" || serviceClass("sentinel") != "system" || serviceClass("clamd") != "workloads" {
		t.Error("classes")
	}
	if _, err := serviceCgroup(&ServiceDef{Name: "../x"}); err == nil {
		t.Error("bad name accepted")
	}
}

func TestContainerResourceArgs(t *testing.T) {
	if got := strings.Join(containerResourceArgs(nil), " "); got != "--oom-score-adj 300" {
		t.Errorf("unbounded: %s", got)
	}
	got := containerResourceArgs(&Resources{Memory: "512Mi", CPUs: 0.5, PIDs: 100})
	if !slices.Equal(got, []string{"--memory", "536870912", "--cpus", "0.5", "--pids-limit", "100"}) {
		t.Errorf("limited: %v", got)
	}
}

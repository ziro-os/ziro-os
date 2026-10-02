package cmd

import (
	"os"
	"syscall"
)

// startInCgroup makes the child start inside dir (clone3 CLONE_INTO_CGROUP), so it never runs
// outside its limits. The returned func closes the directory after Start.
func startInCgroup(attr *syscall.SysProcAttr, dir string) func() {
	f, err := os.Open(dir)
	if err != nil {
		return func() {}
	}
	attr.UseCgroupFD, attr.CgroupFD = true, int(f.Fd())
	return func() { f.Close() }
}

package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// lastCap is the highest capability number this kernel knows.
func lastCap() int {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 40
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 || n > 63 {
		return 40
	}
	return n
}

// execWithCaps turns this process into path as uid:gid holding exactly caps: it drops every
// other capability from the bounding set, switches user, sets the permitted, effective,
// inheritable and ambient sets to caps, sets no_new_privs, and execs. It returns only on error.
//
// It all runs on one locked OS thread with per-thread syscalls (x/sys/unix, not syscall.Setuid,
// which changes every thread): execve takes the calling thread's credentials, and the other
// threads disappear with it.
func execWithCaps(path string, argv, env []string, uid, gid uint32, caps []int) error {
	runtime.LockOSThread()
	keep := map[int]bool{}
	for _, c := range caps {
		keep[c] = true
	}
	// 1. Bounding set: needs CAP_SETPCAP, so before the user changes.
	for c := 0; c <= lastCap(); c++ {
		if keep[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			return fmt.Errorf("drop capability %d: %w", c, err)
		}
	}
	// 2. Keep the permitted set across the change of user, then become uid:gid with no groups.
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("keepcaps: %w", err)
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := unix.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	// 3. Exactly caps, in every set the exec can inherit them from.
	lo, hi := capMask(caps)
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: lo, Permitted: lo, Inheritable: lo},
		{Effective: hi, Permitted: hi, Inheritable: hi},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	for _, c := range caps {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("ambient capability %d: %w", c, err)
		}
	}
	// 4. Nothing the service runs can gain more.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	return syscall.Exec(path, argv, env)
}

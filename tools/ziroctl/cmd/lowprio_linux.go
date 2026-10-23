package cmd

import "golang.org/x/sys/unix"

// lowPriority makes a background process yield the CPU and the disk to everything else: nice 19
// and the idle I/O class (it only gets disk time nobody else wants).
func lowPriority(pid int) {
	_ = unix.Setpriority(unix.PRIO_PROCESS, pid, 19)
	const whoProcess, classIdle = 1, 3
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, whoProcess, uintptr(pid), classIdle<<13)
}

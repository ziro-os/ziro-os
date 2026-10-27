//go:build linux

package cmd

import (
	"net"
	"syscall"
)

// peerCred returns the user and process on the other end of a unix socket connection, as the kernel
// recorded them when it was made (SO_PEERCRED): they cannot be claimed, only observed.
func peerCred(c net.Conn) (uid, pid int, ok bool) {
	uc, isUnix := c.(*net.UnixConn)
	if !isUnix {
		return 0, 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil || cred == nil {
		return 0, 0, false
	}
	return int(cred.Uid), int(cred.Pid), true
}

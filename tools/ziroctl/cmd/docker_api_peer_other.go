//go:build !linux

package cmd

import "net"

// peerCred: the kernel interface behind the audit entry's peer is Linux's; elsewhere (development
// builds) the peer is unknown and the entry says "docker-socket".
func peerCred(net.Conn) (uid, pid int, ok bool) { return 0, 0, false }

package cmd

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// originalDst is where a connection redirected by nftables was going (SO_ORIGINAL_DST).
func originalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ap netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		// struct sockaddr_in in the first 16 bytes: family, port (big endian), address.
		m, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
		if err != nil {
			serr = err
			return
		}
		b := m.Multiaddr
		ap = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), binary.BigEndian.Uint16(b[2:4]))
	})
	if err == nil {
		err = serr
	}
	return ap, err
}

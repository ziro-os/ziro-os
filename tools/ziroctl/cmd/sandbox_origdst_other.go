//go:build !linux

package cmd

import (
	"errors"
	"net"
	"net/netip"
)

func originalDst(c net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent proxying needs Linux")
}

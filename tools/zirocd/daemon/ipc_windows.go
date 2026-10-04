package daemon

import (
	"net"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// Listen opens the control pipe: SYSTEM and Administrators only.
func Listen() (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(ControlPath())
}

func Dial() (net.Conn, error) {
	timeout := 5 * time.Second
	return namedpipe.DialTimeout(ControlPath(), timeout)
}

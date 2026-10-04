//go:build !windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
)

// Listen opens the root-only control socket.
func Listen() (net.Listener, error) {
	p := ControlPath()
	_ = os.MkdirAll(filepath.Dir(p), 0755)
	_ = os.Remove(p)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Dial connects the CLI to the daemon.
func Dial() (net.Conn, error) { return net.Dial("unix", ControlPath()) }

package router

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Relay wire format over TLS 1.3: frames of [type:1][length:3][payload]. A device sends
// FrameSend (destination WireGuard key + packet); the relay delivers FrameRecv (source key +
// packet) to the connection of the device holding that key. The relay derives the sender's key
// from its certificate, never from the frame.

const (
	FrameSend      = 1
	FrameRecv      = 2
	FrameKeepalive = 3
	MaxFrame       = 64 << 10
	RelayKeepalive = 25 * time.Second
)

var errFrameTooBig = errors.New("relay frame too large")

// RelayConn is one framed relay connection (used by both ends).
type RelayConn struct {
	Conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

func NewRelayConn(c net.Conn) *RelayConn {
	return &RelayConn{Conn: c, r: bufio.NewReaderSize(c, 64<<10)}
}

// WriteFrame writes one frame: key (32 bytes, may be nil) followed by payload.
func (rc *RelayConn) WriteFrame(typ byte, key []byte, payload []byte) error {
	n := len(key) + len(payload)
	if n > MaxFrame {
		return errFrameTooBig
	}
	buf := make([]byte, 4+n)
	buf[0] = typ
	buf[1], buf[2], buf[3] = byte(n>>16), byte(n>>8), byte(n)
	copy(buf[4:], key)
	copy(buf[4+len(key):], payload)
	rc.wmu.Lock()
	defer rc.wmu.Unlock()
	_ = rc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := rc.Conn.Write(buf)
	return err
}

// ReadFrame returns the next frame; for Send/Recv frames key is the 32-byte peer key.
func (rc *RelayConn) ReadFrame() (typ byte, key [32]byte, payload []byte, err error) {
	var h [4]byte
	if _, err = io.ReadFull(rc.r, h[:]); err != nil {
		return
	}
	typ = h[0]
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if n > MaxFrame {
		return typ, key, nil, errFrameTooBig
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(rc.r, body); err != nil {
		return
	}
	if typ == FrameSend || typ == FrameRecv {
		if n < 32 {
			return typ, key, nil, errors.New("short relay frame")
		}
		copy(key[:], body[:32])
		body = body[32:]
	}
	return typ, key, body, nil
}

func (rc *RelayConn) Close() error { return rc.Conn.Close() }

// DialRelay opens a relay connection with the device certificate, verifying the relay against
// the cluster CA.
func DialRelay(ctx context.Context, addr string, ca *x509.Certificate, cert *tls.Certificate) (*RelayConn, error) {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: ServerName,
			Certificates: []tls.Certificate{*cert}}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*tls.Conn); ok {
		if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
	}
	return NewRelayConn(c), nil
}

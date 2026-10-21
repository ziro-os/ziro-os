package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Request identity: the canonical path, host and client address the gateway matches, limits and
// logs on. Anything a client controls is normalized here, before any policy looks at it.

// pathIsClean reports whether a decoded request path is already canonical: no empty, "." or ".."
// segments and no control characters.
func pathIsClean(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	for i := 0; i < len(p); {
		j := i + 1
		for j < len(p) && p[j] != '/' {
			j++
		}
		seg := p[i+1 : j]
		if seg == "." || seg == ".." || seg == "" && j < len(p) {
			return false
		}
		i = j
	}
	return true
}

// cleanRequestPath returns the canonical form of a decoded request path. Matching and forwarding
// both use it, so a route's access rules cannot be sidestepped with "/public/../admin" or
// "//admin" (decoded %2e%2e and %2f included) while the upstream resolves the path to somewhere
// else. ok is false for paths that are not a path at all (no leading slash, control characters).
func cleanRequestPath(p string) (out string, ok bool) {
	if p == "" {
		return "/", true
	}
	if p == "*" { // OPTIONS *
		return p, true
	}
	if p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	if pathIsClean(p) {
		return p, true
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c, true
}

// normalizeHost lowercases a Host header and drops the port, brackets and trailing dot, without
// allocating in the common case.
func normalizeHost(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") {
		if j := strings.IndexByte(h, ']'); j > 0 {
			return h[1:j]
		}
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.IndexByte(h, ':') == i {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// gwPeerIP is the host part of a "host:port" remote address.
func gwPeerIP(remote string) string {
	if i := strings.LastIndexByte(remote, ':'); i >= 0 {
		return strings.Trim(remote[:i], "[]")
	}
	return remote
}

// rateKey is the limiter key of a client: IPv6 clients share their /64, since one subscriber
// typically holds a whole /64 and could otherwise rotate addresses to dodge a limit.
func rateKey(ip string) string {
	if strings.IndexByte(ip, ':') < 0 {
		return ip
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4In6() {
		return ip
	}
	return netip.PrefixFrom(a, 64).Masked().Addr().String()
}

// ---- gateway-wide settings, parsed ----

type gwSettings struct {
	trusted    []netip.Prefix
	proxyProto bool
	drain      time.Duration
}

func newGWSettings(s GatewaySettings) (*gwSettings, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	out := &gwSettings{proxyProto: s.ProxyProtocol, drain: s.Drain()}
	for _, c := range s.TrustedProxies {
		p, _ := schema.ParseProxyPrefix(c)
		out.trusted = append(out.trusted, p)
	}
	return out, nil
}

func (s *gwSettings) trustedAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *gwSettings) isTrusted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && s.trustedAddr(a)
}

// clientIP is the address policy applies to. By default it is the TCP peer. When the peer is a
// trusted proxy, it is the right-most X-Forwarded-For entry that is not itself a trusted proxy
// (or the left-most entry when every hop is trusted).
func clientIP(peer string, hdr http.Header, s *gwSettings) string {
	if s == nil || len(s.trusted) == 0 || !s.isTrusted(peer) {
		return peer
	}
	cand := peer
	vals := hdr["X-Forwarded-For"]
	for vi := len(vals) - 1; vi >= 0; vi-- {
		v := vals[vi]
		for {
			i := strings.LastIndexByte(v, ',')
			tok := strings.TrimSpace(v[i+1:])
			addr, err := netip.ParseAddr(tok)
			if err != nil {
				return cand // garbage entry: trust nothing left of it
			}
			if !s.trustedAddr(addr) {
				return addr.Unmap().String()
			}
			cand = addr.Unmap().String()
			if i < 0 {
				break
			}
			v = v[:i]
		}
	}
	return cand
}

// ---- PROXY protocol (v1 and v2) ----

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyV1Max = 107 // longest legal v1 line
	proxyV2Max = 536 // header body we accept (addresses plus a few TLVs)
)

var errProxyHeader = errors.New("bad PROXY protocol header")

// parseProxyHeader consumes a PROXY protocol header from br. It returns the original client
// address, or ok=false for LOCAL/UNKNOWN headers, which carry none (use the peer).
func parseProxyHeader(br *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
	sig, err := br.Peek(12)
	if err != nil {
		return src, false, errProxyHeader
	}
	switch {
	case bytes.Equal(sig, proxyV2Sig):
		return parseProxyV2(br)
	case bytes.HasPrefix(sig, []byte("PROXY ")):
		return parseProxyV1(br)
	}
	return src, false, errProxyHeader
}

func parseProxyV1(br *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > proxyV1Max || !bytes.HasSuffix(line, []byte("\r\n")) {
		return src, false, errProxyHeader
	}
	f := strings.Fields(string(line[:len(line)-2]))
	if len(f) < 2 || f[0] != "PROXY" {
		return src, false, errProxyHeader
	}
	if f[1] == "UNKNOWN" {
		return src, false, nil
	}
	if len(f) != 6 || f[1] != "TCP4" && f[1] != "TCP6" {
		return src, false, errProxyHeader
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil || f[1] == "TCP4" && !a.Is4() || f[1] == "TCP6" && !a.Is6() {
		return src, false, errProxyHeader
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil {
		return src, false, errProxyHeader
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true, nil
}

func parseProxyV2(br *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[12]>>4 != 2 {
		return src, false, errProxyHeader
	}
	n := int(hdr[14])<<8 | int(hdr[15])
	if n > proxyV2Max {
		return src, false, errProxyHeader
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return src, false, errProxyHeader
	}
	switch hdr[12] & 0xf {
	case 0: // LOCAL: a health check from the proxy itself
		return src, false, nil
	case 1:
	default:
		return src, false, errProxyHeader
	}
	switch hdr[13] {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return src, false, errProxyHeader
		}
		a, _ := netip.AddrFromSlice(body[0:4])
		return netip.AddrPortFrom(a, uint16(body[8])<<8|uint16(body[9])), true, nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return src, false, errProxyHeader
		}
		a, _ := netip.AddrFromSlice(body[0:16])
		return netip.AddrPortFrom(a.Unmap(), uint16(body[32])<<8|uint16(body[33])), true, nil
	}
	return src, false, nil // UDP, unix sockets, unspecified: no client address to use
}

// proxyConn serves a connection whose PROXY header has been consumed, reporting the client the
// proxy saw as the remote address.
type proxyConn struct {
	net.Conn
	br     *bufio.Reader
	remote net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.br.Read(b) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

func (c *proxyConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// acceptProxy reads the PROXY header when settings ask for it and the peer is a trusted proxy.
// Other peers are served as they are: an untrusted client cannot claim an address.
func (g *gatewayServer) acceptProxy(c net.Conn) (net.Conn, error) {
	s := g.settings.Load()
	if s == nil || !s.proxyProto || !s.isTrusted(gwPeerIP(c.RemoteAddr().String())) {
		return c, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(c, 256)
	src, ok, err := parseProxyHeader(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.RemoteAddr(), err)
	}
	remote := c.RemoteAddr()
	if ok {
		remote = &net.TCPAddr{IP: src.Addr().AsSlice(), Port: int(src.Port())}
	}
	return &proxyConn{Conn: c, br: br, remote: remote}, nil
}

// proxyListener accepts connections and parses their PROXY headers concurrently, so a slow or
// silent proxy connection never delays the next accept.
type proxyListener struct {
	net.Listener
	g    *gatewayServer
	ch   chan net.Conn
	done chan struct{}
}

func (g *gatewayServer) wrapProxyListener(ln net.Listener) net.Listener {
	pl := &proxyListener{Listener: ln, g: g, ch: make(chan net.Conn), done: make(chan struct{})}
	go pl.loop()
	return pl
}

func (l *proxyListener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			close(l.done)
			return
		}
		if !l.g.proxyProtoOn() { // the common case: nothing to read, no extra goroutine
			select {
			case l.ch <- c:
			case <-l.done:
				c.Close()
			}
			continue
		}
		go func() {
			pc, err := l.g.acceptProxy(c)
			if err != nil {
				c.Close()
				return
			}
			select {
			case l.ch <- pc:
			case <-l.done:
				pc.Close()
			}
		}()
	}
}

func (l *proxyListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

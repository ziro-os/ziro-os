package cmd

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// ---- L4: TCP routes and TLS passthrough ----

func (g *gatewayServer) serveL4(conn net.Conn, r *gwRoute) {
	g.l4wg.Add(1)
	defer g.l4wg.Done()
	g.metrics.l4conns.Add(1)
	defer g.metrics.l4conns.Add(-1)
	defer conn.Close()
	start := time.Now()
	ip := gwPeerIP(conn.RemoteAddr().String())
	if !clientAllowed(r, ip) {
		r.m.deny(denyACL)
		r.m.observe(403, 0)
		return
	}
	if r.limiter != nil && !r.limiter.allow(rateKey(ip), start) {
		r.m.deny(denyRate)
		r.m.observe(403, 0)
		return
	}
	var triedBuf [8]*gwTarget
	tried := triedBuf[:0]
	var up net.Conn
	var tg *gwTarget
	for range r.targets {
		tg = g.pick(r, ip, time.Now(), tried)
		if tg == nil {
			break
		}
		tried = append(tried, tg)
		c, err := net.DialTimeout("tcp", tg.addr, 5*time.Second)
		if err == nil {
			up = c
			break
		}
		tg.up.markDown(time.Now())
		g.metrics.upstreamFailure(r.Name, tg.addr)
	}
	if up == nil {
		r.m.observe(502, time.Since(start))
		return
	}
	defer up.Close()
	tg.up.active.Add(1)
	defer tg.up.active.Add(-1)
	r.m.inflight.Add(1)
	defer r.m.inflight.Add(-1)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src) // TCPConn.ReadFrom uses splice(2) on Linux
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, conn)
	go pipe(conn, up)
	<-done
	<-done
	r.m.observe(200, time.Since(start))
	g.log(map[string]any{"ts": start.UTC().Format(time.RFC3339Nano), "client": ip, "route": r.Name, "kind": r.Kind,
		"upstream": tg.addr, "ms": time.Since(start).Milliseconds()})
}

// syncL4Listeners opens a listener per tcp route port and closes ports no route uses.
func (g *gatewayServer) syncL4Listeners() {
	t := g.tbl.Load()
	want := map[int]bool{}
	for p := range t.tcp {
		want[p] = true
	}
	g.l4Mu.Lock()
	defer g.l4Mu.Unlock()
	for p, ln := range g.l4 {
		if !want[p] {
			ln.Close()
			delete(g.l4, p)
		}
	}
	if g.draining.Load() {
		return
	}
	for p := range want {
		if g.l4[p] != nil {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			fmt.Printf("[gateway] tcp :%d: %v\n", p, err)
			continue
		}
		g.l4[p] = ln
		go func(p int, ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					pc, err := g.acceptProxy(c)
					if err != nil {
						c.Close()
						return
					}
					r := g.tbl.Load().tcp[p]
					if r == nil {
						pc.Close()
						return
					}
					g.serveL4(pc, r)
				}()
			}
		}(p, ln)
	}
}

// closeL4 stops accepting on every TCP route port.
func (g *gatewayServer) closeL4() {
	g.l4Mu.Lock()
	defer g.l4Mu.Unlock()
	for p, ln := range g.l4 {
		ln.Close()
		delete(g.l4, p)
	}
}

// peekSNI reads the TLS ClientHello's server name without consuming it: the returned bytes are
// replayed to whoever handles the connection next.
func peekSNI(conn net.Conn) (string, []byte, error) {
	rec := &recordingConn{Conn: conn}
	var sni string
	errStop := errors.New("peeked")
	err := tls.Server(rec, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, errStop
	}}).Handshake()
	if sni == "" && !errors.Is(err, errStop) {
		return "", rec.buf.Bytes(), err
	}
	return sni, rec.buf.Bytes(), nil
}

// recordingConn records what is read and never writes (a peek that leaves the client unaware).
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.buf.Write(b[:n])
	return n, err
}

func (c *recordingConn) Write(b []byte) (int, error) { return 0, io.ErrClosedPipe }

// replayConn serves already-read bytes before the rest of the connection.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite half-closes the underlying TCP connection (passthrough proxying).
func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// chanListener hands connections to http.Server (HTTPS after the SNI split).
type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// push hands a connection to the HTTPS server unless it is shutting down.
func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

// splitTLS accepts on :443 and routes each connection: TLS passthrough routes (by SNI) are
// proxied raw; everything else goes to the HTTPS server. Without passthrough routes and PROXY
// protocol nothing is read before the TLS handshake.
func (g *gatewayServer) splitTLS(ln net.Listener, https *chanListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			https.Close()
			return
		}
		if !g.hasSNI.Load() && !g.proxyProtoOn() {
			https.push(c)
			continue
		}
		go func(c net.Conn) {
			pc, err := g.acceptProxy(c)
			if err != nil {
				c.Close()
				return
			}
			if !g.hasSNI.Load() {
				https.push(pc)
				return
			}
			_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
			sni, buf, err := peekSNI(pc)
			_ = pc.SetReadDeadline(time.Time{})
			rc := &replayConn{Conn: pc, r: io.MultiReader(bytes.NewReader(buf), pc)}
			if err == nil {
				if r := g.sniRoute(sni); r != nil {
					g.serveL4(rc, r)
					return
				}
			}
			https.push(rc)
		}(c)
	}
}

func (g *gatewayServer) proxyProtoOn() bool {
	s := g.settings.Load()
	return s != nil && s.proxyProto
}

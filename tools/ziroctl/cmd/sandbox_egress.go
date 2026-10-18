package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// The egress proxy behind credential injection (sandbox_secrets.go). nftables redirects the
// port-443 traffic of sandboxes that have secrets here; the proxy checks the destination
// against the sandbox's network policy (redirected traffic leaves from the host, so the forward
// rules no longer see it), reads the server name, and either splices the connection through
// untouched or, for a host a secret is bound to, terminates TLS and injects the secrets.

type egressProxy struct {
	m        *sandboxManager
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	roots    *tls.Config // upstream verification (nil: the host's roots)
	origDst  func(net.Conn) (netip.AddrPort, error)
	secretMu sync.Mutex
	secrets  map[string]*sandboxSecrets
}

func newEgressProxy(m *sandboxManager) *egressProxy {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &egressProxy{m: m, dial: d.DialContext, origDst: originalDst, secrets: map[string]*sandboxSecrets{}}
}

func (p *egressProxy) secretsOf(id string) (*sandboxSecrets, error) {
	p.secretMu.Lock()
	defer p.secretMu.Unlock()
	if s := p.secrets[id]; s != nil {
		return s, nil
	}
	s, err := loadSandboxSecrets(id)
	if err == nil {
		p.secrets[id] = s
	}
	return s, err
}

func (p *egressProxy) forget(id string) {
	p.secretMu.Lock()
	delete(p.secrets, id)
	p.secretMu.Unlock()
}

func (p *egressProxy) serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	sem := make(chan struct{}, 1024)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() { defer func() { <-sem }(); p.handle(c) }()
		default:
			c.Close()
		}
	}
}

func (p *egressProxy) handle(c net.Conn) {
	defer c.Close()
	src := addrIP(c.RemoteAddr())
	pol := p.m.net.policyOf(src)
	if pol.net == nil {
		return // not a sandbox (the listener is reachable from the sandbox subnet only)
	}
	dst, err := p.origDst(c)
	if err != nil || !p.m.net.egressAllowed(pol, dst.Addr()) {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, head, err := peekSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	in := &replayConn{Conn: c, r: io.MultiReader(strings.NewReader(string(head)), c)}
	sec, err := p.secretsOf(pol.id)
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if err != nil || sni == "" || !sec.boundTo(sni) {
		p.splice(in, dst.String())
		return
	}
	p.intercept(in, pol.id, sni, dst.String(), sec)
}

// splice passes a connection through untouched.
func (p *egressProxy) splice(in net.Conn, dst string) {
	up, err := p.dial(context.Background(), "tcp", dst)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, in)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(in, up)
	<-done
}

// intercept terminates TLS for sni with the sandbox's CA and serves its requests through a
// reverse proxy that injects the secrets and verifies the real server.
func (p *egressProxy) intercept(in net.Conn, id, sni, dst string, sec *sandboxSecrets) {
	cert, err := sec.leaf(sni)
	if err != nil {
		return
	}
	tc := tls.Server(in, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	upTLS := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}
	if p.roots != nil {
		upTLS.RootCAs = p.roots.RootCAs
	}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := p.dial(ctx, "tcp", dst) // the address the sandbox resolved and was allowed
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, upTLS)
			if err := c.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return c, nil
		},
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 5 * time.Minute,
		MaxIdleConnsPerHost:   4,
	}
	defer transport.CloseIdleConnections()
	logged := map[string]bool{}
	var logMu sync.Mutex
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "https", sni
			pr.Out.Host = pr.In.Host
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "ziro egress: "+err.Error(), http.StatusBadGateway)
		},
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != sni { // a request for another name on this connection: no secrets for it
			host = ""
		}
		used, err := sec.rewriteRequest(r, host)
		if errors.Is(err, errCredentialMismatch) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error":"credential_endpoint_mismatch","message":"a secret was sent to a host it isn't bound to"}`)
			_ = auditLog("ziro-sandboxd", "sandbox:"+id, "sandbox secret refused", sni, err)
			return
		}
		logMu.Lock()
		for _, n := range used {
			if !logged[n] { // once per connection: names only, never values
				logged[n] = true
				_ = auditLog("ziro-sandboxd", "sandbox:"+id, "sandbox secret use", n+" -> "+sni, nil)
			}
		}
		logMu.Unlock()
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	_ = srv.Serve(&oneConnListener{c: tc})
}

// oneConnListener hands one connection to an http.Server, then waits until it is closed.
type oneConnListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
	mu   sync.Mutex
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.done == nil {
		l.done = make(chan struct{})
	}
	done := l.done
	l.mu.Unlock()
	var c net.Conn
	l.once.Do(func() { c = &notifyConn{Conn: l.c, closed: done} })
	if c != nil {
		return c, nil
	}
	<-done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

type notifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

// ---- routing table ----

type gwHeaderMatch struct{ name, value string } // name is canonical

type gwRoute struct {
	GatewayRouteState
	fp         string // fingerprint of the config this route was built from
	allow      []netip.Prefix
	hdrs       []gwHeaderMatch
	limiter    *tokenBucket
	authFail   *tokenBucket // failed basic-auth attempts per client
	next       atomic.Uint64
	targets    []*gwTarget
	timeout    time.Duration
	tr         http.RoundTripper // the shared upstream transport (replaced in tests)
	m          *routeMetrics
	cookieName string
	realm      string
}

// matches reports whether the request fits the route's path, method and header matchers.
func (r *gwRoute) matches(req *http.Request) bool {
	path := req.URL.Path
	p := r.PathPrefix
	if r.PathExact {
		if path != p {
			return false
		}
	} else if !(p == "/" || path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/")) {
		return false
	}
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			ok = ok || m == req.Method
		}
		if !ok {
			return false
		}
	}
	for _, h := range r.hdrs {
		if req.Header.Get(h.name) != h.value {
			return false
		}
	}
	return true
}

// specificity orders routes of one host: exact paths, then longer prefixes, then more matchers.
func (r *gwRoute) specificity() int {
	s := len(r.PathPrefix) * 4
	if r.PathExact {
		s += 100000
	}
	return s + len(r.Methods) + len(r.Headers)*2
}

// routeTable is an immutable snapshot of what the gateway serves. A reload builds a new one and
// swaps the pointer, so the request path takes no lock and in-flight requests finish on the
// table they started with.
type routeTable struct {
	exact map[string][]*gwRoute // host -> most specific first
	wild  map[string][]*gwRoute // "example.com" for "*.example.com"
	tcp   map[int]*gwRoute      // listen port -> route
	sniEx map[string]*gwRoute   // tls passthrough routes
	sniWd map[string]*gwRoute
	all   []*gwRoute // every route once, in config order
	cfg   *GatewayConfig
}

func newRouteTable() *routeTable {
	return &routeTable{exact: map[string][]*gwRoute{}, wild: map[string][]*gwRoute{}, tcp: map[int]*gwRoute{},
		sniEx: map[string]*gwRoute{}, sniWd: map[string]*gwRoute{}}
}

func hostCandidates(host string) (exact, parent string) {
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host, host[i+1:]
	}
	return host, ""
}

func (t *routeTable) match(host string, req *http.Request) *gwRoute {
	ex, parent := hostCandidates(host)
	for _, r := range t.exact[ex] {
		if r.matches(req) {
			return r
		}
	}
	for _, r := range t.wild[parent] {
		if r.matches(req) {
			return r
		}
	}
	return nil
}

// hostRoute is the most specific route serving host (for TLS decisions).
func (t *routeTable) hostRoute(host string) *gwRoute {
	ex, parent := hostCandidates(host)
	if rs := t.exact[ex]; len(rs) > 0 {
		return rs[0]
	}
	if rs := t.wild[parent]; len(rs) > 0 {
		return rs[0]
	}
	return nil
}

func (t *routeTable) sniRoute(host string) *gwRoute {
	ex, parent := hostCandidates(strings.ToLower(host))
	if r := t.sniEx[ex]; r != nil {
		return r
	}
	return t.sniWd[parent]
}

func (g *gatewayServer) match(host string, req *http.Request) *gwRoute {
	return g.tbl.Load().match(host, req)
}
func (g *gatewayServer) hostRoute(host string) *gwRoute { return g.tbl.Load().hostRoute(host) }
func (g *gatewayServer) sniRoute(host string) *gwRoute  { return g.tbl.Load().sniRoute(host) }

// acmeHost: hosts whose certificate comes from ACME.
func (g *gatewayServer) acmeHost(host string) bool {
	r := g.hostRoute(host)
	return r != nil && r.TLS == "auto"
}

// ---- server ----

type gatewayServer struct {
	tbl      atomic.Pointer[routeTable]
	settings atomic.Pointer[gwSettings]

	upstreams sync.Map // addr -> *gwUpstream
	checks    map[string]checkEntry
	checkMu   sync.Mutex

	transports sync.Map // response timeout -> *http.Transport
	proxy      *httputil.ReverseProxy
	log        func(v any) // events (health changes, config problems); the access log is alog
	alog       *accessLog  // nil: requests are not logged
	metrics    *gwMetrics
	auth       authCache

	certMu    sync.Mutex
	certs     map[string]*tls.Certificate // uploaded, by name
	leafs     map[string]*tls.Certificate // internal CA leafs, by host
	leafLimit *tokenBucket
	ca        *tls.Certificate
	caPEM     []byte
	acmeMgr   *autocert.Manager
	h3        atomic.Pointer[http3.Server]
	hasSNI    atomic.Bool
	l4        map[int]net.Listener
	l4Mu      sync.Mutex
	reqIDGen  func() string
	httpsPort int // the public HTTPS port when it is not 443 (for redirects)
	draining  atomic.Bool
	l4wg      sync.WaitGroup // open TCP and passthrough connections
}

type gwCtxKey struct{}

// gwCtx is the per-request state the proxy callbacks need.
type gwCtx struct {
	route    *gwRoute
	target   *gwTarget
	tls      bool
	clientIP string
	reqID    string
	upStatus int
	upNS     int64
	err      error
	tried    [8]*gwTarget
	nTried   int
}

func (c *gwCtx) markTried(t *gwTarget) {
	if c.nTried < len(c.tried) {
		c.tried[c.nTried] = t
		c.nTried++
	}
}

// reqState is everything one request needs; it is pooled, so the request path allocates little.
type reqState struct {
	sw    statusWriter
	c     gwCtx
	g     *gatewayServer
	start time.Time
	host  string
	ip    string
	route *gwRoute
	waf   string
}

var reqPool = sync.Pool{New: func() any { return new(reqState) }}

func newGatewayServer() *gatewayServer {
	g := &gatewayServer{checks: map[string]checkEntry{},
		certs: map[string]*tls.Certificate{}, leafs: map[string]*tls.Certificate{}, l4: map[int]net.Listener{},
		metrics: newGWMetrics(), leafLimit: newTokenBucket(leafIssuePerSec)}
	g.tbl.Store(newRouteTable())
	g.log = func(v any) {
		if b, err := json.Marshal(v); err == nil {
			fmt.Println(string(b))
		}
	}
	g.reqIDGen = func() string {
		var b [8]byte
		_, _ = rand.Read(b[:])
		return hex.EncodeToString(b[:])
	}
	bufPool := &gwBufferPool{}
	g.proxy = &httputil.ReverseProxy{
		BufferPool: bufPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			c := pr.In.Context().Value(gwCtxKey{}).(*gwCtx)
			out := pr.Out
			out.URL.Scheme, out.URL.Host = "http", c.target.addr
			if sp := c.route.StripPrefix; sp != "" && strings.HasPrefix(out.URL.Path, sp) {
				out.URL.Path = "/" + strings.TrimLeft(strings.TrimPrefix(out.URL.Path, sp), "/")
				out.URL.RawPath = ""
			}
			out.Host = pr.In.Host
			h := out.Header
			// The proxy removed the client's forwarding headers; these are the gateway's word, never appended.
			h.Set("X-Forwarded-For", c.clientIP)
			h.Set("X-Forwarded-Host", pr.In.Host)
			if c.tls {
				h.Set("X-Forwarded-Proto", "https")
			} else {
				h.Set("X-Forwarded-Proto", "http")
			}
			for _, k := range clientIPHeaders { // other headers a client could use to claim an address
				h.Del(k)
			}
			h.Set("X-Request-ID", c.reqID)
			applyHeaderRules(h, c.route.RequestHeaders)
		},
		Transport: gwRoundTripper{g},
		ModifyResponse: func(resp *http.Response) error {
			c := resp.Request.Context().Value(gwCtxKey{}).(*gwCtx)
			if c.tls && resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=31536000")
			}
			resp.Header.Set("X-Request-ID", c.reqID)
			applyHeaderRules(resp.Header, c.route.ResponseHeaders)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			c := r.Context().Value(gwCtxKey{}).(*gwCtx)
			c.err = err
			status := http.StatusBadGateway
			var tooBig *http.MaxBytesError
			switch {
			case errors.As(err, &tooBig):
				status = http.StatusRequestEntityTooLarge
				c.route.m.deny(denyBody)
			case errors.Is(err, context.Canceled):
				status = 499 // client went away
			case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
				status = http.StatusGatewayTimeout
			}
			if status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
				c.route.m.upErrors.Add(1)
			}
			w.WriteHeader(status)
		},
	}
	return g
}

// clientIPHeaders are removed from proxied requests: only X-Forwarded-For, set by the gateway,
// carries the client address.
var clientIPHeaders = []string{"X-Real-Ip", "True-Client-Ip", "X-Client-Ip"}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isDialErr(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "dial"
}

func applyHeaderRules(h http.Header, hr *HeaderRules) {
	if hr == nil {
		return
	}
	for _, k := range hr.Remove {
		h.Del(k)
	}
	for k, v := range hr.Set {
		h.Set(k, v)
	}
}

// gwBufferPool reuses 32 KB copy buffers across proxied requests.
type gwBufferPool struct{ p sync.Pool }

func (b *gwBufferPool) Get() []byte {
	if v := b.p.Get(); v != nil {
		return *v.(*[]byte)
	}
	return make([]byte, 32<<10)
}

func (b *gwBufferPool) Put(v []byte) { b.p.Put(&v) }

// transport returns the shared upstream transport for a response timeout.
func (g *gatewayServer) transport(timeout time.Duration) *http.Transport {
	if t, ok := g.transports.Load(timeout); ok {
		return t.(*http.Transport)
	}
	t := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          8192,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
		ReadBufferSize:        32 << 10,
		WriteBufferSize:       32 << 10,
	}
	v, _ := g.transports.LoadOrStore(timeout, t)
	return v.(*http.Transport)
}

// gwRoundTripper sends a request to the chosen upstream and, for idempotent requests, retries
// another upstream after a dial error (the request never reached the first one).
type gwRoundTripper struct{ g *gatewayServer }

func (rt gwRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	g := rt.g
	c := req.Context().Value(gwCtxKey{}).(*gwCtx)
	tr := c.route.tr
	for attempt := 0; ; attempt++ {
		tg := c.target
		c.markTried(tg)
		tg.up.active.Add(1)
		t0 := time.Now()
		resp, err := tr.RoundTrip(req)
		if err == nil {
			c.upStatus, c.upNS = resp.StatusCode, time.Since(t0).Nanoseconds()
			resp.Body = &countedBody{ReadCloser: resp.Body, cnt: &tg.up.active}
			return resp, nil
		}
		tg.up.active.Add(-1)
		if !isDialErr(err) { // after a dial the request may have reached the upstream: never resend
			return nil, err
		}
		tg.up.markDown(time.Now())
		g.metrics.upstreamFailure(c.route.Name, tg.addr)
		idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions
		if attempt >= c.route.Retries || !idempotent {
			return nil, err
		}
		next := g.pick(c.route, c.clientIP, time.Now(), c.tried[:c.nTried])
		if next == nil {
			return nil, err
		}
		c.route.m.retries.Add(1)
		req = req.Clone(req.Context())
		req.URL.Host = next.addr
		c.target = next
	}
}

type countedBody struct {
	io.ReadCloser
	cnt  *atomic.Int64
	once sync.Once
}

func (b *countedBody) Close() error {
	b.once.Do(func() { b.cnt.Add(-1) })
	return b.ReadCloser.Close()
}

// load swaps in a new route table. Everything is re-validated: the file is written by root
// (agent or ziroctl), but nothing unchecked should steer the proxy. A route that did not change
// is carried over as the same object, with its rate-limit buckets, counters and health state.
func (g *gatewayServer) load(cfg *GatewayConfig) error {
	settings, err := newGWSettings(cfg.Settings)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	old := g.tbl.Load()
	oldByName := make(map[string]*gwRoute, len(old.all))
	for _, r := range old.all {
		oldByName[r.Name] = r
	}
	t := newRouteTable()
	t.cfg = cfg
	order := map[*gwRoute]int{}
	certs := map[string]*tls.Certificate{}
	for name, c := range cfg.Certs {
		if validName(name) != nil {
			return fmt.Errorf("invalid certificate name %q", name)
		}
		kp, err := tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
		if err != nil {
			return fmt.Errorf("certificate %s: %w", name, err)
		}
		certs[name] = &kp
	}
	seenNames := map[string]bool{}
	for i, rs := range cfg.Routes {
		rs.Normalize()
		if err := validateRoute(&rs.GatewayRoute); err != nil {
			return fmt.Errorf("route %q: %w", rs.Name, err)
		}
		if seenNames[rs.Name] {
			return fmt.Errorf("duplicate route %q", rs.Name)
		}
		seenNames[rs.Name] = true
		fpb, _ := json.Marshal(rs)
		fp := string(fpb)
		prev := oldByName[rs.Name]
		r := prev
		if prev == nil || prev.fp != fp {
			if r, err = g.buildRoute(rs, fp, prev); err != nil {
				return err
			}
		}
		order[r] = i
		t.all = append(t.all, r)
		switch rs.Kind {
		case "tcp":
			if t.tcp[rs.Listen] != nil {
				return fmt.Errorf("two tcp routes on port %d", rs.Listen)
			}
			t.tcp[rs.Listen] = r
		case "tls":
			for _, h := range rs.Hosts {
				if strings.HasPrefix(h, "*.") {
					t.sniWd[h[2:]] = r
				} else {
					t.sniEx[h] = r
				}
			}
		default:
			for _, h := range rs.Hosts {
				if strings.HasPrefix(h, "*.") {
					t.wild[h[2:]] = append(t.wild[h[2:]], r)
				} else {
					t.exact[h] = append(t.exact[h], r)
				}
			}
		}
	}
	for _, m := range []map[string][]*gwRoute{t.exact, t.wild} {
		for _, rs := range m {
			sort.SliceStable(rs, func(i, j int) bool {
				if a, b := rs[i].specificity(), rs[j].specificity(); a != b {
					return a > b
				}
				return order[rs[i]] < order[rs[j]]
			})
		}
	}
	g.certMu.Lock()
	g.certs = certs
	g.certMu.Unlock()
	g.settings.Store(settings)
	g.tbl.Store(t)
	g.hasSNI.Store(len(t.sniEx)+len(t.sniWd) > 0)
	g.prune(t)
	g.syncHealthChecks(t)
	return nil
}

// buildRoute resolves one route's runtime state. prev, the route of the same name before the
// reload, lends the state worth keeping: a rate limit's buckets, the round-robin position and
// the health of targets that are still there.
func (g *gatewayServer) buildRoute(rs GatewayRouteState, fp string, prev *gwRoute) (*gwRoute, error) {
	r := &gwRoute{GatewayRouteState: rs, fp: fp, timeout: 60 * time.Second, m: g.metrics.route(rs.Name),
		cookieName: "ziro_gw_" + rs.Name, realm: rs.Name}
	if rs.Timeout != "" {
		r.timeout, _ = time.ParseDuration(rs.Timeout)
	}
	r.tr = g.transport(r.timeout)
	targets := rs.Targets
	if len(targets) == 0 {
		for _, u := range rs.Upstreams {
			targets = append(targets, GatewayTarget{Addr: u, Weight: 1})
		}
	}
	if len(targets) > gatewayMaxTargets*4 {
		return nil, fmt.Errorf("route %q: too many targets", rs.Name)
	}
	for _, t := range targets {
		if _, err := netip.ParseAddrPort(t.Addr); err != nil || t.Weight < 1 {
			return nil, fmt.Errorf("route %q: invalid upstream %q", rs.Name, t.Addr)
		}
		tg := &gwTarget{addr: t.Addr, weight: t.Weight, sticky: stickyValue(t.Addr), up: g.upstreamFor(t.Addr)}
		if prev != nil {
			for _, pt := range prev.targets {
				if pt.addr == t.Addr {
					tg.unhealthy.Store(pt.unhealthy.Load())
				}
			}
		}
		r.targets = append(r.targets, tg)
	}
	for _, c := range rs.AllowCIDRs {
		p, _ := netip.ParsePrefix(c)
		r.allow = append(r.allow, p.Masked())
	}
	for k, v := range rs.Headers {
		r.hdrs = append(r.hdrs, gwHeaderMatch{http.CanonicalHeaderKey(k), v})
	}
	if rs.RateRPS > 0 {
		if prev != nil && prev.limiter != nil && prev.RateRPS == rs.RateRPS {
			r.limiter = prev.limiter
		} else {
			r.limiter = newTokenBucket(rs.RateRPS)
		}
	}
	if len(rs.BasicAuth) > 0 {
		if prev != nil && prev.authFail != nil {
			r.authFail = prev.authFail
		} else {
			r.authFail = newTokenBucket(1) // one failed login per second per client, in bursts of 10
		}
	}
	if prev != nil {
		r.next.Store(prev.next.Load())
	}
	return r, nil
}

// prune forgets state of upstreams and routes the new table no longer has.
func (g *gatewayServer) prune(t *routeTable) {
	routes, ups := map[string]bool{}, map[string]bool{}
	for _, r := range t.all {
		routes[r.Name] = true
		for _, tg := range r.targets {
			ups[tg.addr] = true
		}
	}
	g.upstreams.Range(func(k, _ any) bool {
		if !ups[k.(string)] {
			g.upstreams.Delete(k)
		}
		return true
	})
	g.metrics.prune(routes, ups)
}

// ---- HTTP handler ----

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush/Hijack (streaming, WebSocket upgrades).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func clientAllowed(r *gwRoute, ip string) bool {
	if len(r.allow) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range r.allow {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// dummyHash makes a check for an unknown user cost the same as for a known one.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("zirogate"), bcrypt.DefaultCost)
	return h
})

// checkBasicAuth verifies credentials. Verified credentials are cached for a few minutes, so a
// client pays for bcrypt once; failures are limited per client, so guessing is slow and cannot
// be used to burn CPU (limited reports that the client is over its failure budget).
func (g *gatewayServer) checkBasicAuth(r *gwRoute, req *http.Request, ip string, now time.Time) (ok, limited bool) {
	if len(r.BasicAuth) == 0 {
		return true, false
	}
	user, pass, has := req.BasicAuth()
	if !has {
		return false, false
	}
	key := rateKey(ip)
	if !r.authFail.has(key, now) {
		return false, true
	}
	hash, known := r.BasicAuth[user]
	if known {
		d := authDigest(user, pass, hash)
		if g.auth.ok(d, now) {
			return true, false
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil {
			g.auth.put(d, now)
			return true, false
		}
	} else {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(pass))
	}
	r.authFail.take(key, now)
	return false, false
}

// deny answers a refused request and counts it.
func (st *reqState) deny(reason denyReason, code int, msg string) {
	if st.route != nil {
		st.route.m.deny(reason)
	} else {
		st.g.metrics.none.deny(reason)
	}
	http.Error(&st.sw, msg, code)
}

func (g *gatewayServer) handler(isTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		st := reqPool.Get().(*reqState)
		st.g, st.start = g, time.Now()
		st.sw.ResponseWriter = w
		start := st.start
		defer g.finish(st, req)
		secure := cfTunnelRequest(req) || isTLS // through a Cloudflare Tunnel: visitor's address and scheme
		st.host = normalizeHost(req.Host)
		st.ip = clientIP(gwPeerIP(req.RemoteAddr), req.Header, g.settings.Load())
		host, ip := st.host, st.ip
		reqID := req.Header.Get("X-Request-ID")
		if len(reqID) < 8 || len(reqID) > 64 || strings.ContainsAny(reqID, " \t\r\n") {
			reqID = g.reqIDGen()
		}
		c := &st.c
		c.reqID = reqID

		// Match and forward the canonical path, so no rule is sidestepped by how the path is spelled.
		p, ok := cleanRequestPath(req.URL.Path)
		if !ok {
			st.deny(denyPath, http.StatusBadRequest, "bad request")
			return
		}
		if p != req.URL.Path {
			req.URL.Path, req.URL.RawPath = p, ""
		}

		rt := g.match(host, req)
		if rt == nil {
			http.Error(&st.sw, "no route", http.StatusNotFound)
			return
		}
		st.route = rt
		rt.m.inflight.Add(1)
		if !secure && rt.TLS != "off" {
			target := host
			if g.httpsPort != 0 && g.httpsPort != 443 {
				target = net.JoinHostPort(host, strconv.Itoa(g.httpsPort))
			}
			http.Redirect(&st.sw, req, "https://"+target+req.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		if !clientAllowed(rt, ip) {
			st.deny(denyACL, http.StatusForbidden, "forbidden")
			return
		}
		if rt.limiter != nil && !rt.limiter.allow(rateKey(ip), start) {
			st.sw.Header().Set("Retry-After", "1")
			st.deny(denyRate, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		if ok, limited := g.checkBasicAuth(rt, req, ip, start); !ok {
			if limited {
				st.sw.Header().Set("Retry-After", "1")
				st.deny(denyAuth, http.StatusTooManyRequests, "too many failed attempts")
				return
			}
			st.sw.Header().Set("WWW-Authenticate", `Basic realm="`+rt.realm+`", charset="UTF-8"`)
			st.deny(denyAuth, http.StatusUnauthorized, "unauthorized")
			return
		}
		if h3 := g.h3.Load(); h3 != nil && isTLS {
			_ = h3.SetQUICHeaders(st.sw.Header())
		}
		st.sw.Header().Set("X-Request-ID", reqID)
		switch {
		case rt.Redirect != "":
			http.Redirect(&st.sw, req, strings.ReplaceAll(rt.Redirect, "{uri}", req.URL.RequestURI()), rt.RedirectCode)
			return
		case rt.Respond != nil:
			st.sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			st.sw.Header().Set("X-Content-Type-Options", "nosniff")
			st.sw.WriteHeader(rt.Respond.Status)
			_, _ = io.WriteString(&st.sw, rt.Respond.Body)
			return
		}
		limit := int64(rt.MaxBodyMB)
		if limit == 0 {
			limit = gatewayDefaultBody
		}
		if req.ContentLength > limit<<20 {
			st.deny(denyBody, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if req.ContentLength != 0 { // no ReadTimeout on the server: bound slow uploads here instead
			_ = http.NewResponseController(&st.sw).SetReadDeadline(start.Add(gatewayBodyTimeout))
		}
		req.Body = http.MaxBytesReader(&st.sw, req.Body, limit<<20)
		var tg *gwTarget
		if rt.LB == "cookie" {
			tg = g.stickyTarget(rt, req, start)
		}
		if tg == nil {
			tg = g.pick(rt, ip, start, nil)
		}
		if tg == nil {
			st.deny(denyNoUp, http.StatusServiceUnavailable, "no healthy upstream")
			return
		}
		if rt.LB == "cookie" {
			http.SetCookie(&st.sw, &http.Cookie{Name: rt.cookieName, Value: tg.sticky, Path: "/",
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		}
		var out http.ResponseWriter = &st.sw
		if rt.Compress && req.Method != http.MethodHead && strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {
			gz := &gzipWriter{ResponseWriter: &st.sw}
			defer gz.Close()
			out = gz
		}
		c.route, c.target, c.tls, c.clientIP = rt, tg, secure, ip
		g.proxy.ServeHTTP(out, req.WithContext(context.WithValue(req.Context(), gwCtxKey{}, c)))
	})
}

// finish records a finished request (metrics, access log) and recycles its state.
func (g *gatewayServer) finish(st *reqState, req *http.Request) {
	code := st.sw.status
	if code == 0 {
		code = http.StatusOK
		if req.Header.Get("Upgrade") != "" { // a hijacked connection (WebSocket) never calls WriteHeader
			code = http.StatusSwitchingProtocols
		}
	}
	d := time.Since(st.start)
	rm := g.metrics.none
	routeName := ""
	if st.route != nil {
		rm, routeName = st.route.m, st.route.Name
		rm.inflight.Add(-1)
	}
	rm.observe(code, d)
	rm.bytesOut.Add(uint64(st.sw.bytes))
	if req.ContentLength > 0 {
		rm.bytesIn.Add(uint64(req.ContentLength))
	}
	if g.alog != nil {
		bp := logBufPool.Get().(*[]byte)
		rec := gwAccessRecord{start: st.start, client: st.ip, host: st.host, method: req.Method, path: req.URL.Path,
			status: code, bytes: st.sw.bytes, ms: d.Milliseconds(), route: routeName, requestID: st.c.reqID,
			userAgent: req.UserAgent(), waf: st.waf}
		if st.c.target != nil {
			rec.upstream = st.c.target.addr
			rec.upStatus, rec.upMS = st.c.upStatus, st.c.upNS/1e6
		}
		if req.TLS != nil {
			rec.tls = tlsVersionName(req.TLS.Version)
		}
		*bp = rec.appendJSON(*bp)
		g.alog.write(bp)
	}
	*st = reqState{}
	reqPool.Put(st)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return ""
}

// ---- status and admin endpoint ----

func (g *gatewayServer) status() GatewayStatus {
	t := g.tbl.Load()
	st := GatewayStatus{Routes: []GatewayRouteStatus{}}
	if t.cfg == nil {
		return st
	}
	now := time.Now().UnixNano()
	for _, r := range t.all {
		match, _ := describeRoute(r.GatewayRouteState)
		rst := GatewayRouteStatus{Name: r.Name, Kind: r.Kind, Match: match, TLS: r.TLS, Upstreams: []UpstreamHealth{}}
		total := 0
		for _, tg := range r.targets {
			total += tg.weight
		}
		for _, tg := range r.targets {
			rst.Upstreams = append(rst.Upstreams, UpstreamHealth{Addr: tg.addr, Share: tg.weight * 100 / max(total, 1),
				Healthy: tg.usable(now), Active: tg.up.active.Load()})
		}
		if r.m.count.Load() > 0 {
			rst.Requests = r.m.requestCounts()
		}
		st.Routes = append(st.Routes, rst)
	}
	g.certMu.Lock()
	st.CA = string(g.caPEM)
	g.certMu.Unlock()
	return st
}

// adminHandler serves /metrics and /status on loopback (the API server reads /status).
func (g *gatewayServer) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		g.metrics.write(w)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.status())
	})
	return mux
}

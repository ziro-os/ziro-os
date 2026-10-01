package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

// ---- rate limiting ----

// tokenBucket allows rate requests/second with a burst of max(rate, 10) per client.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	clients map[string]*bucketState
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newTokenBucket(rps int) *tokenBucket {
	return &tokenBucket{rate: float64(rps), burst: math.Max(float64(rps), 10), clients: map[string]*bucketState{}}
}

func (b *tokenBucket) allow(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.clients[key]
	if s == nil {
		if len(b.clients) >= 100000 { // bound memory under a spoofed-source flood: evict full buckets
			for k, v := range b.clients {
				if v.tokens+now.Sub(v.last).Seconds()*b.rate >= b.burst {
					delete(b.clients, k)
				}
			}
		}
		s = &bucketState{tokens: b.burst, last: now}
		b.clients[key] = s
	}
	s.tokens = math.Min(b.burst, s.tokens+now.Sub(s.last).Seconds()*b.rate)
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// ---- routing table ----

type gwRoute struct {
	GatewayRouteState
	allow   []netip.Prefix
	limiter *tokenBucket
	next    atomic.Uint64
	targets []GatewayTarget
	timeout time.Duration
	order   int // tie-breaker: config order
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
	for k, v := range r.Headers {
		if req.Header.Get(k) != v {
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

type gatewayServer struct {
	mu    sync.RWMutex
	exact map[string][]*gwRoute // host -> most specific first
	wild  map[string][]*gwRoute // "example.com" for "*.example.com"
	tcp   map[int]*gwRoute      // listen port -> route
	sniEx map[string]*gwRoute   // tls passthrough routes
	sniWd map[string]*gwRoute
	cfg   *GatewayConfig

	down    sync.Map // upstream -> time.Time (skip until)
	health  sync.Map // route|upstream -> bool (active checks)
	active  sync.Map // upstream -> *atomic.Int64 (least_conn)
	checks  map[string]context.CancelFunc
	checkMu sync.Mutex

	transports sync.Map // timeout -> *http.Transport
	proxy      *httputil.ReverseProxy
	log        func(v any)
	metrics    *gwMetrics

	certMu   sync.Mutex
	certs    map[string]*tls.Certificate // uploaded, by name
	leafs    map[string]*tls.Certificate // internal CA leafs, by host
	ca       *tls.Certificate
	caPEM    []byte
	acmeMgr  *autocert.Manager
	h3       *http3.Server
	hasSNI   atomic.Bool
	l4       map[int]net.Listener
	l4Mu     sync.Mutex
	reqIDGen func() string
}

type gwCtxKey struct{}

type gwCtx struct {
	route    *gwRoute
	upstream string
	tls      bool
	clientIP string
	reqID    string
}

func newGatewayServer() *gatewayServer {
	g := &gatewayServer{exact: map[string][]*gwRoute{}, wild: map[string][]*gwRoute{}, tcp: map[int]*gwRoute{},
		sniEx: map[string]*gwRoute{}, sniWd: map[string]*gwRoute{}, checks: map[string]context.CancelFunc{},
		certs: map[string]*tls.Certificate{}, leafs: map[string]*tls.Certificate{}, l4: map[int]net.Listener{},
		metrics: newGWMetrics()}
	g.log = func(v any) {
		if b, err := json.Marshal(v); err == nil {
			fmt.Println(string(b))
		}
	}
	g.reqIDGen = func() string {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	bufPool := &gwBufferPool{}
	g.proxy = &httputil.ReverseProxy{
		BufferPool: bufPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			c := pr.In.Context().Value(gwCtxKey{}).(*gwCtx)
			pr.SetURL(&url.URL{Scheme: "http", Host: c.upstream})
			if sp := c.route.StripPrefix; sp != "" && strings.HasPrefix(pr.Out.URL.Path, sp) {
				pr.Out.URL.Path = "/" + strings.TrimLeft(strings.TrimPrefix(pr.Out.URL.Path, sp), "/")
				pr.Out.URL.RawPath = ""
			}
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded() // replaces any client-supplied X-Forwarded-* headers
			pr.Out.Header.Set("X-Request-ID", c.reqID)
			applyHeaderRules(pr.Out.Header, c.route.RequestHeaders)
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
			status := http.StatusBadGateway
			if errors.Is(err, context.Canceled) {
				status = 499 // client went away
			} else if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				status = http.StatusGatewayTimeout
			}
			w.WriteHeader(status)
		},
	}
	return g
}

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
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
	}
	v, _ := g.transports.LoadOrStore(timeout, t)
	return v.(*http.Transport)
}

func (g *gatewayServer) activeCounter(addr string) *atomic.Int64 {
	if v, ok := g.active.Load(addr); ok {
		return v.(*atomic.Int64)
	}
	v, _ := g.active.LoadOrStore(addr, new(atomic.Int64))
	return v.(*atomic.Int64)
}

// gwRoundTripper sends a request to the chosen upstream and, for idempotent requests, retries
// another upstream after a dial error (the request never reached the first one).
type gwRoundTripper struct{ g *gatewayServer }

func (rt gwRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	g := rt.g
	c := req.Context().Value(gwCtxKey{}).(*gwCtx)
	tr := g.transport(c.route.timeout)
	tried := map[string]bool{}
	for attempt := 0; ; attempt++ {
		tried[c.upstream] = true
		cnt := g.activeCounter(c.upstream)
		cnt.Add(1)
		resp, err := tr.RoundTrip(req)
		if err == nil {
			resp.Body = &countedBody{ReadCloser: resp.Body, cnt: cnt}
			return resp, nil
		}
		cnt.Add(-1)
		if !isDialErr(err) { // after a dial the request may have reached the upstream: never resend
			return nil, err
		}
		g.down.Store(c.upstream, time.Now().Add(gatewayDownFor))
		g.metrics.upstreamFailure(c.route.Name, c.upstream)
		idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions
		if attempt >= c.route.Retries || !idempotent {
			return nil, err
		}
		next := g.pickExcluding(c.route, c.clientIP, time.Now(), tried)
		if next == "" {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL.Host = next
		c.upstream = next
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
// (agent or ziroctl), but nothing unchecked should steer the proxy.
func (g *gatewayServer) load(cfg *GatewayConfig) error {
	exact, wild := map[string][]*gwRoute{}, map[string][]*gwRoute{}
	tcp, sniEx, sniWd := map[int]*gwRoute{}, map[string]*gwRoute{}, map[string]*gwRoute{}
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
	for i, rs := range cfg.Routes {
		rs.Normalize()
		if err := validateRoute(&rs.GatewayRoute); err != nil {
			return fmt.Errorf("route %q: %w", rs.Name, err)
		}
		r := &gwRoute{GatewayRouteState: rs, order: i, timeout: 60 * time.Second}
		if rs.Timeout != "" {
			r.timeout, _ = time.ParseDuration(rs.Timeout)
		}
		targets := rs.Targets
		if len(targets) == 0 {
			for _, u := range rs.Upstreams {
				targets = append(targets, GatewayTarget{Addr: u, Weight: 1})
			}
		}
		if len(targets) > gatewayMaxTargets*4 {
			return fmt.Errorf("route %q: too many targets", rs.Name)
		}
		for _, t := range targets {
			if _, err := netip.ParseAddrPort(t.Addr); err != nil || t.Weight < 1 {
				return fmt.Errorf("route %q: invalid upstream %q", rs.Name, t.Addr)
			}
		}
		r.targets = targets
		for _, c := range rs.AllowCIDRs {
			p, _ := netip.ParsePrefix(c)
			r.allow = append(r.allow, p.Masked())
		}
		if rs.RateRPS > 0 {
			r.limiter = newTokenBucket(rs.RateRPS)
		}
		switch rs.Kind {
		case "tcp":
			if tcp[rs.Listen] != nil {
				return fmt.Errorf("two tcp routes on port %d", rs.Listen)
			}
			tcp[rs.Listen] = r
		case "tls":
			for _, h := range rs.Hosts {
				if strings.HasPrefix(h, "*.") {
					sniWd[h[2:]] = r
				} else {
					sniEx[h] = r
				}
			}
		default:
			for _, h := range rs.Hosts {
				if strings.HasPrefix(h, "*.") {
					wild[h[2:]] = append(wild[h[2:]], r)
				} else {
					exact[h] = append(exact[h], r)
				}
			}
		}
	}
	for _, m := range []map[string][]*gwRoute{exact, wild} {
		for _, rs := range m {
			sort.SliceStable(rs, func(i, j int) bool {
				if a, b := rs[i].specificity(), rs[j].specificity(); a != b {
					return a > b
				}
				return rs[i].order < rs[j].order
			})
		}
	}
	g.certMu.Lock()
	g.certs = certs
	g.certMu.Unlock()
	g.mu.Lock()
	g.exact, g.wild, g.tcp, g.sniEx, g.sniWd, g.cfg = exact, wild, tcp, sniEx, sniWd, cfg
	g.mu.Unlock()
	g.hasSNI.Store(len(sniEx)+len(sniWd) > 0)
	g.syncHealthChecks()
	return nil
}

func hostCandidates(host string) (exact, parent string) {
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host, host[i+1:]
	}
	return host, ""
}

func (g *gatewayServer) match(host string, req *http.Request) *gwRoute {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ex, parent := hostCandidates(host)
	for _, r := range g.exact[ex] {
		if r.matches(req) {
			return r
		}
	}
	for _, r := range g.wild[parent] {
		if r.matches(req) {
			return r
		}
	}
	return nil
}

// hostRoute is the most specific route serving host (for TLS decisions).
func (g *gatewayServer) hostRoute(host string) *gwRoute {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ex, parent := hostCandidates(host)
	if rs := g.exact[ex]; len(rs) > 0 {
		return rs[0]
	}
	if rs := g.wild[parent]; len(rs) > 0 {
		return rs[0]
	}
	return nil
}

func (g *gatewayServer) sniRoute(host string) *gwRoute {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ex, parent := hostCandidates(strings.ToLower(host))
	if r := g.sniEx[ex]; r != nil {
		return r
	}
	return g.sniWd[parent]
}

// acmeHost: hosts whose certificate comes from ACME.
func (g *gatewayServer) acmeHost(host string) bool {
	r := g.hostRoute(host)
	return r != nil && r.TLS == "auto"
}

// ---- load balancing ----

func (g *gatewayServer) usable(r *gwRoute, addr string, now time.Time) bool {
	if until, ok := g.down.Load(addr); ok && now.Before(until.(time.Time)) {
		return false
	}
	if h, ok := g.health.Load(r.Name + "|" + addr); ok && !h.(bool) {
		return false
	}
	return true
}

func (g *gatewayServer) pick(r *gwRoute, clientIP string, now time.Time) string {
	return g.pickExcluding(r, clientIP, now, nil)
}

// pickExcluding chooses an upstream by the route's policy among usable targets; when none is
// usable it tries one anyway (better a probe than a guaranteed 503).
func (g *gatewayServer) pickExcluding(r *gwRoute, clientIP string, now time.Time, exclude map[string]bool) string {
	var cands []GatewayTarget
	total := 0
	for _, t := range r.targets {
		if !exclude[t.Addr] && g.usable(r, t.Addr, now) {
			cands = append(cands, t)
			total += t.Weight
		}
	}
	if len(cands) == 0 {
		for _, t := range r.targets {
			if !exclude[t.Addr] {
				cands = append(cands, t)
				total += t.Weight
			}
		}
		if len(cands) == 0 {
			return ""
		}
	}
	byWeight := func(n uint64) string {
		x := int(n % uint64(total))
		for _, t := range cands {
			if x < t.Weight {
				return t.Addr
			}
			x -= t.Weight
		}
		return cands[0].Addr
	}
	switch r.LB {
	case "least_conn":
		best, bestScore := "", math.MaxFloat64
		for _, t := range cands {
			score := float64(g.activeCounter(t.Addr).Load()+1) / float64(t.Weight)
			if score < bestScore {
				best, bestScore = t.Addr, score
			}
		}
		return best
	case "ip_hash":
		h := fnv.New64a()
		h.Write([]byte(clientIP))
		return byWeight(h.Sum64())
	default: // round_robin, and cookie when there is no valid sticky cookie
		return byWeight(r.next.Add(1) - 1)
	}
}

func stickyValue(addr string) string {
	h := fnv.New64a()
	h.Write([]byte(addr))
	return strconv.FormatUint(h.Sum64(), 36)
}

// stickyTarget returns the target a sticky cookie points at, if it is still usable.
func (g *gatewayServer) stickyTarget(r *gwRoute, req *http.Request, now time.Time) string {
	ck, err := req.Cookie("ziro_gw_" + r.Name)
	if err != nil {
		return ""
	}
	for _, t := range r.targets {
		if stickyValue(t.Addr) == ck.Value && g.usable(r, t.Addr, now) {
			return t.Addr
		}
	}
	return ""
}

// ---- active health checks ----

// syncHealthChecks runs one checker per (route, target) with a health check; removed ones stop.
func (g *gatewayServer) syncHealthChecks() {
	g.mu.RLock()
	want := map[string]func(ctx context.Context){}
	add := func(r *gwRoute) {
		if r.Health == nil {
			return
		}
		for _, t := range r.targets {
			key := r.Name + "|" + t.Addr
			r, addr := r, t.Addr
			want[key] = func(ctx context.Context) { g.healthLoop(ctx, r, addr) }
		}
	}
	seen := map[*gwRoute]bool{}
	for _, m := range []map[string][]*gwRoute{g.exact, g.wild} {
		for _, rs := range m {
			for _, r := range rs {
				if !seen[r] {
					seen[r] = true
					add(r)
				}
			}
		}
	}
	for _, r := range g.tcp {
		add(r)
	}
	g.mu.RUnlock()

	g.checkMu.Lock()
	defer g.checkMu.Unlock()
	for key, cancel := range g.checks {
		if want[key] == nil {
			cancel()
			delete(g.checks, key)
			g.health.Delete(key)
		}
	}
	for key, run := range want {
		if g.checks[key] != nil {
			g.checks[key]() // restart: the route's settings may have changed
		}
		ctx, cancel := context.WithCancel(context.Background())
		g.checks[key] = cancel
		go run(ctx)
	}
}

func (g *gatewayServer) healthLoop(ctx context.Context, r *gwRoute, addr string) {
	interval := 10 * time.Second
	if r.Health.Interval != "" {
		interval, _ = time.ParseDuration(r.Health.Interval)
	}
	client := &http.Client{Timeout: min(interval, 5*time.Second), Transport: g.transport(5 * time.Second),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	key := r.Name + "|" + addr
	check := func() {
		ok := false
		if r.Kind == "tcp" {
			if c, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
				c.Close()
				ok = true
			}
		} else if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+r.Health.Path, nil); err == nil {
			if len(r.Hosts) > 0 && !strings.HasPrefix(r.Hosts[0], "*.") {
				req.Host = r.Hosts[0]
			}
			req.Header.Set("User-Agent", "zirogate-health/1")
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				if r.Health.Expect != 0 {
					ok = resp.StatusCode == r.Health.Expect
				} else {
					ok = resp.StatusCode >= 200 && resp.StatusCode < 400
				}
			}
		}
		if prev, loaded := g.health.Swap(key, ok); !loaded || prev.(bool) != ok {
			g.log(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "health", "route": r.Name, "upstream": addr, "healthy": ok})
		}
		g.metrics.setHealth(r.Name, addr, ok)
	}
	check()
	jitter := time.Duration(time.Now().UnixNano() % int64(interval/5+1))
	t := time.NewTicker(interval + jitter)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
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

func checkBasicAuth(r *gwRoute, req *http.Request) bool {
	if len(r.BasicAuth) == 0 {
		return true
	}
	user, pass, ok := req.BasicAuth()
	hash, known := r.BasicAuth[user]
	h := []byte(hash)
	if !known {
		h = dummyHash()
	}
	return bcrypt.CompareHashAndPassword(h, []byte(pass)) == nil && ok && known
}

func (g *gatewayServer) handler(isTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		host := strings.ToLower(req.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip, _, _ := net.SplitHostPort(req.RemoteAddr)
		upstream, routeName := "", ""
		reqID := req.Header.Get("X-Request-ID")
		if len(reqID) < 8 || len(reqID) > 64 || strings.ContainsAny(reqID, " \t\r\n") {
			reqID = g.reqIDGen()
		}
		defer func() {
			g.metrics.observe(routeName, sw.status, time.Since(start))
			g.log(map[string]any{"ts": start.UTC().Format(time.RFC3339Nano), "client": ip, "host": host,
				"method": req.Method, "path": req.URL.Path, "status": sw.status, "bytes": sw.bytes,
				"ms": time.Since(start).Milliseconds(), "upstream": upstream, "route": routeName, "request_id": reqID})
		}()

		rt := g.match(host, req)
		if rt == nil {
			http.Error(sw, "no route", http.StatusNotFound)
			return
		}
		routeName = rt.Name
		if !isTLS && rt.TLS != "off" {
			http.Redirect(sw, req, "https://"+host+req.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		if !clientAllowed(rt, ip) {
			http.Error(sw, "forbidden", http.StatusForbidden)
			return
		}
		if rt.limiter != nil && !rt.limiter.allow(ip, start) {
			sw.Header().Set("Retry-After", "1")
			http.Error(sw, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		if !checkBasicAuth(rt, req) {
			sw.Header().Set("WWW-Authenticate", `Basic realm="`+rt.Name+`", charset="UTF-8"`)
			http.Error(sw, "unauthorized", http.StatusUnauthorized)
			return
		}
		if g.h3 != nil && isTLS {
			_ = g.h3.SetQUICHeaders(sw.Header())
		}
		sw.Header().Set("X-Request-ID", reqID)
		switch {
		case rt.Redirect != "":
			http.Redirect(sw, req, strings.ReplaceAll(rt.Redirect, "{uri}", req.URL.RequestURI()), rt.RedirectCode)
			return
		case rt.Respond != nil:
			sw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			sw.Header().Set("X-Content-Type-Options", "nosniff")
			sw.WriteHeader(rt.Respond.Status)
			_, _ = io.WriteString(sw, rt.Respond.Body)
			return
		}
		limit := int64(rt.MaxBodyMB)
		if limit == 0 {
			limit = gatewayDefaultBody
		}
		if req.ContentLength > limit<<20 {
			http.Error(sw, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = http.MaxBytesReader(sw, req.Body, limit<<20)
		if rt.LB == "cookie" {
			upstream = g.stickyTarget(rt, req, start)
		}
		if upstream == "" {
			upstream = g.pick(rt, ip, start)
		}
		if upstream == "" {
			http.Error(sw, "no healthy upstream", http.StatusServiceUnavailable)
			return
		}
		if rt.LB == "cookie" {
			http.SetCookie(sw, &http.Cookie{Name: "ziro_gw_" + rt.Name, Value: stickyValue(upstream), Path: "/",
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		}
		var out http.ResponseWriter = sw
		if rt.Compress && req.Method != http.MethodHead && strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {
			gz := &gzipWriter{ResponseWriter: sw}
			defer gz.Close()
			out = gz
		}
		c := &gwCtx{route: rt, upstream: upstream, tls: isTLS, clientIP: ip, reqID: reqID}
		g.proxy.ServeHTTP(out, req.WithContext(context.WithValue(req.Context(), gwCtxKey{}, c)))
		upstream = c.upstream
	})
}

// ---- compression ----

var gzipPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression); return w }}

func compressible(ct string) bool {
	ct = strings.ToLower(ct)
	for _, p := range []string{"text/", "application/json", "application/javascript", "application/xml", "application/x-javascript",
		"image/svg+xml", "application/wasm", "application/ld+json", "application/manifest+json"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// gzipWriter compresses compressible responses the upstream didn't compress itself.
type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
}

func (w *gzipWriter) WriteHeader(code int) {
	if !w.decided {
		w.decided = true
		h := w.Header()
		cl, _ := strconv.Atoi(h.Get("Content-Length"))
		if h.Get("Content-Encoding") == "" && compressible(h.Get("Content-Type")) && code != http.StatusNoContent &&
			code != http.StatusNotModified && (h.Get("Content-Length") == "" || cl >= 1024) {
			h.Del("Content-Length")
			h.Set("Content-Encoding", "gzip")
			h.Add("Vary", "Accept-Encoding")
			w.gz = gzipPool.Get().(*gzip.Writer)
			w.gz.Reset(w.ResponseWriter)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.gz != nil {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *gzipWriter) Close() {
	if w.gz != nil {
		_ = w.gz.Close()
		gzipPool.Put(w.gz)
		w.gz = nil
	}
}

func (w *gzipWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ---- TLS: ACME, uploaded certificates, internal CA ----

func (g *gatewayServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(hello.ServerName)
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto && g.acmeMgr != nil {
			return g.acmeMgr.GetCertificate(hello) // TLS-ALPN-01 challenge
		}
	}
	r := g.hostRoute(host)
	if r == nil {
		return nil, fmt.Errorf("no route for %q", host)
	}
	switch {
	case r.TLS == "auto" && g.acmeMgr != nil:
		return g.acmeMgr.GetCertificate(hello)
	case r.TLS == "internal":
		return g.internalLeaf(host)
	case strings.HasPrefix(r.TLS, "cert:"):
		g.certMu.Lock()
		c := g.certs[strings.TrimPrefix(r.TLS, "cert:")]
		g.certMu.Unlock()
		if c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("certificate %s not uploaded", r.TLS)
	}
	return nil, fmt.Errorf("no TLS for %q", host)
}

// loadInternalCA uses the cluster's internal CA (distributed to gateway nodes) or a local one,
// created on first use (ECDSA P-256, root-only files).
func (g *gatewayServer) loadInternalCA() error {
	g.certMu.Lock()
	defer g.certMu.Unlock()
	var certPEM, keyPEM []byte
	if g.cfg != nil && g.cfg.InternalCA != nil {
		certPEM, keyPEM = []byte(g.cfg.InternalCA.Cert), []byte(g.cfg.InternalCA.Key)
	} else {
		var err error
		if certPEM, keyPEM, err = localInternalCA(); err != nil {
			return err
		}
	}
	if g.ca != nil && bytes.Equal(certPEM, g.caPEM) {
		return nil
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	g.ca, g.caPEM, g.leafs = &kp, certPEM, map[string]*tls.Certificate{}
	return nil
}

var internalCAPaths = func() (string, string) {
	return filepath.Join(gatewayCertDir, "internal-ca.crt"), filepath.Join(gatewayCertDir, "internal-ca.key")
}

func localInternalCA() ([]byte, []byte, error) {
	crtPath, keyPath := internalCAPaths()
	if c, err := os.ReadFile(crtPath); err == nil {
		k, err := os.ReadFile(keyPath)
		return c, k, err
	}
	c, k, err := newInternalCA()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(crtPath), 0700); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(keyPath, k, 0600); err != nil {
		return nil, nil, err
	}
	return c, k, writeFileAtomic(crtPath, c, 0644)
}

// newInternalCA creates the gateway's private CA (10 years; signs only server certificates).
func newInternalCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Ziro gateway internal CA", Organization: []string{"Ziro OS"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// internalLeaf issues (and caches) a 30-day server certificate for host from the internal CA.
func (g *gatewayServer) internalLeaf(host string) (*tls.Certificate, error) {
	if err := g.loadInternalCA(); err != nil {
		return nil, err
	}
	g.certMu.Lock()
	defer g.certMu.Unlock()
	if c := g.leafs[host]; c != nil && time.Until(c.Leaf.NotAfter) > 10*24*time.Hour {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, g.ca.Leaf, &key.PublicKey, g.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	c := &tls.Certificate{Certificate: [][]byte{der, g.ca.Certificate[0]}, PrivateKey: key, Leaf: leaf}
	g.leafs[host] = c
	return c, nil
}

// ---- L4: TCP routes and TLS passthrough ----

func (g *gatewayServer) serveL4(conn net.Conn, r *gwRoute) {
	defer conn.Close()
	start := time.Now()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !clientAllowed(r, ip) || r.limiter != nil && !r.limiter.allow(ip, start) {
		g.metrics.observe(r.Name, 403, 0)
		return
	}
	tried := map[string]bool{}
	var up net.Conn
	upstream := ""
	for range r.targets {
		upstream = g.pickExcluding(r, ip, time.Now(), tried)
		if upstream == "" {
			break
		}
		tried[upstream] = true
		c, err := net.DialTimeout("tcp", upstream, 5*time.Second)
		if err == nil {
			up = c
			break
		}
		g.down.Store(upstream, time.Now().Add(gatewayDownFor))
		g.metrics.upstreamFailure(r.Name, upstream)
	}
	if up == nil {
		g.metrics.observe(r.Name, 502, time.Since(start))
		return
	}
	defer up.Close()
	cnt := g.activeCounter(upstream)
	cnt.Add(1)
	defer cnt.Add(-1)
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
	g.metrics.observe(r.Name, 200, time.Since(start))
	g.log(map[string]any{"ts": start.UTC().Format(time.RFC3339Nano), "client": ip, "route": r.Name, "kind": r.Kind,
		"upstream": upstream, "ms": time.Since(start).Milliseconds()})
}

// syncL4Listeners opens a listener per tcp route port and closes ports no route uses.
func (g *gatewayServer) syncL4Listeners() {
	g.mu.RLock()
	want := map[int]bool{}
	for p := range g.tcp {
		want[p] = true
	}
	g.mu.RUnlock()
	g.l4Mu.Lock()
	defer g.l4Mu.Unlock()
	for p, ln := range g.l4 {
		if !want[p] {
			ln.Close()
			delete(g.l4, p)
		}
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
				g.mu.RLock()
				r := g.tcp[p]
				g.mu.RUnlock()
				if r == nil {
					c.Close()
					continue
				}
				go g.serveL4(c, r)
			}
		}(p, ln)
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

// splitTLS accepts on :443 and routes each connection: TLS passthrough routes (by SNI) are
// proxied raw; everything else goes to the HTTPS server. Without passthrough routes nothing is
// peeked.
func (g *gatewayServer) splitTLS(ln net.Listener, https *chanListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			https.Close()
			return
		}
		if !g.hasSNI.Load() {
			https.ch <- c
			continue
		}
		go func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			sni, buf, err := peekSNI(c)
			_ = c.SetReadDeadline(time.Time{})
			rc := &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(buf), c)}
			if err == nil {
				if r := g.sniRoute(sni); r != nil {
					g.serveL4(rc, r)
					return
				}
			}
			https.ch <- rc
		}(c)
	}
}

// ---- metrics (Prometheus text format) ----

var gwBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type gwRouteMetrics struct {
	codes  map[int]uint64
	bucket []uint64
	sum    float64
	count  uint64
}

type gwMetrics struct {
	mu       sync.Mutex
	routes   map[string]*gwRouteMetrics
	failures map[string]uint64 // route|upstream
	health   map[string]bool
}

func newGWMetrics() *gwMetrics {
	return &gwMetrics{routes: map[string]*gwRouteMetrics{}, failures: map[string]uint64{}, health: map[string]bool{}}
}

func (m *gwMetrics) observe(route string, code int, d time.Duration) {
	if route == "" {
		route = "_none"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rm := m.routes[route]
	if rm == nil {
		rm = &gwRouteMetrics{codes: map[int]uint64{}, bucket: make([]uint64, len(gwBuckets))}
		m.routes[route] = rm
	}
	rm.codes[code]++
	s := d.Seconds()
	for i, b := range gwBuckets {
		if s <= b {
			rm.bucket[i]++
		}
	}
	rm.sum += s
	rm.count++
}

func (m *gwMetrics) upstreamFailure(route, up string) {
	m.mu.Lock()
	m.failures[route+"|"+up]++
	m.mu.Unlock()
}

func (m *gwMetrics) setHealth(route, up string, ok bool) {
	m.mu.Lock()
	m.health[route+"|"+up] = ok
	m.mu.Unlock()
}

func (m *gwMetrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.routes))
	for n := range m.routes {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "# HELP zirogate_requests_total Requests (or L4 connections) by route and status.")
	fmt.Fprintln(w, "# TYPE zirogate_requests_total counter")
	for _, n := range names {
		codes := make([]int, 0, len(m.routes[n].codes))
		for c := range m.routes[n].codes {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Fprintf(w, "zirogate_requests_total{route=%q,code=\"%d\"} %d\n", n, c, m.routes[n].codes[c])
		}
	}
	fmt.Fprintln(w, "# HELP zirogate_request_duration_seconds Time to serve a request.")
	fmt.Fprintln(w, "# TYPE zirogate_request_duration_seconds histogram")
	for _, n := range names {
		rm := m.routes[n]
		for i, b := range gwBuckets {
			fmt.Fprintf(w, "zirogate_request_duration_seconds_bucket{route=%q,le=\"%g\"} %d\n", n, b, rm.bucket[i])
		}
		fmt.Fprintf(w, "zirogate_request_duration_seconds_bucket{route=%q,le=\"+Inf\"} %d\n", n, rm.count)
		fmt.Fprintf(w, "zirogate_request_duration_seconds_sum{route=%q} %g\n", n, rm.sum)
		fmt.Fprintf(w, "zirogate_request_duration_seconds_count{route=%q} %d\n", n, rm.count)
	}
	keys := func(mp map[string]uint64) []string {
		var out []string
		for k := range mp {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	fmt.Fprintln(w, "# HELP zirogate_upstream_failures_total Failed dials to an upstream.")
	fmt.Fprintln(w, "# TYPE zirogate_upstream_failures_total counter")
	for _, k := range keys(m.failures) {
		r, u, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "zirogate_upstream_failures_total{route=%q,upstream=%q} %d\n", r, u, m.failures[k])
	}
	fmt.Fprintln(w, "# HELP zirogate_upstream_healthy Active health check result (1 healthy).")
	fmt.Fprintln(w, "# TYPE zirogate_upstream_healthy gauge")
	hk := make([]string, 0, len(m.health))
	for k := range m.health {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	for _, k := range hk {
		r, u, _ := strings.Cut(k, "|")
		v := 0
		if m.health[k] {
			v = 1
		}
		fmt.Fprintf(w, "zirogate_upstream_healthy{route=%q,upstream=%q} %d\n", r, u, v)
	}
}

func (g *gatewayServer) status() GatewayStatus {
	g.mu.RLock()
	cfg := g.cfg
	g.mu.RUnlock()
	st := GatewayStatus{Routes: []GatewayRouteStatus{}}
	if cfg == nil {
		return st
	}
	now := time.Now()
	g.metrics.mu.Lock()
	defer g.metrics.mu.Unlock()
	for _, rs := range cfg.Routes {
		rs.Normalize()
		match, _ := describeRoute(rs)
		rst := GatewayRouteStatus{Name: rs.Name, Kind: rs.Kind, Match: match, TLS: rs.TLS, Upstreams: []UpstreamHealth{}}
		r := &gwRoute{GatewayRouteState: rs}
		targets := rs.Targets
		if len(targets) == 0 {
			for _, u := range rs.Upstreams {
				targets = append(targets, GatewayTarget{Addr: u, Weight: 1})
			}
		}
		total := 0
		for _, t := range targets {
			total += t.Weight
		}
		for _, t := range targets {
			rst.Upstreams = append(rst.Upstreams, UpstreamHealth{Addr: t.Addr, Share: t.Weight * 100 / max(total, 1), Healthy: g.usable(r, t.Addr, now),
				Active: g.activeCounter(t.Addr).Load()})
		}
		if rm := g.metrics.routes[rs.Name]; rm != nil {
			rst.Requests = map[string]uint64{}
			for c, n := range rm.codes {
				rst.Requests[strconv.Itoa(c)] = n
			}
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

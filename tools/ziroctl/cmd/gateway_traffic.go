package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Traffic management at run time: matchers, retries and their budget, ejection of failing
// upstreams, load shedding, mirroring, CORS and tracing. The settings come from the route
// (sdk/schema/gateway_traffic.go); everything here is resolved when a route is built, so the
// request path only evaluates.

// ---- matchers ----

type gwMatcher struct {
	name, op, value string
	re              *regexp.Regexp
}

func compileMatchers(ms []GatewayMatcher, header bool) ([]gwMatcher, error) {
	out := make([]gwMatcher, 0, len(ms))
	for _, m := range ms {
		gm := gwMatcher{name: m.Name, op: m.Op, value: m.Value}
		if header {
			gm.name = http.CanonicalHeaderKey(m.Name)
		}
		if gm.op == "" {
			gm.op = "eq"
		}
		if gm.op == "regex" {
			re, err := regexp.Compile(m.Value)
			if err != nil {
				return nil, err
			}
			gm.re = re
		}
		out = append(out, gm)
	}
	return out, nil
}

func (m *gwMatcher) test(v string, found bool) bool {
	switch m.op {
	case "present":
		return found
	case "prefix":
		return found && strings.HasPrefix(v, m.value)
	case "regex":
		return found && m.re.MatchString(v)
	}
	return found && v == m.value
}

// queryGet returns the first value of a query parameter without parsing the whole query.
func queryGet(raw, name string) (string, bool) {
	for raw != "" {
		var pair string
		pair, raw, _ = strings.Cut(raw, "&")
		k, v, _ := strings.Cut(pair, "=")
		if strings.ContainsAny(k, "%+") {
			if u, err := url.QueryUnescape(k); err == nil {
				k = u
			}
		}
		if k != name {
			continue
		}
		if strings.ContainsAny(v, "%+") {
			if u, err := url.QueryUnescape(v); err == nil {
				v = u
			}
		}
		return v, true
	}
	return "", false
}

// cookieGet returns the first cookie of that name.
func cookieGet(h http.Header, name string) (string, bool) {
	for _, line := range h["Cookie"] {
		for line != "" {
			var part string
			part, line, _ = strings.Cut(line, ";")
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == name {
				return strings.Trim(v, `"`), true
			}
		}
	}
	return "", false
}

// keySpec says which part of a request identifies a client, a session or a shard: the address,
// or a header, cookie or query parameter.
type keySpec struct {
	kind byte // 0 = address, 'h', 'c', 'q'
	name string
}

func parseKeySpec(s string) keySpec {
	kind, name, ok := strings.Cut(s, ":")
	if !ok {
		return keySpec{}
	}
	return keySpec{kind: kind[0], name: http.CanonicalHeaderKey(name)}
}

// value returns the request's value for the spec, falling back to ip when the request has none.
func (k keySpec) value(req *http.Request, ip string) string {
	var v string
	var ok bool
	switch k.kind {
	case 'h':
		v = req.Header.Get(k.name)
		ok = v != ""
	case 'c':
		v, ok = cookieGet(req.Header, k.name)
	case 'q':
		v, ok = queryGet(req.URL.RawQuery, k.name)
	}
	if ok && v != "" {
		return v
	}
	return ip
}

// ---- retries ----

const (
	retry5xx uint8 = 1 << iota
	retryTimeout
	retryReset
)

func retryMask(on []string) uint8 {
	var m uint8
	for _, c := range on {
		switch c {
		case "5xx":
			m |= retry5xx
		case "timeout":
			m |= retryTimeout
		case "reset":
			m |= retryReset
		}
	}
	return m
}

// retryBudget keeps retries a bounded share of the traffic, so a struggling upstream is not
// buried under retries on top of the load that hurt it: each request earns ratio of a retry and
// each retry spends one, with a small reserve for bursts.
type retryBudget struct {
	milli atomic.Int64 // thousandths of a retry
	ratio int64
}

const (
	retryReserve = 10_000 // initial and maximum balance: 10 retries
	retryCost    = 1000
)

func newRetryBudget(percent int) *retryBudget {
	if percent == 0 {
		percent = 20
	}
	b := &retryBudget{ratio: int64(percent) * 10}
	b.milli.Store(retryReserve)
	return b
}

func (b *retryBudget) request() {
	if b.milli.Add(b.ratio) > retryReserve {
		b.milli.Store(retryReserve)
	}
}

func (b *retryBudget) take() bool {
	for {
		v := b.milli.Load()
		if v < retryCost {
			return false
		}
		if b.milli.CompareAndSwap(v, v-retryCost) {
			return true
		}
	}
}

func idempotentMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// backoff is the wait before retry number attempt+1: 25ms doubling to 250ms, jittered.
func backoff(attempt int) time.Duration {
	d := min(25*time.Millisecond<<attempt, 250*time.Millisecond)
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// ---- ejecting failing upstreams ----

// gwOutlier is the ejection policy of a route. A route without one ejects an upstream for a
// short fixed time after a single failed dial.
type gwOutlier struct {
	consecutive int
	ejectFor    time.Duration
	maxPct      int
	slowStart   time.Duration
	grow        bool // ejection time multiplies with repeated ejections
}

var legacyOutlier = &gwOutlier{consecutive: 1, ejectFor: gatewayDownFor, maxPct: 100}

const maxEject = 10 * time.Minute

func newOutlier(o *GatewayOutlier) *gwOutlier {
	if o == nil {
		return legacyOutlier
	}
	out := &gwOutlier{consecutive: o.Consecutive, ejectFor: 30 * time.Second, maxPct: o.MaxEjectPercent, grow: true}
	if out.consecutive == 0 {
		out.consecutive = 5
	}
	if out.maxPct == 0 {
		out.maxPct = 50
	}
	if o.EjectFor != "" {
		out.ejectFor, _ = time.ParseDuration(o.EjectFor)
	}
	if o.SlowStart != "" {
		out.slowStart, _ = time.ParseDuration(o.SlowStart)
	}
	return out
}

// recordFailure counts a failed attempt against the upstream and ejects it once the policy says
// so. dial is true when the upstream could not be reached at all.
func (g *gatewayServer) recordFailure(r *gwRoute, tg *gwTarget, now time.Time, dial bool) {
	o := r.outlier
	if o == legacyOutlier && !dial {
		return // without a policy only a failed dial counts
	}
	if int(tg.up.consec.Add(1)) < o.consecutive {
		return
	}
	tg.up.consec.Store(0)
	nano := now.UnixNano()
	if o.maxPct < 100 {
		ejected := 1 // this one
		for _, t := range r.targets {
			if t != tg && t.up.downUntil.Load() > nano {
				ejected++
			}
		}
		if ejected*100 > o.maxPct*len(r.targets) {
			return // keep serving rather than empty the pool
		}
	}
	d := o.ejectFor
	if o.grow {
		d = min(d*time.Duration(tg.up.ejections.Add(1)), maxEject)
	}
	until := now.Add(d).UnixNano()
	tg.up.downUntil.Store(until)
	tg.up.rampStart.Store(until)
	r.m.ejections.Add(1)
}

// recordSuccess ends a run of failures; an upstream that has behaved for a while is forgiven
// its earlier ejections.
func (g *gatewayServer) recordSuccess(tg *gwTarget, now time.Time) {
	if tg.up.consec.Load() != 0 {
		tg.up.consec.Store(0)
	}
	if tg.up.ejections.Load() != 0 && now.UnixNano() > tg.up.downUntil.Load()+int64(2*time.Minute) {
		tg.up.ejections.Store(0)
	}
}

// effWeight is the weight a target gets now: reduced while it ramps back after an ejection.
func (p *picker) effWeight(t *gwTarget) int {
	if p.slowStart == 0 {
		return t.weight
	}
	rs := t.up.rampStart.Load()
	if rs == 0 || p.now < rs || p.now >= rs+int64(p.slowStart) {
		return t.weight
	}
	pct := 10 + 90*(p.now-rs)/int64(p.slowStart)
	return max(int(int64(t.weight)*pct/100), 1)
}

// ---- hashing ----

func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ x>>31
}

// rendezvous picks the eligible target with the highest weighted hash score: the same key keeps
// its target, and when a target leaves only its own keys move.
func rendezvous(targets []*gwTarget, p *picker, key string) *gwTarget {
	kh := fnv64(key)
	var best *gwTarget
	bestScore := -1.0
	for _, t := range targets {
		if !p.ok(t) {
			continue
		}
		u := (float64(mix64(kh^t.seed)>>11) + 0.5) / (1 << 53)
		if s := float64(p.effWeight(t)) / -math.Log(u); s > bestScore {
			best, bestScore = t, s
		}
	}
	return best
}

// ---- mirroring ----

const (
	mirrorMaxBody    = 64 << 10
	mirrorMaxPending = 128
	mirrorTimeout    = 5 * time.Second
)

// hopHeaders must not be copied to a new request.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// maybeMirror sends a copy of the request to the mirror target and discards the answer. It never
// slows or fails the real request: a copy that does not fit the limits is skipped and counted.
func (g *gatewayServer) maybeMirror(r *gwRoute, req *http.Request, ip string) {
	if len(r.mirror) == 0 || (r.mirrorPct < 100 && rand.IntN(100) >= r.mirrorPct) {
		return
	}
	var body []byte
	if req.ContentLength != 0 {
		if req.ContentLength < 0 || req.ContentLength > mirrorMaxBody {
			r.m.mirrorSkipped.Add(1)
			return
		}
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return // the real request will report the same failure
		}
		body = b
		req.Body = io.NopCloser(bytes.NewReader(b))
	}
	select {
	case g.mirrorSem <- struct{}{}:
	default:
		r.m.mirrorSkipped.Add(1)
		return
	}
	tg := r.mirror[int(r.next.Add(1))%len(r.mirror)]
	mreq := req.Clone(context.Background())
	mreq.Body, mreq.RequestURI = nil, ""
	mreq.URL.Scheme, mreq.URL.Host, mreq.Host = r.scheme, tg.addr, req.Host
	if len(body) > 0 {
		mreq.Body = io.NopCloser(bytes.NewReader(body))
	}
	for _, h := range hopHeaders {
		mreq.Header.Del(h)
	}
	mreq.Header.Set("X-Forwarded-For", ip)
	mreq.Header.Set("X-Mirror", "1")
	go func() {
		defer func() { <-g.mirrorSem }()
		ctx, cancel := context.WithTimeout(context.Background(), mirrorTimeout)
		defer cancel()
		resp, err := r.tr.RoundTrip(mreq.WithContext(ctx))
		if err != nil {
			r.m.mirrorErrors.Add(1)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		r.m.mirrored.Add(1)
	}()
}

// ---- CORS and response presets ----

type gwCORS struct {
	any                              bool
	origins                          map[string]bool
	methods, headers, expose, maxAge string
	credentials                      bool
}

func newCORS(c *GatewayCORS) *gwCORS {
	if c == nil {
		return nil
	}
	out := &gwCORS{origins: map[string]bool{}, credentials: c.Credentials}
	for _, o := range c.Origins {
		if o == "*" {
			out.any = true
		}
		out.origins[o] = true
	}
	methods := c.Methods
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "POST"}
	}
	out.methods = strings.Join(methods, ", ")
	out.headers = strings.Join(c.Headers, ", ")
	out.expose = strings.Join(c.Expose, ", ")
	age := c.MaxAge
	if age == 0 {
		age = 600
	}
	out.maxAge = strconv.Itoa(age)
	return out
}

func (c *gwCORS) allowed(origin string) bool { return origin != "" && (c.any || c.origins[origin]) }

// apply adds the response headers for an allowed origin.
func (c *gwCORS) apply(h http.Header, origin string) {
	if !c.allowed(origin) {
		return
	}
	if c.any && !c.credentials {
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Add("Vary", "Origin")
	}
	if c.credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if c.expose != "" {
		h.Set("Access-Control-Expose-Headers", c.expose)
	}
}

// preflight answers a CORS preflight request itself.
func (c *gwCORS) preflight(w http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodOptions || req.Header.Get("Origin") == "" || req.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	origin := req.Header.Get("Origin")
	h := w.Header()
	if c.allowed(origin) {
		c.apply(h, origin)
		h.Set("Access-Control-Allow-Methods", c.methods)
		if c.headers != "" {
			h.Set("Access-Control-Allow-Headers", c.headers)
		} else if rh := req.Header.Get("Access-Control-Request-Headers"); rh != "" {
			h.Set("Access-Control-Allow-Headers", rh)
		}
		h.Set("Access-Control-Max-Age", c.maxAge)
	}
	h.Add("Vary", "Access-Control-Request-Method")
	w.WriteHeader(http.StatusNoContent)
	return true
}

// setSecurityHeaders adds the preset headers the application did not set itself.
func setSecurityHeaders(h http.Header) {
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN",
		"Referrer-Policy": "strict-origin-when-cross-origin"} {
		if h.Get(k) == "" {
			h.Set(k, v)
		}
	}
}

// ---- idle timeout while streaming ----

// idleBody cancels the request when the upstream is silent for the idle time.
type idleBody struct {
	io.ReadCloser
	t    *time.Timer
	idle time.Duration
}

func newIdleBody(rc io.ReadCloser, idle time.Duration, cancel context.CancelFunc) *idleBody {
	return &idleBody{ReadCloser: rc, idle: idle, t: time.AfterFunc(idle, cancel)}
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.t.Reset(b.idle)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.t.Stop()
	return b.ReadCloser.Close()
}

// ---- tracing ----

const hexLower = "0123456789abcdef"

func appendHex64(b []byte, v uint64) []byte {
	for i := 60; i >= 0; i -= 4 {
		b = append(b, hexLower[v>>uint(i)&0xf])
	}
	return b
}

func isHexLower(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// traceContext continues the W3C trace in an incoming traceparent header, or starts one. It
// returns the trace ID and the traceparent to send upstream, which names a new span for this hop.
func traceContext(in string) (traceID, out string) {
	flags := "01"
	b := make([]byte, 0, 55)
	b = append(b, "00-"...)
	if len(in) == 55 && in[:3] == "00-" && in[35] == '-' && in[52] == '-' && isHexLower(in[3:35]) &&
		isHexLower(in[36:52]) && isHexLower(in[53:]) && in[3:35] != "00000000000000000000000000000000" && in[36:52] != "0000000000000000" {
		b = append(b, in[3:35]...)
		flags = in[53:]
	} else {
		b = appendHex64(b, rand.Uint64())
		b = appendHex64(b, rand.Uint64()|1)
	}
	b = append(b, '-')
	b = appendHex64(b, rand.Uint64()|1)
	b = append(b, '-')
	b = append(b, flags...)
	out = string(b)
	return out[3:35], out
}

// ---- upstream transports ----

func newUpstreamTransport(connect, header time.Duration) *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          8192,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: header,
		ReadBufferSize:        32 << 10,
		WriteBufferSize:       32 << 10,
	}
}

// routeTransport builds the transport of a route that speaks https or h2c to its upstreams.
func routeTransport(rs GatewayRouteState, connect, header time.Duration) (*http.Transport, error) {
	t := newUpstreamTransport(connect, header)
	switch rs.UpstreamProto {
	case "https":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if u := rs.UpstreamTLS; u != nil {
			cfg.ServerName = u.ServerName
			if u.CAPEM != "" {
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM([]byte(u.CAPEM)) {
					return nil, errors.New("upstream_tls ca_pem holds no certificate")
				}
				cfg.RootCAs = pool
			}
		}
		t.TLSClientConfig = cfg
		t.ForceAttemptHTTP2 = true
	case "h2c":
		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
	}
	return t, nil
}

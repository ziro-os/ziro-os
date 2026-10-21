package cmd

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---- metrics (Prometheus text format) ----
//
// The request path only touches atomics. Series are resolved once, when a route is loaded, so
// recording a request takes no lock and allocates nothing. A scrape copies the registry's
// pointers under a read lock and renders without holding anything.

var gwBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

const gwNumBuckets = 11 // len(gwBuckets)

// denyReason says why the gateway refused a request before it reached an upstream.
type denyReason uint8

const (
	denyACL  denyReason = iota // client outside allow_cidrs
	denyRate                   // rate limit
	denyAuth                   // missing or wrong credentials, or too many failures
	denyBody                   // request body over the limit
	denyShed                   // concurrency limit
	denyWAF                    // blocked by the WAF
	denyBan                    // client is banned
	denyList                   // client is on a deny list
	denyPath                   // malformed request path
	denyNoUp                   // no upstream available
	numDeny
)

var denyNames = [numDeny]string{"acl", "rate", "auth", "body", "shed", "waf", "ban", "deny", "path", "no_upstream"}

// routeMetrics are one route's series.
type routeMetrics struct {
	codes    [600]atomic.Uint64
	hist     [gwNumBuckets + 1]atomic.Uint64 // per-bucket counts; the last is +Inf. Made cumulative at scrape.
	sumNs    atomic.Uint64
	count    atomic.Uint64
	inflight atomic.Int64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	denied   [numDeny]atomic.Uint64
	retries  atomic.Uint64
	upErrors atomic.Uint64 // transport errors talking to an upstream

	ejections     atomic.Uint64 // upstreams ejected by the outlier policy
	mirrored      atomic.Uint64
	mirrorErrors  atomic.Uint64
	mirrorSkipped atomic.Uint64 // copies not sent: too large, or too many pending
}

// observe records a finished request or L4 connection.
func (m *routeMetrics) observe(code int, d time.Duration) {
	if code < 0 || code >= len(m.codes) {
		code = 0
	}
	m.codes[code].Add(1)
	s := d.Seconds()
	i := 0
	for i < gwNumBuckets && s > gwBuckets[i] {
		i++
	}
	m.hist[i].Add(1)
	m.sumNs.Add(uint64(d))
	m.count.Add(1)
}

func (m *routeMetrics) deny(r denyReason) { m.denied[r].Add(1) }

type gwMetrics struct {
	mu     sync.RWMutex
	routes map[string]*routeMetrics
	none   *routeMetrics // requests no route matched

	fmu      sync.Mutex // upstream failures and health: written only on state changes
	failures map[string]uint64
	health   map[string]bool

	logDropped atomic.Uint64
}

func newGWMetrics() *gwMetrics {
	return &gwMetrics{routes: map[string]*routeMetrics{}, none: &routeMetrics{},
		failures: map[string]uint64{}, health: map[string]bool{}}
}

// route returns the series of a route, creating them on first use.
func (m *gwMetrics) route(name string) *routeMetrics {
	m.mu.RLock()
	rm := m.routes[name]
	m.mu.RUnlock()
	if rm != nil {
		return rm
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if rm = m.routes[name]; rm == nil {
		rm = &routeMetrics{}
		m.routes[name] = rm
	}
	return rm
}

// prune drops the series of routes and upstreams that are gone, so the registry cannot grow
// with pod churn.
func (m *gwMetrics) prune(routes map[string]bool, upstreams map[string]bool) {
	m.mu.Lock()
	for n := range m.routes {
		if !routes[n] {
			delete(m.routes, n)
		}
	}
	m.mu.Unlock()
	m.fmu.Lock()
	for k := range m.failures {
		if _, u, _ := strings.Cut(k, "|"); !upstreams[u] {
			delete(m.failures, k)
		}
	}
	for k := range m.health {
		if _, u, _ := strings.Cut(k, "|"); !upstreams[u] {
			delete(m.health, k)
		}
	}
	m.fmu.Unlock()
}

func (m *gwMetrics) upstreamFailure(route, up string) {
	m.fmu.Lock()
	m.failures[route+"|"+up]++
	m.fmu.Unlock()
}

func (m *gwMetrics) setHealth(route, up string, ok bool) {
	m.fmu.Lock()
	m.health[route+"|"+up] = ok
	m.fmu.Unlock()
}

type namedMetrics struct {
	name string
	m    *routeMetrics
}

func (m *gwMetrics) snapshot() []namedMetrics {
	m.mu.RLock()
	out := make([]namedMetrics, 0, len(m.routes)+1)
	for n, rm := range m.routes {
		out = append(out, namedMetrics{n, rm})
	}
	m.mu.RUnlock()
	out = append(out, namedMetrics{"_none", m.none})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (m *gwMetrics) write(w io.Writer) {
	bw := bufio.NewWriterSize(w, 32<<10)
	defer bw.Flush()
	routes := m.snapshot()

	family := func(name, help, typ string) {
		fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	family("zirogate_requests_total", "Requests (or L4 connections) by route and status.", "counter")
	for _, r := range routes {
		for c := range r.m.codes {
			if n := r.m.codes[c].Load(); n > 0 {
				fmt.Fprintf(bw, "zirogate_requests_total{route=%q,code=\"%d\"} %d\n", r.name, c, n)
			}
		}
	}
	family("zirogate_request_duration_seconds", "Time to serve a request.", "histogram")
	for _, r := range routes {
		var cum uint64
		for i, b := range gwBuckets {
			cum += r.m.hist[i].Load()
			fmt.Fprintf(bw, "zirogate_request_duration_seconds_bucket{route=%q,le=\"%g\"} %d\n", r.name, b, cum)
		}
		cum += r.m.hist[gwNumBuckets].Load()
		fmt.Fprintf(bw, "zirogate_request_duration_seconds_bucket{route=%q,le=\"+Inf\"} %d\n", r.name, cum)
		fmt.Fprintf(bw, "zirogate_request_duration_seconds_sum{route=%q} %g\n", r.name, float64(r.m.sumNs.Load())/1e9)
		fmt.Fprintf(bw, "zirogate_request_duration_seconds_count{route=%q} %d\n", r.name, r.m.count.Load())
	}
	family("zirogate_requests_in_flight", "Requests being served.", "gauge")
	for _, r := range routes {
		fmt.Fprintf(bw, "zirogate_requests_in_flight{route=%q} %d\n", r.name, max(r.m.inflight.Load(), 0))
	}
	family("zirogate_request_bytes_total", "Request body bytes received (declared length).", "counter")
	for _, r := range routes {
		fmt.Fprintf(bw, "zirogate_request_bytes_total{route=%q} %d\n", r.name, r.m.bytesIn.Load())
	}
	family("zirogate_response_bytes_total", "Response body bytes sent to clients.", "counter")
	for _, r := range routes {
		fmt.Fprintf(bw, "zirogate_response_bytes_total{route=%q} %d\n", r.name, r.m.bytesOut.Load())
	}
	family("zirogate_denied_total", "Requests refused by the gateway before reaching an upstream, by reason.", "counter")
	for _, r := range routes {
		for i := range r.m.denied {
			if n := r.m.denied[i].Load(); n > 0 {
				fmt.Fprintf(bw, "zirogate_denied_total{route=%q,reason=%q} %d\n", r.name, denyNames[i], n)
			}
		}
	}
	family("zirogate_retries_total", "Requests sent to another upstream after a failed attempt.", "counter")
	for _, r := range routes {
		if n := r.m.retries.Load(); n > 0 {
			fmt.Fprintf(bw, "zirogate_retries_total{route=%q} %d\n", r.name, n)
		}
	}
	family("zirogate_upstream_errors_total", "Transport errors talking to an upstream (after retries).", "counter")
	for _, r := range routes {
		if n := r.m.upErrors.Load(); n > 0 {
			fmt.Fprintf(bw, "zirogate_upstream_errors_total{route=%q} %d\n", r.name, n)
		}
	}

	family("zirogate_outlier_ejections_total", "Upstreams ejected for failing repeatedly.", "counter")
	for _, r := range routes {
		if n := r.m.ejections.Load(); n > 0 {
			fmt.Fprintf(bw, "zirogate_outlier_ejections_total{route=%q} %d\n", r.name, n)
		}
	}
	family("zirogate_mirror_requests_total", "Mirrored requests by result.", "counter")
	for _, r := range routes {
		for res, c := range map[string]*atomic.Uint64{"ok": &r.m.mirrored, "error": &r.m.mirrorErrors, "skipped": &r.m.mirrorSkipped} {
			if n := c.Load(); n > 0 {
				fmt.Fprintf(bw, "zirogate_mirror_requests_total{route=%q,result=%q} %d\n", r.name, res, n)
			}
		}
	}

	m.fmu.Lock()
	fk := gwSortedKeys(m.failures)
	fv := make([]uint64, len(fk))
	for i, k := range fk {
		fv[i] = m.failures[k]
	}
	hk := gwSortedKeys(m.health)
	hv := make([]bool, len(hk))
	for i, k := range hk {
		hv[i] = m.health[k]
	}
	m.fmu.Unlock()

	family("zirogate_upstream_failures_total", "Failed dials to an upstream.", "counter")
	for i, k := range fk {
		r, u, _ := strings.Cut(k, "|")
		fmt.Fprintf(bw, "zirogate_upstream_failures_total{route=%q,upstream=%q} %d\n", r, u, fv[i])
	}
	family("zirogate_upstream_healthy", "Active health check result (1 healthy).", "gauge")
	for i, k := range hk {
		r, u, _ := strings.Cut(k, "|")
		v := 0
		if hv[i] {
			v = 1
		}
		fmt.Fprintf(bw, "zirogate_upstream_healthy{route=%q,upstream=%q} %d\n", r, u, v)
	}
	family("zirogate_log_dropped_total", "Access log lines dropped because the log writer fell behind.", "counter")
	fmt.Fprintf(bw, "zirogate_log_dropped_total %d\n", m.logDropped.Load())
}

func gwSortedKeys[V any](mp map[string]V) []string {
	out := make([]string, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// requestCounts returns a route's request count by status code (the status view).
func (m *routeMetrics) requestCounts() map[string]uint64 {
	out := map[string]uint64{}
	for c := range m.codes {
		if n := m.codes[c].Load(); n > 0 {
			out[strconv.Itoa(c)] = n
		}
	}
	return out
}

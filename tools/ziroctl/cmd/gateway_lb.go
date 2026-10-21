package cmd

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ---- upstreams and load balancing ----

// gwUpstream is the per-address state shared by every route that targets the address, so least_conn
// and passive ejection see the whole load on a backend.
type gwUpstream struct {
	addr      string
	active    atomic.Int64 // requests in flight
	downUntil atomic.Int64 // unix nanoseconds: skipped until then after a dial failure
}

func (g *gatewayServer) upstreamFor(addr string) *gwUpstream {
	if v, ok := g.upstreams.Load(addr); ok {
		return v.(*gwUpstream)
	}
	v, _ := g.upstreams.LoadOrStore(addr, &gwUpstream{addr: addr})
	return v.(*gwUpstream)
}

// gwTarget is one resolved backend of a route. Everything the request path needs is computed at
// load time.
type gwTarget struct {
	addr      string
	weight    int
	sticky    string // value of the sticky-session cookie that pins a client to this target
	up        *gwUpstream
	unhealthy atomic.Bool // the last active health check failed
}

func (t *gwTarget) usable(now int64) bool {
	return t.up.downUntil.Load() <= now && !t.unhealthy.Load()
}

// markDown skips the upstream for gatewayDownFor after a failed dial.
func (u *gwUpstream) markDown(now time.Time) { u.downUntil.Store(now.Add(gatewayDownFor).UnixNano()) }

// fnv64 is FNV-1a over a string, without allocating.
func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * 1099511628211
	}
	return h
}

func stickyValue(addr string) string { return strconv.FormatUint(fnv64(addr), 36) }

// picker filters the candidates of one selection.
type picker struct {
	tried  []*gwTarget // already attempted by this request
	strict bool        // only usable targets (false: none were, so probe any)
	now    int64
}

func (p *picker) ok(t *gwTarget) bool {
	for _, x := range p.tried {
		if x == t {
			return false
		}
	}
	return !p.strict || t.usable(p.now)
}

// pick chooses a target by the route's policy among the usable ones, skipping the targets in
// tried. When none is usable it probes one anyway: better a try than a guaranteed 503.
func (g *gatewayServer) pick(r *gwRoute, clientIP string, now time.Time, tried []*gwTarget) *gwTarget {
	p := picker{tried: tried, strict: true, now: now.UnixNano()}
	total := 0
	for _, t := range r.targets {
		if p.ok(t) {
			total += t.weight
		}
	}
	if total == 0 {
		p.strict = false
		for _, t := range r.targets {
			if p.ok(t) {
				total += t.weight
			}
		}
		if total == 0 {
			return nil
		}
	}
	switch r.LB {
	case "least_conn":
		var best *gwTarget
		bestScore := math.MaxFloat64
		for _, t := range r.targets {
			if !p.ok(t) {
				continue
			}
			if score := float64(t.up.active.Load()+1) / float64(t.weight); score < bestScore {
				best, bestScore = t, score
			}
		}
		return best
	case "ip_hash":
		return weightedAt(r.targets, &p, total, fnv64(clientIP))
	default: // round_robin, and cookie when there is no valid sticky cookie
		return weightedAt(r.targets, &p, total, r.next.Add(1)-1)
	}
}

func weightedAt(targets []*gwTarget, p *picker, total int, n uint64) *gwTarget {
	x := int(n % uint64(total))
	var first *gwTarget
	for _, t := range targets {
		if !p.ok(t) {
			continue
		}
		if first == nil {
			first = t
		}
		if x < t.weight {
			return t
		}
		x -= t.weight
	}
	return first
}

// stickyTarget returns the target a sticky cookie points at, if it is still usable.
func (g *gatewayServer) stickyTarget(r *gwRoute, req *http.Request, now time.Time) *gwTarget {
	ck, err := req.Cookie(r.cookieName)
	if err != nil {
		return nil
	}
	nano := now.UnixNano()
	for _, t := range r.targets {
		if t.sticky == ck.Value && t.usable(nano) {
			return t
		}
	}
	return nil
}

// ---- active health checks ----

type checkEntry struct {
	cancel context.CancelFunc
	r      *gwRoute
}

// syncHealthChecks runs one checker per (route, target) of routes with a health check. A route
// that is unchanged by a reload is the same object, so its checkers keep running; checkers of
// changed routes restart and those of removed routes stop.
func (g *gatewayServer) syncHealthChecks(t *routeTable) {
	want := map[string]*gwRoute{}
	for _, r := range t.all {
		if r.Health == nil {
			continue
		}
		for _, tg := range r.targets {
			want[r.Name+"|"+tg.addr] = r
		}
	}
	g.checkMu.Lock()
	defer g.checkMu.Unlock()
	for key, e := range g.checks {
		if want[key] != e.r {
			e.cancel()
			delete(g.checks, key)
		}
	}
	for key, r := range want {
		if g.checks[key].cancel != nil {
			continue
		}
		var tg *gwTarget
		for _, c := range r.targets {
			if r.Name+"|"+c.addr == key {
				tg = c
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		g.checks[key] = checkEntry{cancel: cancel, r: r}
		go g.healthLoop(ctx, r, tg)
	}
}

func (g *gatewayServer) healthLoop(ctx context.Context, r *gwRoute, tg *gwTarget) {
	interval := 10 * time.Second
	if r.Health.Interval != "" {
		interval, _ = time.ParseDuration(r.Health.Interval)
	}
	addr := tg.addr
	client := &http.Client{Timeout: min(interval, 5*time.Second), Transport: g.transport(5 * time.Second),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last *bool
	check := func() {
		ok := false
		if r.Kind != "http" {
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
		if ctx.Err() != nil {
			return
		}
		tg.unhealthy.Store(!ok)
		if last == nil || *last != ok {
			g.log(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "health", "route": r.Name, "upstream": addr, "healthy": ok})
		}
		last = &ok
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

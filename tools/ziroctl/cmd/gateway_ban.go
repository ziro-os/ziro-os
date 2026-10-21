package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Automatic bans. A client that keeps getting blocked (WAF blocks, basic-auth guessing) is
// banned for a while, then for longer if it comes back. Each gateway node counts for itself.
// Manual bans and deny lists are static address sets (gateway_cidr.go) and live elsewhere.

const (
	banShards      = 32
	banCapPerShard = 4096 // bans and strike records per shard: about 130k addresses per table
	banMaxLevel    = 16
	gwStrikeForget = 24 * time.Hour // a quiet client's history is dropped after this
)

type gwAutoBan struct {
	strikes  int
	window   time.Duration
	duration time.Duration
	max      time.Duration
	kernel   bool
}

func newAutoBan(a *GatewayAutoBan) *gwAutoBan {
	if a == nil {
		return nil
	}
	p := &gwAutoBan{strikes: a.Strikes, window: time.Minute, duration: 10 * time.Minute, max: 24 * time.Hour, kernel: a.Kernel}
	if p.strikes == 0 {
		p.strikes = 5
	}
	if a.Window != "" {
		p.window, _ = time.ParseDuration(a.Window)
	}
	if a.Duration != "" {
		p.duration, _ = time.ParseDuration(a.Duration)
	}
	if a.Max != "" {
		p.max, _ = time.ParseDuration(a.Max)
	}
	p.max = max(p.max, p.duration)
	return p
}

type banInfo struct {
	until  int64 // unix nanoseconds
	reason string
}

type strikeState struct {
	n     int
	start int64
	bans  int // earlier bans: each one doubles the next
	last  int64
}

type banShard struct {
	mu      sync.Mutex
	bans    map[netip.Addr]banInfo
	strikes map[netip.Addr]*strikeState
	_       [32]byte
}

type gwBanTable struct {
	shards [banShards]banShard
	active atomic.Int64 // bans in force, to skip the lookup when there are none
}

func (t *gwBanTable) shard(a netip.Addr) *banShard {
	b := a.As16()
	h := uint32(b[15]) | uint32(b[14])<<8 | uint32(b[13])<<16 | uint32(b[12])<<24
	return &t.shards[(h*2654435761)>>27%banShards]
}

// banned reports whether the address is banned at now (unix nanoseconds).
func (t *gwBanTable) banned(a netip.Addr, now int64) bool {
	if t.active.Load() == 0 {
		return false
	}
	a = a.Unmap()
	s := t.shard(a)
	s.mu.Lock()
	b, ok := s.bans[a]
	s.mu.Unlock()
	return ok && now < b.until
}

// strike records one offence. When the client reaches the policy's strikes within its window it
// is banned, and the ban reports (true, until).
func (t *gwBanTable) strike(a netip.Addr, now time.Time, p *gwAutoBan, reason string) (bool, time.Time) {
	if p == nil {
		return false, time.Time{}
	}
	a = a.Unmap()
	s := t.shard(a)
	nano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.strikes == nil {
		s.strikes, s.bans = map[netip.Addr]*strikeState{}, map[netip.Addr]banInfo{}
	}
	st := s.strikes[a]
	if st == nil {
		if len(s.strikes) >= banCapPerShard {
			for k := range s.strikes {
				delete(s.strikes, k)
				break
			}
		}
		st = &strikeState{start: nano}
		s.strikes[a] = st
	}
	if nano-st.start > int64(p.window) {
		st.n, st.start = 0, nano
	}
	st.n++
	st.last = nano
	if st.n < p.strikes {
		return false, time.Time{}
	}
	st.n, st.start = 0, nano
	d := p.duration << min(st.bans, banMaxLevel)
	if d <= 0 || d > p.max {
		d = p.max
	}
	st.bans++
	until := now.Add(d)
	if len(s.bans) >= banCapPerShard {
		for k := range s.bans {
			delete(s.bans, k)
			t.active.Add(-1)
			break
		}
	}
	if _, was := s.bans[a]; !was {
		t.active.Add(1)
	}
	s.bans[a] = banInfo{until: until.UnixNano(), reason: reason}
	return true, until
}

// BanStatus is one ban in force on this gateway node.
type BanStatus struct {
	Addr   string `json:"addr"`
	Until  string `json:"until"`
	Reason string `json:"reason,omitempty"`
	Source string `json:"source"` // auto or manual
}

func (t *gwBanTable) list(now time.Time) []BanStatus {
	var out []BanStatus
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for a, b := range s.bans {
			if now.UnixNano() < b.until {
				out = append(out, BanStatus{Addr: a.String(), Until: time.Unix(0, b.until).UTC().Format(time.RFC3339), Reason: b.reason, Source: "auto"})
			}
		}
		s.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// unban lifts an automatic ban and forgets the client's history.
func (t *gwBanTable) unban(a netip.Addr) bool {
	a = a.Unmap()
	s := t.shard(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.bans[a]
	if ok {
		delete(s.bans, a)
		t.active.Add(-1)
	}
	delete(s.strikes, a)
	return ok
}

// sweep drops expired bans and the history of clients that went quiet.
func (t *gwBanTable) sweep(now time.Time) {
	nano := now.UnixNano()
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for a, b := range s.bans {
			if nano >= b.until {
				delete(s.bans, a)
				t.active.Add(-1)
			}
		}
		for a, st := range s.strikes {
			if nano-st.last > int64(gwStrikeForget) {
				delete(s.strikes, a)
			}
		}
		s.mu.Unlock()
	}
}

// strike counts an offence by the client of the request and, when the policy says so, bans it.
func (g *gatewayServer) strike(ip, reason string) {
	set := g.settings.Load()
	if set == nil || set.autoBan == nil {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	if set.neverBan(a) {
		return
	}
	banned, until := g.bans.strike(a, time.Now(), set.autoBan, reason)
	if !banned {
		return
	}
	go g.announceBan(a, until, reason, set.autoBan.kernel)
}

// announceBan makes a new ban visible: audit log, alert and, if asked, the host firewall. It runs
// off the request path.
func (g *gatewayServer) announceBan(a netip.Addr, until time.Time, reason string, kernel bool) {
	d := time.Until(until).Round(time.Second)
	g.metrics.bansTotal.Add(1)
	_ = auditLog("gateway", "gateway", "auto-ban", fmt.Sprintf("%s for %s (%s)", a, d, reason), nil)
	alertf("medium", "gateway", "gateway banned "+a.String(), map[string]any{"addr": a.String(), "for": d.String(), "reason": reason})
	if kernel && g.kernelBan != nil {
		g.kernelBan(a, time.Until(until))
	}
}

// startKernelBans runs the worker that applies bans to the host firewall one at a time, so a
// flood of bans never blocks the gateway or fork-storms nft.
func (g *gatewayServer) startKernelBans(ctx context.Context) {
	type kb struct {
		a netip.Addr
		d time.Duration
	}
	ch := make(chan kb, 256)
	g.kernelBan = func(a netip.Addr, d time.Duration) {
		select {
		case ch <- kb{a, d}:
		default: // the queue is full: the in-process ban still holds
		}
	}
	go func() {
		recent := map[netip.Addr]time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case k := <-ch:
				if t, ok := recent[k.a]; ok && time.Since(t) < time.Minute {
					continue
				}
				recent[k.a] = time.Now()
				if len(recent) > 4096 {
					clear(recent)
				}
				if guardAllowed(k.a, loadFirewallConfig().Guard) {
					continue // never ban loopback, the mesh or the operator's allow list
				}
				if err := banIP(k.a, k.d); err != nil {
					g.log(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "kernel-ban-failed", "addr": k.a.String(), "error": err.Error()})
				}
			}
		}
	}()
}

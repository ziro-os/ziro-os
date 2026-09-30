package cmd

import (
	"container/list"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Ziro smart DNS: a caching, split-horizon resolver for the host (127.0.0.53).
//
//   query -> blocklist -> local records -> cache -> forward rule (longest suffix) or default
//   pool -> fastest healthy upstream (EWMA RTT, passive health) -> cache (RFC 2308 negative
//   caching) ; serve-stale when every upstream is down.
//
// Upstreams speak plain DNS (UDP, TCP on truncation) or DNS-over-TLS with verified certificates.
// Only loopback and configured networks may query: never an open resolver.

// DNSUpstream: Addr is an IP (or IP:port). With TLSName it is DNS-over-TLS (port 853 default).
type DNSUpstream struct {
	Addr    string `json:"addr"`
	TLSName string `json:"tls_name,omitempty"`
}

type DNSForward struct {
	Domain    string        `json:"domain"`
	Upstreams []DNSUpstream `json:"upstreams"`
}

type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // A, AAAA, CNAME, TXT
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// ---- upstreams ----

var dotRoots *x509.CertPool // nil: system roots (tests inject a CA)

type resolverUpstream struct {
	cfg       DNSUpstream
	addr      string // host:port
	ewma      float64
	fails     int
	downUntil time.Time
	tlsConns  chan *tls.Conn
	queries   atomic.Uint64
	errors    atomic.Uint64
}

func newUpstream(u DNSUpstream) (*resolverUpstream, error) {
	host, port, err := net.SplitHostPort(u.Addr)
	if err != nil {
		host, port = u.Addr, "53"
		if u.TLSName != "" {
			port = "853"
		}
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
		return nil, fmt.Errorf("upstream %q must be an IP address", u.Addr)
	}
	if u.TLSName != "" && validHostname(strings.ToLower(u.TLSName)) != nil {
		return nil, fmt.Errorf("upstream %s: invalid tls_name %q", u.Addr, u.TLSName)
	}
	return &resolverUpstream{cfg: u, addr: net.JoinHostPort(strings.Trim(host, "[]"), port), ewma: 50,
		tlsConns: make(chan *tls.Conn, 4)}, nil
}

func (u *resolverUpstream) exchange(q []byte) ([]byte, error) {
	if u.cfg.TLSName != "" {
		return u.exchangeTLS(q)
	}
	c, err := net.DialTimeout("udp", u.addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	_, err = c.Write(q)
	n := 0
	if err == nil {
		n, err = c.Read(buf)
	}
	c.Close()
	if err != nil {
		return nil, err
	}
	resp := buf[:n]
	if len(resp) >= 3 && resp[2]&0x02 != 0 { // TC: retry over TCP
		tc, err := net.DialTimeout("tcp", u.addr, 2*time.Second)
		if err != nil {
			return nil, err
		}
		defer tc.Close()
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		return tcpExchange(tc, q)
	}
	return resp, nil
}

func (u *resolverUpstream) exchangeTLS(q []byte) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var c *tls.Conn
		select {
		case c = <-u.tlsConns:
		default:
			d := &net.Dialer{Timeout: 3 * time.Second}
			nc, err := tls.DialWithDialer(d, "tcp", u.addr, &tls.Config{ServerName: u.cfg.TLSName, MinVersion: tls.VersionTLS12, RootCAs: dotRoots})
			if err != nil {
				return nil, err
			}
			c = nc
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		resp, err := tcpExchange(c, q)
		if err != nil {
			c.Close() // stale pooled connection: retry once on a fresh one
			continue
		}
		select {
		case u.tlsConns <- c:
		default:
			c.Close()
		}
		return resp, nil
	}
	return nil, errors.New("DNS-over-TLS exchange failed")
}

type upstreamPool struct {
	mu  sync.Mutex
	ups []*resolverUpstream
}

func newPool(cfgs []DNSUpstream) (*upstreamPool, error) {
	p := &upstreamPool{}
	for _, c := range cfgs {
		u, err := newUpstream(c)
		if err != nil {
			return nil, err
		}
		p.ups = append(p.ups, u)
	}
	return p, nil
}

// order returns healthy upstreams fastest first, then the ones marked down (last resort).
func (p *upstreamPool) order(now time.Time) []*resolverUpstream {
	p.mu.Lock()
	defer p.mu.Unlock()
	up := append([]*resolverUpstream{}, p.ups...)
	sort.SliceStable(up, func(i, j int) bool {
		di, dj := now.Before(up[i].downUntil), now.Before(up[j].downUntil)
		if di != dj {
			return !di
		}
		return up[i].ewma < up[j].ewma
	})
	return up
}

func (p *upstreamPool) report(u *resolverUpstream, rtt time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u.queries.Add(1)
	if err != nil {
		u.errors.Add(1)
		u.fails++
		if u.fails >= 3 {
			u.downUntil = time.Now().Add(30 * time.Second)
		}
		return
	}
	u.fails, u.downUntil = 0, time.Time{}
	u.ewma = 0.8*u.ewma + 0.2*float64(rtt.Milliseconds())
}

func (p *upstreamPool) exchange(q []byte) ([]byte, error) {
	var last error = errors.New("no upstreams")
	for i, u := range p.order(time.Now()) {
		if i >= 3 {
			break
		}
		t0 := time.Now()
		resp, err := u.exchange(q)
		if err == nil && (len(resp) < 12 || resp[0] != q[0] || resp[1] != q[1]) {
			err = errors.New("mismatched response")
		}
		if err == nil && resp[3]&0x0f == 2 { // SERVFAIL: try another upstream
			err = errors.New("SERVFAIL")
		}
		p.report(u, time.Since(t0), err)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

// ---- cache ----

type cacheEntry struct {
	key     string
	msg     dnsmessage.Message
	stored  time.Time
	expires time.Time
}

type dnsCache struct {
	mu    sync.Mutex
	max   int
	lru   *list.List
	items map[string]*list.Element
}

func newDNSCache(max int) *dnsCache {
	return &dnsCache{max: max, lru: list.New(), items: map[string]*list.Element{}}
}

const maxStale = time.Hour

// get returns a copy of the cached answer with TTLs aged; stale answers only when allowStale.
func (c *dnsCache) get(key string, now time.Time, allowStale bool) (*dnsmessage.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	fresh := now.Before(e.expires)
	if !fresh && (!allowStale || now.Sub(e.expires) > maxStale) {
		return nil, false
	}
	c.lru.MoveToFront(el)
	m := e.msg
	m.Answers = append([]dnsmessage.Resource{}, e.msg.Answers...)
	m.Authorities = append([]dnsmessage.Resource{}, e.msg.Authorities...)
	m.Additionals = append([]dnsmessage.Resource{}, e.msg.Additionals...)
	age := uint32(now.Sub(e.stored) / time.Second)
	for _, rrs := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range rrs {
			if rrs[i].Header.Type == dnsmessage.TypeOPT {
				continue
			}
			switch {
			case !fresh:
				rrs[i].Header.TTL = 30
			case rrs[i].Header.TTL > age:
				rrs[i].Header.TTL -= age
			default:
				rrs[i].Header.TTL = 1
			}
		}
	}
	return &m, fresh
}

func (c *dnsCache) put(key string, m dnsmessage.Message, ttl time.Duration, now time.Time) {
	if ttl <= 0 || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.lru.Remove(el)
	}
	c.items[key] = c.lru.PushFront(&cacheEntry{key: key, msg: m, stored: now, expires: now.Add(ttl)})
	for c.lru.Len() > c.max {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.items, old.Value.(*cacheEntry).key)
	}
}

// cacheTTL: positive answers live for their smallest TTL; NXDOMAIN/NODATA for the SOA minimum
// (RFC 2308), capped at 5 minutes; failures and truncated answers are not cached.
func cacheTTL(m *dnsmessage.Message) time.Duration {
	if m.Header.Truncated || (m.Header.RCode != dnsmessage.RCodeSuccess && m.Header.RCode != dnsmessage.RCodeNameError) {
		return 0
	}
	if m.Header.RCode == dnsmessage.RCodeSuccess && len(m.Answers) > 0 {
		min := uint32(86400)
		for _, rr := range m.Answers {
			if rr.Header.TTL < min {
				min = rr.Header.TTL
			}
		}
		return time.Duration(min) * time.Second
	}
	neg := uint32(30)
	for _, rr := range m.Authorities {
		if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
			neg = min(rr.Header.TTL, soa.MinTTL)
		}
	}
	return time.Duration(min(neg, 300)) * time.Second
}

// ---- server ----

type dnsStats struct {
	Queries, CacheHits, Stale, Blocked, Local, Forwarded, Failed, Refused, RateLimited atomic.Uint64
}

type localRR struct {
	rtype dnsmessage.Type
	ttl   uint32
	body  dnsmessage.ResourceBody
}

type dnsServer struct {
	mu       sync.RWMutex
	pool     *upstreamPool
	forwards []struct {
		suffix string
		pool   *upstreamPool
	}
	records map[string][]localRR // fqdn -> records
	block   map[string]bool      // fqdn (subdomains included)
	allow   []netip.Prefix
	cache   *dnsCache
	logQ    bool
	stats   dnsStats

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall

	limiter *tokenBucket // per-client queries/second (shared with zirogate)
}

type inflightCall struct {
	done chan struct{}
	resp []byte
	err  error
}

func fqdn(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func (s *dnsServer) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *dnsServer) limited(ip netip.Addr, now time.Time) bool {
	return s.limiter != nil && !s.limiter.allow(ip.String(), now)
}

// matchSuffix reports whether name is domain or one of its subdomains (both fqdn).
func matchSuffix(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func (s *dnsServer) blocked(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for n := name; n != "." && n != ""; {
		if s.block[n] {
			return true
		}
		_, rest, ok := strings.Cut(n, ".")
		if !ok {
			break
		}
		n = rest
		if n == "" {
			break
		}
	}
	return false
}

func (s *dnsServer) poolFor(name string) *upstreamPool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	best, bestLen := s.pool, -1
	for _, f := range s.forwards {
		if matchSuffix(name, f.suffix) && len(f.suffix) > bestLen {
			best, bestLen = f.pool, len(f.suffix)
		}
	}
	return best
}

func reply(q dnsmessage.Message, rcode dnsmessage.RCode, answers []dnsmessage.Resource, authoritative bool) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{ID: q.Header.ID, Response: true, OpCode: q.Header.OpCode, Authoritative: authoritative,
			RecursionDesired: q.Header.RecursionDesired, RecursionAvailable: true, RCode: rcode},
		Questions: q.Questions,
		Answers:   answers,
	}
}

// localAnswer answers from configured records (following one local CNAME).
func (s *dnsServer) localAnswer(q dnsmessage.Message) (*dnsmessage.Message, bool) {
	qs := q.Questions[0]
	name := strings.ToLower(qs.Name.String())
	s.mu.RLock()
	rrs, ok := s.records[name]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	var ans []dnsmessage.Resource
	add := func(owner string, rr localRR) {
		ans = append(ans, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner),
			Type: rr.rtype, Class: dnsmessage.ClassINET, TTL: rr.ttl}, Body: rr.body})
	}
	for _, rr := range rrs {
		switch {
		case rr.rtype == qs.Type || qs.Type == dnsmessage.TypeALL:
			add(name, rr)
		case rr.rtype == dnsmessage.TypeCNAME:
			add(name, rr)
			target := strings.ToLower(rr.body.(*dnsmessage.CNAMEResource).CNAME.String())
			s.mu.RLock()
			for _, t := range s.records[target] {
				if t.rtype == qs.Type {
					add(target, t)
				}
			}
			s.mu.RUnlock()
		}
	}
	m := reply(q, dnsmessage.RCodeSuccess, ans, true)
	return &m, true
}

func cacheKey(qs dnsmessage.Question) string {
	return strings.ToLower(qs.Name.String()) + "|" + qs.Type.String() + "|" + qs.Class.String()
}

// resolve answers one query (wire format); it never returns nil for a parsable query.
func (s *dnsServer) resolve(raw []byte) []byte {
	s.stats.Queries.Add(1)
	var q dnsmessage.Message
	if err := q.Unpack(raw); err != nil || len(q.Questions) != 1 || q.Header.Response {
		return nil
	}
	qs := q.Questions[0]
	name := strings.ToLower(qs.Name.String())
	now := time.Now()
	pack := func(m dnsmessage.Message) []byte {
		b, _ := m.Pack()
		return b
	}
	if s.blocked(name) {
		s.stats.Blocked.Add(1)
		return pack(reply(q, dnsmessage.RCodeNameError, nil, true))
	}
	if m, ok := s.localAnswer(q); ok {
		s.stats.Local.Add(1)
		return pack(*m)
	}
	key := cacheKey(qs)
	if m, fresh := s.cache.get(key, now, false); fresh {
		s.stats.CacheHits.Add(1)
		m.Header.ID = q.Header.ID
		return pack(*m)
	}
	resp, err := s.forwardDedup(key, name, raw)
	if err == nil {
		var m dnsmessage.Message
		if m.Unpack(resp) == nil {
			s.cache.put(key, m, cacheTTL(&m), now)
			m.Header.ID = q.Header.ID
			s.stats.Forwarded.Add(1)
			return pack(m)
		}
	}
	if m, _ := s.cache.get(key, now, true); m != nil { // every upstream down: serve stale
		s.stats.Stale.Add(1)
		m.Header.ID = q.Header.ID
		return pack(*m)
	}
	s.stats.Failed.Add(1)
	return pack(reply(q, dnsmessage.RCodeServerFailure, nil, false))
}

// forwardDedup sends identical concurrent queries upstream once.
func (s *dnsServer) forwardDedup(key, name string, raw []byte) ([]byte, error) {
	s.inflightMu.Lock()
	if s.inflight == nil {
		s.inflight = map[string]*inflightCall{}
	}
	if c, ok := s.inflight[key]; ok {
		s.inflightMu.Unlock()
		<-c.done
		if c.err != nil {
			return nil, c.err
		}
		out := append([]byte{}, c.resp...)
		out[0], out[1] = raw[0], raw[1] // this caller's ID
		return out, nil
	}
	c := &inflightCall{done: make(chan struct{})}
	s.inflight[key] = c
	s.inflightMu.Unlock()
	c.resp, c.err = s.poolFor(name).exchange(raw)
	s.inflightMu.Lock()
	delete(s.inflight, key)
	s.inflightMu.Unlock()
	close(c.done)
	return c.resp, c.err
}

// udpLimit is the reply size the client accepts over UDP (512, or its EDNS0 buffer).
func udpLimit(raw []byte) int {
	var q dnsmessage.Message
	if q.Unpack(raw) != nil {
		return 512
	}
	for _, rr := range q.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			if sz := int(rr.Header.Class); sz > 512 {
				return min(sz, 4096)
			}
		}
	}
	return 512
}

// truncate returns a header+question reply with TC set, so the client retries over TCP.
func truncate(resp []byte) []byte {
	var m dnsmessage.Message
	if m.Unpack(resp) != nil {
		return resp[:12]
	}
	m.Header.Truncated = true
	m.Answers, m.Authorities, m.Additionals = nil, nil, nil
	b, _ := m.Pack()
	return b
}

func (s *dnsServer) serveUDP(pc net.PacketConn) {
	sem := make(chan struct{}, 512)
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, _ := from.(*net.UDPAddr)
		if ua == nil {
			continue
		}
		ip, _ := netip.AddrFromSlice(ua.IP)
		ip = ip.Unmap()
		if !s.allowed(ip) {
			s.stats.Refused.Add(1)
			continue
		}
		if s.limited(ip, time.Now()) {
			s.stats.RateLimited.Add(1)
			continue
		}
		q := append([]byte{}, buf[:n]...)
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				resp := s.resolve(q)
				if resp == nil {
					return
				}
				if len(resp) > udpLimit(q) {
					resp = truncate(resp)
				}
				_, _ = pc.WriteTo(resp, from)
			}()
		default: // overloaded: drop; the client retries
		}
	}
}

func (s *dnsServer) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ta, _ := c.RemoteAddr().(*net.TCPAddr)
		ip := netip.Addr{}
		if ta != nil {
			ip, _ = netip.AddrFromSlice(ta.IP)
		}
		if !s.allowed(ip.Unmap()) {
			s.stats.Refused.Add(1)
			c.Close()
			continue
		}
		go func() {
			defer c.Close()
			for i := 0; i < 100; i++ { // pipelined queries on one connection
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil || s.limited(ip.Unmap(), time.Now()) {
					return
				}
				resp := s.resolve(q)
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream answers A queries with ip (TTL ttl), or NXDOMAIN with an SOA for names under "nx.".
type fakeUpstream struct {
	pc    net.PacketConn
	hits  atomic.Int32
	ip    [4]byte
	ttl   uint32
	delay time.Duration
	big   int // extra A records, to force truncation
}

func (f *fakeUpstream) answer(raw []byte) []byte {
	var q dnsmessage.Message
	if q.Unpack(raw) != nil {
		return nil
	}
	f.hits.Add(1)
	time.Sleep(f.delay)
	qs := q.Questions[0]
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
	if strings.HasPrefix(qs.Name.String(), "nx.") {
		m.Header.RCode = dnsmessage.RCodeNameError
		m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 900},
			Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("h.example."), MinTTL: 120}}}
	} else {
		for i := 0; i <= f.big; i++ {
			a := f.ip
			a[3] += byte(i)
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: qs.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: f.ttl}, Body: &dnsmessage.AResource{A: a}})
		}
	}
	b, _ := m.Pack()
	return b
}

func startFakeUpstream(t *testing.T, ip [4]byte, ttl uint32) *fakeUpstream {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{pc: pc, ip: ip, ttl: ttl}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte{}, buf[:n]...)
			go func() {
				if r := f.answer(q); r != nil {
					pc.WriteTo(r, from)
				}
			}()
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return f
}

func (f *fakeUpstream) cfg() DNSUpstream { return DNSUpstream{Addr: f.pc.LocalAddr().String()} }

func query(name string, t dnsmessage.Type, id uint16) []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET}}}
	b, _ := m.Pack()
	return b
}

func decode(t *testing.T, b []byte) dnsmessage.Message {
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return m
}

func newTestServer(t *testing.T, c *DNSConfig) *dnsServer {
	s, err := buildDNSServer(c, clusterDNSFile{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDNSLocalRecordsAndBlocking(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{192, 0, 2, 1}, 60)
	s := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{up.cfg()},
		Records: []DNSRecord{{Name: "db.internal", Type: "A", Value: "10.0.0.20", TTL: 60}, {Name: "www.internal", Type: "CNAME", Value: "db.internal"}},
		Block:   []string{"ads.example"}})
	m := decode(t, s.resolve(query("DB.internal.", dnsmessage.TypeA, 1)))
	if !m.Header.Authoritative || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 0, 0, 20} || m.Header.ID != 1 {
		t.Fatalf("local A: %+v", m)
	}
	m = decode(t, s.resolve(query("www.internal.", dnsmessage.TypeA, 2)))
	if len(m.Answers) != 2 || m.Answers[0].Header.Type != dnsmessage.TypeCNAME {
		t.Fatalf("CNAME chase: %+v", m.Answers)
	}
	m = decode(t, s.resolve(query("db.internal.", dnsmessage.TypeAAAA, 3)))
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("NODATA expected: %+v", m)
	}
	for _, n := range []string{"ads.example.", "tracker.ads.example."} {
		if m := decode(t, s.resolve(query(n, dnsmessage.TypeA, 4))); m.Header.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s not blocked", n)
		}
	}
	if m := decode(t, s.resolve(query("notads.example.", dnsmessage.TypeA, 5))); m.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatal("suffix match must respect label boundaries")
	}
	if up.hits.Load() != 1 {
		t.Fatalf("upstream queried %d times (only notads.example should reach it)", up.hits.Load())
	}
}

func TestDNSCacheNegativeAndStale(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{192, 0, 2, 7}, 100)
	s := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{up.cfg()}})
	s.resolve(query("a.example.", dnsmessage.TypeA, 1))
	m := decode(t, s.resolve(query("a.example.", dnsmessage.TypeA, 2)))
	if up.hits.Load() != 1 || m.Header.ID != 2 || m.Answers[0].Header.TTL > 100 {
		t.Fatalf("cache: hits=%d %+v", up.hits.Load(), m.Header)
	}
	// TTLs age in the cache.
	key := cacheKey(dnsmessage.Question{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if cm, _ := s.cache.get(key, time.Now().Add(40*time.Second), false); cm == nil || cm.Answers[0].Header.TTL > 61 {
		t.Fatalf("TTL not aged: %+v", cm)
	}
	// NXDOMAIN cached for the SOA minimum (120s), not the SOA TTL (900s).
	s.resolve(query("nx.example.", dnsmessage.TypeA, 3))
	s.resolve(query("nx.example.", dnsmessage.TypeA, 4))
	if up.hits.Load() != 2 {
		t.Fatalf("negative answer not cached: %d", up.hits.Load())
	}
	nk := cacheKey(dnsmessage.Question{Name: dnsmessage.MustNewName("nx.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if m, fresh := s.cache.get(nk, time.Now().Add(121*time.Second), false); m != nil || fresh {
		t.Fatal("negative entry outlived the SOA minimum")
	}
	// Upstream gone and the entry expired: the stale answer is served (TTL 30).
	up.pc.Close()
	s.cache.mu.Lock()
	s.cache.items[key].Value.(*cacheEntry).expires = time.Now().Add(-time.Minute)
	s.cache.mu.Unlock()
	m = decode(t, s.resolve(query("a.example.", dnsmessage.TypeA, 5)))
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Answers[0].Header.TTL != 30 || s.stats.Stale.Load() != 1 {
		t.Fatalf("stale: %+v", m)
	}
	if m := decode(t, s.resolve(query("never.example.", dnsmessage.TypeA, 6))); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("no upstream and nothing cached must be SERVFAIL")
	}
}

func TestDNSSplitForwardFailoverDedup(t *testing.T) {
	pub := startFakeUpstream(t, [4]byte{192, 0, 2, 1}, 60)
	corp := startFakeUpstream(t, [4]byte{10, 9, 9, 9}, 60)
	dead := DNSUpstream{Addr: "127.0.0.1:1"} // nothing listens: fails fast
	s := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{dead, pub.cfg()},
		Forwards: []DNSForward{{Domain: "corp.example", Upstreams: []DNSUpstream{corp.cfg()}}}})
	m := decode(t, s.resolve(query("git.corp.example.", dnsmessage.TypeA, 1)))
	if m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 9, 9, 9} || pub.hits.Load() != 0 {
		t.Fatal("split DNS: corp.example must go to the corp resolver only")
	}
	m = decode(t, s.resolve(query("www.example.", dnsmessage.TypeA, 2)))
	if m.Header.RCode != dnsmessage.RCodeSuccess || pub.hits.Load() != 1 {
		t.Fatalf("failover to the live upstream: %+v", m.Header)
	}
	for i := 0; i < 3; i++ { // the dead one is marked down and sorted last
		s.resolve(query("x"+string(rune('a'+i))+".example.", dnsmessage.TypeA, 3))
	}
	if o := s.pool.order(time.Now()); o[0].addr != pub.pc.LocalAddr().String() {
		t.Fatalf("fastest healthy upstream not first: %s", o[0].addr)
	}
	// Concurrent identical queries reach the upstream once.
	pub.delay = 200 * time.Millisecond
	before := pub.hits.Load()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			if m := decode(t, s.resolve(query("same.example.", dnsmessage.TypeA, id))); m.Header.ID != id {
				t.Errorf("reply ID %d, want %d", m.Header.ID, id)
			}
		}(uint16(100 + i))
	}
	wg.Wait()
	if n := pub.hits.Load() - before; n != 1 {
		t.Fatalf("deduplication: %d upstream queries", n)
	}
}

func TestDNSTruncationAndAccess(t *testing.T) {
	up := startFakeUpstream(t, [4]byte{192, 0, 2, 1}, 60)
	up.big = 40 // ~40 A records: more than 512 bytes
	s := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{up.cfg()}, Allow: []string{"10.0.0.0/8"}})
	q := query("many.example.", dnsmessage.TypeA, 9)
	resp := s.resolve(q)
	if len(resp) <= udpLimit(q) {
		t.Fatalf("test answer too small: %d", len(resp))
	}
	if tr := decode(t, truncate(resp)); !tr.Header.Truncated || len(tr.Answers) != 0 || tr.Header.ID != 9 {
		t.Fatal("truncation must set TC and drop records")
	}
	for ip, want := range map[string]bool{"127.0.0.1": true, "::1": true, "10.1.2.3": true, "203.0.113.5": false, "192.168.1.2": false} {
		if got := s.allowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("client %s allowed=%v, want %v (never an open resolver)", ip, got, want)
		}
	}
}

// DNS-over-TLS: the certificate must match tls_name.
func TestDNSOverTLS(t *testing.T) {
	cert := selfSigned(t, "dot") // DNSNames: clusterSNI, legacySNI
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	dotRoots = x509.NewCertPool()
	dotRoots.AddCert(leaf)
	defer func() { dotRoots = nil }()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fake := &fakeUpstream{ip: [4]byte{198, 51, 100, 4}, ttl: 60}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					q, err := readTCPMsg(c)
					if err != nil {
						return
					}
					r := fake.answer(q)
					out := make([]byte, 2+len(r))
					binary.BigEndian.PutUint16(out, uint16(len(r)))
					copy(out[2:], r)
					c.Write(out)
				}
			}()
		}
	}()
	good := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{{Addr: ln.Addr().String(), TLSName: legacySNI}}})
	for i := 0; i < 3; i++ { // the second and third reuse the pooled connection
		m := decode(t, good.resolve(query("dot"+string(rune('a'+i))+".example.", dnsmessage.TypeA, uint16(i+1))))
		if len(m.Answers) != 1 {
			t.Fatalf("DoT query %d: %+v", i, m.Header)
		}
	}
	bad := newTestServer(t, &DNSConfig{Upstreams: []DNSUpstream{{Addr: ln.Addr().String(), TLSName: "wrong.example"}}})
	if m := decode(t, bad.resolve(query("x.example.", dnsmessage.TypeA, 1))); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("a certificate for another name must not be trusted")
	}
}

func TestDNSConfigValidation(t *testing.T) {
	for _, bad := range []DNSConfig{
		{Upstreams: []DNSUpstream{{Addr: "dns.example"}}},
		{Upstreams: []DNSUpstream{{Addr: "1.1.1.1", TLSName: "bad name"}}},
		{Forwards: []DNSForward{{Domain: "corp.example"}}},
		{Records: []DNSRecord{{Name: "x.internal", Type: "A", Value: "::1"}}},
		{Records: []DNSRecord{{Name: "x.internal", Type: "MX", Value: "mail"}}},
		{Block: []string{"bad domain"}},
		{Blocklists: []string{"http://insecure.example/list"}},
		{Allow: []string{"everyone"}},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if u, err := parseUpstreamArg("tls://1.1.1.1#cloudflare-dns.com"); err != nil || u.TLSName != "cloudflare-dns.com" {
		t.Fatalf("%+v %v", u, err)
	}
	blocked := map[string]bool{}
	parseBlocklist(strings.NewReader("# comment\n0.0.0.0 ads.example\n127.0.0.1 localhost\ntracker.example # trailing\nbad domain!\n"), blocked)
	if !blocked["ads.example."] || !blocked["tracker.example."] || len(blocked) != 2 {
		t.Fatalf("blocklist parse: %v", blocked)
	}
}

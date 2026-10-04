package daemon

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// A tiny authoritative DNS responder for <device>.<network>.ziro, bound to the device's own
// tunnel address. The OS sends it only that domain (split DNS), so it never relays anything.

type dnsServer struct {
	mu      sync.RWMutex
	domain  string // "office.ziro."
	records map[string][]netip.Addr
	conn    net.PacketConn
}

func (d *dnsServer) set(domain string, records map[string][]netip.Addr) {
	d.mu.Lock()
	d.domain, d.records = strings.ToLower(domain)+".", records
	d.mu.Unlock()
}

// listen serves on addr:53 until close.
func (d *dnsServer) listen(addr netip.Addr) error {
	c, err := net.ListenPacket("udp", netip.AddrPortFrom(addr, 53).String())
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.conn = c
	d.mu.Unlock()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := d.answer(buf[:n]); resp != nil {
				_, _ = c.WriteTo(resp, from)
			}
		}
	}()
	return nil
}

func (d *dnsServer) close() {
	d.mu.Lock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}
	d.mu.Unlock()
}

// answer builds the reply to one query (nil = ignore a malformed packet).
func (d *dnsServer) answer(q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired}
	name := strings.ToLower(question.Name.String())
	d.mu.RLock()
	domain := d.domain
	addrs, found := d.records[strings.TrimSuffix(name, "."+domain)]
	d.mu.RUnlock()
	switch {
	case domain == "." || !strings.HasSuffix(name, "."+domain):
		rh.RCode, rh.Authoritative = dnsmessage.RCodeRefused, false
	case !found:
		rh.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), rh)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(question) != nil || b.StartAnswers() != nil {
		return nil
	}
	rr := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
	for _, a := range addrs {
		switch {
		case a.Is4() && question.Type == dnsmessage.TypeA:
			_ = b.AResource(rr, dnsmessage.AResource{A: a.As4()})
		case a.Is6() && question.Type == dnsmessage.TypeAAAA:
			_ = b.AAAAResource(rr, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

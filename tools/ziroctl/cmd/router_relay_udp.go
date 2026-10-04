package cmd

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/conn"
)

// The relay's UDP side: one port (IPv4 and IPv6) answers STUN, binds UDP sessions from
// authenticated hellos, and forwards relayed datagrams. I/O goes through wireguard-go's
// StdNetBind, the socket layer zirocd uses too: batched reads with UDP GRO, batched writes with
// UDP GSO (a run of packets to one receiver leaves in one syscall), large socket buffers.

const (
	udpHelloSkew  = 60 * time.Second
	udpBindingTTL = 90 * time.Second // a binding not refreshed (hello every 5-25s, or traffic) expires
)

func (s *relayServer) listenUDP(addr string) error {
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return err
	}
	b := conn.NewStdNetBind()
	fns, _, err := b.Open(uint16(port))
	if err != nil {
		return err
	}
	s.udp = b
	for _, fn := range fns {
		go s.udpLoop(fn)
	}
	return nil
}

func (s *relayServer) closeUDP() {
	if s.udp != nil {
		s.udp.Close()
	}
}

func (s *relayServer) endpoint(a netip.AddrPort) conn.Endpoint {
	ep, err := s.udp.ParseEndpoint(a.String())
	if err != nil {
		return nil
	}
	return ep
}

// udpOut collects one batch's outgoing datagrams per destination, so each destination's run is
// written with one Send (GSO).
type udpOut struct {
	order []netip.AddrPort
	bufs  map[netip.AddrPort][][]byte
	eps   map[netip.AddrPort]conn.Endpoint
}

func (o *udpOut) add(to netip.AddrPort, ep conn.Endpoint, b []byte) {
	if _, ok := o.bufs[to]; !ok {
		o.order = append(o.order, to)
		o.eps[to] = ep
	}
	o.bufs[to] = append(o.bufs[to], b)
}

func (s *relayServer) udpLoop(fn conn.ReceiveFunc) {
	bs := s.udp.BatchSize()
	bufs, sizes, eps := make([][]byte, bs), make([]int, bs), make([]conn.Endpoint, bs)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	out := udpOut{bufs: map[netip.AddrPort][][]byte{}, eps: map[netip.AddrPort]conn.Endpoint{}}
	for {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			se, ok := eps[i].(*conn.StdNetEndpoint)
			if !ok {
				continue
			}
			from := netip.AddrPortFrom(se.AddrPort.Addr().Unmap(), se.AddrPort.Port())
			s.handleUDP(bufs[i][:sizes[i]], from, eps[i], &out)
		}
		for _, to := range out.order {
			_ = s.udp.Send(out.bufs[to], out.eps[to])
			delete(out.bufs, to)
			delete(out.eps, to)
		}
		out.order = out.order[:0]
	}
}

// handleUDP processes one datagram; replies and forwarded packets go into out.
func (s *relayServer) handleUDP(b []byte, from netip.AddrPort, fromEP conn.Endpoint, out *udpOut) {
	if len(b) == 0 {
		return
	}
	switch {
	case zr.IsSTUN(b):
		if tx, ok := zr.ParseSTUNRequest(b); ok {
			out.add(from, fromEP, zr.STUNResponse(tx, from))
		}
	case b[0] == zr.UDPHello:
		session, ms, ok := zr.ParseUDPHello(b)
		if !ok {
			return
		}
		s.mu.RLock()
		c := s.sessions[session]
		s.mu.RUnlock()
		now := time.Now()
		if c == nil || !zr.VerifyUDPHello(b, c.skey) {
			return
		}
		sent := time.UnixMilli(int64(ms))
		if sent.Before(now.Add(-udpHelloSkew)) || sent.After(now.Add(udpHelloSkew)) {
			return
		}
		if cur := c.udp.Load(); cur != nil && ms <= cur.ms { // a replayed hello cannot move the session
			return
		}
		c.udp.Store(&udpBinding{addr: from, ep: s.endpoint(from), ms: ms, seen: now})
		out.add(from, fromEP, zr.UDPAckPacket(session, ms, from)) // smaller than the hello
	case b[0] == zr.UDPSend && len(b) > zr.UDPSendHdr:
		session := uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
		s.mu.RLock()
		c := s.sessions[session]
		s.mu.RUnlock()
		if c == nil {
			return
		}
		if bind := c.udp.Load(); bind == nil || bind.addr != from { // only from the bound address
			s.drop()
			return
		}
		dst := [32]byte(b[5:37])
		to, ok := s.route(c, dst, len(b)-zr.UDPSendHdr)
		if !ok {
			return
		}
		if bind := to.udp.Load(); bind != nil && bind.ep != nil && time.Since(bind.seen) < udpBindingTTL {
			// Rewrite the header in place (send: 0xE2|session|dst, recv: 0xE3|src, 4 bytes
			// shorter): forwarding allocates nothing; the batch is sent before the next read.
			fwd := b[4:]
			fwd[0] = zr.UDPRecv
			copy(fwd[1:33], c.key[:])
			out.add(bind.addr, bind.ep, fwd)
			return
		}
		s.deliver(c, to, b[zr.UDPSendHdr:])
	}
}

// route applies the sender's and the relay's rate limits and finds the receiving device (same
// network only).
func (s *relayServer) route(c *relayClient, dst [32]byte, n int) (*relayClient, bool) {
	now := time.Now()
	if !c.bucket.allow(n, now) || !s.global.allow(n, now) {
		s.drop()
		return nil, false
	}
	s.mu.RLock()
	to := s.byKey[dst]
	s.mu.RUnlock()
	if to == nil || to.network != c.network {
		s.drop()
		return nil, false
	}
	return to, true
}

// deliver hands a packet from c to its receiver: as a UDP datagram when the receiver has a live
// UDP session, otherwise over its TLS connection. (UDP-to-UDP forwarding takes the in-place path
// in handleUDP; this serves packets that arrived over TLS.)
func (s *relayServer) deliver(c, to *relayClient, payload []byte) {
	if bind := to.udp.Load(); bind != nil && bind.ep != nil && time.Since(bind.seen) < udpBindingTTL {
		pkt := make([]byte, 0, zr.UDPRecvHdr+len(payload))
		pkt = append(append(append(pkt, zr.UDPRecv), c.key[:]...), payload...)
		_ = s.udp.Send([][]byte{pkt}, bind.ep)
		return
	}
	n := 32 + len(payload)
	f := make([]byte, 4+n)
	f[0], f[1], f[2], f[3] = zr.FrameRecv, byte(n>>16), byte(n>>8), byte(n)
	copy(f[4:], c.key[:])
	copy(f[36:], payload)
	select {
	case to.out <- f:
	default: // receiver too slow: drop like a congested link would
		s.drop()
	}
}

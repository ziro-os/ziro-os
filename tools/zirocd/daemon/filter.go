package daemon

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/tun"
)

// The inbound packet filter. Packets the device sends are let out and remembered as flows;
// packets arriving from peers are delivered only when they answer such a flow or match a rule
// the router compiled for this device. With no rules (or before the first netmap) nothing
// unsolicited gets in: default deny.

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
	flowTTL     = 5 * time.Minute
	maxFlows    = 1 << 18
)

type packet struct {
	proto      uint8
	src, dst   netip.Addr
	sport      uint16
	dport      uint16
	hasPorts   bool
	isFragment bool // a non-first fragment: no transport header
}

// parsePacket reads the fields the filter needs from an IPv4 or IPv6 packet.
func parsePacket(p []byte) (pk packet, ok bool) {
	if len(p) < 1 {
		return pk, false
	}
	var hl int
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return pk, false
		}
		hl = int(p[0]&0x0f) * 4
		if hl < 20 || len(p) < hl {
			return pk, false
		}
		pk.proto = p[9]
		pk.src = netip.AddrFrom4([4]byte(p[12:16]))
		pk.dst = netip.AddrFrom4([4]byte(p[16:20]))
		pk.isFragment = binary.BigEndian.Uint16(p[6:8])&0x1fff != 0
	case 6:
		if len(p) < 40 {
			return pk, false
		}
		hl = 40
		pk.proto = p[6]
		pk.src = netip.AddrFrom16([16]byte(p[8:24]))
		pk.dst = netip.AddrFrom16([16]byte(p[24:40]))
	default:
		return pk, false
	}
	if pk.proto == protoICMPv6 {
		pk.proto = protoICMP
	}
	if (pk.proto == protoTCP || pk.proto == protoUDP) && !pk.isFragment && len(p) >= hl+4 {
		pk.sport = binary.BigEndian.Uint16(p[hl : hl+2])
		pk.dport = binary.BigEndian.Uint16(p[hl+2 : hl+4])
		pk.hasPorts = true
	}
	return pk, true
}

type filterRule struct {
	src, dst []netip.Prefix
	proto    uint8 // 0 = any
	ports    []zr.PortRange
}

func compileFilter(rules []zr.FilterRule) []filterRule {
	var out []filterRule
	for _, r := range rules {
		fr := filterRule{ports: r.Ports}
		switch r.Proto {
		case "tcp":
			fr.proto = protoTCP
		case "udp":
			fr.proto = protoUDP
		case "icmp":
			fr.proto = protoICMP
		case "":
		default:
			continue // unknown protocol: allow nothing rather than everything
		}
		for _, s := range r.Src {
			if p, err := netip.ParsePrefix(s); err == nil {
				fr.src = append(fr.src, p)
			}
		}
		for _, d := range r.Dst {
			if p, err := netip.ParsePrefix(d); err == nil {
				fr.dst = append(fr.dst, p)
			}
		}
		out = append(out, fr)
	}
	return out
}

func containsAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (r *filterRule) match(pk *packet) bool {
	if r.proto != 0 && r.proto != pk.proto {
		return false
	}
	if !containsAny(r.src, pk.src) || !containsAny(r.dst, pk.dst) {
		return false
	}
	if len(r.ports) == 0 {
		return true
	}
	if !pk.hasPorts {
		// ponytail: a later IP fragment carries no ports; it passes when the rule's addresses and
		// protocol match. Track fragment IDs if port-scoped rules must hold for fragments too.
		return pk.isFragment && pk.proto != protoICMP
	}
	for _, pr := range r.ports {
		if pk.dport >= pr.First && pk.dport <= pr.Last {
			return true
		}
	}
	return false
}

type flowKey struct {
	proto        uint8
	local, peer  netip.Addr
	lport, pport uint16
}

// Filter wraps the TUN device: Read is the device's outbound path, Write its inbound one.
type Filter struct {
	tun.Device
	mu      sync.RWMutex
	rules   []filterRule
	flowMu  sync.Mutex
	flows   map[flowKey]int64 // unix nanos expiry
	dropped atomic.Uint64
}

func NewFilter(dev tun.Device) *Filter {
	return &Filter{Device: dev, flows: map[flowKey]int64{}}
}

func (f *Filter) SetRules(rules []zr.FilterRule) {
	c := compileFilter(rules)
	f.mu.Lock()
	f.rules = c
	f.mu.Unlock()
}

// ponytail: one mutex over the flow table; shard it if profiles show contention at multi-Gbps.
func (f *Filter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := f.Device.Read(bufs, sizes, offset)
	if n > 0 {
		exp := time.Now().Add(flowTTL).UnixNano()
		f.flowMu.Lock()
		for i := 0; i < n; i++ {
			if pk, ok := parsePacket(bufs[i][offset : offset+sizes[i]]); ok {
				f.flows[flowKey{pk.proto, pk.src, pk.dst, pk.sport, pk.dport}] = exp
			}
		}
		if len(f.flows) > maxFlows {
			f.expireLocked(time.Now().UnixNano())
		}
		f.flowMu.Unlock()
	}
	return n, err
}

func (f *Filter) expireLocked(now int64) {
	for k, exp := range f.flows {
		if exp < now {
			delete(f.flows, k)
		}
	}
	if len(f.flows) > maxFlows { // still full: start over rather than grow without bound
		f.flows = map[flowKey]int64{}
	}
}

// Expire drops idle flows; the daemon calls it every minute.
func (f *Filter) Expire() {
	f.flowMu.Lock()
	f.expireLocked(time.Now().UnixNano())
	f.flowMu.Unlock()
}

// allowedLocked: callers hold flowMu and mu (read).
func (f *Filter) allowedLocked(pk *packet, now int64) bool {
	if exp, ok := f.flows[flowKey{pk.proto, pk.dst, pk.src, pk.dport, pk.sport}]; ok && exp >= now {
		return true
	}
	for i := range f.rules {
		if f.rules[i].match(pk) {
			return true
		}
	}
	return false
}

// Write delivers the inbound packets the filter allows and silently drops the rest. wireguard-go
// calls it from several goroutines; the common all-allowed batch passes through without copying.
func (f *Filter) Write(bufs [][]byte, offset int) (int, error) {
	now := time.Now().UnixNano()
	var keep [][]byte
	f.mu.RLock() // both locks once per batch, not per packet
	f.flowMu.Lock()
	for i, b := range bufs {
		pk, ok := parsePacket(b[offset:])
		if ok && f.allowedLocked(&pk, now) {
			if keep != nil {
				keep = append(keep, b)
			}
			continue
		}
		f.dropped.Add(1)
		if keep == nil {
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	f.flowMu.Unlock()
	f.mu.RUnlock()
	if keep == nil {
		keep = bufs
	}
	if len(keep) > 0 {
		if _, err := f.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// Dropped counts packets the filter refused.
func (f *Filter) Dropped() uint64 { return f.dropped.Load() }

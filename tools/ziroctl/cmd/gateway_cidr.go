package cmd

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

// cidrSet answers "is this address inside any of these networks?" in O(log n) with no
// allocation: the networks are merged into sorted, disjoint address ranges and looked up by
// binary search. A set of 100,000 networks costs about 1.6 MB and 17 comparisons per lookup.
// A set is immutable once built, so readers need no lock.
type cidrSet struct {
	v4 []range4
	v6 []range6
}

type range4 struct{ lo, hi uint32 }

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

type range6 struct{ lo, hi u128 }

// newCIDRSet builds a set from addresses and networks (an address is a /32 or /128).
func newCIDRSet(list []string) (*cidrSet, error) {
	s := &cidrSet{}
	for _, c := range list {
		p, err := parseNet(c)
		if err != nil {
			return nil, err
		}
		s.add(p)
	}
	s.finish()
	return s, nil
}

func parseNet(c string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(c)
	if err != nil {
		a, aerr := netip.ParseAddr(c)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address or network %q", c)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() { // ::ffff:a.b.c.d/N is the IPv4 network a.b.c.d/(N-96)
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid address or network %q", c)
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

func (s *cidrSet) add(p netip.Prefix) {
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		lo := binary.BigEndian.Uint32(b[:])
		host := uint32(0)
		if p.Bits() < 32 {
			host = 1<<uint(32-p.Bits()) - 1
		}
		s.v4 = append(s.v4, range4{lo, lo | host})
		return
	}
	b := a.As16()
	lo := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
	hi := lo
	switch host := 128 - p.Bits(); {
	case host >= 128:
		hi = u128{^uint64(0), ^uint64(0)}
	case host >= 64:
		hi = u128{lo.hi | (1<<uint(host-64) - 1), ^uint64(0)}
	case host > 0:
		hi = u128{lo.hi, lo.lo | (1<<uint(host) - 1)}
	}
	s.v6 = append(s.v6, range6{lo, hi})
}

// finish sorts the ranges and merges the ones that overlap or touch.
func (s *cidrSet) finish() {
	sort.Slice(s.v4, func(i, j int) bool { return s.v4[i].lo < s.v4[j].lo })
	out4 := s.v4[:0]
	for _, r := range s.v4 {
		if n := len(out4); n > 0 && (r.lo <= out4[n-1].hi || out4[n-1].hi != ^uint32(0) && r.lo == out4[n-1].hi+1) {
			out4[n-1].hi = max(out4[n-1].hi, r.hi)
			continue
		}
		out4 = append(out4, r)
	}
	s.v4 = out4

	sort.Slice(s.v6, func(i, j int) bool { return s.v6[i].lo.less(s.v6[j].lo) })
	out6 := s.v6[:0]
	for _, r := range s.v6 {
		if n := len(out6); n > 0 && !out6[n-1].hi.less(r.lo) {
			if out6[n-1].hi.less(r.hi) {
				out6[n-1].hi = r.hi
			}
			continue
		}
		out6 = append(out6, r)
	}
	s.v6 = out6
}

// size is the number of merged ranges.
func (s *cidrSet) size() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}

func (s *cidrSet) contains(a netip.Addr) bool {
	if s == nil {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		if len(s.v4) == 0 {
			return false
		}
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:])
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].lo > x }) - 1
		return i >= 0 && x <= s.v4[i].hi
	}
	if len(s.v6) == 0 {
		return false
	}
	b := a.As16()
	x := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
	i := sort.Search(len(s.v6), func(i int) bool { return x.less(s.v6[i].lo) }) - 1
	return i >= 0 && !s.v6[i].hi.less(x)
}

// containsIP is contains for an address in text form (the client address); false if it is not one.
func (s *cidrSet) containsIP(ip string) bool {
	if s.size() == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && s.contains(a)
}

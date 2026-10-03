package cmd

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Router ACLs, addressing and the per-device view. Pure functions over the router state: the
// server (router_server.go) and the CLI (router.go) share them, so `acl test` answers exactly
// what devices enforce.

const (
	routerPool    = "100.64.0.0/10" // CGNAT space: one /16 per network
	maxACLRules   = 1000
	maxRoutes     = 16
	maxPending    = 1000 // approval requests waiting per network
	routerTagMax  = 32
	routerDomainS = ".ziro"
)

var (
	tagRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// validLabel: network, member and group names are DNS labels (<member>.<network>.ziro).
func validLabel(s string) error {
	if !labelRe.MatchString(s) {
		return fmt.Errorf("invalid name %q (a DNS label: a-z, 0-9 and inner dashes)", s)
	}
	return nil
}

func validTags(tags []string) error {
	if len(tags) > routerTagMax {
		return fmt.Errorf("at most %d tags", routerTagMax)
	}
	for _, t := range tags {
		if !tagRe.MatchString(t) {
			return fmt.Errorf("invalid tag %q (lowercase letters, digits and dashes)", t)
		}
	}
	return nil
}

// validSelector checks a src selector, or a dst selector without its ports.
func validSelector(s string, groups map[string][]string) error {
	switch {
	case s == "*":
		return nil
	case strings.HasPrefix(s, "tag:"):
		return validTags([]string{s[4:]})
	case strings.HasPrefix(s, "group:"):
		if _, ok := groups[s[6:]]; !ok {
			return fmt.Errorf("unknown group %q", s[6:])
		}
		return nil
	case strings.HasPrefix(s, "member:"):
		return validLabel(s[7:])
	}
	if _, err := netip.ParsePrefix(s); err != nil {
		return fmt.Errorf("invalid selector %q (want *, tag:, group:, member: or a CIDR)", s)
	}
	return nil
}

// splitDst parses "selector:ports"; ports are "*" (nil = all) or a comma list of N or N-M.
func splitDst(d string) (string, []zr.PortRange, error) {
	i := strings.LastIndex(d, ":")
	if i <= 0 {
		return "", nil, fmt.Errorf("dst %q needs ports, e.g. %q", d, d+":*")
	}
	sel, ps := d[:i], d[i+1:]
	if ps == "*" {
		return sel, nil, nil
	}
	var out []zr.PortRange
	for _, p := range strings.Split(ps, ",") {
		lo, hi, isRange := strings.Cut(p, "-")
		if !isRange {
			hi = lo
		}
		a, err1 := strconv.ParseUint(lo, 10, 16)
		b, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 != nil || err2 != nil || a == 0 || a > b {
			return "", nil, fmt.Errorf("invalid ports %q in %q", p, d)
		}
		out = append(out, zr.PortRange{First: uint16(a), Last: uint16(b)})
	}
	return sel, out, nil
}

func validateACL(a zr.ACL) error {
	if len(a.Rules) > maxACLRules {
		return fmt.Errorf("at most %d rules", maxACLRules)
	}
	for g, names := range a.Groups {
		if err := validLabel(g); err != nil {
			return fmt.Errorf("group %q: %w", g, err)
		}
		for _, n := range names {
			if err := validLabel(n); err != nil {
				return fmt.Errorf("group %q member %q: %w", g, n, err)
			}
		}
	}
	for i, r := range a.Rules {
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("rule %d: src and dst are required", i+1)
		}
		switch r.Proto {
		case "", "tcp", "udp", "icmp":
		default:
			return fmt.Errorf("rule %d: proto must be tcp, udp, icmp or empty", i+1)
		}
		for _, s := range r.Src {
			if err := validSelector(s, a.Groups); err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
		for _, d := range r.Dst {
			sel, _, err := splitDst(d)
			if err == nil {
				err = validSelector(sel, a.Groups)
			}
			if err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
	}
	return nil
}

func memberAddrs(m *zr.Member) []string {
	out := []string{m.IPv4 + "/32"}
	if m.IPv6 != "" {
		out = append(out, m.IPv6+"/128")
	}
	return out
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// selMatches reports whether member m is selected by s (a CIDR selects the members inside it).
func selMatches(s string, m *zr.Member, groups map[string][]string) bool {
	switch {
	case s == "*":
		return true
	case strings.HasPrefix(s, "tag:"):
		return hasString(m.Tags, s[4:])
	case strings.HasPrefix(s, "group:"):
		return hasString(groups[s[6:]], m.Name)
	case strings.HasPrefix(s, "member:"):
		return m.Name == s[7:]
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	for _, a := range []string{m.IPv4, m.IPv6} {
		if ip, err := netip.ParseAddr(a); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// compiledACL is a network's ACL resolved against its authorized members, built once per state
// change; each device's view is then a walk over member sets, not over selectors.
type compiledACL struct {
	rules   []compiledRule
	routers []*zr.Member // members with approved subnet routes
}

type compiledRule struct {
	src       map[string]bool // member IDs
	srcPrefix []string        // filter sources: member addresses and src CIDRs ("*" = anything the peer may send)
	proto     string
	dsts      []compiledDst
}

type compiledDst struct {
	ids   map[string]bool
	cidrs []netip.Prefix // CIDR selectors: reach subnet routes too
	ports []zr.PortRange
}

func compileACL(a zr.ACL, members []*zr.Member) *compiledACL {
	c := &compiledACL{}
	for _, m := range members {
		if len(m.Approved) > 0 {
			c.routers = append(c.routers, m)
		}
	}
	for _, r := range a.Rules {
		cr := compiledRule{src: map[string]bool{}, proto: r.Proto}
		any := false
		for _, s := range r.Src {
			if s == "*" {
				any = true
			}
			if p, err := netip.ParsePrefix(s); err == nil {
				cr.srcPrefix = append(cr.srcPrefix, p.Masked().String())
			}
			for _, m := range members {
				if selMatches(s, m, a.Groups) {
					cr.src[m.ID] = true
				}
			}
		}
		if any {
			// WireGuard's cryptokey routing already limits a peer to its AllowedIPs.
			cr.srcPrefix = []string{"0.0.0.0/0", "::/0"}
		} else {
			for _, m := range members {
				if cr.src[m.ID] {
					cr.srcPrefix = append(cr.srcPrefix, memberAddrs(m)...)
				}
			}
		}
		for _, d := range r.Dst {
			sel, ports, _ := splitDst(d) // validated on write
			cd := compiledDst{ids: map[string]bool{}, ports: ports}
			if p, err := netip.ParsePrefix(sel); err == nil {
				cd.cidrs = append(cd.cidrs, p.Masked())
			}
			for _, m := range members {
				if selMatches(sel, m, a.Groups) {
					cd.ids[m.ID] = true
				}
			}
			cr.dsts = append(cr.dsts, cd)
		}
		c.rules = append(c.rules, cr)
	}
	return c
}

func routesOverlapping(m *zr.Member, cidrs []netip.Prefix) []string {
	var out []string
	for _, r := range m.Approved {
		rp, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		for _, c := range cidrs {
			if rp.Overlaps(c) {
				if c.Bits() > rp.Bits() { // the narrower of the two
					out = append(out, c.String())
				} else {
					out = append(out, rp.String())
				}
			}
		}
	}
	return out
}

// view returns the members d may exchange packets with (least visibility: nobody else is in
// its netmap) and the inbound filter it enforces.
func (c *compiledACL) view(d *zr.Member) (visible map[string]bool, filter []zr.FilterRule) {
	visible = map[string]bool{}
	for _, r := range c.rules {
		isSrc := r.src[d.ID]
		for _, dst := range r.dsts {
			if isSrc {
				for id := range dst.ids {
					visible[id] = true
				}
				for _, rt := range c.routers {
					if len(routesOverlapping(rt, dst.cidrs)) > 0 {
						visible[rt.ID] = true
					}
				}
			}
			var to []string
			if dst.ids[d.ID] {
				to = append(to, memberAddrs(d)...)
			}
			to = append(to, routesOverlapping(d, dst.cidrs)...)
			if len(to) == 0 {
				continue
			}
			filter = append(filter, zr.FilterRule{Src: r.srcPrefix, Dst: to, Proto: r.proto, Ports: dst.ports})
			for id := range r.src {
				visible[id] = true
			}
		}
	}
	delete(visible, d.ID)
	return visible, filter
}

// allowed answers `acl test`: may src open proto/port to dst?
func (c *compiledACL) allowed(src, dst *zr.Member, proto string, port uint16) bool {
	_, filter := c.view(dst)
	for _, f := range filter {
		if f.Proto != "" && f.Proto != proto {
			continue
		}
		okSrc := false
		for _, s := range f.Src {
			p, _ := netip.ParsePrefix(s)
			ip, _ := netip.ParseAddr(src.IPv4)
			okSrc = okSrc || p.Contains(ip)
		}
		okPort := len(f.Ports) == 0
		for _, pr := range f.Ports {
			okPort = okPort || (port >= pr.First && port <= pr.Last)
		}
		if okSrc && okPort {
			return true
		}
	}
	return false
}

// ---- addressing ----

// allocNetwork picks the first free /16 of the CGNAT pool and a random ULA /48.
func allocNetwork(st *zr.State, want string) (v4, v6 string, err error) {
	var taken []netip.Prefix
	for _, n := range st.Networks {
		if p, err := netip.ParsePrefix(n.IPv4); err == nil {
			taken = append(taken, p)
		}
	}
	free := func(p netip.Prefix) bool {
		for _, t := range taken {
			if t.Overlaps(p) {
				return false
			}
		}
		return true
	}
	if want != "" {
		p, err := netip.ParsePrefix(want)
		if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 24 || p != p.Masked() {
			return "", "", fmt.Errorf("invalid --cidr %q (want an IPv4 network /8 to /24)", want)
		}
		if !free(p) {
			return "", "", fmt.Errorf("%s overlaps another network", want)
		}
		v4 = p.String()
	} else {
		pool := netip.MustParsePrefix(routerPool)
		for a := pool.Addr(); pool.Contains(a); {
			p := netip.PrefixFrom(a, 16)
			if free(p) {
				v4 = p.String()
				break
			}
			b := a.As4()
			b[1]++
			if b[1] == 0 {
				break
			}
			a = netip.AddrFrom4(b)
		}
		if v4 == "" {
			return "", "", fmt.Errorf("the %s pool is full; pass --cidr", routerPool)
		}
	}
	var r [2]byte
	_, _ = rand.Read(r[:])
	v6 = fmt.Sprintf("fd7a:5a72:%04x::/48", binary.BigEndian.Uint16(r[:]))
	return v4, v6, nil
}

// allocMemberIP returns the first free host address of the network and its IPv6 twin (the ULA
// prefix with the IPv4 address in the low 32 bits).
func allocMemberIP(st *zr.State, n *zr.Network) (string, string, error) {
	used := map[string]bool{}
	for _, m := range st.Members {
		if m.Network == n.ID {
			used[m.IPv4] = true
		}
	}
	p, err := netip.ParsePrefix(n.IPv4)
	if err != nil {
		return "", "", err
	}
	for a := p.Addr().Next(); p.Contains(a.Next()); a = a.Next() { // skips network and broadcast
		if used[a.String()] {
			continue
		}
		v6p, err := netip.ParsePrefix(n.IPv6)
		if err != nil {
			return a.String(), "", nil
		}
		b6, b4 := v6p.Addr().As16(), a.As4()
		copy(b6[12:], b4[:])
		return a.String(), netip.AddrFrom16(b6).String(), nil
	}
	return "", "", fmt.Errorf("network %s is full", n.Name)
}

func validRoutes(routes []string) ([]string, error) {
	if len(routes) > maxRoutes {
		return nil, fmt.Errorf("at most %d routes", maxRoutes)
	}
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("invalid route %q", r)
		}
		out = append(out, p.Masked().String())
	}
	sort.Strings(out)
	return out, nil
}

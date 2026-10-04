package daemon

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// MTU leaves room for WireGuard over IPv6 and for relayed paths (R3) on any internet link.
const MTU = 1280

// Engine is the userspace data plane: wireguard-go over a TUN device wrapped by the packet
// filter. Netmap messages are applied as diffs (peers configured one by one, never
// replace_peers), so a change never resets sessions it does not touch.
type Engine struct {
	name   string
	tun    tun.Device
	filter *Filter
	bind   *MagicBind
	dev    *device.Device
	dns    dnsServer

	mu        sync.Mutex
	peers     map[string]zr.Peer // by member ID
	self      *zr.Peer
	networks  []netip.Prefix
	routes    map[netip.Prefix]bool
	domain    string
	dnsUp     bool
	addrsSet  bool
	acceptDNS bool
}

func NewEngine(wgPriv, discoPriv string, port int, acceptDNS bool, auth RelayAuth, onChange func()) (*Engine, error) {
	k, err := base64.StdEncoding.DecodeString(wgPriv)
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("invalid WireGuard key")
	}
	bind, err := NewMagicBind(discoPriv, auth, onChange)
	if err != nil {
		return nil, err
	}
	t, err := tun.CreateTUN(ifaceName, MTU)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return nil, err
	}
	e := &Engine{name: name, tun: t, filter: NewFilter(t), bind: bind, peers: map[string]zr.Peer{}, routes: map[netip.Prefix]bool{}, acceptDNS: acceptDNS}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) { log.Printf("wireguard: "+f, a...) }}
	e.dev = device.NewDevice(e.filter, bind, logger)
	if err := e.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(k), port)); err != nil {
		e.dev.Close()
		return nil, err
	}
	if err := e.dev.Up(); err != nil {
		e.dev.Close()
		return nil, err
	}
	return e, nil
}

func (e *Engine) Name() string { return e.name }

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dns.close()
	if e.dnsUp {
		clearDNS(e.name, e.domain)
	}
	e.dev.Close() // closes the TUN too
}

func keyHex(b64 string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", false
	}
	return hex.EncodeToString(b), true
}

func prefixes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// peerUAPI renders one peer for IpcSet (removal when p is nil).
func peerUAPI(b *strings.Builder, key string, p *zr.Peer, endpoint string) {
	fmt.Fprintf(b, "public_key=%s\n", key)
	if p == nil {
		b.WriteString("remove=true\n")
		return
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range prefixes(p.AllowedIPs) {
		fmt.Fprintf(b, "allowed_ip=%s\n", a)
	}
	if endpoint != "" {
		fmt.Fprintf(b, "endpoint=%s\n", endpoint)
	}
	b.WriteString("persistent_keepalive_interval=25\n")
}

func samePeer(a, b zr.Peer) bool {
	return a.NodeKey == b.NodeKey && strings.Join(a.AllowedIPs, ",") == strings.Join(b.AllowedIPs, ",")
}

// Bind is the socket layer (endpoints, home relay, paths, netcheck).
func (e *Engine) Bind() *MagicBind { return e.bind }

// Apply converges the data plane to one netmap message.
func (e *Engine) Apply(m zr.MapMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := map[string]zr.Peer{}
	if m.Type != "full" {
		for id, p := range e.peers {
			next[id] = p
		}
	} else {
		e.networks = prefixes(m.Networks)
		e.domain = m.Domain
	}
	for _, p := range m.Peers {
		next[p.ID] = p
	}
	for _, id := range m.Removed {
		delete(next, id)
	}
	if m.Self != nil {
		s := *m.Self
		e.self = &s
	}

	var b strings.Builder
	for id, old := range e.peers {
		if p, ok := next[id]; !ok || p.NodeKey != old.NodeKey {
			if k, ok := keyHex(old.NodeKey); ok {
				peerUAPI(&b, k, nil, "")
			}
		}
	}
	list := make([]zr.Peer, 0, len(next))
	for id, p := range next {
		if _, ok := keyHex(p.NodeKey); !ok {
			delete(next, id)
			continue
		}
		list = append(list, p)
	}
	e.bind.SetPeers(list) // before IpcSet: WireGuard resolves zrpeer: endpoints through it
	if m.RelaysChanged {
		e.bind.SetRelays(m.Relays)
	}
	for id, p := range next {
		old, had := e.peers[id]
		if had && samePeer(old, p) {
			continue
		}
		k, _ := keyHex(p.NodeKey)
		ep := ""
		if !had || old.NodeKey != p.NodeKey {
			ep = "zrpeer:" + k // the socket layer picks the path (direct or relay) per packet
		}
		pp := p
		peerUAPI(&b, k, &pp, ep)
	}
	if b.Len() > 0 {
		if err := e.dev.IpcSet(b.String()); err != nil {
			return fmt.Errorf("configure peers: %w", err)
		}
	}
	e.peers = next
	if m.FilterChanged {
		e.filter.SetRules(m.Filter)
	}
	return e.converge()
}

// converge applies addresses, routes and DNS for the current state (callers hold e.mu).
func (e *Engine) converge() error {
	if e.self == nil {
		return nil
	}
	selfAddrs := prefixes(e.self.Addresses)
	if !e.addrsSet {
		var addrs []netip.Prefix
		for _, a := range selfAddrs {
			p := netip.PrefixFrom(a.Addr(), a.Bits())
			for _, n := range e.networks {
				if n.Contains(a.Addr()) {
					p = netip.PrefixFrom(a.Addr(), n.Bits())
				}
			}
			addrs = append(addrs, p)
		}
		if err := configureInterface(e.name, addrs); err != nil {
			return err
		}
		e.addrsSet = true
	}
	want := map[netip.Prefix]bool{}
	for _, n := range e.networks {
		want[n] = true
	}
	for _, p := range e.peers {
		addrs := map[string]bool{}
		for _, a := range p.Addresses {
			addrs[a] = true
		}
		for _, r := range prefixes(p.AllowedIPs) {
			if !addrs[r.String()] {
				want[r] = true // an approved subnet route behind this peer
			}
		}
	}
	var errs []string
	for r := range e.routes {
		if !want[r] {
			if err := delRoute(e.name, r); err != nil {
				errs = append(errs, err.Error())
			}
			delete(e.routes, r)
		}
	}
	for r := range want {
		if !e.routes[r] {
			if err := addRoute(e.name, r); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			e.routes[r] = true
		}
	}

	records := map[string][]netip.Addr{}
	for _, p := range append(e.peerList(), *e.self) {
		for _, a := range prefixes(p.Addresses) {
			records[p.Name] = append(records[p.Name], a.Addr())
		}
	}
	e.dns.set(e.domain, records)
	if e.acceptDNS && !e.dnsUp && len(selfAddrs) > 0 {
		ns := selfAddrs[0].Addr()
		if err := e.dns.listen(ns); err != nil {
			errs = append(errs, "dns: "+err.Error())
		} else if err := setDNS(e.name, e.domain, ns); err != nil {
			errs = append(errs, "dns: "+err.Error())
		} else {
			e.dnsUp = true
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (e *Engine) peerList() []zr.Peer {
	out := make([]zr.Peer, 0, len(e.peers))
	for _, p := range e.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// PeerStatus is a peer as `zirocd status` shows it.
type PeerStatus struct {
	Name          string   `json:"name"`
	Addresses     []string `json:"addresses"`
	Path          string   `json:"path,omitempty"` // direct <addr> (rtt) or relay <name>
	Online        bool     `json:"online"`
	LastHandshake int64    `json:"last_handshake,omitempty"` // unix seconds
	RxBytes       uint64   `json:"rx_bytes"`
	TxBytes       uint64   `json:"tx_bytes"`
}

// Peers reports peers with WireGuard's live counters.
func (e *Engine) Peers() []PeerStatus {
	e.mu.Lock()
	list := e.peerList()
	e.mu.Unlock()
	stats := map[string]map[string]string{}
	cfg, _ := e.dev.IpcGet()
	var cur map[string]string
	for _, l := range strings.Split(cfg, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			cur = map[string]string{}
			stats[v] = cur
		} else if cur != nil {
			cur[k] = v
		}
	}
	out := make([]PeerStatus, 0, len(list))
	for _, p := range list {
		ps := PeerStatus{Name: p.Name, Addresses: p.Addresses, Online: p.Online}
		if raw, err := base64.StdEncoding.DecodeString(p.NodeKey); err == nil && len(raw) == 32 {
			ps.Path = e.bind.Path([32]byte(raw))
		}
		if k, ok := keyHex(p.NodeKey); ok && stats[k] != nil {
			s := stats[k]
			fmt.Sscan(s["last_handshake_time_sec"], &ps.LastHandshake)
			fmt.Sscan(s["rx_bytes"], &ps.RxBytes)
			fmt.Sscan(s["tx_bytes"], &ps.TxBytes)
		}
		out = append(out, ps)
	}
	return out
}

func (e *Engine) Dropped() uint64 { return e.filter.Dropped() }

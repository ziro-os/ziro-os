package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

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
	stop   context.CancelFunc // roaming watcher and port mapper

	netMu       sync.Mutex
	onNetChange func() // the daemon's reaction to a network change (fresh control connections)

	mu              sync.Mutex
	peers           map[string]zr.Peer // by member ID
	self            *zr.Peer
	networks        []netip.Prefix
	routes          map[netip.Prefix]bool
	domain          string
	dnsUp           bool
	addrsSet        bool
	routing         bool // this device routes approved subnets into the network
	port            int
	noSubnetRouting bool
	acceptDNS       bool
}

// Options configure an engine. zirocd uses the defaults; the cluster agent runs the cluster mesh
// on the same engine (interface ziro0, no packet filter: the node's nft policy enforces app
// policy; no subnet routing or DNS of its own).
type Options struct {
	WGKey, DiscoKey string // base64 private keys
	Port            int
	Iface           string // "" = the platform default (zr0, utunN, Ziro)
	MTU             int    // 0 = MTU
	AcceptDNS       bool
	NoFilter        bool
	NoSubnetRouting bool
	NoPortMapping   bool
	Auth            RelayAuth
	OnChange        func() // endpoints, NAT type or relays changed: report them
}

func NewEngine(wgPriv, discoPriv string, port int, acceptDNS bool, auth RelayAuth, onChange func()) (*Engine, error) {
	return NewEngineWith(Options{WGKey: wgPriv, DiscoKey: discoPriv, Port: port, AcceptDNS: acceptDNS, Auth: auth, OnChange: onChange})
}

func NewEngineWith(o Options) (*Engine, error) {
	wgPriv, discoPriv, port, acceptDNS, auth, onChange := o.WGKey, o.DiscoKey, o.Port, o.AcceptDNS, o.Auth, o.OnChange
	iface, mtu := o.Iface, o.MTU
	if iface == "" {
		iface = ifaceName
	}
	if mtu == 0 {
		mtu = MTU
	}
	k, err := base64.StdEncoding.DecodeString(wgPriv)
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("invalid WireGuard key")
	}
	bind, err := NewMagicBind(discoPriv, auth, onChange)
	if err != nil {
		return nil, err
	}
	t, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return nil, err
	}
	e := &Engine{name: name, tun: t, filter: NewFilter(t), bind: bind, peers: map[string]zr.Peer{}, routes: map[netip.Prefix]bool{},
		acceptDNS: acceptDNS, port: port, noSubnetRouting: o.NoSubnetRouting}
	var dev tun.Device = e.filter
	if o.NoFilter {
		dev = t
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) { log.Printf("wireguard: "+f, a...) }}
	e.dev = device.NewDevice(dev, bind, logger)
	// The socket layer chooses every packet's path (direct, relayed, probed). WireGuard must not
	// "roam" a peer to whatever address a packet came from: that would bypass path selection,
	// failover and status. Peers are configured with an endpoint, which pins them.
	e.dev.DisableSomeRoamingForBrokenMobileSemantics()
	if err := e.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(k), port)); err != nil {
		e.dev.Close()
		return nil, err
	}
	if err := e.dev.Up(); err != nil {
		e.dev.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.stop = cancel
	go watchNetwork(ctx, name, 2*time.Second, func() { // roaming: new paths within seconds
		bind.Rebind()
		e.netMu.Lock()
		f := e.onNetChange
		e.netMu.Unlock()
		if f != nil {
			f()
		}
	})
	if !o.NoPortMapping {
		go runPortMapper(ctx, bind, uint16(port)) // PCP / NAT-PMP / UPnP on the home router
	}
	return e, nil
}

func (e *Engine) Name() string { return e.name }

func (e *Engine) Close() {
	if e.stop != nil {
		e.stop()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dns.close()
	if e.dnsUp {
		clearDNS(e.name, e.domain)
	}
	if e.routing {
		_ = setSubnetRouter(e.name, e.networks, false)
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

// OnNetworkChange sets what to do, besides re-finding paths, when the host's network changes.
func (e *Engine) OnNetworkChange(f func()) {
	e.netMu.Lock()
	e.onNetChange = f
	e.netMu.Unlock()
}

// Report is this device's soft state for the control plane: its local and public endpoints, the
// relays it is registered with, and its NAT type.
func (e *Engine) Report(version string) zr.MapRequest {
	eps := localEndpoints(e.port, e.name)
	for _, p := range e.bind.PublicEndpoints() {
		if !slices.Contains(eps, p) && len(eps) < zr.MaxEndpoints {
			eps = append(eps, p)
		}
	}
	return zr.MapRequest{Endpoints: eps, Version: version, HomeRelay: e.bind.Home(), Relays: e.bind.Relays(), NAT: e.bind.NATType()}
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
		if _, ok := keyHex(p.DiscoKey); ok && (!had || old.NodeKey != p.NodeKey) {
			ep = "zrpeer:" + k // the socket layer picks the path (direct or relay) per packet
		}
		// A peer without a disco key is a plain WireGuard client (e.g. a gateway remote peer): no
		// endpoint, so WireGuard learns its address from its own packets.
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
	overlay := make([]netip.Prefix, 0, len(want))
	for r := range want {
		overlay = append(overlay, r)
	}
	e.bind.SetOverlay(overlay)
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

	// Approved subnet routes for this device: forward and masquerade into them.
	own := map[string]bool{}
	for _, a := range e.self.Addresses {
		own[a] = true
	}
	approved := false
	for _, a := range e.self.AllowedIPs {
		if !own[a] {
			approved = true
		}
	}
	if approved != e.routing && !e.noSubnetRouting {
		if err := setSubnetRouter(e.name, e.networks, approved); err != nil {
			errs = append(errs, "subnet routing: "+err.Error())
		} else {
			e.routing = approved
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

package cmd

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The network pane of `system top`: interface rates, every connection the kernel tracks
// (conntrack: per-flow bytes, also for NAT'd container traffic) with its direction, the busiest
// remote peers and what listens on which port. Read from /proc only. Without conntrack it falls
// back to the socket tables (states only, no bytes).

type IfaceRate struct {
	Name   string `json:"name"`
	RxBps  uint64 `json:"rx_bps"`
	TxBps  uint64 `json:"tx_bps"`
	RxPps  uint64 `json:"rx_pps"`
	TxPps  uint64 `json:"tx_pps"`
	Errors uint64 `json:"errors"`
	Drops  uint64 `json:"drops"`
}

type Flow struct {
	Proto  string `json:"proto"`
	Dir    string `json:"dir"` // in, out
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state,omitempty"`
	RxBps  uint64 `json:"rx_bps"`
	TxBps  uint64 `json:"tx_bps"`
	Bytes  uint64 `json:"bytes"` // both directions, since the flow started
}

type Peer struct {
	IP    string `json:"ip"`
	Flows int    `json:"flows"`
	Bps   uint64 `json:"bps"`
	Bytes uint64 `json:"bytes"`
}

type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Process string `json:"process,omitempty"`
}

type NetSnapshot struct {
	Source    string         `json:"source"` // conntrack, sockets
	Ifaces    []IfaceRate    `json:"interfaces"`
	Primary   string         `json:"primary"`
	States    map[string]int `json:"states"`
	In        int            `json:"inbound"`
	Out       int            `json:"outbound"`
	Flows     []Flow         `json:"flows"`
	Peers     []Peer         `json:"peers"`
	Listeners []Listener     `json:"listeners"`
	RxHist    []uint64       `json:"-"`
	TxHist    []uint64       `json:"-"`
}

type ifPrev struct{ rx, tx, rxp, txp uint64 }

// ponytail: flows past maxTrackedFlows show totals but no rate; raise it if hosts track more.
const maxTrackedFlows = 16384

type netCollector struct {
	ifs       map[string]ifPrev
	flows     map[string][2]uint64 // flow key -> orig, reply bytes at the last sample
	rx, tx    [60]uint64           // primary interface rate history (ring)
	hist      int                  // samples in the ring
	pos       int
	owners    map[string]string // socket inode -> process name
	ownersAt  time.Time
	acctTried bool
}

func newNetCollector() *netCollector {
	return &netCollector{ifs: map[string]ifPrev{}, flows: map[string][2]uint64{}, owners: map[string]string{}}
}

func (n *netCollector) sample(dt float64, buf []byte) NetSnapshot {
	s := NetSnapshot{States: map[string]int{}, Primary: defaultRouteIface()}
	rate := func(a, b uint64) uint64 {
		if a < b || dt <= 0 {
			return 0
		}
		return uint64(float64(a-b) / dt)
	}

	// Interfaces (/proc/net/dev: rx bytes packets errs drop ... tx bytes packets errs drop).
	seen := map[string]bool{}
	for _, line := range strings.Split(string(readInto(buf, filepath.Join(procRoot, "net", "dev"))), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if !ok || name == "lo" || len(f) < 12 {
			continue
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		cur := ifPrev{u(0), u(8), u(1), u(9)}
		seen[name] = true
		ir := IfaceRate{Name: name, Errors: u(2) + u(10), Drops: u(3) + u(11)}
		if p, ok := n.ifs[name]; ok {
			ir.RxBps, ir.TxBps, ir.RxPps, ir.TxPps = rate(cur.rx, p.rx), rate(cur.tx, p.tx), rate(cur.rxp, p.rxp), rate(cur.txp, p.txp)
		}
		n.ifs[name] = cur
		if name == s.Primary && dt > 0 {
			n.rx[n.pos], n.tx[n.pos] = ir.RxBps, ir.TxBps
			n.pos, n.hist = (n.pos+1)%len(n.rx), min(n.hist+1, len(n.rx))
		}
		s.Ifaces = append(s.Ifaces, ir)
	}
	for k := range n.ifs {
		if !seen[k] {
			delete(n.ifs, k)
		}
	}
	sort.Slice(s.Ifaces, func(i, j int) bool {
		a, b := s.Ifaces[i], s.Ifaces[j]
		if (a.Name == s.Primary) != (b.Name == s.Primary) {
			return a.Name == s.Primary
		}
		return a.RxBps+a.TxBps > b.RxBps+b.TxBps
	})
	for i := range n.hist { // oldest first
		j := (n.pos - n.hist + i + len(n.rx)) % len(n.rx)
		s.RxHist, s.TxHist = append(s.RxHist, n.rx[j]), append(s.TxHist, n.tx[j])
	}

	local := localIPs()
	listen := map[string]bool{} // "proto/port" listening on the host
	if time.Since(n.ownersAt) > 10*time.Second {
		n.owners, n.ownersAt = socketOwners(), time.Now()
	}
	for _, t := range []string{"tcp", "tcp6", "udp", "udp6"} {
		for _, so := range parseSockets(readInto(buf, filepath.Join(procRoot, "net", t))) {
			proto := strings.TrimSuffix(t, "6")
			if so.listening(proto) {
				listen[proto+"/"+so.lport] = true
				s.Listeners = append(s.Listeners, Listener{Proto: proto, Addr: joinHostPort(so.local, so.lport), Process: n.owners[so.inode]})
			}
		}
	}
	sort.Slice(s.Listeners, func(i, j int) bool { return s.Listeners[i].Addr < s.Listeners[j].Addr })

	ct := readInto(buf, filepath.Join(procRoot, "net", "nf_conntrack"))
	if len(ct) > 0 {
		s.Source = "conntrack"
		n.enableAccounting()
		live := make(map[string]bool, len(n.flows))
		sc := bufio.NewScanner(bytes.NewReader(ct))
		for sc.Scan() {
			e, ok := parseConntrack(sc.Text())
			if !ok {
				continue
			}
			f := Flow{Proto: e.proto, State: e.state, Bytes: e.ob + e.rb}
			var rx, tx uint64
			if local[e.dst] { // the remote end opened it
				f.Dir, f.Local, f.Remote = "in", joinHostPort(e.dst, e.dport), joinHostPort(e.src, e.sport)
			} else {
				f.Dir, f.Local, f.Remote = "out", joinHostPort(e.src, e.sport), joinHostPort(e.dst, e.dport)
			}
			key := e.proto + " " + e.src + " " + e.sport + " " + e.dst + " " + e.dport
			if p, ok := n.flows[key]; ok {
				tx, rx = rate(e.ob, p[0]), rate(e.rb, p[1]) // orig = initiator's bytes
				live[key] = true
				n.flows[key] = [2]uint64{e.ob, e.rb}
			} else if len(n.flows) < maxTrackedFlows {
				live[key] = true
				n.flows[key] = [2]uint64{e.ob, e.rb}
			}
			if f.Dir == "in" {
				f.RxBps, f.TxBps = tx, rx
			} else {
				f.RxBps, f.TxBps = rx, tx
			}
			s.addFlow(f)
		}
		for k := range n.flows {
			if !live[k] {
				delete(n.flows, k)
			}
		}
	} else {
		s.Source = "sockets"
		for _, t := range []string{"tcp", "tcp6", "udp", "udp6"} {
			proto := strings.TrimSuffix(t, "6")
			for _, so := range parseSockets(readInto(buf, filepath.Join(procRoot, "net", t))) {
				if so.listening(proto) || so.remote == "" {
					continue
				}
				f := Flow{Proto: proto, State: so.state, Local: joinHostPort(so.local, so.lport), Remote: joinHostPort(so.remote, so.rport), Dir: "out"}
				if listen[proto+"/"+so.lport] {
					f.Dir = "in"
				}
				s.addFlow(f)
			}
		}
	}
	s.States["LISTEN"] = len(s.Listeners)

	peers := map[string]*Peer{}
	for _, f := range s.Flows {
		ip, _, _ := net.SplitHostPort(f.Remote)
		p := peers[ip]
		if p == nil {
			p = &Peer{IP: ip}
			peers[ip] = p
		}
		p.Flows++
		p.Bps += f.RxBps + f.TxBps
		p.Bytes += f.Bytes
	}
	for _, p := range peers {
		s.Peers = append(s.Peers, *p)
	}
	sort.Slice(s.Peers, func(i, j int) bool {
		a, b := s.Peers[i], s.Peers[j]
		if a.Bps != b.Bps {
			return a.Bps > b.Bps
		}
		if a.Flows != b.Flows {
			return a.Flows > b.Flows
		}
		return a.IP < b.IP
	})
	return s
}

func (s *NetSnapshot) addFlow(f Flow) {
	if f.Dir == "in" {
		s.In++
	} else {
		s.Out++
	}
	st := f.State
	if st == "" {
		st = strings.ToUpper(f.Proto)
	}
	s.States[st]++
	s.Flows = append(s.Flows, f)
}

// enableAccounting turns on conntrack byte counters (net.netfilter.nf_conntrack_acct, also set
// at boot) when top runs as root on a host where they're off; counting starts with new flows.
func (n *netCollector) enableAccounting() {
	if n.acctTried {
		return
	}
	n.acctTried = true
	p := filepath.Join(procRoot, "sys", "net", "netfilter", "nf_conntrack_acct")
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == "0" {
		_ = os.WriteFile(p, []byte("1"), 0644)
	}
}

type ctEntry struct {
	proto, state, src, dst, sport, dport string
	ob, rb                               uint64 // bytes in the original and reply direction
}

// parseConntrack reads one /proc/net/nf_conntrack line:
// "ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=2 packets=3 bytes=4 src=B dst=A ... bytes=5 ..."
func parseConntrack(line string) (ctEntry, bool) {
	f := strings.Fields(line)
	if len(f) < 6 {
		return ctEntry{}, false
	}
	e := ctEntry{proto: f[2]}
	tuples := 0
	for _, x := range f[5:] {
		k, v, ok := strings.Cut(x, "=")
		if !ok {
			if tuples == 0 && x == strings.ToUpper(x) && !strings.HasPrefix(x, "[") {
				e.state = x
			}
			continue
		}
		switch k {
		case "src":
			tuples++
			if tuples == 1 {
				e.src = v
			}
		case "dst":
			if tuples == 1 {
				e.dst = v
			}
		case "sport":
			if tuples == 1 {
				e.sport = v
			}
		case "dport":
			if tuples == 1 {
				e.dport = v
			}
		case "bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			if tuples == 1 {
				e.ob = n
			} else {
				e.rb = n
			}
		}
	}
	return e, e.src != "" && e.dst != ""
}

type sockEntry struct {
	local, lport, remote, rport, state, inode string
}

var tcpStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}

func (s sockEntry) listening(proto string) bool {
	if proto == "tcp" {
		return s.state == "LISTEN"
	}
	return s.remote == "" // an unconnected UDP socket receives from anyone
}

// parseSockets reads /proc/net/{tcp,udp}[6]: "sl local rem st ... inode" with hex addresses.
func parseSockets(b []byte) []sockEntry {
	var out []sockEntry
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		la, lp := hexAddr(f[1])
		ra, rp := hexAddr(f[2])
		e := sockEntry{local: la, lport: lp, state: tcpStates[f[3]], inode: f[9]}
		if rp != "0" {
			e.remote, e.rport = ra, rp
		}
		out = append(out, e)
	}
	return out
}

// hexAddr decodes "0100007F:0016" (IPv4) or a 32-hex-digit IPv6 address, stored as host-order
// 32-bit words.
func hexAddr(s string) (string, string) {
	a, p, _ := strings.Cut(s, ":")
	port, _ := strconv.ParseUint(p, 16, 16)
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", "0"
	}
	for i := 0; i < len(raw); i += 4 { // little-endian words
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String(), strconv.FormatUint(port, 10)
}

func joinHostPort(ip, port string) string {
	if port == "" {
		return ip
	}
	return net.JoinHostPort(ip, port)
}

func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out[ipn.IP.String()] = true
		}
	}
	return out
}

// socketOwners maps socket inodes to the process holding them (one walk of /proc/*/fd).
func socketOwners() map[string]string {
	out := map[string]string{}
	pids, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	for _, pd := range pids {
		fds, err := os.ReadDir(filepath.Join(pd, "fd"))
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(pd, "fd", fd.Name()))
			if ino, ok := strings.CutPrefix(l, "socket:["); err == nil && ok {
				if comm == "" {
					b, _ := os.ReadFile(filepath.Join(pd, "comm"))
					comm = strings.TrimSpace(string(b)) + "/" + filepath.Base(pd)
				}
				out[strings.TrimSuffix(ino, "]")] = comm
			}
		}
	}
	return out
}

// readInto reads a small /proc file into buf (reused between refreshes) and returns the bytes
// read; /proc files are generated on read, so size them by reading, not by stat.
func readInto(buf []byte, p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	if n == len(buf) { // larger than the buffer (a big conntrack table): read the rest normally
		rest, _ := readAllFrom(f)
		return append(buf[:n:n], rest...)
	}
	return buf[:n]
}

func readAllFrom(f *os.File) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(f)
	return b.Bytes(), err
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// sparkline draws vals (oldest first) scaled to their max, width cells wide.
func sparkline(vals []uint64, width int, unicode bool) string {
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	var peak uint64 = 1
	for _, v := range vals {
		peak = max(peak, v)
	}
	var b strings.Builder
	for _, v := range vals {
		i := int(v * uint64(len(sparkRunes)-1) / peak)
		if unicode {
			b.WriteRune(sparkRunes[i])
		} else {
			b.WriteByte(" .:-=+*#"[i])
		}
	}
	return b.String()
}

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Ziro Guard: in-kernel flood/scan defense and IP bans in their own nftables table.
//
// The inet ziro_guard table is never deleted while protection is on: every apply re-declares it
// (idempotent), flushes its chains and static sets, and re-adds the rules. Dynamic sets (bans,
// rate meters) therefore keep their elements and remaining timeouts across firewall changes, and
// bans expire in the kernel on their own. Its chains run at priority -10, before the inet ziro
// filter (0): a drop here is final, an accept only ends this table's evaluation.

const guardTable = "inet ziro_guard"

type GuardConfig struct {
	Disabled   bool     `json:"disabled,omitempty"`
	SynRate    int      `json:"syn_rate,omitempty"`         // new TCP connections/second per source (100)
	ConnLimit  int      `json:"conn_limit,omitempty"`       // concurrent connections per source (256)
	ICMPRate   int      `json:"icmp_rate,omitempty"`        // ICMP packets/second per source (20)
	ScanRate   int      `json:"scan_rate,omitempty"`        // SYNs/minute to closed ports before a ban (20)
	ScanBan    string   `json:"scan_ban,omitempty"`         // ban for port scanners (10m)
	SSHMaxFail int      `json:"ssh_max_failures,omitempty"` // failed SSH logins inside SSHWindow before a ban (5)
	SSHWindow  string   `json:"ssh_window,omitempty"`       // (10m)
	SSHBan     string   `json:"ssh_ban,omitempty"`          // first ban; doubles per repeat offense, max 24h (1h)
	Allow      []string `json:"allow,omitempty"`            // CIDRs never banned or rate-limited
}

func (g GuardConfig) withDefaults() GuardConfig {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defs := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&g.SynRate, 100)
	def(&g.ConnLimit, 256)
	def(&g.ICMPRate, 20)
	def(&g.ScanRate, 20)
	def(&g.SSHMaxFail, 5)
	defs(&g.ScanBan, "10m")
	defs(&g.SSHWindow, "10m")
	defs(&g.SSHBan, "1h")
	return g
}

func (g GuardConfig) validate() error {
	for name, v := range map[string]int{"syn_rate": g.SynRate, "conn_limit": g.ConnLimit, "icmp_rate": g.ICMPRate,
		"scan_rate": g.ScanRate, "ssh_max_failures": g.SSHMaxFail} {
		if v < 1 || v > 1000000 {
			return fmt.Errorf("guard %s must be 1..1000000, got %d", name, v)
		}
	}
	for name, v := range map[string]string{"scan_ban": g.ScanBan, "ssh_window": g.SSHWindow, "ssh_ban": g.SSHBan} {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second || d > 30*24*time.Hour {
			return fmt.Errorf("guard %s must be a duration between 1s and 720h, got %q", name, v)
		}
	}
	for _, c := range g.Allow {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("invalid guard allow CIDR %q", c)
		}
	}
	return nil
}

// Interfaces whose traffic the guard never limits: loopback, the WireGuard mesh (authenticated
// peers) and container bridges/veths (a container probing host ports must not ban itself).
var guardSkipIfaces = []string{"ziro0", "ziro-br0", "veth*", "nerdctl*", "cni*", "br-*"}

func nftSeconds(d string) int {
	v, _ := time.ParseDuration(d)
	return int(v / time.Second)
}

func buildGuardScript(cfg FirewallConfig) (string, error) {
	g := cfg.Guard.withDefaults()
	if err := g.validate(); err != nil {
		return "", err
	}
	var allow4, allow6 []string
	for _, c := range g.Allow {
		p := netip.MustParsePrefix(c).Masked()
		if p.Addr().Is4() {
			allow4 = append(allow4, p.String())
		} else {
			allow6 = append(allow6, p.String())
		}
	}
	var open []string
	seen := map[int]bool{}
	for _, r := range cfg.AllowedPorts {
		if r.Protocol == "tcp" && !seen[r.Port] && r.Port > 0 && r.Port < 65536 {
			seen[r.Port] = true
			open = append(open, strconv.Itoa(r.Port))
		}
	}

	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f+"\n", a...) }
	w("table %s {", guardTable)
	for _, fam := range []struct{ n, t string }{{"4", "ipv4_addr"}, {"6", "ipv6_addr"}} {
		w("  set ban%s { type %s; flags dynamic,timeout; }", fam.n, fam.t)
		w("  set allow%s { type %s; flags interval; }", fam.n, fam.t)
		for _, meter := range []string{"syn", "icmp", "scan"} {
			w("  set %s%s { type %s; flags dynamic,timeout; timeout 1m; size 65536; }", meter, fam.n, fam.t)
		}
		w("  set conn%s { type %s; flags dynamic; size 65536; }", fam.n, fam.t)
	}
	w("  set tcp_open { type inet_service; }")
	w("  chain input { type filter hook input priority -10; policy accept; }")
	w("  chain forward { type filter hook forward priority -10; policy accept; }")
	w("}")
	for _, c := range []string{"input", "forward"} {
		w("flush chain %s %s", guardTable, c)
	}
	for _, s := range []string{"allow4", "allow6", "tcp_open"} {
		w("flush set %s %s", guardTable, s)
	}
	if len(allow4) > 0 {
		w("add element %s allow4 { %s }", guardTable, strings.Join(allow4, ", "))
	}
	if len(allow6) > 0 {
		w("add element %s allow6 { %s }", guardTable, strings.Join(allow6, ", "))
	}
	if len(open) > 0 {
		w("add element %s tcp_open { %s }", guardTable, strings.Join(open, ", "))
	}
	in := "add rule " + guardTable + " input "
	w(in + `iif "lo" accept`)
	for _, ifc := range append(append([]string{}, guardSkipIfaces...), cfg.TrustedInterfaces...) {
		if !ifaceNameRe.MatchString(strings.TrimSuffix(ifc, "*")) {
			return "", fmt.Errorf("invalid interface %q", ifc)
		}
		w(in+"iifname %q accept", ifc)
	}
	w(in + "ip saddr @allow4 accept")
	w(in + "ip6 saddr @allow6 accept")
	w(in + "ip saddr @ban4 drop")
	w(in + "ip6 saddr @ban6 drop")
	w(in + "ct state established,related accept")
	const syn = "tcp flags & (fin|syn|rst|ack) == syn "
	for _, f := range []struct{ n, a string }{{"4", "ip saddr"}, {"6", "ip6 saddr"}} {
		w(in+syn+"update @syn%s { %s limit rate over %d/second burst %d packets } drop", f.n, f.a, g.SynRate, 2*g.SynRate)
		w(in+"ct state new add @conn%s { %s ct count over %d } drop", f.n, f.a, g.ConnLimit)
	}
	w(in+"meta l4proto icmp update @icmp4 { ip saddr limit rate over %d/second burst %d packets } drop", g.ICMPRate, 2*g.ICMPRate+10)
	w(in+"meta l4proto ipv6-icmp update @icmp6 { ip6 saddr limit rate over %d/second burst %d packets } drop", g.ICMPRate, 2*g.ICMPRate+10)
	// Scan detection needs a default-drop firewall: with default accept, "closed" is unknowable.
	if !strings.EqualFold(cfg.DefaultInput, "ACCEPT") {
		for _, f := range []struct{ n, a string }{{"4", "ip saddr"}, {"6", "ip6 saddr"}} {
			w(in+syn+"tcp dport != @tcp_open update @scan%s { %s limit rate over %d/minute burst %d packets } add @ban%s { %s timeout %ds } drop",
				f.n, f.a, g.ScanRate, g.ScanRate/2+1, f.n, f.a, nftSeconds(g.ScanBan))
		}
	}
	// Banned sources can't reach published container ports either (DNAT'd traffic is forwarded).
	w("add rule %s forward ip saddr @ban4 drop", guardTable)
	w("add rule %s forward ip6 saddr @ban6 drop", guardTable)
	return sb.String(), nil
}

func nftRun(script string) error {
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(script)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyGuard installs (or removes) the guard table to match cfg.
func applyGuard(cfg FirewallConfig) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil // iptables fallback hosts have no guard
	}
	if !cfg.Enabled || cfg.Guard.Disabled {
		return removeGuard()
	}
	script, err := buildGuardScript(cfg)
	if err != nil {
		return err
	}
	return nftRun(script)
}

func removeGuard() error {
	return nftRun("table " + guardTable + "\ndelete table " + guardTable + "\n")
}

// ---- bans ----

var guardStateDir = "/var/lib/ziro/guard"

type offender struct {
	Strikes int       `json:"strikes"`
	Last    time.Time `json:"last"`
}

const strikeForget = 7 * 24 * time.Hour // a clean week resets escalation

// banDuration escalates: base, 2x, 4x ... capped at 24h.
func banDuration(base time.Duration, strikes int) time.Duration {
	d := base
	for i := 1; i < strikes && d < 24*time.Hour; i++ {
		d *= 2
	}
	return min(d, 24*time.Hour)
}

var guardMu sync.Mutex

// recordStrike bumps ip's offense count (persisted, so escalation survives restarts).
func recordStrike(ip string, now time.Time) int {
	guardMu.Lock()
	defer guardMu.Unlock()
	path := filepath.Join(guardStateDir, "offenders.json")
	st := map[string]offender{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	for k, o := range st {
		if now.Sub(o.Last) > strikeForget {
			delete(st, k)
		}
	}
	o := st[ip]
	o.Strikes++
	o.Last = now
	st[ip] = o
	if b, err := json.Marshal(st); err == nil && os.MkdirAll(guardStateDir, 0700) == nil {
		_ = writeFileAtomic(path, b, 0600)
	}
	return o.Strikes
}

// guardAllowed reports whether ip must never be banned: loopback, link-local, the configured
// allowlist, and the cluster mesh.
func guardAllowed(ip netip.Addr, g GuardConfig) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	allow := append([]string{}, g.Allow...)
	if c, err := loadClusterConfig(); err == nil && c != nil && c.MeshCIDR != "" {
		allow = append(allow, c.MeshCIDR)
	}
	for _, c := range allow {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func banSet(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return "ban4"
	}
	return "ban6"
}

// banIP bans ip for d in the kernel (the timeout is refreshed if it is already banned).
func banIP(ip netip.Addr, d time.Duration) error {
	ip = ip.Unmap()
	secs := int(d / time.Second)
	if secs < 1 {
		return fmt.Errorf("ban duration too short")
	}
	set := banSet(ip)
	// delete+add refreshes the timeout; the delete fails harmlessly when not banned yet.
	_ = exec.Command("nft", "delete", "element", "inet", "ziro_guard", set, "{ "+ip.String()+" }").Run()
	out, err := exec.Command("nft", "add", "element", "inet", "ziro_guard", set,
		fmt.Sprintf("{ %s timeout %ds }", ip.String(), secs)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s (is the firewall enabled?)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unbanIP(ip netip.Addr) error {
	ip = ip.Unmap()
	out, err := exec.Command("nft", "delete", "element", "inet", "ziro_guard", banSet(ip), "{ "+ip.String()+" }").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s is not banned (%s)", ip, strings.TrimSpace(string(out)))
	}
	return nil
}

type BanEntry struct {
	IP        string `json:"ip"`
	ExpiresIn int    `json:"expires_in_s"`
	Timeout   int    `json:"timeout_s"`
}

func parseBanSet(data []byte) []BanEntry {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []BanEntry
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if json.Unmarshal(raw, &set) != nil {
			continue
		}
		for _, e := range set.Elem {
			var el struct {
				Elem struct {
					Val     string `json:"val"`
					Timeout int    `json:"timeout"`
					Expires int    `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(e, &el) == nil && el.Elem.Val != "" {
				out = append(out, BanEntry{IP: el.Elem.Val, ExpiresIn: el.Elem.Expires, Timeout: el.Elem.Timeout})
			}
		}
	}
	return out
}

func listBans() ([]BanEntry, error) {
	var all []BanEntry
	for _, set := range []string{"ban4", "ban6"} {
		out, err := exec.Command("nft", "-j", "list", "set", "inet", "ziro_guard", set).Output()
		if err != nil {
			return nil, fmt.Errorf("guard table not active (enable the firewall): %v", err)
		}
		all = append(all, parseBanSet(out)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].IP < all[j].IP })
	return all, nil
}

// ---- SSH brute-force watcher (runs inside Sentinel) ----

var sshLogPath = "/var/log/sshd.log"

// The source address is the token before the LAST " port N": attacker-controlled usernames come
// earlier in the line, so they can't make us ban someone else.
var sshPortRe = regexp.MustCompile(`(\S+) port \d+`)

// OpenSSH >= 9.8 PerSourcePenalties: after a few failures sshd refuses the source itself, so
// retries never reach authentication and only show up as penalty lines. Only auth-related
// penalties count; "connections without attempting authentication" (e.g. load balancer TCP
// health checks) must never lead to a ban.
var (
	sshPenaltyReasons = []string{"penalty: failed authentication", "penalty: attempted authentication by invalid user",
		"penalty: exceeded LoginGraceTime"}
	sshPenaltyOnRe = regexp.MustCompile(`srclimit_penalise: (\S+)/(\d+): activating`)
	sshPenaltyDrop = regexp.MustCompile(`drop connection #\d+ from \[([^\]]+)\]:\d+ on `)
)

func sshPenaltyIP(line string) (netip.Addr, bool) {
	abuse := false
	for _, r := range sshPenaltyReasons {
		abuse = abuse || strings.Contains(line, r)
	}
	if !abuse {
		return netip.Addr{}, false
	}
	if m := sshPenaltyDrop.FindStringSubmatch(line); m != nil {
		ip, err := netip.ParseAddr(m[1])
		return ip.Unmap(), err == nil
	}
	// Activation lines name the penalised prefix: only a full-length one is one address
	// (IPv6 penalties cover a /64; its drop lines carry the exact address).
	if m := sshPenaltyOnRe.FindStringSubmatch(line); m != nil {
		ip, err := netip.ParseAddr(m[1])
		if err == nil && strconv.Itoa(ip.BitLen()) == m[2] {
			return ip.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// sshFailureIP returns the client address of an authentication-failure line (one line per
// failed attempt; follow-up lines like "Connection closed by invalid user" are not counted).
func sshFailureIP(line string) (netip.Addr, bool) {
	if strings.Contains(line, " penalty") {
		return sshPenaltyIP(line)
	}
	switch {
	case strings.Contains(line, "Failed "),
		strings.Contains(line, "Invalid user "),
		strings.Contains(line, "maximum authentication attempts exceeded"),
		strings.Contains(line, "Connection closed by authenticating user "),
		strings.Contains(line, "Disconnected from authenticating user "),
		strings.Contains(line, "banner exchange: Connection from "),
		strings.Contains(line, "Unable to negotiate with "),
		strings.Contains(line, "Timeout before authentication for "):
	default:
		return netip.Addr{}, false
	}
	m := sshPortRe.FindAllStringSubmatch(line, -1)
	if len(m) == 0 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(m[len(m)-1][1])
	return ip.Unmap(), err == nil
}

type sshGuard struct {
	cfg    GuardConfig
	window time.Duration
	base   time.Duration
	off    int64
	ino    uint64
	rest   string
	fails  map[netip.Addr][]time.Time
	drops  map[netip.Addr]time.Time // last counted penalty drop line per source
	ban    func(netip.Addr, time.Duration) error
}

func newSSHGuard(g GuardConfig) *sshGuard {
	g = g.withDefaults()
	w, _ := time.ParseDuration(g.SSHWindow)
	b, _ := time.ParseDuration(g.SSHBan)
	sg := &sshGuard{cfg: g, window: w, base: b, fails: map[netip.Addr][]time.Time{},
		drops: map[netip.Addr]time.Time{}, ban: banIP}
	if fi, err := os.Stat(sshLogPath); err == nil { // start at the end: don't replay history
		sg.off = fi.Size()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			sg.ino = st.Ino
		}
	}
	return sg
}

// poll reads new log lines (following copy-truncate and rename rotation) and bans offenders.
func (s *sshGuard) poll(now time.Time) {
	f, err := os.Open(sshLogPath)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	if ino != s.ino || fi.Size() < s.off {
		s.off, s.ino, s.rest = 0, ino, ""
	}
	if fi.Size() == s.off {
		return
	}
	buf, err := io.ReadAll(io.LimitReader(io.NewSectionReader(f, s.off, fi.Size()-s.off), 1<<20))
	if err != nil {
		return
	}
	s.off += int64(len(buf))
	data := s.rest + string(buf)
	lines := strings.Split(data, "\n")
	s.rest = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		ip, ok := sshFailureIP(line)
		if !ok {
			continue
		}
		// sshd logs a drop for EVERY connection during its penalty, with the original reason. Count
		// those once per 30s per source: a client that merely retries (e.g. after an admin unban)
		// must not re-ban itself, while sustained hammering still escalates.
		if strings.Contains(line, "drop connection #") {
			if t, seen := s.drops[ip]; seen && now.Sub(t) < 30*time.Second {
				continue
			}
			s.drops[ip] = now
		}
		s.fail(ip, now)
	}
}

func (s *sshGuard) fail(ip netip.Addr, now time.Time) {
	if guardAllowed(ip, s.cfg) {
		return
	}
	kept := s.fails[ip][:0]
	for _, t := range s.fails[ip] {
		if now.Sub(t) < s.window {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) < s.cfg.SSHMaxFail {
		s.fails[ip] = kept
		return
	}
	delete(s.fails, ip)
	strikes := recordStrike(ip.String(), now)
	d := banDuration(s.base, strikes)
	err := s.ban(ip, d)
	markOwnBan(ip.String())
	_ = auditLog("sentinel", "ssh-guard", "security ban", ip.String()+" for "+d.String(), err)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guard] ban %s: %v\n", ip, err)
		return
	}
	fmt.Printf("[%s] 🚫 SSH brute force: banned %s for %s (%d failures, offense #%d)\n",
		now.Format("15:04:05"), ip, d, s.cfg.SSHMaxFail, strikes)
	alertf("high", "ban", "SSH brute force from "+ip.String()+" banned",
		map[string]any{"ip": ip.String(), "failures": s.cfg.SSHMaxFail, "window": s.cfg.SSHWindow,
			"ban": d.String(), "offense": strikes, "reason": "ssh"})
}

// Kernel-side bans (port scans) happen without us: Sentinel diffs the ban sets to report them.
var (
	ownBans   = map[string]time.Time{}
	knownBans = map[string]bool{}
	bansMu    sync.Mutex
)

func markOwnBan(ip string) {
	bansMu.Lock()
	ownBans[ip] = time.Now()
	bansMu.Unlock()
}

func reportKernelBans() {
	bans, err := listBans()
	if err != nil {
		return
	}
	bansMu.Lock()
	defer bansMu.Unlock()
	now := map[string]bool{}
	for _, b := range bans {
		now[b.IP] = true
		if knownBans[b.IP] {
			continue
		}
		if t, ok := ownBans[b.IP]; ok && time.Since(t) < time.Minute {
			continue
		}
		alertf("medium", "ban", "Port scan from "+b.IP+" banned",
			map[string]any{"ip": b.IP, "ban_s": b.Timeout, "reason": "scan"})
	}
	knownBans = now
}

// runGuardWatcher is started by Sentinel: SSH log every 2s, kernel ban report every 30s.
func runGuardWatcher() {
	fw := loadFirewallConfig()
	if !fw.Enabled || fw.Guard.Disabled {
		return
	}
	sg := newSSHGuard(fw.Guard)
	fmt.Printf("🚧 Ziro Guard: banning SSH sources after %d failures in %s (%s)\n", sg.cfg.SSHMaxFail, sg.cfg.SSHWindow, sshLogPath)
	if bans, err := listBans(); err == nil { // don't re-report bans that predate this Sentinel
		bansMu.Lock()
		for _, b := range bans {
			knownBans[b.IP] = true
		}
		bansMu.Unlock()
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for i := 0; ; i++ {
		sg.poll(time.Now())
		if i%15 == 0 {
			reportKernelBans()
		}
		<-tick.C
	}
}

// ---- CLI ----

var banFor time.Duration

var securityBansCmd = &cobra.Command{
	Use:   "bans",
	Short: "Show and manage banned IPs (SSH brute force, port scans, manual)",
}

var bansListCmd = &cobra.Command{
	Use:   "list",
	Short: "List banned IPs and their remaining time",
	RunE: func(cmd *cobra.Command, args []string) error {
		bans, err := listBans()
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(bans)
		}
		if len(bans) == 0 {
			fmt.Println("No banned IPs.")
			return nil
		}
		fmt.Printf("%-40s %s\n", "IP", "EXPIRES IN")
		for _, b := range bans {
			fmt.Printf("%-40s %s\n", b.IP, time.Duration(b.ExpiresIn)*time.Second)
		}
		return nil
	},
}

func parseBanIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ip, fmt.Errorf("invalid IP %q", s)
	}
	return ip.Unmap(), nil
}

var bansBanCmd = &cobra.Command{
	Use:   "ban <ip>",
	Short: "Ban an IP now",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip, err := parseBanIP(args[0])
		if err != nil {
			return err
		}
		if guardAllowed(ip, loadFirewallConfig().Guard) {
			return fmt.Errorf("%s is allowlisted (loopback, link-local, mesh or guard allow list)", ip)
		}
		if err := banIP(ip, banFor); err != nil {
			return err
		}
		markOwnBan(ip.String())
		fmt.Printf("Banned %s for %s\n", ip, banFor)
		return nil
	},
}

var bansUnbanCmd = &cobra.Command{
	Use:   "unban <ip>",
	Short: "Lift a ban",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip, err := parseBanIP(args[0])
		if err != nil {
			return err
		}
		if err := unbanIP(ip); err != nil {
			return err
		}
		fmt.Printf("Unbanned %s\n", ip)
		return nil
	},
}

var securityProtectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Flood, port-scan and SSH brute-force protection (Ziro Guard)",
}

var protectStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show protection settings and state",
	RunE: func(cmd *cobra.Command, args []string) error {
		fw := loadFirewallConfig()
		g := fw.Guard.withDefaults()
		active := fw.Enabled && !fw.Guard.Disabled
		bans, _ := listBans()
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"active": active, "config": g, "bans": len(bans)})
		}
		fmt.Printf("Ziro Guard:   %s\n", map[bool]string{true: "active", false: "inactive (firewall disabled or guard disabled)"}[active])
		fmt.Printf("SYN flood:    > %d new connections/s per source are dropped\n", g.SynRate)
		fmt.Printf("Conn limit:   > %d concurrent connections per source are dropped\n", g.ConnLimit)
		fmt.Printf("ICMP flood:   > %d packets/s per source are dropped\n", g.ICMPRate)
		fmt.Printf("Port scans:   > %d SYNs/min to closed ports -> ban %s\n", g.ScanRate, g.ScanBan)
		fmt.Printf("SSH:          %d failures in %s -> ban %s (doubling per repeat, max 24h)\n", g.SSHMaxFail, g.SSHWindow, g.SSHBan)
		fmt.Printf("Allowlist:    %s\n", strings.Join(append([]string{"loopback", "link-local", "cluster mesh"}, g.Allow...), ", "))
		fmt.Printf("Banned now:   %d\n", len(bans))
		return nil
	},
}

var guardSet GuardConfig

var protectSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Tune protection thresholds",
	Example: `  ziroctl security protect set --ssh-max-failures 3 --ssh-ban 2h
  ziroctl security protect set --syn-rate 500 --conn-limit 1024`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateGuard(func(g *GuardConfig) {
			fl := cmd.Flags()
			if fl.Changed("syn-rate") {
				g.SynRate = guardSet.SynRate
			}
			if fl.Changed("conn-limit") {
				g.ConnLimit = guardSet.ConnLimit
			}
			if fl.Changed("icmp-rate") {
				g.ICMPRate = guardSet.ICMPRate
			}
			if fl.Changed("scan-rate") {
				g.ScanRate = guardSet.ScanRate
			}
			if fl.Changed("scan-ban") {
				g.ScanBan = guardSet.ScanBan
			}
			if fl.Changed("ssh-max-failures") {
				g.SSHMaxFail = guardSet.SSHMaxFail
			}
			if fl.Changed("ssh-window") {
				g.SSHWindow = guardSet.SSHWindow
			}
			if fl.Changed("ssh-ban") {
				g.SSHBan = guardSet.SSHBan
			}
		})
	},
}

// updateGuard edits the guard config, validates it, saves and re-applies the firewall.
func updateGuard(edit func(*GuardConfig)) error {
	fw := loadFirewallConfig()
	edit(&fw.Guard)
	if err := fw.Guard.withDefaults().validate(); err != nil {
		return err
	}
	if err := saveFirewallConfig(fw); err != nil {
		return err
	}
	if fw.Enabled {
		if err := applyFirewallRules(fw); err != nil {
			return err
		}
	}
	fmt.Println("Protection settings saved and applied. Restart Sentinel to pick up SSH thresholds: ziroctl service restart sentinel")
	return nil
}

var protectAllowCmd = &cobra.Command{
	Use:   "allow <cidr>",
	Short: "Never ban or rate-limit a network (e.g. your office or monitoring)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := netip.ParsePrefix(args[0])
		if err != nil {
			if ip, e := netip.ParseAddr(args[0]); e == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				return fmt.Errorf("invalid CIDR %q", args[0])
			}
		}
		c := p.Masked().String()
		return updateGuard(func(g *GuardConfig) {
			for _, a := range g.Allow {
				if a == c {
					return
				}
			}
			g.Allow = append(g.Allow, c)
		})
	},
}

var protectDisallowCmd = &cobra.Command{
	Use:   "disallow <cidr>",
	Short: "Remove a network from the protection allowlist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateGuard(func(g *GuardConfig) {
			kept := g.Allow[:0]
			for _, a := range g.Allow {
				if a != args[0] {
					kept = append(kept, a)
				}
			}
			g.Allow = kept
		})
	},
}

var protectEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Ziro Guard (default)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateGuard(func(g *GuardConfig) { g.Disabled = false })
	},
}

var protectDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Ziro Guard (removes bans and flood limits)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateGuard(func(g *GuardConfig) { g.Disabled = true })
	},
}

func init() {
	bansBanCmd.Flags().DurationVar(&banFor, "for", time.Hour, "Ban duration")
	securityBansCmd.AddCommand(bansListCmd, bansBanCmd, bansUnbanCmd)
	f := protectSetCmd.Flags()
	f.IntVar(&guardSet.SynRate, "syn-rate", 0, "New TCP connections/second per source")
	f.IntVar(&guardSet.ConnLimit, "conn-limit", 0, "Concurrent connections per source")
	f.IntVar(&guardSet.ICMPRate, "icmp-rate", 0, "ICMP packets/second per source")
	f.IntVar(&guardSet.ScanRate, "scan-rate", 0, "SYNs/minute to closed ports before a ban")
	f.StringVar(&guardSet.ScanBan, "scan-ban", "", "Ban duration for port scanners (e.g. 10m)")
	f.IntVar(&guardSet.SSHMaxFail, "ssh-max-failures", 0, "Failed SSH logins before a ban")
	f.StringVar(&guardSet.SSHWindow, "ssh-window", "", "Window for counting SSH failures (e.g. 10m)")
	f.StringVar(&guardSet.SSHBan, "ssh-ban", "", "First SSH ban duration (doubles per repeat, max 24h)")
	securityProtectCmd.AddCommand(protectStatusCmd, protectSetCmd, protectAllowCmd, protectDisallowCmd, protectEnableCmd, protectDisableCmd)
	securityCmd.AddCommand(securityBansCmd, securityProtectCmd)
}

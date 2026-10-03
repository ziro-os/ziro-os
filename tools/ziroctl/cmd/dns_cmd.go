package cmd

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	dnsConfigPath    = "/etc/ziro/dns.json"
	dnsClusterPath   = "/etc/ziro/dns/cluster.json" // cluster-wide records, written by the agent
	dnsBlocklistDir  = "/var/lib/ziro/dns"
	dnsStatsPath     = "/run/ziro/dns-stats.json"
	dnsDHCPResolv    = "/run/ziro/dhcp-resolv.conf" // DHCP-provided resolvers while smart DNS is on
	dnsListenDefault = "127.0.0.53"
)

type DNSConfig struct {
	Listen     []string      `json:"listen,omitempty"`     // default 127.0.0.53
	Allow      []string      `json:"allow,omitempty"`      // client CIDRs besides loopback
	Upstreams  []DNSUpstream `json:"upstreams,omitempty"`  // empty: DHCP-provided (fallback 1.1.1.1, 9.9.9.9)
	Forwards   []DNSForward  `json:"forwards,omitempty"`   // split DNS
	Records    []DNSRecord   `json:"records,omitempty"`    // local authoritative records
	Block      []string      `json:"block,omitempty"`      // domains (and subdomains) answered NXDOMAIN
	Blocklists []string      `json:"blocklists,omitempty"` // https URLs (hosts or domain-per-line format)
	CacheSize  int           `json:"cache_size,omitempty"` // default 10000 answers
	RateLimit  int           `json:"rate_limit,omitempty"` // queries/second per client, default 200
	LogQueries bool          `json:"log_queries,omitempty"`
}

var dnsDomainRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+$`)

func validDomain(d string) bool { return len(d) <= 254 && dnsDomainRe.MatchString(fqdn(d)) }

func parseRecord(r DNSRecord) (string, localRR, error) {
	name := fqdn(r.Name)
	if !validDomain(name) {
		return "", localRR{}, fmt.Errorf("invalid record name %q", r.Name)
	}
	ttl := uint32(300)
	if r.TTL > 0 {
		ttl = uint32(min(r.TTL, 86400))
	}
	switch strings.ToUpper(r.Type) {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(r.Value)
		if err != nil || (strings.ToUpper(r.Type) == "A") != ip.Is4() {
			return "", localRR{}, fmt.Errorf("%s record %s: invalid address %q", r.Type, r.Name, r.Value)
		}
		if ip.Is4() {
			return name, localRR{dnsmessage.TypeA, ttl, &dnsmessage.AResource{A: ip.As4()}}, nil
		}
		return name, localRR{dnsmessage.TypeAAAA, ttl, &dnsmessage.AAAAResource{AAAA: ip.As16()}}, nil
	case "CNAME":
		if !validDomain(r.Value) {
			return "", localRR{}, fmt.Errorf("CNAME %s: invalid target %q", r.Name, r.Value)
		}
		return name, localRR{dnsmessage.TypeCNAME, ttl, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(fqdn(r.Value))}}, nil
	case "TXT":
		if len(r.Value) == 0 || len(r.Value) > 255 {
			return "", localRR{}, fmt.Errorf("TXT %s: value must be 1-255 bytes", r.Name)
		}
		return name, localRR{dnsmessage.TypeTXT, ttl, &dnsmessage.TXTResource{TXT: []string{r.Value}}}, nil
	}
	return "", localRR{}, fmt.Errorf("record type %q not supported (A, AAAA, CNAME, TXT)", r.Type)
}

// parseUpstreamArg: "1.1.1.1", "[2606:4700::1111]:53" or "tls://1.1.1.1#cloudflare-dns.com".
func parseUpstreamArg(s string) (DNSUpstream, error) {
	u := DNSUpstream{Addr: s}
	if rest, ok := strings.CutPrefix(s, "tls://"); ok {
		addr, name, found := strings.Cut(rest, "#")
		if !found {
			return u, fmt.Errorf("DNS-over-TLS upstream needs a certificate name: tls://%s#dns.example", rest)
		}
		u = DNSUpstream{Addr: addr, TLSName: name}
	}
	_, err := newUpstream(u)
	return u, err
}

func (c *DNSConfig) validate() error {
	for _, l := range c.Listen {
		if _, err := netip.ParseAddr(l); err != nil {
			return fmt.Errorf("invalid listen address %q", l)
		}
	}
	for _, a := range c.Allow {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("invalid allow CIDR %q", a)
		}
	}
	for _, u := range c.Upstreams {
		if _, err := newUpstream(u); err != nil {
			return err
		}
	}
	for _, f := range c.Forwards {
		if !validDomain(f.Domain) || len(f.Upstreams) == 0 {
			return fmt.Errorf("invalid forward for %q", f.Domain)
		}
		for _, u := range f.Upstreams {
			if _, err := newUpstream(u); err != nil {
				return err
			}
		}
	}
	for _, r := range c.Records {
		if _, _, err := parseRecord(r); err != nil {
			return err
		}
	}
	for _, b := range c.Block {
		if !validDomain(b) {
			return fmt.Errorf("invalid block domain %q", b)
		}
	}
	for _, u := range c.Blocklists {
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("blocklist %q must be https://", u)
		}
	}
	if c.CacheSize < 0 || c.CacheSize > 1000000 || c.RateLimit < 0 || c.RateLimit > 100000 {
		return errors.New("cache_size or rate_limit out of range")
	}
	return nil
}

func loadDNSConfig() (*DNSConfig, error) {
	c := &DNSConfig{}
	b, err := os.ReadFile(dnsConfigPath)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return c, err
	}
	return c, c.validate()
}

func saveDNSConfig(c *DNSConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(dnsConfigPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(dnsConfigPath, b, 0644)
}

// nameservers reads "nameserver" lines, skipping our own listener.
func nameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) == 2 && fl[0] == "nameserver" && fl[1] != dnsListenDefault {
			if _, err := netip.ParseAddr(fl[1]); err == nil {
				out = append(out, fl[1])
			}
		}
	}
	return out
}

func effectiveUpstreams(c *DNSConfig) []DNSUpstream {
	if len(c.Upstreams) > 0 {
		return c.Upstreams
	}
	var ups []DNSUpstream
	for _, ns := range nameservers(dnsDHCPResolv) {
		ups = append(ups, DNSUpstream{Addr: ns})
	}
	if len(ups) == 0 {
		ups = []DNSUpstream{{Addr: "1.1.1.1"}, {Addr: "9.9.9.9"}}
	}
	return ups
}

func blocklistFile(url string) string {
	h := sha256.Sum256([]byte(url))
	return filepath.Join(dnsBlocklistDir, "blocklist-"+hex.EncodeToString(h[:8])+".txt")
}

// parseBlocklist accepts hosts files ("0.0.0.0 ads.example") and domain-per-line lists.
func parseBlocklist(r io.Reader, into map[string]bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		d := f[len(f)-1]
		if d == "localhost" || d == "localhost.localdomain" {
			continue
		}
		if validDomain(d) {
			into[fqdn(d)] = true
		}
	}
}

// buildDNSServer turns a config (+ cluster records) into a server state.
func buildDNSServer(c *DNSConfig, cl clusterDNSFile) (*dnsServer, error) {
	cluster := cl.Records
	s := &dnsServer{records: map[string][]localRR{}, block: map[string]bool{}, logQ: c.LogQueries}
	pool, err := newPool(effectiveUpstreams(c))
	if err != nil {
		return nil, err
	}
	s.pool = pool
	for _, f := range c.Forwards {
		p, err := newPool(f.Upstreams)
		if err != nil {
			return nil, err
		}
		s.forwards = append(s.forwards, struct {
			suffix string
			pool   *upstreamPool
		}{fqdn(f.Domain), p})
	}
	if cl.PodDNS != "" { // <app>.cluster.ziro: the node's pod DNS responder
		if p, err := newPool([]DNSUpstream{{Addr: cl.PodDNS}}); err == nil {
			s.forwards = append(s.forwards, struct {
				suffix string
				pool   *upstreamPool
			}{meshDomain + ".", p})
		}
	}
	for _, r := range append(append([]DNSRecord{}, cluster...), c.Records...) {
		name, rr, err := parseRecord(r)
		if err != nil {
			continue // a bad cluster record must not take the resolver down
		}
		s.records[name] = append(s.records[name], rr)
	}
	for _, b := range c.Block {
		s.block[fqdn(b)] = true
	}
	for _, u := range c.Blocklists {
		if f, err := os.Open(blocklistFile(u)); err == nil {
			parseBlocklist(f, s.block)
			f.Close()
		}
	}
	for _, a := range c.Allow {
		s.allow = append(s.allow, netip.MustParsePrefix(a).Masked())
	}
	size := c.CacheSize
	if size == 0 {
		size = 10000
	}
	s.cache = newDNSCache(size)
	rate := c.RateLimit
	if rate == 0 {
		rate = 200
	}
	s.limiter = newTokenBucket(rate)
	return s, nil
}

// adopt moves a rebuilt configuration into the running server (the cache stays warm).
func (s *dnsServer) adopt(n *dnsServer) {
	s.mu.Lock()
	s.pool, s.forwards, s.records, s.block, s.allow, s.logQ = n.pool, n.forwards, n.records, n.block, n.allow, n.logQ
	s.mu.Unlock()
	s.cache.mu.Lock()
	s.cache.max = n.cache.max
	s.cache.mu.Unlock()
	s.limiter = n.limiter
}

// clusterDNSFile is what the cluster agent hands the host resolver: cluster-wide records, and
// on pod-network nodes the local pod DNS responder that answers <app>.cluster.ziro.
type clusterDNSFile struct {
	Records []DNSRecord `json:"records,omitempty"`
	PodDNS  string      `json:"pod_dns,omitempty"`
}

func loadClusterDNS() clusterDNSFile {
	var c clusterDNSFile
	if b, err := os.ReadFile(dnsClusterPath); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func loadClusterRecords() []DNSRecord { return loadClusterDNS().Records }

// writeClusterDNS is called by the agent after every heartbeat; it writes only on change (the
// resolver reloads when the file changes).
func writeClusterDNS(resp heartbeatResponse) {
	c := clusterDNSFile{Records: resp.DNSRecords}
	if resp.PodCIDR != "" {
		c.PodDNS = podGateway(resp.PodCIDR)
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if cur, err := os.ReadFile(dnsClusterPath); err == nil && string(cur) == string(b) {
		return
	}
	if len(c.Records) == 0 && c.PodDNS == "" && !fileExists(dnsClusterPath) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(dnsClusterPath), 0755); err == nil {
		_ = writeFileAtomic(dnsClusterPath, b, 0644)
	}
}

func dnsInputsStamp(c *DNSConfig) string {
	var b strings.Builder
	paths := append([]string{dnsConfigPath, dnsClusterPath, dnsDHCPResolv}, func() []string {
		var p []string
		for _, u := range c.Blocklists {
			p = append(p, blocklistFile(u))
		}
		return p
	}()...)
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", p, fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String()
}

type dnsStatsFile struct {
	Time      string            `json:"time"`
	Queries   uint64            `json:"queries"`
	CacheHits uint64            `json:"cache_hits"`
	Stale     uint64            `json:"stale"`
	Blocked   uint64            `json:"blocked"`
	Local     uint64            `json:"local"`
	Forwarded uint64            `json:"forwarded"`
	Failed    uint64            `json:"failed"`
	Refused   uint64            `json:"refused"`
	Limited   uint64            `json:"rate_limited"`
	Upstreams []dnsUpstreamStat `json:"upstreams"`
}

type dnsUpstreamStat struct {
	Addr    string  `json:"addr"`
	TLS     bool    `json:"tls"`
	RTTms   float64 `json:"rtt_ms"`
	Queries uint64  `json:"queries"`
	Errors  uint64  `json:"errors"`
	Healthy bool    `json:"healthy"`
}

func (s *dnsServer) snapshot() dnsStatsFile {
	st := dnsStatsFile{Time: time.Now().UTC().Format(time.RFC3339), Queries: s.stats.Queries.Load(),
		CacheHits: s.stats.CacheHits.Load(), Stale: s.stats.Stale.Load(), Blocked: s.stats.Blocked.Load(),
		Local: s.stats.Local.Load(), Forwarded: s.stats.Forwarded.Load(), Failed: s.stats.Failed.Load(),
		Refused: s.stats.Refused.Load(), Limited: s.stats.RateLimited.Load()}
	s.mu.RLock()
	pools := []*upstreamPool{s.pool}
	for _, f := range s.forwards {
		pools = append(pools, f.pool)
	}
	s.mu.RUnlock()
	now := time.Now()
	for _, p := range pools {
		p.mu.Lock()
		for _, u := range p.ups {
			st.Upstreams = append(st.Upstreams, dnsUpstreamStat{Addr: u.addr, TLS: u.cfg.TLSName != "", RTTms: u.ewma,
				Queries: u.queries.Load(), Errors: u.errors.Load(), Healthy: !now.Before(u.downUntil)})
		}
		p.mu.Unlock()
	}
	return st
}

func runDNSServer() error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	s, err := buildDNSServer(cfg, loadClusterDNS())
	if err != nil {
		return err
	}
	listen := cfg.Listen
	if len(listen) == 0 {
		listen = []string{dnsListenDefault}
	}
	for _, l := range listen {
		addr := net.JoinHostPort(l, "53")
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go s.serveUDP(pc)
		go s.serveTCP(ln)
	}
	fmt.Printf("🧭 Ziro DNS listening on %s (upstreams: %d, forwards: %d, records: %d, blocked: %d)\n",
		strings.Join(listen, ", "), len(effectiveUpstreams(cfg)), len(cfg.Forwards), len(s.records), len(s.block))
	stamp := dnsInputsStamp(cfg)
	_ = os.MkdirAll(filepath.Dir(dnsStatsPath), 0755)
	for i := 0; ; i++ {
		time.Sleep(2 * time.Second)
		if cur := dnsInputsStamp(cfg); cur != stamp {
			if nc, err := loadDNSConfig(); err == nil {
				if ns, err := buildDNSServer(nc, loadClusterDNS()); err == nil {
					s.adopt(ns)
					cfg, stamp = nc, dnsInputsStamp(nc)
					fmt.Printf("[dns] configuration reloaded (records: %d, blocked: %d)\n", len(ns.records), len(ns.block))
				} else {
					fmt.Printf("[dns] reload rejected: %v\n", err)
				}
			}
		}
		if i%5 == 0 {
			if b, err := json.Marshal(s.snapshot()); err == nil {
				_ = writeFileAtomic(dnsStatsPath, b, 0644)
			}
		}
	}
}

// ---- enabling: point the host at 127.0.0.53, DHCP resolvers become upstreams ----

const dnsPinMarker = "# Managed by `ziroctl dns`: DHCP resolvers feed the smart DNS upstreams"

func dnsEnabled() bool {
	b, err := os.ReadFile(resolvPinned)
	return err == nil && strings.Contains(string(b), dnsPinMarker)
}

var dnsService = ServiceDef{Name: "dns", Description: "Ziro smart DNS resolver (127.0.0.53)", Exec: "/usr/bin/ziroctl",
	Args: "dns serve", PIDFile: "/run/ziro-dns.pid", LogFile: "/var/log/dns.log", Autostart: true}

func dnsServiceConf() string { return supervisedConf(dnsService) }

// waitDNS waits until 127.0.0.53 answers a query.
func waitDNS(timeout time.Duration) error {
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("localhost."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, _ := q.Pack()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		c, err := net.DialTimeout("udp", net.JoinHostPort(dnsListenDefault, "53"), time.Second)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 512)
		if _, err := c.Write(raw); err == nil {
			if n, err := c.Read(buf); err == nil && n >= 12 {
				c.Close()
				return nil
			}
		}
		c.Close()
	}
	return errors.New("smart DNS did not answer on 127.0.0.53")
}

func enableDNS() error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Resolvers pinned with `network dns` become the upstreams.
	if len(cfg.Upstreams) == 0 && fileExists(resolvPinned) && !dnsEnabled() {
		for _, ns := range nameservers(resolvPath) {
			cfg.Upstreams = append(cfg.Upstreams, DNSUpstream{Addr: ns})
		}
	}
	if err := saveDNSConfig(cfg); err != nil {
		return err
	}
	// Until the next DHCP renewal, today's resolvers are the DHCP ones.
	if !fileExists(dnsDHCPResolv) {
		if b, err := os.ReadFile(resolvPath); err == nil {
			_ = os.MkdirAll(filepath.Dir(dnsDHCPResolv), 0755)
			_ = os.WriteFile(dnsDHCPResolv, b, 0644)
		}
	}
	if err := writeFileAtomic(filepath.Join(servicesDir, "dns.conf"), []byte(dnsServiceConf()), 0644); err != nil {
		return err
	}
	if err := startService("dns"); err != nil && !strings.Contains(err.Error(), "already running") {
		return err
	}
	if err := waitDNS(10 * time.Second); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(resolvPinned), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(resolvPinned, []byte(dnsPinMarker+"\nRESOLV_CONF="+dnsDHCPResolv+"\n"), 0644); err != nil {
		return err
	}
	return writeFileAtomic(resolvPath, []byte("# Managed by `ziroctl dns` (smart DNS on 127.0.0.53)\nnameserver "+dnsListenDefault+"\noptions edns0 timeout:2 attempts:2\n"), 0644)
}

func disableDNS() error {
	if !dnsEnabled() {
		return errors.New("smart DNS is not enabled")
	}
	// Restore resolvers first, so the host never points at a stopped listener.
	servers := nameservers(dnsDHCPResolv)
	if cfg, err := loadDNSConfig(); err == nil && len(cfg.Upstreams) > 0 {
		servers = nil
		for _, u := range cfg.Upstreams {
			if u.TLSName == "" {
				host, _, err := net.SplitHostPort(u.Addr)
				if err != nil {
					host = u.Addr
				}
				servers = append(servers, host)
			}
		}
	}
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "9.9.9.9"}
	}
	var b strings.Builder
	b.WriteString("# Restored by `ziroctl dns disable`\n")
	for i, s := range servers {
		if i < 3 {
			b.WriteString("nameserver " + s + "\n")
		}
	}
	if err := writeFileAtomic(resolvPath, []byte(b.String()), 0644); err != nil {
		return err
	}
	_ = os.Remove(resolvPinned)
	_ = stopService("dns")
	return os.Remove(filepath.Join(servicesDir, "dns.conf"))
}

// updateBlocklists downloads every configured list (HTTPS, verified, size-capped).
func updateBlocklists(cfg *DNSConfig) error {
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}
	if err := os.MkdirAll(dnsBlocklistDir, 0755); err != nil {
		return err
	}
	var errs []string
	for _, u := range cfg.Blocklists {
		resp, err := client.Get(u)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Sprintf("%s: %s", u, resp.Status))
			continue
		}
		n := map[string]bool{}
		parseBlocklist(strings.NewReader(string(body)), n)
		if len(n) == 0 {
			errs = append(errs, u+": no domains found (keeping the previous copy)")
			continue
		}
		if err := writeFileAtomic(blocklistFile(u), body, 0644); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		fmt.Printf("✓ %s: %d domains\n", u, len(n))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ---- CLI ----

var (
	dnsRecordTTL int
)

func editDNS(edit func(*DNSConfig) error) error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := edit(cfg); err != nil {
		return err
	}
	if err := saveDNSConfig(cfg); err != nil {
		return err
	}
	if dnsEnabled() {
		fmt.Println("✓ Saved; the running resolver reloads within 2s")
	} else {
		fmt.Println("✓ Saved. Turn the resolver on with: ziroctl dns enable")
	}
	return nil
}

// addDNSRecord normalizes and validates a local record and adds it (CLI and API).
func addDNSRecord(c *DNSConfig, r DNSRecord) error {
	r.Name, r.Type = strings.TrimSuffix(strings.ToLower(r.Name), "."), strings.ToUpper(r.Type)
	if _, _, err := parseRecord(r); err != nil {
		return err
	}
	c.Records = append(c.Records, r)
	return nil
}

// removeDNSRecords removes the records named name (of type typ, or every type when empty).
func removeDNSRecords(c *DNSConfig, name, typ string) error {
	kept := c.Records[:0]
	for _, r := range c.Records {
		if fqdn(r.Name) == fqdn(name) && (typ == "" || strings.EqualFold(r.Type, typ)) {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == len(c.Records) {
		return errNotFound("no record " + name)
	}
	c.Records = kept
	return nil
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Run the caching resolver with split DNS and blocklists",
	Example: `  ziroctl dns enable
  ziroctl dns forward add corp.example 10.0.0.53
  ziroctl dns status`,
}

var dnsEnableCmd = &cobra.Command{
	Use:     "enable",
	Short:   "Start the resolver and point the host at it",
	Example: `  ziroctl dns enable`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := enableDNS(); err != nil {
			return err
		}
		fmt.Println("✅ Smart DNS enabled: /etc/resolv.conf -> 127.0.0.53 (upstreams: DHCP or `ziroctl dns upstream`)")
		return nil
	},
}

var dnsDisableCmd = &cobra.Command{
	Use:     "disable",
	Short:   "Stop the resolver and restore plain resolvers",
	Example: `  ziroctl dns disable`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := disableDNS(); err != nil {
			return err
		}
		fmt.Println("✅ Smart DNS disabled; resolv.conf restored")
		return nil
	},
}

var dnsServeCmd = &cobra.Command{
	Use:    "serve",
	Hidden: true,
	Short:  "Run the resolver (the dns service)",
	RunE:   func(cmd *cobra.Command, args []string) error { return runDNSServer() },
}

var dnsStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show the resolver, cache and upstream health",
	Example: `  ziroctl dns status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := loadDNSConfig()
		var st dnsStatsFile
		b, err := os.ReadFile(dnsStatsPath)
		if err == nil {
			_ = json.Unmarshal(b, &st)
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"enabled": dnsEnabled(), "config": cfg, "stats": st})
		}
		fmt.Printf("Smart DNS:  %s\n", map[bool]string{true: "enabled (127.0.0.53)", false: "disabled"}[dnsEnabled()])
		if err != nil {
			return nil
		}
		hit := 0.0
		if st.Queries > 0 {
			hit = 100 * float64(st.CacheHits) / float64(st.Queries)
		}
		fmt.Printf("Queries:    %d (cache hits %.0f%%, local %d, blocked %d, stale %d, failed %d, refused %d, rate-limited %d)\n",
			st.Queries, hit, st.Local, st.Blocked, st.Stale, st.Failed, st.Refused, st.Limited)
		fmt.Printf("%-28s %-5s %-9s %-8s %-7s %s\n", "UPSTREAM", "TLS", "RTT(ms)", "QUERIES", "ERRORS", "HEALTHY")
		for _, u := range st.Upstreams {
			fmt.Printf("%-28s %-5v %-9.1f %-8d %-7d %v\n", u.Addr, u.TLS, u.RTTms, u.Queries, u.Errors, u.Healthy)
		}
		return nil
	},
}

var dnsUpstreamCmd = &cobra.Command{
	Use:   "upstream <auto | server...>",
	Short: "Set the upstream resolvers",
	Example: `  ziroctl dns upstream tls://1.1.1.1#cloudflare-dns.com tls://9.9.9.9#dns.quad9.net
  ziroctl dns upstream 10.0.0.2 10.0.0.3
  ziroctl dns upstream auto`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			if len(args) == 1 && args[0] == "auto" {
				c.Upstreams = nil
				return nil
			}
			c.Upstreams = nil
			for _, a := range args {
				u, err := parseUpstreamArg(a)
				if err != nil {
					return err
				}
				c.Upstreams = append(c.Upstreams, u)
			}
			return nil
		})
	},
}

var dnsForwardCmd = &cobra.Command{Use: "forward", Short: "Send a domain to specific resolvers", Example: "  ziroctl dns forward add corp.example 10.0.0.53\n  ziroctl dns forward remove corp.example"}

var dnsForwardAddCmd = &cobra.Command{
	Use:     "add <domain> <server...>",
	Short:   "Forward a domain and its subdomains",
	Example: `  ziroctl dns forward add corp.example 10.0.0.2 10.0.0.3`,
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			f := DNSForward{Domain: strings.TrimSuffix(strings.ToLower(args[0]), ".")}
			for _, a := range args[1:] {
				u, err := parseUpstreamArg(a)
				if err != nil {
					return err
				}
				f.Upstreams = append(f.Upstreams, u)
			}
			kept := c.Forwards[:0]
			for _, x := range c.Forwards {
				if fqdn(x.Domain) != fqdn(f.Domain) {
					kept = append(kept, x)
				}
			}
			c.Forwards = append(kept, f)
			return nil
		})
	},
}

var dnsForwardRmCmd = &cobra.Command{
	Use:     "remove <domain>",
	Short:   "Remove a forward rule",
	Example: `  ziroctl dns forward remove corp.example`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			kept := c.Forwards[:0]
			for _, x := range c.Forwards {
				if fqdn(x.Domain) != fqdn(args[0]) {
					kept = append(kept, x)
				}
			}
			if len(kept) == len(c.Forwards) {
				return fmt.Errorf("no forward for %s", args[0])
			}
			c.Forwards = kept
			return nil
		})
	},
}

var dnsRecordCmd = &cobra.Command{Use: "record", Short: "Manage local A, AAAA, CNAME and TXT records", Example: "  ziroctl dns record add nas.lan A 192.168.1.20\n  ziroctl dns record list"}

var dnsRecordAddCmd = &cobra.Command{
	Use:     "add <name> <type> <value>",
	Short:   "Add a local record",
	Example: `  ziroctl dns record add db.internal A 10.0.0.20 --ttl 60`,
	Args:    cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			return addDNSRecord(c, DNSRecord{Name: args[0], Type: args[1], Value: args[2], TTL: dnsRecordTTL})
		})
	},
}

var dnsRecordRmCmd = &cobra.Command{
	Use:   "remove <name> [type]",
	Short: "Remove local records by name and type",
	Example: `  ziroctl dns record remove nas.lan
  ziroctl dns record remove nas.lan A`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		typ := ""
		if len(args) == 2 {
			typ = args[1]
		}
		return editDNS(func(c *DNSConfig) error { return removeDNSRecords(c, args[0], typ) })
	},
}

var dnsRecordListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List local and cluster records",
	Example: `  ziroctl dns record list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := loadDNSConfig()
		cl := loadClusterRecords()
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"local": cfg.Records, "cluster": cl})
		}
		fmt.Printf("%-36s %-6s %-6s %-8s %s\n", "NAME", "TYPE", "TTL", "SOURCE", "VALUE")
		for src, rs := range map[string][]DNSRecord{"local": cfg.Records, "cluster": cl} {
			for _, r := range rs {
				fmt.Printf("%-36s %-6s %-6d %-8s %s\n", r.Name, r.Type, r.TTL, src, r.Value)
			}
		}
		return nil
	},
}

var dnsBlockCmd = &cobra.Command{Use: "block", Short: "Block domains", Example: "  ziroctl dns block add ads.example.com\n  ziroctl dns block remove ads.example.com"}

var dnsBlockAddCmd = &cobra.Command{
	Use:     "add <domain...>",
	Short:   "Block domains and their subdomains",
	Example: `  ziroctl dns block add ads.example.com tracker.example.net`,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			for _, d := range args {
				d = strings.TrimSuffix(strings.ToLower(d), ".")
				if !validDomain(d) {
					return fmt.Errorf("invalid domain %q", d)
				}
				c.Block = append(c.Block, d)
			}
			return nil
		})
	},
}

var dnsBlockRmCmd = &cobra.Command{
	Use:     "remove <domain...>",
	Short:   "Unblock domains",
	Example: `  ziroctl dns block remove ads.example.com`,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editDNS(func(c *DNSConfig) error {
			drop := map[string]bool{}
			for _, d := range args {
				drop[fqdn(d)] = true
			}
			kept := c.Block[:0]
			for _, b := range c.Block {
				if !drop[fqdn(b)] {
					kept = append(kept, b)
				}
			}
			c.Block = kept
			return nil
		})
	},
}

var dnsBlocklistCmd = &cobra.Command{Use: "blocklist", Short: "Subscribe to blocklists over HTTPS", Example: "  ziroctl dns blocklist add https://big.oisd.nl/domainswild\n  ziroctl dns blocklist update"}

var dnsBlocklistAddCmd = &cobra.Command{
	Use:     "add <https-url>",
	Short:   "Subscribe to a blocklist, refreshed daily",
	Example: `  ziroctl dns blocklist add https://big.oisd.nl/domainswild`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := editDNS(func(c *DNSConfig) error {
			for _, u := range c.Blocklists {
				if u == args[0] {
					return nil
				}
			}
			c.Blocklists = append(c.Blocklists, args[0])
			return nil
		}); err != nil {
			return err
		}
		cfg, _ := loadDNSConfig()
		return updateBlocklists(&DNSConfig{Blocklists: []string{args[0]}, CacheSize: cfg.CacheSize})
	},
}

var dnsBlocklistRmCmd = &cobra.Command{
	Use:     "remove <https-url>",
	Short:   "Unsubscribe from a blocklist",
	Example: `  ziroctl dns blocklist remove https://big.oisd.nl/domainswild`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = os.Remove(blocklistFile(args[0]))
		return editDNS(func(c *DNSConfig) error {
			kept := c.Blocklists[:0]
			for _, u := range c.Blocklists {
				if u != args[0] {
					kept = append(kept, u)
				}
			}
			c.Blocklists = kept
			return nil
		})
	},
}

var dnsBlocklistUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Download every subscribed blocklist now",
	Example: `  ziroctl dns blocklist update`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadDNSConfig()
		if err != nil {
			return err
		}
		return updateBlocklists(cfg)
	},
}

func init() {
	dnsRecordAddCmd.Flags().IntVar(&dnsRecordTTL, "ttl", 300, "TTL in seconds")
	dnsForwardCmd.AddCommand(dnsForwardAddCmd, dnsForwardRmCmd)
	dnsRecordCmd.AddCommand(dnsRecordAddCmd, dnsRecordRmCmd, dnsRecordListCmd)
	dnsBlockCmd.AddCommand(dnsBlockAddCmd, dnsBlockRmCmd)
	dnsBlocklistCmd.AddCommand(dnsBlocklistAddCmd, dnsBlocklistRmCmd, dnsBlocklistUpdateCmd)
	dnsCmd.AddCommand(dnsEnableCmd, dnsDisableCmd, dnsServeCmd, dnsStatusCmd, dnsUpstreamCmd, dnsForwardCmd,
		dnsRecordCmd, dnsBlockCmd, dnsBlocklistCmd)
	rootCmd.AddCommand(dnsCmd)
}

// setDNSUpstreamsFromResolvers is `network dns` while smart DNS runs: servers become its
// upstreams (nil: from DHCP again); resolv.conf keeps pointing at 127.0.0.53, with the search list.
func setDNSUpstreamsFromResolvers(servers, search []string) error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	cfg.Upstreams = nil
	for _, sv := range servers {
		if _, err := netip.ParseAddr(sv); err != nil {
			return fmt.Errorf("invalid nameserver %q", sv)
		}
		cfg.Upstreams = append(cfg.Upstreams, DNSUpstream{Addr: sv})
	}
	if err := saveDNSConfig(cfg); err != nil {
		return err
	}
	content := "# Managed by `ziroctl dns` (smart DNS on 127.0.0.53)\n"
	if len(search) > 0 {
		for _, d := range search {
			if validHostname(strings.ToLower(d)) != nil {
				return fmt.Errorf("invalid search domain %q", d)
			}
		}
		content += "search " + strings.Join(search, " ") + "\n"
	}
	content += "nameserver " + dnsListenDefault + "\noptions edns0 timeout:2 attempts:2\n"
	return writeFileAtomic(resolvPath, []byte(content), 0644)
}

// ---- cluster-wide records (master) ----

var clusterDNSCmd = &cobra.Command{Use: "dns", Short: "Manage DNS records every node resolves", Example: "  ziroctl cluster dns add db.internal A 10.200.0.5\n  ziroctl cluster dns ls"}

var clusterDNSRecordAddCmd = &cobra.Command{
	Use:     "add <name> <type> <value>",
	Short:   "Add a record every node resolves",
	Example: `  ziroctl cluster dns add registry.internal A 10.0.0.40`,
	Args:    cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		r := DNSRecord{Name: strings.TrimSuffix(strings.ToLower(args[0]), "."), Type: strings.ToUpper(args[1]), Value: args[2], TTL: dnsRecordTTL}
		if _, _, err := parseRecord(r); err != nil {
			return err
		}
		if strings.HasSuffix(fqdn(r.Name), "."+meshDomain+".") {
			return fmt.Errorf("%s is reserved for app discovery", meshDomain)
		}
		return withState(func(st *ClusterState) error {
			if len(st.DNSRecords) >= 1000 {
				return errors.New("too many cluster records (max 1000)")
			}
			st.DNSRecords = append(st.DNSRecords, r)
			fmt.Printf("✓ %s %s %s (nodes pick it up on their next heartbeat)\n", r.Name, r.Type, r.Value)
			return nil
		})
	},
}

var clusterDNSRecordRmCmd = &cobra.Command{
	Use:   "rm <name> [type]",
	Short: "Remove cluster DNS records by name and type",
	Example: `  ziroctl cluster dns rm db.internal
  ziroctl cluster dns rm db.internal A`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			kept := st.DNSRecords[:0]
			for _, r := range st.DNSRecords {
				if fqdn(r.Name) == fqdn(args[0]) && (len(args) == 1 || strings.EqualFold(r.Type, args[1])) {
					continue
				}
				kept = append(kept, r)
			}
			if len(kept) == len(st.DNSRecords) {
				return fmt.Errorf("no cluster record %s", args[0])
			}
			st.DNSRecords = kept
			return nil
		})
	},
}

var clusterDNSRecordLsCmd = &cobra.Command{
	Use: "ls", Short: "List cluster DNS records", Example: "  ziroctl cluster dns ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		return printResult(st.DNSRecords, func() {
			for _, r := range st.DNSRecords {
				fmt.Printf("%-36s %-6s %s\n", r.Name, r.Type, r.Value)
			}
		})
	},
}

func init() {
	clusterDNSRecordAddCmd.Flags().IntVar(&dnsRecordTTL, "ttl", 300, "TTL in seconds")
	clusterDNSCmd.AddCommand(clusterDNSRecordAddCmd, clusterDNSRecordRmCmd, clusterDNSRecordLsCmd)
	clusterCmd.AddCommand(clusterDNSCmd)
}

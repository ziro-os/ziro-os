package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- address sets ----

func TestCIDRSetAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 13))
	var list []string
	var prefixes []netip.Prefix
	for i := 0; i < 400; i++ {
		var p netip.Prefix
		switch rng.IntN(3) {
		case 0:
			a := netip.AddrFrom4([4]byte{byte(rng.IntN(4) + 10), byte(rng.IntN(4)), byte(rng.IntN(256)), byte(rng.IntN(256))})
			p = netip.PrefixFrom(a, 8+rng.IntN(25)).Masked()
		case 1:
			var b [16]byte
			b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, byte(rng.IntN(3))
			b[7], b[15] = byte(rng.IntN(256)), byte(rng.IntN(256))
			p = netip.PrefixFrom(netip.AddrFrom16(b), 32+rng.IntN(97)).Masked()
		default:
			a := netip.AddrFrom4([4]byte{192, 168, byte(rng.IntN(256)), byte(rng.IntN(256))})
			p = netip.PrefixFrom(a, 32)
		}
		prefixes = append(prefixes, p)
		list = append(list, p.String())
	}
	set, err := newCIDRSet(list)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		var a netip.Addr
		if rng.IntN(2) == 0 {
			a = netip.AddrFrom4([4]byte{byte(rng.IntN(4) + 10), byte(rng.IntN(4)), byte(rng.IntN(256)), byte(rng.IntN(256))})
		} else {
			var b [16]byte
			b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, byte(rng.IntN(3))
			b[7], b[15] = byte(rng.IntN(256)), byte(rng.IntN(256))
			a = netip.AddrFrom16(b)
		}
		want := false
		for _, p := range prefixes {
			want = want || p.Contains(a)
		}
		if set.contains(a) != want {
			t.Fatalf("contains(%s) = %v, want %v", a, !want, want)
		}
	}
	if set.size() >= len(list) {
		t.Errorf("ranges were not merged: %d of %d", set.size(), len(list))
	}
}

func TestCIDRSetEdges(t *testing.T) {
	all, _ := newCIDRSet([]string{"0.0.0.0/0"})
	if !all.contains(netip.MustParseAddr("255.255.255.255")) || !all.contains(netip.MustParseAddr("0.0.0.0")) || !all.contains(netip.MustParseAddr("::ffff:1.2.3.4")) {
		t.Error("0.0.0.0/0 matches every IPv4 address, mapped ones included")
	}
	if all.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("an IPv4 set must not match IPv6")
	}
	v6, _ := newCIDRSet([]string{"::/0", "::ffff:10.0.0.0/104"})
	if !v6.contains(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) || !v6.contains(netip.MustParseAddr("10.9.9.9")) {
		t.Error("::/0 and a mapped network")
	}
	adj, _ := newCIDRSet([]string{"10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24", "255.255.255.255"})
	if adj.size() != 2 || !adj.contains(netip.MustParseAddr("10.0.1.255")) || adj.contains(netip.MustParseAddr("10.0.2.0")) || !adj.contains(netip.MustParseAddr("255.255.255.255")) {
		t.Errorf("adjacent ranges: %d", adj.size())
	}
	if _, err := newCIDRSet([]string{"not-a-network"}); err == nil {
		t.Error("garbage accepted")
	}
	var none *cidrSet
	if none.contains(netip.MustParseAddr("1.2.3.4")) || none.containsIP("1.2.3.4") {
		t.Error("a nil set is empty")
	}
}

func BenchmarkCIDRSetLookup(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 1))
	list := make([]string, 100000)
	for i := range list {
		list[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(rng.IntN(224)), byte(rng.IntN(256)), byte(rng.IntN(256)), 0}), 24).String()
	}
	set, _ := newCIDRSet(list)
	addrs := make([]netip.Addr, 1024)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{byte(rng.IntN(224)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.contains(addrs[i&1023])
	}
}

// ---- bans ----

func TestGatewayBanEscalation(t *testing.T) {
	var tab gwBanTable
	pol := newAutoBan(&GatewayAutoBan{Strikes: 3, Window: "1m", Duration: "10m", Max: "30m"})
	a := netip.MustParseAddr("203.0.113.5")
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2; i++ {
		if banned, _ := tab.strike(a, now, pol, "t"); banned {
			t.Fatal("banned before the third strike")
		}
	}
	if tab.banned(a, now.UnixNano()) {
		t.Fatal("banned too early")
	}
	banned, until := tab.strike(a, now, pol, "t")
	if !banned || until.Sub(now) != 10*time.Minute {
		t.Fatalf("first ban: %v %v", banned, until.Sub(now))
	}
	if !tab.banned(a, now.Add(9*time.Minute).UnixNano()) || tab.banned(a, now.Add(11*time.Minute).UnixNano()) {
		t.Fatal("ban window")
	}
	// A repeat offender is banned for twice as long, up to the maximum.
	later := now.Add(12 * time.Minute)
	for _, want := range []time.Duration{20 * time.Minute, 30 * time.Minute, 30 * time.Minute} {
		var got time.Duration
		for i := 0; i < 3; i++ {
			if b, u := tab.strike(a, later, pol, "t"); b {
				got = u.Sub(later)
			}
		}
		if got != want {
			t.Fatalf("repeat ban lasted %v, want %v", got, want)
		}
		later = later.Add(got + time.Second)
	}
	// Strikes outside the window do not add up.
	b := netip.MustParseAddr("203.0.113.6")
	for i := 0; i < 5; i++ {
		if ok, _ := tab.strike(b, now.Add(time.Duration(i)*2*time.Minute), pol, "t"); ok {
			t.Fatal("slow strikes must not ban")
		}
	}
	if !tab.unban(a) || tab.banned(a, later.UnixNano()-1) || tab.unban(a) {
		t.Fatal("unban")
	}
	tab.sweep(later.Add(48 * time.Hour))
	if tab.active.Load() != 0 || len(tab.list(later)) != 0 {
		t.Fatal("sweep left bans")
	}
}

func TestBanTableConcurrentAndBounded(t *testing.T) {
	var tab gwBanTable
	pol := newAutoBan(&GatewayAutoBan{Strikes: 1})
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 5000; i++ {
				a := netip.AddrFrom4([4]byte{10, byte(w), byte(i >> 8), byte(i)})
				tab.strike(a, time.Now(), pol, "x")
				tab.banned(a, time.Now().UnixNano())
			}
		}()
	}
	for w := 0; w < 4; w++ {
		<-done
	}
	if n := tab.active.Load(); n <= 0 || n > banShards*banCapPerShard {
		t.Fatalf("%d bans tracked", n)
	}
	if got := len(tab.list(time.Now())); int64(got) != tab.active.Load() {
		t.Fatalf("list has %d bans, counter %d", got, tab.active.Load())
	}
}

// ---- the firewall in the request path ----

type fwReq struct {
	method, target, body, ct, ip string
	hdr                          map[string]string
}

func fwDo(h http.Handler, r fwReq) *httptest.ResponseRecorder {
	method := r.method
	if method == "" {
		method = "GET"
	}
	req := httptest.NewRequest(method, "http://w.test"+r.target, strings.NewReader(r.body))
	if r.body == "" {
		req = httptest.NewRequest(method, "http://w.test"+r.target, nil)
	}
	if r.ct != "" {
		req.Header.Set("Content-Type", r.ct)
	}
	for k, v := range r.hdr {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = r.ip
	if r.ip == "" {
		req.RemoteAddr = "198.51.100.10:4000"
	} else if !strings.Contains(r.ip, ":") || strings.Count(r.ip, ":") == 0 {
		req.RemoteAddr = r.ip + ":4000"
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func fwServer(t testing.TB, set GatewaySettings, routes ...GatewayRouteState) *gatewayServer {
	t.Helper()
	g := newGatewayServer()
	g.log = func(any) {}
	if err := g.load(&GatewayConfig{Settings: set, Routes: routes}); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGatewayWAFBlocksAndPasses(t *testing.T) {
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok %s %d", r.URL.Path, len(b))
	})
	g := fwServer(t, GatewaySettings{}, rs(GatewayRoute{Name: "w", Hosts: []string{"w.test"}, WAF: &GatewayWAF{Mode: "block"}}, up))
	var logbuf gwLogBuffer
	g.alog = newAccessLog(&logbuf, &g.metrics.logDropped)
	h := g.handler(false)

	if w := fwDo(h, fwReq{target: "/shop?id=1+union+select+password+from+users"}); w.Code != 403 || strings.Contains(body(w), "union") {
		t.Fatalf("SQL injection: %d %q", w.Code, body(w))
	}
	if w := fwDo(h, fwReq{target: "/shop?q=blue+shoes&page=2"}); w.Code != 200 {
		t.Fatalf("clean request: %d %q", w.Code, body(w))
	}
	if w := fwDo(h, fwReq{method: "POST", target: "/c", ct: "application/json", body: `{"c":"<script>alert(1)</script>"}`}); w.Code != 403 {
		t.Fatalf("XSS in a JSON body: %d", w.Code)
	}
	// A clean body reaches the upstream whole, however large.
	big := `{"data":"` + strings.Repeat("x", 100_000) + `"}`
	w := fwDo(h, fwReq{method: "POST", target: "/upload", ct: "application/json", body: big})
	if w.Code != 200 || body(w) != fmt.Sprintf("ok /upload %d", len(big)) {
		t.Fatalf("a large clean body: %d %q", w.Code, body(w))
	}
	if w := fwDo(h, fwReq{target: "/", hdr: map[string]string{"User-Agent": "${jndi:ldap://x.example/a}"}}); w.Code != 403 {
		t.Fatalf("Log4Shell in a header: %d", w.Code)
	}
	if w := fwDo(h, fwReq{target: "/", hdr: map[string]string{"X-Request-ID": "caller-supplied-id"}, ip: "10.0.0.9", body: ""}); w.Header().Get("X-Request-ID") != "caller-supplied-id" {
		t.Errorf("request ID lost: %v", w.Header())
	}

	g.alog.close()
	if !strings.Contains(logbuf.String(), `"waf":"block:ZW-942100`) {
		t.Errorf("the access log must name the rule:\n%s", logbuf.String())
	}
	m := g.metricsText()
	for _, want := range []string{`zirogate_waf_matches_total{route="w",group="sqli",action="block"} 1`,
		`zirogate_waf_matches_total{route="w",group="xss",action="block"} 1`, `zirogate_denied_total{route="w",reason="waf"} 3`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestGatewayWAFDetectModeOnlyObserves(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := fwServer(t, GatewaySettings{WAF: &GatewayWAF{Mode: "detect"}}, rs(GatewayRoute{Name: "w", Hosts: []string{"w.test"}}, up))
	if w := fwDo(g.handler(false), fwReq{target: "/?q=<script>alert(1)</script>"}); w.Code != 200 {
		t.Fatalf("detect mode blocked: %d", w.Code)
	}
	if !strings.Contains(g.metricsText(), `zirogate_waf_matches_total{route="w",group="xss",action="detect"} 1`) {
		t.Errorf("detection not counted:\n%s", g.metricsText())
	}
}

func TestGatewayWAFDefaultAndOverride(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	def := &GatewayWAF{Mode: "block"}
	g := fwServer(t, GatewaySettings{WAF: def},
		rs(GatewayRoute{Name: "inherits", Hosts: []string{"a.test"}}, up),
		rs(GatewayRoute{Name: "off", Hosts: []string{"b.test"}, WAF: &GatewayWAF{Mode: "off"}}, up),
		rs(GatewayRoute{Name: "lenient", Hosts: []string{"c.test"}, WAF: &GatewayWAF{Mode: "block", Exclude: []string{"xss"}}}, up))
	h := g.handler(false)
	attack := "/?q=<script>alert(1)</script>"
	for host, want := range map[string]int{"a.test": 403, "b.test": 200, "c.test": 200} {
		r := httptest.NewRequest("GET", "http://"+host+attack, nil)
		r.RemoteAddr = "198.51.100.10:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", host, w.Code, want)
		}
	}
	// Changing the default applies without rebuilding the routes.
	r1 := g.routeNamed("inherits")
	cfg := g.tbl.Load().cfg
	cfg.Settings.WAF = &GatewayWAF{Mode: "off"}
	if err := g.load(cfg); err != nil {
		t.Fatal(err)
	}
	if g.routeNamed("inherits") != r1 {
		t.Error("a settings change rebuilt an unchanged route")
	}
	r := httptest.NewRequest("GET", "http://a.test"+attack, nil)
	r.RemoteAddr = "198.51.100.10:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("default turned off: %d", w.Code)
	}
}

func TestGatewayDenyListsAndManualBans(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	g := fwServer(t, GatewaySettings{
		DenyCIDRs: []string{"192.0.2.0/24", "2001:db8:bad::/48"},
		Bans:      []GatewayBan{{Addr: "198.51.100.77"}, {Addr: "203.0.113.0/24", Until: future}, {Addr: "100.64.0.0/10", Until: past}},
	}, rs(GatewayRoute{Name: "r", Hosts: []string{"w.test"}, AllowCIDRs: []string{"10.0.0.0/8", "198.18.0.0/15"}, DenyCIDRs: []string{"10.66.0.0/16"}}, up))
	h := g.handler(false)
	for ip, want := range map[string]int{
		"10.1.2.3": 200, "10.66.1.1": 403, // route deny wins over the route's allow list
		"192.0.2.9": 403, "[2001:db8:bad::1]": 403, // global deny
		"198.51.100.77": 403, "203.0.113.50": 403, // manual bans
		"198.18.0.5":  200,
		"100.64.1.1":  403, // expired ban no longer applies, but this address is outside the allow list
		"203.0.114.1": 403, // not on any list, outside the allow list
	} {
		r := httptest.NewRequest("GET", "http://w.test/", nil)
		r.RemoteAddr = ip + ":1"
		if strings.HasPrefix(ip, "[") {
			r.RemoteAddr = ip + ":1"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", ip, w.Code, want)
		}
	}
	m := g.metricsText()
	for _, want := range []string{`reason="deny"`, `reason="ban"`, `reason="acl"`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestGatewayAutoBan(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := fwServer(t, GatewaySettings{TrustedProxies: []string{"10.0.0.0/8"}, AutoBan: &GatewayAutoBan{Strikes: 3, Duration: "10m", Kernel: true}},
		rs(GatewayRoute{Name: "w", Hosts: []string{"w.test"}, WAF: &GatewayWAF{Mode: "block"}}, up))
	var kernel atomic.Int32
	var kernelAddr atomic.Value
	g.kernelBan = func(a netip.Addr, d time.Duration) { kernel.Add(1); kernelAddr.Store(a.String()) }
	h := g.handler(false)
	attack := fwReq{target: "/?q=<script>alert(1)</script>", ip: "203.0.113.50"}
	for i := 0; i < 3; i++ {
		if w := fwDo(h, attack); w.Code != 403 {
			t.Fatalf("attack %d: %d", i, w.Code)
		}
	}
	gwWaitFor(t, func() bool { return kernel.Load() == 1 })
	if a, _ := kernelAddr.Load().(string); a != "203.0.113.50" {
		t.Errorf("kernel ban for %q", a)
	}
	// Now even a clean request from that client is refused, by the ban.
	if w := fwDo(h, fwReq{target: "/ok", ip: "203.0.113.50"}); w.Code != 403 {
		t.Fatalf("a banned client's clean request: %d", w.Code)
	}
	if w := fwDo(h, fwReq{target: "/ok", ip: "203.0.113.51"}); w.Code != 200 {
		t.Fatalf("another client: %d", w.Code)
	}
	if !strings.Contains(g.metricsText(), "zirogate_bans_total 1") || !strings.Contains(g.metricsText(), `reason="ban"`) {
		t.Errorf("metrics:\n%s", g.metricsText())
	}
	// The client behind a trusted proxy is the one banned, never the proxy.
	for i := 0; i < 3; i++ {
		fwDo(h, fwReq{target: attack.target, ip: "10.1.1.1", hdr: map[string]string{"X-Forwarded-For": "203.0.113.99"}})
	}
	gwWaitFor(t, func() bool { return g.bans.banned(netip.MustParseAddr("203.0.113.99"), time.Now().UnixNano()) })
	if g.bans.banned(netip.MustParseAddr("10.1.1.1"), time.Now().UnixNano()) {
		t.Error("the trusted proxy was banned")
	}
	if w := fwDo(h, fwReq{target: "/ok", ip: "10.1.1.1", hdr: map[string]string{"X-Forwarded-For": "203.0.113.5"}}); w.Code != 200 {
		t.Errorf("other clients behind the proxy: %d", w.Code)
	}
	// Loopback and a proxy are never banned, whatever they do.
	for i := 0; i < 6; i++ {
		fwDo(h, fwReq{target: attack.target, ip: "127.0.0.1"})
		fwDo(h, fwReq{target: attack.target, ip: "10.2.2.2"})
	}
	if g.bans.banned(netip.MustParseAddr("127.0.0.1"), time.Now().UnixNano()) || g.bans.banned(netip.MustParseAddr("10.2.2.2"), time.Now().UnixNano()) {
		t.Error("loopback or a trusted proxy got banned")
	}
}

func gwWaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestGatewayAdminBansEndpoint(t *testing.T) {
	g := newGatewayServer()
	g.adminToken = "s3cret"
	a := netip.MustParseAddr("203.0.113.8")
	g.bans.strike(a, time.Now(), newAutoBan(&GatewayAutoBan{Strikes: 1}), "test")
	h := g.adminHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/bans", nil))
	var list []BanStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Addr != "203.0.113.8" {
		t.Fatalf("list: %v %s", err, rec.Body.String())
	}
	del := func(token string) int {
		r := httptest.NewRequest("DELETE", "/bans/203.0.113.8", nil)
		if token != "" {
			r.Header.Set("X-Gateway-Admin", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := del(""); c != 403 {
		t.Errorf("lifting a ban without the token: %d", c)
	}
	if c := del("wrong"); c != 403 {
		t.Errorf("wrong token: %d", c)
	}
	if c := del("s3cret"); c != 204 {
		t.Errorf("right token: %d", c)
	}
	if c := del("s3cret"); c != 404 {
		t.Errorf("already lifted: %d", c)
	}
	g2 := newGatewayServer() // no token configured: nothing can be lifted
	r := httptest.NewRequest("DELETE", "/bans/203.0.113.8", nil)
	w := httptest.NewRecorder()
	g2.adminHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("no token configured: %d", w.Code)
	}
}

// ---- configuration ----

func TestGatewayRejectsBadFirewallSettings(t *testing.T) {
	g := newGatewayServer()
	for name, set := range map[string]GatewaySettings{
		"bad deny cidr":     {DenyCIDRs: []string{"nope"}},
		"bad ban":           {Bans: []GatewayBan{{Addr: "x"}}},
		"bad regex rule":    {WAF: &GatewayWAF{Mode: "block", Rules: []GatewayWAFRule{{ID: "r", Target: "path", Op: "regex", Value: "(", Action: "deny"}}}},
		"bad waf mode":      {WAF: &GatewayWAF{Mode: "sometimes"}},
		"bad auto-ban":      {AutoBan: &GatewayAutoBan{Window: "forever"}},
		"unknown exclusion": {WAF: &GatewayWAF{Mode: "block", Exclude: []string{"sql"}}},
	} {
		if err := g.load(&GatewayConfig{Settings: set}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	// A rule the catalog no longer has still loads: the gateway only ignores it.
	if err := g.load(&GatewayConfig{Settings: GatewaySettings{WAF: &GatewayWAF{Mode: "block", Exclude: []string{"ZW-999999"}}}}); err != nil {
		t.Errorf("a retired rule ID in the exclusions broke the config: %v", err)
	}
	if err := checkWAFExclusions(&GatewayWAF{Exclude: []string{"ZW-999999"}}); err == nil {
		t.Error("the CLI/API must refuse an unknown rule ID")
	}
}

func TestGatewayBanCommandsAndSettings(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldSync := gatewayLocalDir, syncLocalGatewayService
	gatewayLocalDir = dir
	syncLocalGatewayService = func(bool) error { return nil }
	defer func() { gatewayLocalDir, syncLocalGatewayService = oldDir, oldSync }()
	s := localRouteStore{dir: dir}

	if _, err := addGatewayBan(s, "not-an-address", 0, ""); err == nil {
		t.Fatal("garbage accepted")
	}
	b, err := addGatewayBan(s, "203.0.113.7", time.Hour, "scraper")
	if err != nil || b.Addr != "203.0.113.7" || b.Until == "" {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := addGatewayBan(s, "198.51.100.0/24", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := addGatewayBan(s, "203.0.113.7", 2*time.Hour, "again"); err != nil { // replaces
		t.Fatal(err)
	}
	bans, err := listGatewayBans(s)
	if err != nil || len(bans.Manual) != 2 {
		t.Fatalf("%+v %v", bans, err)
	}
	cfg, _ := s.config()
	if len(cfg.Settings.Bans) != 2 {
		t.Fatalf("gateways receive %d bans", len(cfg.Settings.Bans))
	}
	if m, _, err := removeGatewayBan(s, "198.51.100.0/24"); err != nil || !m {
		t.Fatalf("remove: %v %v", m, err)
	}
	if m, _, _ := removeGatewayBan(s, "198.51.100.0/24"); m {
		t.Fatal("removed twice")
	}
	// Expired manual bans are not sent to gateways.
	_ = s.update(func(d *gatewayData) error {
		d.Settings.Bans = append(d.Settings.Bans, GatewayBan{Addr: "192.0.2.1", Until: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)})
		return nil
	})
	if cfg, _ := s.config(); len(cfg.Settings.Bans) != 1 {
		t.Fatalf("expired ban reached the gateways: %+v", cfg.Settings.Bans)
	}

	// Settings: the WAF default, deny list and auto-ban, validated before storing.
	set, err := putGatewaySettings(s, GatewaySettings{WAF: &GatewayWAF{Mode: "detect"}, DenyCIDRs: []string{"192.0.2.0/24", " "},
		AutoBan: &GatewayAutoBan{Strikes: 4}, TrustedProxies: []string{"10.0.0.0/8", ""}})
	if err != nil || len(set.DenyCIDRs) != 1 || len(set.TrustedProxies) != 1 {
		t.Fatalf("%+v %v", set, err)
	}
	if _, err := putGatewaySettings(s, GatewaySettings{WAF: &GatewayWAF{Mode: "block", Exclude: []string{"bogus"}}}); err == nil {
		t.Fatal("unknown exclusion stored")
	}
}

func TestWAFFlagsAndRouteFlags(t *testing.T) {
	if w, err := (wafFlags{}).build(); w != nil || err != nil {
		t.Fatal("no flags, no WAF")
	}
	if _, err := (wafFlags{level: 2}).build(); err == nil {
		t.Fatal("--waf-level without --waf")
	}
	w, err := wafFlags{mode: "block", level: 2, exclude: []string{"xss"}, rules: []string{
		`{"id":"adm","target":"path","op":"prefix","value":"/admin","action":"score","score":3}`}}.build()
	if err != nil || len(w.Rules) != 1 || w.Rules[0].Score != 3 {
		t.Fatalf("%+v %v", w, err)
	}
	if _, err := (wafFlags{mode: "block", rules: []string{`{"id":"x","bogus":1}`}}).build(); err == nil {
		t.Fatal("unknown rule field accepted")
	}
	if _, err := (wafFlags{mode: "block", rules: []string{`{"id":"x","target":"path","op":"regex","value":"(","action":"deny"}`}}).build(); err == nil {
		t.Fatal("bad regex accepted")
	}
	r, err := routeFromFlags("t", routeFlags{r: GatewayRoute{Hosts: []string{"a.test"}, To: []GatewayUpstream{{Address: "10.0.0.1:80"}}, DenyCIDRs: []string{"192.0.2.0/24"}},
		waf: wafFlags{mode: "detect"}})
	if err != nil || r.WAF == nil || r.WAF.Mode != "detect" || len(r.DenyCIDRs) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r.Normalize()
	if err := validateRoute(&r); err != nil {
		t.Fatal(err)
	}
	r.WAF.Exclude = []string{"ZW-000000"}
	if err := validateRoute(&r); err == nil {
		t.Fatal("route with an unknown exclusion accepted")
	}
}

func TestGatewayFirewallAPI(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldSync := gatewayLocalDir, syncLocalGatewayService
	gatewayLocalDir = dir
	syncLocalGatewayService = func(bool) error { return nil }
	defer func() { gatewayLocalDir, syncLocalGatewayService = oldDir, oldSync }()
	var role string
	api := newAPIHarness(t, registerGatewayRoutes)
	do := func(method, path, body string) *httptest.ResponseRecorder { return api.req(role, method, path, body) }
	role = "viewer"
	if w := do("GET", "/api/v1/gateway/waf/rules", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "ZW-942100") {
		t.Fatalf("rules: %d", w.Code)
	}
	if w := do("POST", "/api/v1/gateway/bans", `{"addr":"203.0.113.1"}`); w.Code != http.StatusForbidden {
		t.Fatalf("viewer ban: %d", w.Code)
	}
	role = "admin"
	if w := do("POST", "/api/v1/gateway/bans", `{"addr":"203.0.113.0/24","for":"2h","reason":"test"}`); w.Code != 200 {
		t.Fatalf("ban: %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", "/api/v1/gateway/bans", `{"addr":"203.0.113.1","for":"soon"}`); w.Code != 400 {
		t.Fatalf("bad duration: %d", w.Code)
	}
	if w := do("GET", "/api/v1/gateway/bans", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "203.0.113.0/24") {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if w := do("DELETE", "/api/v1/gateway/bans/203.0.113.0%2F24", ""); w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body.String())
	}
	if w := do("DELETE", "/api/v1/gateway/bans/203.0.113.0%2F24", ""); w.Code != 404 {
		t.Fatalf("lift twice: %d", w.Code)
	}
	if w := do("PUT", "/api/v1/gateway/settings", `{"waf":{"mode":"detect"},"deny_cidrs":["192.0.2.0/24"],"auto_ban":{"strikes":5}}`); w.Code != 200 {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	if w := do("PUT", "/api/v1/gateway/settings", `{"waf":{"mode":"block","exclude":["bogus"]}}`); w.Code != 400 {
		t.Fatalf("settings with an unknown exclusion: %d", w.Code)
	}
	if w := do("PUT", "/api/v1/gateway/routes/r", `{"hosts":["r.test"],"to":[{"address":"10.0.0.5:9000"}],"waf":{"mode":"block","level":2},"deny_cidrs":["192.0.2.0/24"]}`); w.Code != 200 {
		t.Fatalf("route with a WAF: %d %s", w.Code, w.Body.String())
	}
}

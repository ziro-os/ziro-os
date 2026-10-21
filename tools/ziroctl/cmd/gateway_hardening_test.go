package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---- request identity ----

func TestCleanRequestPath(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"", "/", true},
		{"/", "/", true},
		{"/a/b", "/a/b", true},
		{"/a/b/", "/a/b/", true},
		{"/a/../b", "/b", true},
		{"/public/../admin", "/admin", true},
		{"//admin", "/admin", true},
		{"/a/./b", "/a/b", true},
		{"/a/b/..", "/a", true},
		{"/../../etc/passwd", "/etc/passwd", true},
		{"/a//b///c/", "/a/b/c/", true},
		{"*", "*", true},
		{"admin", "", false},
		{"/a\x00b", "", false},
		{"/a\nb", "", false},
		{"/a\x7fb", "", false},
	}
	for _, c := range cases {
		got, ok := cleanRequestPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("cleanRequestPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func FuzzCleanRequestPath(f *testing.F) {
	for _, s := range []string{"/", "/a/../b", "//x", "/a/./b/", "/%2e%2e/x", "/\x00", "/a/b/.."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, ok := cleanRequestPath(in)
		if !ok {
			return
		}
		if out != "*" && !strings.HasPrefix(out, "/") {
			t.Fatalf("%q -> %q: not rooted", in, out)
		}
		if out != "*" && !pathIsClean(out) {
			t.Fatalf("%q -> %q: not clean", in, out)
		}
		if again, ok := cleanRequestPath(out); !ok || again != out {
			t.Fatalf("%q -> %q -> %q: not idempotent", in, out, again)
		}
	})
}

func TestNormalizeHostAndKeys(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM": "example.com", "example.com:8443": "example.com", "example.com.": "example.com",
		"[::1]:443": "::1", "[::1]": "::1", "a.b.c:80": "a.b.c",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
	if rateKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd") != rateKey("2001:db8:1:2:1::1") {
		t.Error("IPv6 clients of one /64 must share a limiter key")
	}
	if rateKey("2001:db8:1:3::1") == rateKey("2001:db8:1:2::1") {
		t.Error("different /64s must not share a key")
	}
	if rateKey("192.0.2.7") != "192.0.2.7" {
		t.Error("IPv4 keys are the address")
	}
}

// A route's access rules must see the path the upstream will see.
func TestGatewayPathBypassClosed(t *testing.T) {
	pub := echoUpstream(t, "PUB", nil)
	adm := echoUpstream(t, "ADM", nil)
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	g := v2Server(t,
		rs(GatewayRoute{Name: "admin", Hosts: []string{"x.test"}, PathPrefix: "/admin", BasicAuth: map[string]string{"ops": string(hash)}}, adm),
		rs(GatewayRoute{Name: "pub", Hosts: []string{"x.test"}}, pub))
	h := g.handler(false)
	for _, p := range []string{"/admin", "/public/../admin", "//admin/x", "/a/./../admin", "/%2e%2e/admin", "/x/..%2fadmin"} {
		if w := gwGet(h, "GET", "x.test", p, "10.0.0.1:1", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s reached %q with %d, want 401 from the admin route", p, body(w), w.Code)
		}
	}
	if w := gwGet(h, "GET", "x.test", "/public/page", "10.0.0.1:1", ""); w.Code != 200 || !strings.HasPrefix(body(w), "PUB") {
		t.Errorf("public page: %d %q", w.Code, body(w))
	}
	// The upstream receives the canonical path.
	if w := gwGet(h, "GET", "x.test", "/a/../b//c", "10.0.0.1:1", ""); body(w) != "PUB /b/c" {
		t.Errorf("forwarded path %q", body(w))
	}
	if w := gwGet(h, "GET", "x.test", "/bad%00path", "10.0.0.1:1", ""); w.Code != http.StatusBadRequest {
		t.Errorf("NUL in path: %d", w.Code)
	}
}

// ---- trusted proxies and PROXY protocol ----

func TestClientIPFromTrustedProxies(t *testing.T) {
	s, err := newGWSettings(GatewaySettings{TrustedProxies: []string{"10.0.0.0/8", "192.168.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	hdr := func(v ...string) http.Header { return http.Header{"X-Forwarded-For": v} }
	cases := []struct {
		peer string
		h    http.Header
		want string
	}{
		{"203.0.113.9", hdr("1.1.1.1"), "203.0.113.9"},               // untrusted peer: header ignored
		{"10.1.1.1", hdr("9.9.9.9, 8.8.8.8, 10.2.2.2"), "8.8.8.8"},   // right-most untrusted entry
		{"10.1.1.1", hdr("9.9.9.9", "8.8.8.8, 10.2.2.2"), "8.8.8.8"}, // several header lines
		{"10.1.1.1", hdr("10.5.5.5, 10.2.2.2"), "10.5.5.5"},          // every hop trusted: left-most
		{"10.1.1.1", hdr("1.1.1.1, nonsense, 10.2.2.2"), "10.2.2.2"}, // garbage stops the walk
		{"10.1.1.1", nil, "10.1.1.1"},                                // no header
		{"192.168.1.1", hdr("2001:db8::7"), "2001:db8::7"},           // IPv6 client
		{"10.1.1.1", hdr("::ffff:1.2.3.4"), "1.2.3.4"},               // mapped addresses unwrap
		{"10.1.1.1", hdr("1.2.3.4, "), "10.1.1.1"},                   // empty trailing entry
	}
	for _, c := range cases {
		if got := clientIP(c.peer, c.h, s); got != c.want {
			t.Errorf("clientIP(%s, %v) = %q, want %q", c.peer, c.h["X-Forwarded-For"], got, c.want)
		}
	}
	if got := clientIP("10.1.1.1", hdr("1.1.1.1"), nil); got != "10.1.1.1" {
		t.Errorf("no settings: %q", got)
	}
}

func TestGatewaySettingsValidate(t *testing.T) {
	bad := []GatewaySettings{
		{TrustedProxies: []string{"not-an-ip"}},
		{ProxyProtocol: true}, // needs trusted proxies
		{DrainSeconds: -1},
		{DrainSeconds: 3600},
		{TrustedProxies: make([]string, 65)},
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("settings %d accepted: %+v", i, s)
		}
	}
	ok := GatewaySettings{TrustedProxies: []string{"10.0.0.0/8", "2001:db8::/32", "192.0.2.1"}, ProxyProtocol: true, DrainSeconds: 40}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	g := newGatewayServer()
	if err := g.load(&GatewayConfig{Settings: GatewaySettings{ProxyProtocol: true}}); err == nil {
		t.Error("the gateway loaded invalid settings")
	}
}

func proxyReader(s string) *bufio.Reader { return bufio.NewReaderSize(strings.NewReader(s), 256) }

func v2Header(cmd, fam byte, body []byte) string {
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, 0x20|cmd, fam, byte(len(body)>>8), byte(len(body)))
	return string(append(h, body...))
}

func TestParseProxyHeader(t *testing.T) {
	v4 := append(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0x04, 0xd2), 0x00, 0x50) // 1.2.3.4:1234 -> 5.6.7.8:80
	v6 := append(append(netip.MustParseAddr("2001:db8::1").AsSlice(), netip.MustParseAddr("2001:db8::2").AsSlice()...), 0x30, 0x39, 0x01, 0xbb)
	cases := []struct {
		name string
		in   string
		src  string
		ok   bool
		err  bool
	}{
		{"v1 tcp4", "PROXY TCP4 192.0.2.1 198.51.100.1 5555 443\r\nGET /", "192.0.2.1:5555", true, false},
		{"v1 tcp6", "PROXY TCP6 2001:db8::5 2001:db8::6 40000 443\r\n", "[2001:db8::5]:40000", true, false},
		{"v1 unknown", "PROXY UNKNOWN\r\n", "", false, false},
		{"v1 family mismatch", "PROXY TCP4 2001:db8::5 198.51.100.1 1 2\r\n", "", false, true},
		{"v1 bad port", "PROXY TCP4 192.0.2.1 198.51.100.1 99999 2\r\n", "", false, true},
		{"v1 no crlf", "PROXY TCP4 192.0.2.1 198.51.100.1 1 2\n", "", false, true},
		{"v1 too long", "PROXY TCP4 " + strings.Repeat("1", 200) + "\r\n", "", false, true},
		{"v2 tcp4", v2Header(1, 0x11, v4), "1.2.3.4:1234", true, false},
		{"v2 tcp6", v2Header(1, 0x21, v6), "[2001:db8::1]:12345", true, false},
		{"v2 local", v2Header(0, 0x00, nil), "", false, false},
		{"v2 udp ignored", v2Header(1, 0x12, v4), "", false, false},
		{"v2 truncated body", v2Header(1, 0x11, v4[:5]), "", false, true},
		{"v2 bad command", v2Header(5, 0x11, v4), "", false, true},
		{"not proxy", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "", false, true},
		{"empty", "", "", false, true},
	}
	for _, c := range cases {
		src, ok, err := parseProxyHeader(proxyReader(c.in))
		if (err != nil) != c.err || ok != c.ok || (ok && src.String() != c.src) {
			t.Errorf("%s: got %v %v %v, want %q ok=%v err=%v", c.name, src, ok, err, c.src, c.ok, c.err)
		}
	}
	// The header is consumed exactly: what follows is the client's bytes.
	br := proxyReader("PROXY TCP4 192.0.2.1 198.51.100.1 5555 443\r\nGET /")
	parseProxyHeader(br)
	rest, _ := io.ReadAll(br)
	if string(rest) != "GET /" {
		t.Errorf("left %q", rest)
	}
}

func FuzzParseProxyHeader(f *testing.F) {
	f.Add("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n")
	f.Add(v2Header(1, 0x11, make([]byte, 12)))
	f.Add("PROXY UNKNOWN\r\n")
	f.Fuzz(func(t *testing.T, in string) {
		src, ok, err := parseProxyHeader(proxyReader(in))
		if err == nil && ok && !src.IsValid() {
			t.Fatalf("accepted %q with invalid source", in)
		}
	})
}

// A request through a PROXY-protocol connection from a trusted proxy is attributed to the client
// in the header; the same bytes from any other peer are not a PROXY header at all.
func TestGatewayProxyProtocolEndToEnd(t *testing.T) {
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Header.Get("X-Forwarded-For")) })
	g := v2Server(t, rs(GatewayRoute{Name: "p", Hosts: []string{"p.test"}}, up))
	set := func(trusted string) {
		cfg := &GatewayConfig{Settings: GatewaySettings{TrustedProxies: []string{trusted}, ProxyProtocol: true},
			Routes: g.tbl.Load().cfg.Routes}
		if err := g.load(cfg); err != nil {
			t.Fatal(err)
		}
	}
	serve := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: g.handler(false), ReadHeaderTimeout: 2 * time.Second}
		go srv.Serve(g.wrapProxyListener(ln))
		t.Cleanup(func() { srv.Close() })
		return ln.Addr().String()
	}
	get := func(addr, prefix string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "%sGET / HTTP/1.1\r\nHost: p.test\r\nConnection: close\r\n\r\n", prefix)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "error: " + err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	set("127.0.0.0/8")
	addr := serve()
	if got := get(addr, "PROXY TCP4 203.0.113.50 10.0.0.1 4000 80\r\n"); got != "203.0.113.50" {
		t.Errorf("trusted proxy: client seen as %q", got)
	}
	if got := get(addr, "PROXY TCP4 not-an-ip x 1 2\r\n"); !strings.HasPrefix(got, "error") {
		t.Errorf("a malformed header must drop the connection, got %q", got)
	}
	set("198.51.100.0/24") // loopback is no longer a trusted proxy
	if got := get(addr, "PROXY TCP4 203.0.113.50 10.0.0.1 4000 80\r\n"); strings.Contains(got, "203.0.113.50") {
		t.Errorf("an untrusted peer chose its own address: %q", got)
	}
}

// ---- access log ----

func TestAccessLogJSON(t *testing.T) {
	evil := "a\"b\\c\n\r\t\x00\x1b\xff\xfe é 世  </script>"
	rec := gwAccessRecord{start: time.Unix(1700000000, 123), client: "10.0.0.1", host: evil, method: "GET", path: evil, status: 200,
		bytes: 5, ms: 3, upstream: "10.0.0.2:80", upStatus: 200, upMS: 2, route: "r", requestID: "abcdefgh", userAgent: evil, tls: "1.3", waf: "ZW-1"}
	line := rec.appendJSON(nil)
	if !bytes.HasSuffix(line, []byte("}\n")) || bytes.Count(line, []byte("\n")) != 1 {
		t.Fatalf("a record must be exactly one line: %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("invalid JSON %v: %q", err, line)
	}
	if got["status"].(float64) != 200 || got["route"] != "r" || got["upstream_status"].(float64) != 200 {
		t.Errorf("fields: %v", got)
	}
	if !strings.HasPrefix(got["host"].(string), "a\"b\\c\n\r\t") {
		t.Errorf("host did not round-trip: %q", got["host"])
	}
	long := gwAccessRecord{start: time.Now(), path: strings.Repeat("é", 1000)}
	if n := len(long.appendJSON(nil)); n > 1500 {
		t.Errorf("a long path must be truncated, line is %d bytes", n)
	}
}

func TestAccessLogNeverBlocks(t *testing.T) {
	var dropped atomic.Uint64
	block := make(chan struct{})
	w := &blockingWriter{block: block}
	l := newAccessLog(w, &dropped)
	done := make(chan struct{})
	go func() {
		for i := 0; i < accessLogQueue*3; i++ {
			bp := logBufPool.Get().(*[]byte)
			*bp = append(*bp, "line\n"...)
			l.write(bp)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled log writer blocked the request path")
	}
	if dropped.Load() == 0 {
		t.Error("lines were not counted as dropped")
	}
	close(block)
	l.close()
	if w.lines() == 0 {
		t.Error("queued lines were lost on close")
	}
}

type blockingWriter struct {
	block chan struct{}
	mu    sync.Mutex
	n     int
}

func (w *blockingWriter) Write(b []byte) (int, error) {
	<-w.block
	w.mu.Lock()
	w.n += bytes.Count(b, []byte("\n"))
	w.mu.Unlock()
	return len(b), nil
}

func (w *blockingWriter) lines() int { w.mu.Lock(); defer w.mu.Unlock(); return w.n }

func TestGatewayAccessLogRecordsRequest(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "l", Hosts: []string{"l.test"}}, up))
	var buf gwLogBuffer
	g.alog = newAccessLog(&buf, &g.metrics.logDropped)
	h := g.handler(false)
	r := httptest.NewRequest("GET", "http://l.test/p?secret=1", nil)
	r.RemoteAddr = "10.9.8.7:1"
	r.Header.Set("User-Agent", "probe/1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	g.alog.close()
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v: %q", err, buf.String())
	}
	if got["client"] != "10.9.8.7" || got["route"] != "l" || got["path"] != "/p" || got["user_agent"] != "probe/1" || got["upstream"] != up {
		t.Errorf("record: %v", got)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Error("the query string must stay out of the log")
	}
}

type gwLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *gwLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *gwLogBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}
func (s *gwLogBuffer) String() string { return string(s.Bytes()) }

// ---- rate limiting and basic auth ----

func TestTokenBucketSweepAndConcurrency(t *testing.T) {
	b := newTokenBucket(10)
	now := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				b.allow(fmt.Sprintf("10.0.%d.%d", w, i%250), now)
			}
		}()
	}
	wg.Wait()
	if n := b.size(); n == 0 || n > 8*250 {
		t.Fatalf("tracked %d clients", n)
	}
	b.sweep(now.Add(time.Minute)) // everyone has refilled: nothing left to remember
	if n := b.size(); n != 0 {
		t.Fatalf("sweep left %d clients", n)
	}
	if ok, left := b.take("c", now); !ok || left != 9 {
		t.Fatalf("take: %v %v", ok, left)
	}
	if !b.has("c", now) {
		t.Fatal("a client with tokens must be allowed")
	}
	for i := 0; i < 9; i++ {
		b.allow("c", now)
	}
	if b.has("c", now) {
		t.Fatal("an empty bucket must report no token")
	}
}

func TestGatewayBasicAuthCacheAndFailureLimit(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	g := v2Server(t, rs(GatewayRoute{Name: "a", Hosts: []string{"a.test"}, BasicAuth: map[string]string{"ops": string(hash)}}, up))
	h := g.handler(false)
	get := func(ip, user, pass string) int {
		r := httptest.NewRequest("GET", "http://a.test/", nil)
		r.RemoteAddr = ip + ":1"
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := get("10.0.0.1", "ops", "correct horse"); c != 200 {
		t.Fatalf("right password: %d", c)
	}
	d := authDigest("ops", "correct horse", string(hash))
	if !g.auth.ok(d, time.Now()) {
		t.Fatal("a verified credential must be cached")
	}
	if g.auth.ok(authDigest("ops", "correct horse", "different-hash"), time.Now()) {
		t.Fatal("the cache must not answer for another stored hash")
	}
	if c := get("10.0.0.1", "ops", "correct horse"); c != 200 {
		t.Fatalf("cached credential: %d", c)
	}
	if c := get("10.0.0.2", "", ""); c != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", c)
	}
	if c := get("10.0.0.2", "nobody", "x"); c != http.StatusUnauthorized {
		t.Fatalf("unknown user: %d", c)
	}
	// A client guessing passwords is cut off after its failure budget, even when it then
	// presents the right one; others are unaffected.
	limited := 0
	for i := 0; i < 15; i++ {
		if get("10.0.0.3", "ops", fmt.Sprintf("guess-%d", i)) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("password guessing was never limited")
	}
	if c := get("10.0.0.3", "ops", "correct horse"); c != http.StatusTooManyRequests {
		t.Fatalf("a guesser's next attempt: %d", c)
	}
	if c := get("10.0.0.4", "ops", "correct horse"); c != 200 {
		t.Fatalf("another client: %d", c)
	}
}

func TestBasicAuthFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "users")
	os.WriteFile(good, []byte("# ops team\nalice:long-password-1\n\nbob:long-password-2\n"), 0600)
	r, err := routeFromFlags("r", routeFlags{r: GatewayRoute{Hosts: []string{"a.test"}, To: []GatewayUpstream{{App: "x"}}}, basicAuthFile: good})
	if err != nil || len(r.BasicAuth) != 2 {
		t.Fatalf("%v %v", err, r.BasicAuth)
	}
	if bcrypt.CompareHashAndPassword([]byte(r.BasicAuth["alice"]), []byte("long-password-1")) != nil {
		t.Fatal("password not hashed from the file")
	}
	open := filepath.Join(dir, "open")
	os.WriteFile(open, []byte("alice:long-password-1\n"), 0644)
	if _, err := routeFromFlags("r", routeFlags{basicAuthFile: open}); err == nil || !strings.Contains(err.Error(), "accessible by others") {
		t.Fatalf("a world-readable password file was accepted: %v", err)
	}
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("alice:short\n"), 0600)
	if _, err := routeFromFlags("r", routeFlags{basicAuthFile: short}); err == nil {
		t.Fatal("short password accepted")
	}
}

// ---- body limits, metrics, reload ----

func TestGatewayChunkedBodyOverLimit(t *testing.T) {
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	})
	g := v2Server(t, rs(GatewayRoute{Name: "b", Hosts: []string{"b.test"}, MaxBodyMB: 1}, up))
	srv := httptest.NewServer(g.handler(false))
	defer srv.Close()
	post := func(size int, chunked bool) int {
		var rd io.Reader = io.LimitReader(zeroReader{}, int64(size))
		req, _ := http.NewRequest("POST", srv.URL+"/", rd)
		req.Host = "b.test"
		if chunked {
			req.ContentLength = -1
		} else {
			req.ContentLength = int64(size)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if c := post(512<<10, true); c != 200 {
		t.Fatalf("small chunked body: %d", c)
	}
	if c := post(2<<20, false); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize body: %d", c)
	}
	if c := post(2<<20, true); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversize body: %d, want 413", c)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestGatewayMetricsSeries(t *testing.T) {
	up := echoUpstream(t, "A", nil)
	g := v2Server(t, rs(GatewayRoute{Name: "m", Hosts: []string{"m.test"}, AllowCIDRs: []string{"10.0.0.0/8"}}, up))
	h := g.handler(false)
	gwGet(h, "GET", "m.test", "/", "10.0.0.1:1", "")
	gwGet(h, "POST", "m.test", "/", "10.0.0.1:1", "hello")
	gwGet(h, "GET", "m.test", "/", "203.0.113.1:1", "")
	gwGet(h, "GET", "m.test", "/a%00b", "10.0.0.1:1", "")
	rec := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`zirogate_requests_total{route="m",code="200"} 2`,
		`zirogate_requests_total{route="m",code="403"} 1`,
		`zirogate_denied_total{route="m",reason="acl"} 1`,
		`zirogate_denied_total{route="_none",reason="path"} 1`,
		`zirogate_request_duration_seconds_bucket{route="m",le="+Inf"} 3`,
		`zirogate_request_duration_seconds_count{route="m"} 3`,
		`zirogate_requests_in_flight{route="m"} 0`,
		`zirogate_request_bytes_total{route="m"} 5`,
		`zirogate_log_dropped_total 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	// Histogram buckets are cumulative.
	prev := -1
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, `zirogate_request_duration_seconds_bucket{route="m"`) {
			var n int
			fmt.Sscanf(l[strings.LastIndex(l, " ")+1:], "%d", &n)
			if n < prev {
				t.Fatalf("bucket counts fall: %s", l)
			}
			prev = n
		}
	}
	// Removing the route removes its series.
	if err := g.load(&GatewayConfig{}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	g.adminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rec.Body.String(), `route="m"`) {
		t.Error("series of a removed route are still exported")
	}
}

func TestGatewayReloadKeepsState(t *testing.T) {
	a := echoUpstream(t, "A", nil)
	b := echoUpstream(t, "B", nil)
	route := rs(GatewayRoute{Name: "k", Hosts: []string{"k.test"}, RateRPS: 7}, a, b)
	other := rs(GatewayRoute{Name: "o", Hosts: []string{"o.test"}}, a)
	g := v2Server(t, route, other)
	r1 := g.routeNamed("k")
	r1.targets[0].unhealthy.Store(true)
	r1.limiter.allow("1.1.1.1", time.Now())

	// An identical config keeps the very same route objects.
	if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{route, other}}); err != nil {
		t.Fatal(err)
	}
	if g.routeNamed("k") != r1 {
		t.Fatal("an unchanged route was rebuilt")
	}
	// Another route changes: this one keeps its buckets and health.
	changed := rs(GatewayRoute{Name: "o", Hosts: []string{"o2.test"}}, a)
	if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{route, changed}}); err != nil {
		t.Fatal(err)
	}
	if g.routeNamed("k") != r1 || g.routeNamed("o") == nil {
		t.Fatal("route state lost when a neighbour changed")
	}
	// The route itself changes (a new replica): health, buckets and counters carry over.
	scaled := rs(GatewayRoute{Name: "k", Hosts: []string{"k.test"}, RateRPS: 7}, a, b, "127.0.0.1:9")
	if err := g.load(&GatewayConfig{Routes: []GatewayRouteState{scaled, changed}}); err != nil {
		t.Fatal(err)
	}
	r2 := g.routeNamed("k")
	if r2 == r1 || len(r2.targets) != 3 {
		t.Fatal("route was not rebuilt for its new targets")
	}
	if r2.limiter != r1.limiter || r2.m != r1.m {
		t.Error("rate-limit buckets or metrics were reset by a scale event")
	}
	if !r2.targets[0].unhealthy.Load() || r2.targets[1].unhealthy.Load() {
		t.Error("health of surviving targets was not carried over")
	}
	if r2.targets[0].up != r1.targets[0].up {
		t.Error("upstream state must be shared across reloads")
	}
}

// ---- internal CA ----

func TestInternalLeafBoundedAndLimited(t *testing.T) {
	dir := t.TempDir()
	old := gatewayCertDir
	gatewayCertDir = dir
	defer func() { gatewayCertDir = old }()
	g := newGatewayServer()
	issued, refused := 0, 0
	for i := 0; i < leafIssuePerSec*3; i++ {
		if _, err := g.internalLeaf(fmt.Sprintf("h%d.example.internal", i)); err != nil {
			refused++
		} else {
			issued++
		}
	}
	if refused == 0 {
		t.Error("a flood of distinct SNI names was never refused")
	}
	if issued < leafIssuePerSec {
		t.Errorf("only %d certificates issued before limiting", issued)
	}
	if len(g.leafs) > leafCacheMax {
		t.Errorf("leaf cache grew to %d", len(g.leafs))
	}
	c1, err := g.internalLeaf("h0.example.internal")
	if err != nil || c1 == nil {
		t.Fatalf("a cached host must be served without issuing: %v", err)
	}
}

// ---- shutdown ----

func TestGatewayShutdownDrainsInFlight(t *testing.T) {
	started := make(chan struct{})
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, "finished")
	})
	g := v2Server(t, rs(GatewayRoute{Name: "s", Hosts: []string{"s.test"}}, up))
	g.alog = newAccessLog(io.Discard, &g.metrics.logDropped)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: g.handler(false)}
	go srv.Serve(ln)
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	admin := &http.Server{}

	type result struct {
		body string
		err  error
	}
	res := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
		req.Host = "s.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		res <- result{body: string(b)}
	}()
	<-started
	t0 := time.Now()
	g.shutdown([]*http.Server{srv}, raw, admin)
	if time.Since(t0) < 200*time.Millisecond {
		t.Error("shutdown returned before the in-flight request finished")
	}
	r := <-res
	if r.err != nil || r.body != "finished" {
		t.Fatalf("in-flight request: %q %v", r.body, r.err)
	}
	if !g.draining.Load() {
		t.Error("gateway not marked as draining")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 300*time.Millisecond); err == nil {
		t.Error("the listener still accepts after shutdown")
	}
}

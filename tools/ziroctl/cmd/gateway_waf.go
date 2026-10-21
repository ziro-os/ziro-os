package cmd

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unsafe"
)

// The WAF scores a request against the rule catalog (gateway_waf_rules.go). It is built for a
// high request rate:
//
//   - A route without a WAF pays one nil check.
//   - Each part of a request (path, arguments, cookies, headers, body) is normalized once into a
//     pooled buffer, then scanned once by an Aho-Corasick automaton that reports which rules'
//     literals occur. Only those rules' regular expressions run, so ordinary traffic never
//     reaches the regex engine.
//   - Regular expressions are RE2: linear time, no catastrophic backtracking, whatever the input.
//   - Inspection is bounded: values are cut at wafValueCap, the body at the configured size.
//   - In block mode inspection stops as soon as the score reaches the threshold.

const (
	wafValueCap  = 8192 // longest value inspected from its start; a long value's last wafTailCap bytes are inspected too
	wafTailCap   = 1024
	wafPartCap   = 64 << 10 // total bytes inspected per request part (arguments, headers, cookies)
	maxWAFHits   = 8
	wafSeparator = 1 // between values in one buffer; no rule matches across it
	wafRetainMax = 1 << 20
)

// ---- normalization ----

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// wafDecode appends src with percent-escapes decoded ('+' becomes a space for form data) and
// reports whether it changed anything. The output is never longer than the input.
func wafDecode(dst, src []byte, form bool) ([]byte, bool) {
	if bytes.IndexByte(src, '%') < 0 && (!form || bytes.IndexByte(src, '+') < 0) {
		return append(dst, src...), false
	}
	n := len(dst)
	dst = append(dst, make([]byte, len(src))...)[:n+len(src)]
	j, changed := n, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '%' && i+2 < len(src) && isHexDigit(src[i+1]) && isHexDigit(src[i+2]):
			c = unhex(src[i+1])<<4 | unhex(src[i+2])
			i += 2
			changed = true
		case c == '+' && form:
			c = ' '
			changed = true
		}
		dst[j] = c
		j++
	}
	return dst[:j], changed
}

// cleanClass sorts bytes for wafClean: 0 as is, 1 upper case, 2 white space, 3 needs a look.
var cleanClass = func() (t [256]uint8) {
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = 1
	}
	for _, c := range []byte(" \t\n\r\f\v") {
		t[c] = 2
	}
	t[0], t['/'], t['*'] = 3, 3, 3
	return t
}()

// wafClean lower-cases src, collapses white space, drops NUL bytes and replaces comments by a
// space (so UN/**/ION SELECT reads as UN ION SELECT, while MySQL's /*!50000 UNION*/ keeps its
// content). nul reports whether a NUL byte was seen. The output is never longer than the input.
func wafClean(dst, src []byte, nul *bool) []byte {
	n := len(dst)
	dst = append(dst, make([]byte, len(src))...)[:n+len(src)]
	j := n
	last := true // also trims leading white space
	inExec := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch cleanClass[c] {
		case 0:
			dst[j] = c
			j++
			last = false
		case 1:
			dst[j] = c + 'a' - 'A'
			j++
			last = false
		case 2:
			if !last {
				dst[j] = ' '
				j++
				last = true
			}
		default:
			switch {
			case c == 0:
				*nul = true
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				if i+2 < len(src) && src[i+2] == '!' {
					i += 2
					for i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9' {
						i++
					}
					inExec = true
				} else if k := bytes.Index(src[i+2:], []byte("*/")); k < 0 { // unterminated: drop the opener only
					i++
				} else {
					i += 2 + k + 1
				}
				if !last {
					dst[j] = ' '
					j++
					last = true
				}
			case c == '*' && inExec && i+1 < len(src) && src[i+1] == '/':
				inExec = false
				i++
				if !last {
					dst[j] = ' '
					j++
					last = true
				}
			default: // a lone / or *
				dst[j] = c
				j++
				last = false
			}
		}
	}
	return dst[:j]
}

// wafScratch holds the buffers one inspection uses.
type wafScratch struct {
	a, b                []byte
	path, args, cookies []byte
	headers, ua, body   []byte
	nul                 bool
}

var wafScratchPool = sync.Pool{New: func() any { return new(wafScratch) }}

func (s *wafScratch) release() {
	for _, p := range []*[]byte{&s.a, &s.b, &s.path, &s.args, &s.cookies, &s.headers, &s.ua, &s.body} {
		if cap(*p) > wafRetainMax {
			*p = nil
		} else {
			*p = (*p)[:0]
		}
	}
	s.nul = false
	wafScratchPool.Put(s)
}

// normalizeOne appends the normalized form of one value to dst.
func normalizeOne(s *wafScratch, dst, src []byte, form bool) []byte {
	a, changed := wafDecode(s.a[:0], src, form)
	s.a = a
	if changed && bytes.IndexByte(a, '%') >= 0 { // a second round catches double encoding
		b, _ := wafDecode(s.b[:0], a, false)
		s.b, a = b, b
	}
	return wafClean(dst, a, &s.nul)
}

// normalizeValue appends one value to a buffer (separated from the previous one), cutting very
// long values to their head and tail.
func normalizeValue(s *wafScratch, dst, src []byte, form bool) []byte {
	if len(dst) >= wafPartCap {
		return dst
	}
	if len(dst) > 0 {
		dst = append(dst, wafSeparator)
	}
	if len(src) > wafValueCap+wafTailCap {
		dst = normalizeOne(s, dst, src[:wafValueCap], form)
		dst = append(dst, wafSeparator)
		return normalizeOne(s, dst, src[len(src)-wafTailCap:], form)
	}
	return normalizeOne(s, dst, src, form)
}

// normalizeStr is normalizeValue for a string. The string is only read, never modified.
func normalizeStr(s *wafScratch, dst []byte, src string, form bool) []byte {
	return normalizeValue(s, dst, unsafe.Slice(unsafe.StringData(src), len(src)), form)
}

// ---- literal prefilter (Aho-Corasick) ----

// acMachine finds which of a set of lower-case literals occur in a text, in one pass. Each
// literal belongs to a rule (a bit); the result is the set of rules with an occurrence.
type acMachine struct {
	class [256]uint8
	k     int
	next  []uint16  // state*k + class -> state
	out   []uint16  // state -> index into sets: the rules whose literal ends at the state, including via failure links
	sets  []wafBits // distinct rule sets; sets[0] is empty
}

type acNeedle struct {
	text string
	rule int
}

func buildAC(needles []acNeedle) (*acMachine, error) {
	m := &acMachine{}
	for _, n := range needles {
		for i := 0; i < len(n.text); i++ {
			if m.class[n.text[i]] == 0 {
				m.k++
				m.class[n.text[i]] = uint8(m.k)
			}
		}
	}
	m.k++ // class 0: any other byte
	child := [][]int32{make([]int32, m.k)}
	out := []wafBits{{}}
	for _, n := range needles {
		s := int32(0)
		for i := 0; i < len(n.text); i++ {
			c := m.class[n.text[i]]
			if child[s][c] == 0 {
				child = append(child, make([]int32, m.k))
				out = append(out, wafBits{})
				child[s][c] = int32(len(child) - 1)
			}
			s = child[s][c]
		}
		out[s].set(n.rule)
	}
	states := len(child)
	if states > math.MaxUint16 {
		return nil, fmt.Errorf("literal prefilter needs %d states (limit %d)", states, math.MaxUint16)
	}
	m.next = make([]uint16, states*m.k)
	fail := make([]int32, states)
	queue := make([]int32, 0, states)
	for c := 1; c < m.k; c++ {
		if t := child[0][c]; t != 0 {
			m.next[c] = uint16(t)
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		out[s].or(&out[fail[s]])
		for c := 0; c < m.k; c++ {
			t := child[s][c]
			if t == 0 {
				m.next[int(s)*m.k+c] = m.next[int(fail[s])*m.k+c]
				continue
			}
			fail[t] = int32(m.next[int(fail[s])*m.k+c])
			m.next[int(s)*m.k+c] = uint16(t)
			queue = append(queue, t)
		}
	}
	// Most states report nothing and many report the same set: keep each distinct set once.
	m.sets = []wafBits{{}}
	ids := map[wafBits]uint16{{}: 0}
	m.out = make([]uint16, states)
	for s := range out {
		id, ok := ids[out[s]]
		if !ok {
			id = uint16(len(m.sets))
			ids[out[s]] = id
			m.sets = append(m.sets, out[s])
		}
		m.out[s] = id
	}
	return m, nil
}

func acScan[T string | []byte](m *acMachine, s T) (hit wafBits) {
	state := 0
	for i := 0; i < len(s); i++ {
		state = int(m.next[state*m.k+int(m.class[s[i]])])
		if o := m.out[state]; o != 0 {
			hit.or(&m.sets[o])
		}
	}
	return hit
}

var shellCommands = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(`cat ls id whoami uname wget curl nc ncat netcat bash sh zsh python python2 python3 perl ruby php node rm chmod
		chown ping nslookup dig echo sleep env printenv nmap telnet ftp tftp powershell cmd`) {
		m[c] = true
	}
	return m
}()

// matchShellInjection reports a shell command after a command separator (; | || && ` $( ).
func matchShellInjection(b []byte) bool {
	for i := 0; i < len(b); i++ {
		j := i + 1
		switch b[i] {
		case ';', '`':
		case '|':
			if j < len(b) && b[j] == '|' {
				j++
			}
		case '&':
			if j >= len(b) || b[j] != '&' {
				continue
			}
			j++
		case '$':
			if j >= len(b) || b[j] != '(' {
				continue
			}
			j++
		default:
			continue
		}
		for j < len(b) && b[j] == ' ' {
			j++
		}
		k := j
		for k < len(b) && (b[k] >= 'a' && b[k] <= 'z' || b[k] >= '0' && b[k] <= '9' || b[k] == '_') {
			k++
		}
		if k == j || !shellCommands[string(b[j:k])] {
			continue
		}
		if k == len(b) || b[k] == wafSeparator || b[k] == ' ' || strings.IndexByte(";|&`)<>-", b[k]) >= 0 {
			return true
		}
	}
	return false
}

// ---- policy ----

type wafAction uint8

const (
	wafPass wafAction = iota
	wafLogged
	wafWouldBlock // detect mode: the request reached the threshold
	wafBlocked
)

type wafPolicy struct {
	block     bool // block mode (else detect)
	threshold int
	enabled   wafBits
	bodyCap   int
	skipBody  bool
	custom    []wafCustom
	eng       *wafEngine
}

// newWAFPolicy compiles a configuration; it returns nil when the WAF is off.
func newWAFPolicy(w *GatewayWAF) (*wafPolicy, error) {
	if w == nil || w.Mode == "off" {
		return nil, nil
	}
	if err := w.Validate(); err != nil {
		return nil, err
	}
	e := wafEng()
	p := &wafPolicy{block: w.Mode == "block", threshold: w.Threshold, bodyCap: w.InspectBodyKB << 10, skipBody: w.SkipBody, eng: e}
	if p.threshold == 0 {
		p.threshold = 5
	}
	if p.bodyCap == 0 {
		p.bodyCap = 8 << 10
	}
	level := w.Level
	if level == 0 {
		level = 1
	}
	for i, r := range e.rules {
		if r.Level <= level {
			p.enabled.set(i)
		}
	}
	p.enabled.andNot(&e.off)
	for _, ex := range w.Exclude {
		if i, ok := e.index[ex]; ok {
			p.enabled.clear(i)
			continue
		}
		if g, ok := groupIndex(ex); ok {
			p.enabled.andNot(&e.groups[g])
		}
	}
	for _, r := range w.Rules {
		c, err := newWAFCustom(r)
		if err != nil {
			return nil, err
		}
		p.custom = append(p.custom, c)
	}
	return p, nil
}

// ---- custom rules ----

type wafCustom struct {
	id, target, name string // name: the argument, header or cookie
	op               string
	val              string
	re               *regexp.Regexp
	nets             *cidrSet
	not              bool
	action           string
	score            int
}

func newWAFCustom(r GatewayWAFRule) (wafCustom, error) {
	c := wafCustom{id: r.ID, op: r.Op, val: strings.ToLower(r.Value), not: r.Not, action: r.Action, score: r.Score}
	c.target, c.name, _ = strings.Cut(r.Target, ":")
	if c.target == "header" {
		c.name = http.CanonicalHeaderKey(c.name)
	}
	if c.action == "score" && c.score == 0 {
		c.score = 3
	}
	var err error
	switch r.Op {
	case "regex":
		c.re, err = regexp.Compile("(?i)" + r.Value)
	case "cidr", "eq":
		if r.Target == "ip" {
			c.nets, err = newCIDRSet([]string{r.Value})
		}
	}
	return c, err
}

func (c *wafCustom) matches(req *http.Request, ip string, body []byte) bool {
	var v string
	switch c.target {
	case "path":
		v = req.URL.Path
	case "query":
		v = req.URL.RawQuery
	case "arg":
		v, _ = queryGet(req.URL.RawQuery, c.name)
		if v == "" && len(body) > 0 {
			v, _ = queryGet(string(body), c.name)
		}
	case "header":
		v = req.Header.Get(c.name)
	case "cookie":
		v, _ = cookieGet(req.Header, c.name)
	case "body":
		v = string(body)
	case "method":
		v = req.Method
	case "host":
		v = req.Host
	case "user_agent":
		v = req.UserAgent()
	case "ip":
		v = ip
	}
	var ok bool
	switch {
	case c.nets != nil:
		ok = c.nets.containsIP(v)
	case c.op == "regex":
		if c.target == "query" || c.target == "path" || c.target == "body" {
			if u, err := url.QueryUnescape(v); err == nil {
				v = u
			}
		}
		ok = c.re.MatchString(v)
	default:
		if c.target == "query" || c.target == "path" || c.target == "arg" {
			if u, err := url.QueryUnescape(v); err == nil {
				v = u
			}
		}
		v = strings.ToLower(v)
		switch c.op {
		case "eq":
			ok = v == c.val
		case "contains":
			ok = strings.Contains(v, c.val)
		case "prefix":
			ok = strings.HasPrefix(v, c.val)
		case "suffix":
			ok = strings.HasSuffix(v, c.val)
		}
	}
	return ok != c.not
}

// ---- inspection ----

// wafVerdict is the outcome of inspecting one request.
type wafVerdict struct {
	score  int
	allow  bool // a custom allow rule matched: the WAF stood aside
	deny   bool // a custom deny rule matched
	n      int
	ids    [maxWAFHits]string
	groups uint16 // groups with a match
	extra  int    // matches beyond maxWAFHits
}

func (v *wafVerdict) add(id string, score int, g wafGroup) {
	v.score += score
	v.groups |= 1 << g
	if v.n < maxWAFHits {
		v.ids[v.n] = id
		v.n++
	} else {
		v.extra++
	}
}

// String lists the matched rules for the access log.
func (v *wafVerdict) String() string {
	if v.n == 0 {
		return ""
	}
	return strings.Join(v.ids[:v.n], ",")
}

// action is what the gateway does with the request.
func (p *wafPolicy) action(v *wafVerdict) wafAction {
	switch {
	case v.allow || v.n == 0:
		return wafPass
	case v.deny || v.score >= p.threshold:
		if p.block {
			return wafBlocked
		}
		return wafWouldBlock
	}
	return wafLogged
}

// done reports whether further inspection cannot change the decision.
func (p *wafPolicy) done(v *wafVerdict) bool {
	return p.block && (v.deny || v.score >= p.threshold)
}

// wantBody reports whether the request has a body worth reading before it is forwarded.
func (p *wafPolicy) wantBody(req *http.Request) (form, ok bool) {
	if p.skipBody || req.ContentLength == 0 || req.Header.Get("Upgrade") != "" {
		return false, false
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch ct = strings.TrimSpace(ct); {
	case ct == "application/x-www-form-urlencoded":
		return true, true
	case ct == "", ct == "application/json", ct == "application/graphql", ct == "multipart/form-data", ct == "application/soap+xml",
		strings.HasPrefix(ct, "text/") && ct != "text/event-stream", strings.HasSuffix(ct, "+json"), strings.HasSuffix(ct, "+xml"),
		strings.HasSuffix(ct, "/xml"):
		return false, true
	}
	return false, false // binary, gRPC, streams
}

var wafBodyPool = sync.Pool{New: func() any { b := make([]byte, 8<<10); return &b }}

// readBody reads up to the inspection limit from the request and puts it back in front of the
// rest of the stream, so the upstream still receives the whole body. It waits for that many
// bytes (or the end of the body): a sender that stalls is cut off by the request body deadline.
// release returns the buffer once the request is done.
func (p *wafPolicy) readBody(req *http.Request) (body []byte, release func()) {
	n := p.bodyCap
	if req.ContentLength > 0 && req.ContentLength < int64(n) {
		n = int(req.ContentLength)
	}
	var buf []byte
	var pooled *[]byte
	if n <= 8<<10 {
		pooled = wafBodyPool.Get().(*[]byte)
		buf = (*pooled)[:n]
	} else {
		buf = make([]byte, n)
	}
	got, err := io.ReadFull(req.Body, buf)
	body = buf[:got]
	orig := req.Body
	var rest io.Reader = orig
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		rest = http.NoBody // the whole body was read
	}
	req.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), rest), orig}
	return body, func() {
		if pooled != nil {
			wafBodyPool.Put(pooled)
		}
	}
}

// inspect scores the request. body is the start of the request body (nil if none was read).
func (p *wafPolicy) inspect(req *http.Request, ip string, body []byte, formBody bool) (v wafVerdict) {
	e := p.eng
	for i := range p.custom {
		c := &p.custom[i]
		if !c.matches(req, ip, body) {
			continue
		}
		switch c.action {
		case "allow":
			v.allow = true
			return v
		case "deny":
			v.deny = true
			v.add("custom:"+c.id, 0, gProtocol)
		case "log":
			v.add("custom:"+c.id, 0, gProtocol)
		case "score":
			v.add("custom:"+c.id, c.score, gProtocol)
		}
	}
	if p.done(&v) {
		return v
	}

	sc := wafScratchPool.Get().(*wafScratch)
	defer sc.release()
	var hit wafBits // catalog rules that already matched
	add := func(i int) {
		hit.set(i)
		r := &e.rules[i]
		v.add(r.ID, r.score, r.group)
	}
	// scan checks one normalized part: the rules whose literals occur get their expressions run.
	scan := func(target int, buf []byte) {
		if len(buf) == 0 {
			return
		}
		cand := acScan(e.ac, buf)
		for w := range cand {
			x := cand[w] & p.enabled[w] & e.byTarget[target][w] &^ hit[w]
			for x != 0 {
				i := w<<6 + bits.TrailingZeros64(x)
				x &= x - 1
				if e.rules[i].matches(buf) {
					add(i)
				}
			}
		}
	}
	on := func(i int) bool { return p.enabled.has(i) }

	// Protocol checks.
	switch req.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	case "TRACE", "TRACK":
		if on(e.iTrace) {
			add(e.iTrace)
		}
	default:
		if on(e.iMethod) {
			add(e.iMethod)
		}
	}
	if on(e.iHeaders) && len(req.Header) > 100 {
		add(e.iHeaders)
	}
	if on(e.iURI) && len(req.RequestURI) > 8192 {
		add(e.iURI)
	}
	if on(e.iRange) && strings.Count(req.Header.Get("Range"), ",") > 10 {
		add(e.iRange)
	}
	if on(e.iProxy) && len(req.Header["Proxy"]) > 0 {
		add(e.iProxy)
	}
	if p.done(&v) {
		return v
	}

	// Path.
	sc.path = normalizeStr(sc, sc.path, req.URL.Path, false)
	scan(0, sc.path)
	if p.done(&v) {
		return v
	}

	// Arguments (names and values).
	for raw := req.URL.RawQuery; raw != "" && len(sc.args) < wafPartCap; {
		var pair string
		pair, raw, _ = strings.Cut(raw, "&")
		k, val, _ := strings.Cut(pair, "=")
		sc.args = normalizeStr(sc, sc.args, k, true)
		sc.args = normalizeStr(sc, sc.args, val, true)
	}
	if formBody {
		for raw := body; len(raw) > 0 && len(sc.args) < wafPartCap; {
			var pair []byte
			if i := bytes.IndexByte(raw, '&'); i >= 0 {
				pair, raw = raw[:i], raw[i+1:]
			} else {
				pair, raw = raw, nil
			}
			k, val := pair, []byte(nil)
			if i := bytes.IndexByte(pair, '='); i >= 0 {
				k, val = pair[:i], pair[i+1:]
			}
			sc.args = normalizeValue(sc, sc.args, k, true)
			sc.args = normalizeValue(sc, sc.args, val, true)
		}
	}
	scan(1, sc.args)
	if p.done(&v) {
		return v
	}

	// Cookies (values).
	for _, line := range req.Header["Cookie"] {
		for line != "" && len(sc.cookies) < wafPartCap {
			var part string
			part, line, _ = strings.Cut(line, ";")
			if _, val, ok := strings.Cut(part, "="); ok {
				sc.cookies = normalizeStr(sc, sc.cookies, strings.TrimSpace(val), true)
			}
		}
	}
	scan(2, sc.cookies)
	if p.done(&v) {
		return v
	}

	// Headers.
	for name, vals := range req.Header {
		if name == "Cookie" {
			continue
		}
		for _, hv := range vals {
			sc.headers = normalizeStr(sc, sc.headers, hv, false)
		}
	}
	scan(3, sc.headers)
	sc.ua = normalizeStr(sc, sc.ua, req.UserAgent(), false)
	scan(5, sc.ua)
	if p.done(&v) {
		return v
	}

	// Body.
	if len(body) > 0 && !formBody {
		sc.body = normalizeValue(sc, sc.body, body, false)
		scan(4, sc.body)
	}

	if sc.nul && on(e.iNUL) && !hit.has(e.iNUL) {
		add(e.iNUL)
	}
	return v
}

// wafRuleInfo describes one rule for the CLI and the API.
type wafRuleInfo struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Level int    `json:"level"`
	Score int    `json:"score"`
	Msg   string `json:"message"`
	Stage string `json:"stage"`
}

// wafRuleCatalog lists the rules of the engine in use.
func wafRuleCatalog() []wafRuleInfo {
	e := wafEng()
	out := make([]wafRuleInfo, 0, len(e.rules))
	for _, r := range e.rules {
		stage := r.Stage
		if stage == "" {
			stage = wafStageBlock
		}
		out = append(out, wafRuleInfo{r.ID, r.Group, r.Level, r.Score, r.Msg, stage})
	}
	return out
}

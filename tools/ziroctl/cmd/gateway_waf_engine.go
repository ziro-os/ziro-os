package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Building the WAF engine from a rule pack. A pack is data from outside the binary, so it is
// validated as strictly as any other trust boundary: sizes are capped, every rule is checked, every
// expression is compiled (RE2, so matching time is linear whatever a pack contains) and every
// rule's own test samples are run. A pack that fails any check is refused as a whole; the engine
// in use stays in place.

const (
	wafWords        = 4
	wafMaxRules     = wafWords * 64
	wafMaxRegexLen  = 2048
	wafMaxNeedles   = 64
	wafMaxNeedleLen = 64
	wafMaxNeedleSum = 40000 // total needle bytes: bounds the automaton (its states are 16 bits)
	wafMaxMsgLen    = 200
	wafMaxVectors   = 8
	wafMaxVectorLen = 1024
	wafMaxPackBytes = 1 << 20
)

// wafBits is a set of rule indexes.
type wafBits [wafWords]uint64

func (b *wafBits) set(i int)      { b[i>>6] |= 1 << uint(i&63) }
func (b *wafBits) clear(i int)    { b[i>>6] &^= 1 << uint(i&63) }
func (b *wafBits) has(i int) bool { return b[i>>6]&(1<<uint(i&63)) != 0 }
func (b *wafBits) or(o *wafBits) {
	for w := range b {
		b[w] |= o[w]
	}
}
func (b *wafBits) andNot(o *wafBits) {
	for w := range b {
		b[w] &^= o[w]
	}
}

var (
	wafRuleIDRe = regexp.MustCompile(`^ZW-[0-9]{6}$`)

	// The protocol rules inspect the request line and headers in code; a pack may describe them
	// (score, level, stage, message) but not replace their logic.
	wafProtocolIDs = [...]string{"ZW-920100", "ZW-920110", "ZW-920120", "ZW-920130", "ZW-920170", "ZW-920190", "ZW-920200"}
)

func wafIsProtocolID(id string) bool {
	for _, p := range wafProtocolIDs {
		if p == id {
			return true
		}
	}
	return false
}

// decodeWAFPack parses a pack. strict (used by CI and `waf test`) also refuses unknown fields; a
// host accepts them, so a newer pack can add optional fields without breaking older hosts.
func decodeWAFPack(b []byte, strict bool) (*wafPackFile, error) {
	if len(b) > wafMaxPackBytes {
		return nil, errors.New("WAF pack is larger than 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if strict {
		dec.DisallowUnknownFields()
	}
	var p wafPackFile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("WAF pack: %w", err)
	}
	if dec.More() {
		return nil, errors.New("WAF pack: trailing data")
	}
	return &p, nil
}

func groupIndex(name string) (wafGroup, bool) {
	for g, n := range wafGroupNames {
		if n == name {
			return wafGroup(g), true
		}
	}
	return 0, false
}

func cleanText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return utf8.ValidString(s)
}

// validateWAFPack checks the structure of a pack (not that its expressions compile).
func validateWAFPack(p *wafPackFile) error {
	if p.Schema != 1 {
		return fmt.Errorf("WAF pack: unsupported schema %d", p.Schema)
	}
	if err := schema.ValidName(p.Name); err != nil {
		return fmt.Errorf("WAF pack: %w", err)
	}
	if p.Version == "" || len(p.Version) > 64 || !cleanText(p.Version) {
		return errors.New("WAF pack: version must be 1-64 printable characters")
	}
	if len(p.Rules) == 0 || len(p.Rules) > wafMaxRules {
		return fmt.Errorf("WAF pack: %d rules (want 1-%d)", len(p.Rules), wafMaxRules)
	}
	seen := map[string]bool{}
	needleBytes := 0
	for i := range p.Rules {
		d := &p.Rules[i]
		if err := validateWAFRule(d); err != nil {
			return fmt.Errorf("WAF pack: rule %q: %w", d.ID, err)
		}
		if seen[d.ID] {
			return fmt.Errorf("WAF pack: duplicate rule %s", d.ID)
		}
		seen[d.ID] = true
		for _, n := range d.Needles {
			needleBytes += len(n)
		}
	}
	if needleBytes > wafMaxNeedleSum {
		return fmt.Errorf("WAF pack: %d bytes of needles (limit %d)", needleBytes, wafMaxNeedleSum)
	}
	for _, id := range wafProtocolIDs {
		if !seen[id] {
			return fmt.Errorf("WAF pack: protocol rule %s is missing", id)
		}
	}
	for _, id := range p.Retired {
		if !wafRuleIDRe.MatchString(id) {
			return fmt.Errorf("WAF pack: retired %q is not a rule ID", id)
		}
		if seen[id] {
			return fmt.Errorf("WAF pack: %s is both a rule and retired", id)
		}
	}
	return nil
}

func validateWAFRule(d *wafRuleDef) error {
	if !wafRuleIDRe.MatchString(d.ID) {
		return errors.New("id must look like ZW-942100")
	}
	if _, ok := groupIndex(d.Group); !ok {
		return fmt.Errorf("unknown group %q", d.Group)
	}
	if d.Level < 1 || d.Level > 3 {
		return errors.New("level must be 1, 2 or 3")
	}
	if d.Score < scoreNotice || d.Score > scoreCritical {
		return errors.New("score must be 2 to 5")
	}
	if d.Msg == "" || len(d.Msg) > wafMaxMsgLen || !cleanText(d.Msg) {
		return errors.New("msg must be 1-200 printable characters")
	}
	switch d.Stage {
	case "", wafStageBlock, wafStageDetect, wafStageOff:
	default:
		return fmt.Errorf("unknown stage %q", d.Stage)
	}
	if len(d.Refs) > 16 {
		return errors.New("too many refs")
	}
	for _, r := range d.Refs {
		if r == "" || len(r) > 100 || !cleanText(r) {
			return errors.New("refs must be short printable strings")
		}
	}
	if d.Tests != nil && (len(d.Tests.Match) > wafMaxVectors || len(d.Tests.NoMatch) > wafMaxVectors) {
		return fmt.Errorf("at most %d samples of each kind", wafMaxVectors)
	}
	if d.Tests != nil {
		for _, v := range append(append([]string(nil), d.Tests.Match...), d.Tests.NoMatch...) {
			if len(v) > wafMaxVectorLen || !utf8.ValidString(v) {
				return errors.New("samples must be short valid UTF-8")
			}
		}
	}
	if wafIsProtocolID(d.ID) {
		if d.Group != wafGroupNames[gProtocol] || d.Re != "" || len(d.Needles) > 0 || len(d.Targets) > 0 {
			return errors.New("protocol rules are implemented in code: they take no expression, needles or targets")
		}
		return nil
	}
	if d.Re == "" || len(d.Re) > wafMaxRegexLen {
		return fmt.Errorf("re must be 1-%d bytes", wafMaxRegexLen)
	}
	if len(d.Needles) == 0 || len(d.Needles) > wafMaxNeedles {
		return fmt.Errorf("a rule needs 1-%d needles", wafMaxNeedles)
	}
	for _, n := range d.Needles {
		if n == "" || len(n) > wafMaxNeedleLen || n != strings.ToLower(n) || strings.ContainsRune(n, wafSeparator) {
			return fmt.Errorf("needle %q must be 1-%d bytes of lower-case text", n, wafMaxNeedleLen)
		}
	}
	if len(d.Targets) == 0 {
		return errors.New("a rule needs at least one target")
	}
	seen := map[string]bool{}
	for _, t := range d.Targets {
		if _, ok := wafTargetBit(t); !ok || seen[t] {
			return fmt.Errorf("unknown or repeated target %q", t)
		}
		seen[t] = true
	}
	return nil
}

func wafTargetBit(name string) (uint8, bool) {
	for i, n := range wafTargetNames {
		if n == name {
			return 1 << uint(i), true
		}
	}
	return 0, false
}

// ---- the compiled engine ----

type wafPackInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Serial  int64  `json:"serial"`            // the signed index's serial; 0 for the built-in rules
	Digest  string `json:"digest"`            // sha256 of the pack file, hex
	Source  string `json:"source"`            // "builtin" or "catalog"
	Expires string `json:"expires,omitempty"` // when the signed index stops being trusted
}

type wafCompiledRule struct {
	wafRuleDef
	group wafGroup
	mask  uint8 // request parts the rule inspects
	score int   // what a match adds: 0 for a rule at the detect stage
	re    *regexp.Regexp
	fn    func([]byte) bool // a hand-written matcher equivalent to re, for the rules that run most often
}

func (r *wafCompiledRule) matches(b []byte) bool {
	if r.fn != nil {
		return r.fn(b)
	}
	return r.re.Match(b)
}

type wafEngine struct {
	pack     wafPackInfo
	rules    []wafCompiledRule
	ac       *acMachine
	byTarget [numWAFTargets]wafBits // rules that apply to each request part
	groups   [numWAFGroups]wafBits
	off      wafBits // rules at the off stage
	index    map[string]int
	retired  map[string]bool
	// indexes of the protocol rules
	iMethod, iTrace, iHeaders, iURI, iNUL, iRange, iProxy int
}

// wafMatchers replace the regular expression of a rule where profiling showed it dominating. The
// expression stays in the pack as the definition; a test checks the two agree. A matcher applies
// only while the pack still carries the built-in expression for that rule.
var wafMatchers = map[string]func([]byte) bool{"ZW-932100": matchShellInjection}

func wafMatcherFor(d wafRuleDef) func([]byte) bool {
	fn := wafMatchers[d.ID]
	if fn == nil {
		return nil
	}
	for _, b := range wafBuiltinPack().Rules {
		if b.ID == d.ID && b.Re == d.Re {
			return fn
		}
	}
	return nil
}

// wafBuild validates and compiles a pack, then runs its rules' test samples.
func wafBuild(p *wafPackFile, info wafPackInfo) (*wafEngine, error) {
	if err := validateWAFPack(p); err != nil {
		return nil, err
	}
	e := &wafEngine{pack: info, index: map[string]int{}, retired: map[string]bool{}}
	e.pack.Name, e.pack.Version = p.Name, p.Version
	var needles []acNeedle
	for i, d := range p.Rules {
		g, _ := groupIndex(d.Group)
		cr := wafCompiledRule{wafRuleDef: d, group: g, score: d.Score}
		if d.Stage == wafStageDetect {
			cr.score = 0
		}
		if d.Re != "" {
			re, err := regexp.Compile(d.Re)
			if err != nil {
				return nil, fmt.Errorf("WAF pack: rule %s: %w", d.ID, err)
			}
			if re.MatchString("") {
				return nil, fmt.Errorf("WAF pack: rule %s: the expression matches the empty string", d.ID)
			}
			cr.re, cr.fn = re, wafMatcherFor(d)
		}
		for _, t := range d.Targets {
			bit, _ := wafTargetBit(t)
			cr.mask |= bit
		}
		for _, n := range d.Needles {
			needles = append(needles, acNeedle{n, i})
		}
		e.rules = append(e.rules, cr)
		e.index[d.ID] = i
		e.groups[g].set(i)
		if d.Stage == wafStageOff {
			e.off.set(i)
		}
		for t := 0; t < numWAFTargets; t++ {
			if cr.mask&(1<<uint(t)) != 0 {
				e.byTarget[t].set(i)
			}
		}
	}
	var err error
	if e.ac, err = buildAC(needles); err != nil {
		return nil, fmt.Errorf("WAF pack: %w", err)
	}
	for _, id := range p.Retired {
		e.retired[id] = true
	}
	// Every protocol ID is present (validateWAFPack), so none of these lookups can alias rule 0.
	e.iMethod, e.iTrace, e.iHeaders = e.index["ZW-920100"], e.index["ZW-920110"], e.index["ZW-920120"]
	e.iURI, e.iNUL, e.iRange, e.iProxy = e.index["ZW-920130"], e.index["ZW-920170"], e.index["ZW-920190"], e.index["ZW-920200"]
	if bad := e.selfTest(); len(bad) > 0 {
		return nil, fmt.Errorf("WAF pack: %s", strings.Join(bad, "; "))
	}
	return e, nil
}

// selfTest runs the samples every rule carries and reports the ones it gets wrong. A sample is
// normalized like request data and must (or must not) fire its rule: first the literal prefilter,
// then the expression, exactly as inspection does.
func (e *wafEngine) selfTest() (failures []string) {
	sc := wafScratchPool.Get().(*wafScratch)
	defer sc.release()
	fires := func(i int, sample string) bool {
		norm := normalizeOne(sc, nil, []byte(sample), false)
		cand := acScan(e.ac, norm)
		return cand.has(i) && e.rules[i].matches(norm)
	}
	for i := range e.rules {
		r := &e.rules[i]
		if r.Tests == nil {
			continue
		}
		for _, s := range r.Tests.Match {
			if !fires(i, s) {
				failures = append(failures, fmt.Sprintf("%s does not match its sample %q", r.ID, s))
			}
		}
		for _, s := range r.Tests.NoMatch {
			if fires(i, s) {
				failures = append(failures, fmt.Sprintf("%s matches %q, which it must not", r.ID, s))
			}
		}
	}
	return failures
}

// ---- the engine in use ----

// wafCur is the engine new policies are built from. It is replaced atomically when a pack is
// installed; policies already built keep the engine they were built with.
var wafCur atomic.Pointer[wafEngine]

var wafBuiltinEngine = sync.OnceValue(func() *wafEngine {
	sum := sha256.Sum256(wafBuiltinJSON)
	e, err := wafBuild(wafBuiltinPack(), wafPackInfo{Source: "builtin", Digest: hex.EncodeToString(sum[:])})
	if err != nil {
		panic("built-in WAF rules: " + err.Error())
	}
	return e
})

// wafEng returns the engine in use: the installed pack's, or the built-in rules.
func wafEng() *wafEngine {
	if e := wafCur.Load(); e != nil {
		return e
	}
	wafCur.CompareAndSwap(nil, wafBuiltinEngine())
	return wafCur.Load()
}

// wafKnownExclusion reports whether an exclusion names a real or retired rule, or a group.
func wafKnownExclusion(ex string) bool {
	e := wafEng()
	if _, ok := e.index[ex]; ok || e.retired[ex] {
		return true
	}
	_, ok := groupIndex(ex)
	return ok
}

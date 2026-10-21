package cmd

import (
	_ "embed"
	"sync"
)

// The WAF rule format. The built-in rules (gateway_waf_rules.json) and the rule packs published
// in ziro-os/pkgs share it, so the built-in set is simply the pack every host starts with. Rule
// IDs are stable: they appear in logs, metrics and exclusions, so a rule may be refined but its ID
// keeps its meaning.
//
// Every regular expression is matched against normalized text (see wafClean): percent-decoded up
// to twice, lower case, white space collapsed to single spaces, comments replaced by a space.
// Patterns are therefore written in lower case. Needles are the literals a value must contain
// before its rule's expression is worth running; they come from the same normalized text. Values
// in one buffer are separated by \x01, which no pattern matches across.

type wafGroup uint8

const (
	gSQLi wafGroup = iota
	gXSS
	gLFI
	gRCE
	gJava
	gXXE
	gSSRF
	gProtocol
	gScanner
	numWAFGroups
)

var wafGroupNames = [numWAFGroups]string{"sqli", "xss", "lfi", "rce", "java", "xxe", "ssrf", "protocol", "scanner"}

// Request parts a rule inspects; the bit of a part is 1 << its index.
const numWAFTargets = 6

var wafTargetNames = [numWAFTargets]string{"path", "args", "cookies", "headers", "body", "ua"}

// Severity scores, as in the OWASP Core Rule Set.
const (
	scoreCritical = 5
	scoreError    = 4
	scoreWarning  = 3
	scoreNotice   = 2
)

// Rule stages. A staged rule is how maintainers ship a new rule safely: it is matched, logged and
// counted for a while before it is allowed to add to a request's score.
const (
	wafStageBlock  = "block"  // the default: the rule adds its score
	wafStageDetect = "detect" // the rule is logged and counted but adds nothing to the score
	wafStageOff    = "off"    // the rule does not run
)

// wafRuleDef is one rule as written in a pack.
type wafRuleDef struct {
	ID      string        `json:"id"`
	Group   string        `json:"group"`
	Level   int           `json:"level"` // 1 precise ... 3 paranoid
	Score   int           `json:"score"` // 2 notice, 3 warning, 4 error, 5 critical
	Msg     string        `json:"msg"`
	Stage   string        `json:"stage,omitempty"`
	Targets []string      `json:"targets,omitempty"`
	Needles []string      `json:"needles,omitempty"` // lower-case literals; one must appear for Re to run
	Re      string        `json:"re,omitempty"`      // RE2; empty for the protocol rules, which are implemented in code
	Refs    []string      `json:"refs,omitempty"`    // CVE or advisory identifiers
	Tests   *wafRuleTests `json:"tests,omitempty"`
}

// wafRuleTests are samples the rule must (and must not) match. They run when a pack is built in
// CI and by `ziroctl gateway waf test`, so a rule that does not do what it says never ships.
type wafRuleTests struct {
	Match   []string `json:"match,omitempty"`
	NoMatch []string `json:"nomatch,omitempty"`
}

// wafPackFile is a rule pack.
type wafPackFile struct {
	Schema  int          `json:"schema"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Rules   []wafRuleDef `json:"rules"`
	Retired []string     `json:"retired,omitempty"` // IDs that no longer exist; exclusions naming them are accepted
}

//go:embed gateway_waf_rules.json
var wafBuiltinJSON []byte

// wafBuiltinPack is the rule pack compiled into ziroctl: the fallback on a host that has never
// fetched a pack (or whose pack is expired or damaged).
var wafBuiltinPack = sync.OnceValue(func() *wafPackFile {
	p, err := decodeWAFPack(wafBuiltinJSON, true)
	if err != nil {
		panic("built-in WAF rules: " + err.Error())
	}
	return p
})

package schema

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Web application firewall and address-based access control.

// WAF modes.
const (
	WAFOff    = "off"
	WAFDetect = "detect" // match, log and count; let the request through
	WAFBlock  = "block"  // answer 403 when the anomaly score reaches the threshold
)

// WAF bounds and defaults.
const (
	WAFDefaultThreshold = 5
	WAFDefaultBodyKB    = 8
	WAFMaxBodyKB        = 256
	WAFMaxRules         = 64
	MaxRouteDenyCIDRs   = 1000
	MaxGlobalDenyCIDRs  = 10000
	MaxManualBans       = 1000
)

// GatewayWAF configures the firewall of a route, or the default for routes without their own.
// Requests are scored in the style of the OWASP Core Rule Set: every matching rule adds its
// score (critical 5, error 4, warning 3, notice 2) and the request is blocked once the total
// reaches the threshold. Rule IDs (ZW-9xxxxx) are stable.
type GatewayWAF struct {
	Mode      string `json:"mode,omitempty"`      // off, detect or block
	Level     int    `json:"level,omitempty"`     // 1 (default) = precise rules, 2 and 3 add broader ones (more false positives)
	Threshold int    `json:"threshold,omitempty"` // score that blocks (default 5)
	// Exclude turns off rules by ID (ZW-942100) or group (sqli, xss, lfi, rce, java, xxe, ssrf, protocol, scanner).
	Exclude       []string `json:"exclude,omitempty"`
	InspectBodyKB int      `json:"inspect_body_kb,omitempty"` // request body bytes inspected (default 8, max 256)
	SkipBody      bool     `json:"skip_body,omitempty"`       // inspect the URL and headers only
	// Rules are custom rules, evaluated before the built-in ones.
	Rules []GatewayWAFRule `json:"rules,omitempty"`
}

// GatewayWAFRule is a custom rule: when the target matches, the action applies.
type GatewayWAFRule struct {
	ID string `json:"id"`
	// Target: path, query, arg:NAME, header:Name, cookie:NAME, body, method, host, user_agent or ip.
	Target string `json:"target"`
	Op     string `json:"op"` // eq, contains, prefix, suffix, regex (case-insensitive, on the decoded value) or cidr (ip)
	Value  string `json:"value"`
	Not    bool   `json:"not,omitempty"` // the condition is that the op does NOT match
	// Action: allow (skip the WAF for this request), deny, log (record only) or score (add Score).
	Action string `json:"action"`
	Score  int    `json:"score,omitempty"` // 1-20, for action score (default 3)
}

// GatewayBan blocks an address or network until it expires.
type GatewayBan struct {
	Addr   string `json:"addr"`            // IP or CIDR
	Until  string `json:"until,omitempty"` // RFC 3339; empty = until removed
	Reason string `json:"reason,omitempty"`
}

// GatewayAutoBan bans clients that keep getting blocked. Each gateway node counts for itself.
type GatewayAutoBan struct {
	Strikes  int    `json:"strikes,omitempty"`  // blocked requests within Window that earn a ban (default 5)
	Window   string `json:"window,omitempty"`   // default 1m
	Duration string `json:"duration,omitempty"` // first ban (default 10m); doubles per repeat
	Max      string `json:"max,omitempty"`      // longest ban (default 24h)
	// Kernel also bans the address in the host firewall (every port, not just the gateway's).
	Kernel bool `json:"kernel,omitempty"`
}

var (
	wafRuleIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	wafExcludeRe = regexp.MustCompile(`^(ZW-[0-9]{6}|sqli|xss|lfi|rce|java|xxe|ssrf|protocol|scanner)$`)
	wafTargetRe  = regexp.MustCompile(`^(path|query|body|method|host|user_agent|ip|(arg|header|cookie):[A-Za-z0-9_.~-]{1,64})$`)
)

// ParseAddrOrPrefix reads an IP or a CIDR as a masked prefix.
func ParseAddrOrPrefix(s string) (netip.Prefix, error) { return ParseProxyPrefix(s) }

// Validate checks a WAF configuration.
func (w *GatewayWAF) Validate() error {
	switch w.Mode {
	case "", WAFOff, WAFDetect, WAFBlock:
	default:
		return fmt.Errorf("waf mode must be off, detect or block")
	}
	if w.Level < 0 || w.Level > 3 {
		return fmt.Errorf("waf level must be 1-3")
	}
	if w.Threshold < 0 || w.Threshold > 100 {
		return fmt.Errorf("waf threshold must be 1-100")
	}
	if w.InspectBodyKB < 0 || w.InspectBodyKB > WAFMaxBodyKB {
		return fmt.Errorf("waf inspect_body_kb must be 1-%d", WAFMaxBodyKB)
	}
	if len(w.Exclude) > 128 {
		return fmt.Errorf("too many waf exclusions")
	}
	for _, e := range w.Exclude {
		if !wafExcludeRe.MatchString(e) {
			return fmt.Errorf("waf exclusion %q must be a rule ID (ZW-942100) or a group (sqli, xss, lfi, rce, java, xxe, ssrf, protocol, scanner)", e)
		}
	}
	if len(w.Rules) > WAFMaxRules {
		return fmt.Errorf("at most %d custom waf rules", WAFMaxRules)
	}
	seen := map[string]bool{}
	for _, r := range w.Rules {
		if !wafRuleIDRe.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("custom waf rule IDs must be unique names (a-z 0-9 _ -), got %q", r.ID)
		}
		seen[r.ID] = true
		if err := r.validate(); err != nil {
			return fmt.Errorf("waf rule %s: %v", r.ID, err)
		}
	}
	return nil
}

func (r GatewayWAFRule) validate() error {
	if !wafTargetRe.MatchString(r.Target) {
		return fmt.Errorf("target must be path, query, body, method, host, user_agent, ip, arg:NAME, header:Name or cookie:NAME")
	}
	if len(r.Value) > maxMatchValue || strings.ContainsAny(r.Value, "\x00") {
		return fmt.Errorf("value too long or invalid")
	}
	switch r.Op {
	case "eq", "contains", "prefix", "suffix":
		if r.Value == "" {
			return fmt.Errorf("needs a value")
		}
	case "regex":
		if r.Value == "" || len(r.Value) > maxRegexLen {
			return fmt.Errorf("regex must be 1-%d characters", maxRegexLen)
		}
		if _, err := regexp.Compile(r.Value); err != nil {
			return err
		}
	case "cidr":
		if r.Target != "ip" {
			return fmt.Errorf("cidr is for the ip target")
		}
		if _, err := ParseAddrOrPrefix(r.Value); err != nil {
			return fmt.Errorf("invalid address or network %q", r.Value)
		}
	default:
		return fmt.Errorf("op must be eq, contains, prefix, suffix, regex or cidr")
	}
	if r.Target == "ip" && r.Op != "cidr" && r.Op != "eq" {
		return fmt.Errorf("the ip target takes eq or cidr")
	}
	switch r.Action {
	case "allow", "deny", "log":
		if r.Score != 0 {
			return fmt.Errorf("score is for action score")
		}
	case "score":
		if r.Score < 0 || r.Score > 20 {
			return fmt.Errorf("score must be 1-20")
		}
	default:
		return fmt.Errorf("action must be allow, deny, log or score")
	}
	return nil
}

// ValidCIDRList checks a list of addresses and networks.
func ValidCIDRList(list []string, max int) error {
	if len(list) > max {
		return fmt.Errorf("too many entries (max %d)", max)
	}
	for _, c := range list {
		if _, err := ParseAddrOrPrefix(c); err != nil {
			return fmt.Errorf("invalid address or network %q", c)
		}
	}
	return nil
}

// Validate checks a ban.
func (b GatewayBan) Validate() error {
	if _, err := ParseAddrOrPrefix(b.Addr); err != nil {
		return fmt.Errorf("invalid address or network %q", b.Addr)
	}
	if b.Until != "" {
		if _, err := time.Parse(time.RFC3339, b.Until); err != nil {
			return fmt.Errorf("ban until must be RFC 3339")
		}
	}
	if len(b.Reason) > 200 || strings.ContainsAny(b.Reason, "\r\n\x00") {
		return fmt.Errorf("invalid ban reason")
	}
	return nil
}

// Expired reports whether the ban has run out at now.
func (b GatewayBan) Expired(now time.Time) bool {
	if b.Until == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, b.Until)
	return err != nil || !now.Before(t)
}

// Validate checks the automatic-ban policy.
func (a *GatewayAutoBan) Validate() error {
	if a.Strikes < 0 || a.Strikes > 1000 {
		return fmt.Errorf("auto-ban strikes must be 1-1000")
	}
	for name, v := range map[string]struct {
		s      string
		lo, hi time.Duration
	}{"window": {a.Window, time.Second, time.Hour}, "duration": {a.Duration, time.Second, 7 * 24 * time.Hour},
		"max": {a.Max, time.Second, 30 * 24 * time.Hour}} {
		if v.s != "" && !validDuration(v.s, v.lo, v.hi) {
			return fmt.Errorf("auto-ban %s must be between %v and %v", name, v.lo, v.hi)
		}
	}
	return nil
}

package schema

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Traffic management: matching beyond host and path, timeouts, retries, ejection of failing
// upstreams, load shedding, mirroring, rewrites, CORS and TLS to upstreams. Every field is
// optional; a route without them behaves as it always did.

// Matcher operators.
const (
	MatchEq      = "eq" // the value equals (default)
	MatchPresent = "present"
	MatchPrefix  = "prefix"
	MatchRegex   = "regex"
)

// GatewayMatcher is a condition on a request header, query parameter or cookie.
type GatewayMatcher struct {
	Name  string `json:"name"`
	Op    string `json:"op,omitempty"`    // eq (default), present, prefix or regex
	Value string `json:"value,omitempty"` // not used by present; a RE2 expression for regex
}

// GatewayTimeouts bound the phases of a proxied request. Durations are Go durations ("5s").
type GatewayTimeouts struct {
	Connect        string `json:"connect,omitempty"`         // dialing an upstream (default 5s)
	ResponseHeader string `json:"response_header,omitempty"` // waiting for response headers, per attempt (default 60s, or timeout)
	Request        string `json:"request,omitempty"`         // the whole exchange, streaming included (default none)
	Idle           string `json:"idle,omitempty"`            // longest silence from the upstream while streaming (default none)
}

// GatewayOutlier ejects upstreams that keep failing and brings them back gradually.
type GatewayOutlier struct {
	Consecutive     int    `json:"consecutive,omitempty"`       // failures in a row before ejection (default 5)
	EjectFor        string `json:"eject_for,omitempty"`         // first ejection time (default 30s); doubles per repeat, up to 10m
	MaxEjectPercent int    `json:"max_eject_percent,omitempty"` // never eject more than this share of targets (default 50)
	SlowStart       string `json:"slow_start,omitempty"`        // ramp traffic back to a recovered upstream over this long (default off)
}

// GatewayMirror copies a share of the traffic to another upstream and discards the answer.
type GatewayMirror struct {
	App     string `json:"app,omitempty"`
	Address string `json:"address,omitempty"` // IP:port
	Percent int    `json:"percent,omitempty"` // 1-100 (default 100)
}

// GatewayRewrite rewrites the request path with a RE2 expression ($1 refers to a group).
type GatewayRewrite struct {
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// GatewayCORS answers preflight requests and adds the CORS response headers itself.
type GatewayCORS struct {
	Origins     []string `json:"origins"`           // exact origins, or "*"
	Methods     []string `json:"methods,omitempty"` // default GET, HEAD, POST
	Headers     []string `json:"headers,omitempty"` // allowed request headers; empty echoes the request's
	Expose      []string `json:"expose,omitempty"`
	Credentials bool     `json:"credentials,omitempty"`
	MaxAge      int      `json:"max_age,omitempty"` // seconds a preflight may be cached (default 600)
}

// GatewayUpstreamTLS configures certificate verification toward https upstreams.
type GatewayUpstreamTLS struct {
	ServerName string `json:"server_name,omitempty"` // name to verify and send as SNI (default: the upstream address)
	CAPEM      string `json:"ca_pem,omitempty"`      // trusted CA certificates (PEM); empty = the system roots
}

var (
	// QueryNameRe matches query parameter and cookie names.
	QueryNameRe = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,64}$`)
	originRe    = regexp.MustCompile(`^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
	hashKeyRe   = regexp.MustCompile(`^(ip|(header|cookie|query):[A-Za-z0-9_.~-]{1,64})$`)
)

const (
	maxMatchers   = 16
	maxRegexLen   = 256
	maxMatchValue = 1024
)

func validDuration(s string, lo, hi time.Duration) bool {
	d, err := time.ParseDuration(s)
	return err == nil && d >= lo && d <= hi
}

func validMatchers(kind string, ms []GatewayMatcher, name func(string) bool) error {
	if len(ms) > maxMatchers {
		return fmt.Errorf("too many %s matchers (max %d)", kind, maxMatchers)
	}
	for _, m := range ms {
		if !name(m.Name) {
			return fmt.Errorf("invalid %s matcher name %q", kind, m.Name)
		}
		if len(m.Value) > maxMatchValue || strings.ContainsAny(m.Value, "\r\n\x00") {
			return fmt.Errorf("invalid %s matcher value for %q", kind, m.Name)
		}
		switch m.Op {
		case "", MatchEq, MatchPrefix:
		case MatchPresent:
			if m.Value != "" {
				return fmt.Errorf("%s matcher %q: present takes no value", kind, m.Name)
			}
		case MatchRegex:
			if len(m.Value) > maxRegexLen {
				return fmt.Errorf("%s matcher %q: expression longer than %d", kind, m.Name, maxRegexLen)
			}
			if _, err := regexp.Compile(m.Value); err != nil {
				return fmt.Errorf("%s matcher %q: %v", kind, m.Name, err)
			}
		default:
			return fmt.Errorf("%s matcher %q: op must be eq, present, prefix or regex", kind, m.Name)
		}
	}
	return nil
}

// validTraffic checks the traffic-management fields of a route.
func (r *GatewayRoute) validTraffic() error {
	httpOnly := r.PathRegex != "" || len(r.HeaderMatchers)+len(r.QueryMatchers)+len(r.CookieMatchers) > 0 ||
		r.Timeouts != nil || len(r.RetryOn) > 0 || r.Outlier != nil || r.MaxConcurrent != 0 || r.MaxUpstreamConns != 0 ||
		r.HashKey != "" || r.Mirror != nil || r.Rewrite != nil || r.CORS != nil || r.SecurityHeaders ||
		r.UpstreamProto != "" || r.UpstreamTLS != nil || r.RateKey != "" || r.RateBurst != 0
	if httpOnly && r.Kind != "http" {
		return fmt.Errorf("matchers, timeouts, ejection, limits, mirroring, rewrites, CORS and upstream TLS are for http routes")
	}

	if r.PathRegex != "" {
		if len(r.PathRegex) > maxRegexLen {
			return fmt.Errorf("path regex longer than %d", maxRegexLen)
		}
		if _, err := regexp.Compile(r.PathRegex); err != nil {
			return fmt.Errorf("path regex: %v", err)
		}
	}
	if err := validMatchers("header", r.HeaderMatchers, HeaderNameRe.MatchString); err != nil {
		return err
	}
	if err := validMatchers("query", r.QueryMatchers, QueryNameRe.MatchString); err != nil {
		return err
	}
	if err := validMatchers("cookie", r.CookieMatchers, QueryNameRe.MatchString); err != nil {
		return err
	}

	if t := r.Timeouts; t != nil {
		for name, c := range map[string]struct {
			v      string
			lo, hi time.Duration
		}{
			"connect":         {t.Connect, 100 * time.Millisecond, time.Minute},
			"response_header": {t.ResponseHeader, time.Second, time.Hour},
			"request":         {t.Request, time.Second, 24 * time.Hour},
			"idle":            {t.Idle, time.Second, time.Hour},
		} {
			if c.v != "" && !validDuration(c.v, c.lo, c.hi) {
				return fmt.Errorf("timeouts.%s must be between %v and %v", name, c.lo, c.hi)
			}
		}
	}

	if len(r.RetryOn) > 4 {
		return fmt.Errorf("retry_on has too many entries")
	}
	for _, c := range r.RetryOn {
		switch c {
		case "connect", "5xx", "timeout", "reset":
		default:
			return fmt.Errorf("retry_on must be connect, 5xx, timeout or reset")
		}
	}
	if len(r.RetryOn) > 0 && r.Retries == 0 {
		return fmt.Errorf("retry_on needs retries > 0")
	}
	if r.RetryBudget < 0 || r.RetryBudget > 100 {
		return fmt.Errorf("retry_budget must be 0-100 (percent of requests)")
	}

	if o := r.Outlier; o != nil {
		if o.Consecutive < 0 || o.Consecutive > 100 || o.MaxEjectPercent < 0 || o.MaxEjectPercent > 100 {
			return fmt.Errorf("outlier: consecutive and max_eject_percent must be 0-100")
		}
		if o.EjectFor != "" && !validDuration(o.EjectFor, time.Second, time.Hour) {
			return fmt.Errorf("outlier eject_for must be 1s-1h")
		}
		if o.SlowStart != "" && !validDuration(o.SlowStart, time.Second, 10*time.Minute) {
			return fmt.Errorf("outlier slow_start must be 1s-10m")
		}
	}
	if r.MaxConcurrent < 0 || r.MaxConcurrent > 1_000_000 || r.MaxUpstreamConns < 0 || r.MaxUpstreamConns > 1_000_000 {
		return fmt.Errorf("max_concurrent and max_upstream_conns must be 0-1000000")
	}

	if (r.LB == "hash") != (r.HashKey != "") {
		return fmt.Errorf("lb hash needs hash_key (ip, header:Name, cookie:Name or query:name), and only lb hash takes one")
	}
	if r.HashKey != "" && !hashKeyRe.MatchString(r.HashKey) {
		return fmt.Errorf("hash_key must be ip, header:Name, cookie:Name or query:name")
	}
	if r.RateKey != "" && !hashKeyRe.MatchString(r.RateKey) {
		return fmt.Errorf("rate_key must be ip, header:Name, cookie:Name or query:name")
	}
	if (r.RateKey != "" || r.RateBurst != 0) && r.RateRPS == 0 {
		return fmt.Errorf("rate_key and rate_burst need a rate")
	}
	if r.RateBurst < 0 || r.RateBurst > 1_000_000 {
		return fmt.Errorf("rate_burst must be 0-1000000")
	}

	if m := r.Mirror; m != nil {
		if (m.App == "") == (m.Address == "") {
			return fmt.Errorf("a mirror is an app or an address")
		}
		if m.App != "" {
			if err := ValidName(m.App); err != nil {
				return err
			}
		}
		if m.Address != "" {
			if _, err := netip.ParseAddrPort(m.Address); err != nil {
				return fmt.Errorf("invalid mirror address %q (want IP:port)", m.Address)
			}
		}
		if m.Percent < 0 || m.Percent > 100 {
			return fmt.Errorf("mirror percent must be 1-100")
		}
	}

	if w := r.Rewrite; w != nil {
		if w.Pattern == "" || len(w.Pattern) > maxRegexLen || len(w.Replace) > maxRegexLen || strings.ContainsAny(w.Replace, "\r\n\x00?# ") {
			return fmt.Errorf("rewrite needs a pattern and a path replacement")
		}
		if _, err := regexp.Compile(w.Pattern); err != nil {
			return fmt.Errorf("rewrite pattern: %v", err)
		}
	}

	if c := r.CORS; c != nil {
		if len(c.Origins) == 0 || len(c.Origins) > 16 {
			return fmt.Errorf("cors needs 1-16 origins")
		}
		for _, o := range c.Origins {
			if o != "*" && !originRe.MatchString(o) {
				return fmt.Errorf("invalid CORS origin %q (want https://host[:port] or *)", o)
			}
			if o == "*" && c.Credentials {
				return fmt.Errorf("CORS with credentials needs explicit origins, not *")
			}
		}
		if len(c.Methods) > 10 || len(c.Headers) > 16 || len(c.Expose) > 16 {
			return fmt.Errorf("too many CORS methods or headers")
		}
		for _, m := range c.Methods {
			if !MethodRe.MatchString(m) {
				return fmt.Errorf("invalid CORS method %q", m)
			}
		}
		for _, h := range append(append([]string{}, c.Headers...), c.Expose...) {
			if !HeaderNameRe.MatchString(h) {
				return fmt.Errorf("invalid CORS header %q", h)
			}
		}
		if c.MaxAge < 0 || c.MaxAge > 86400 {
			return fmt.Errorf("cors max_age must be 0-86400")
		}
	}

	switch r.UpstreamProto {
	case "", "http", "h2c":
		if r.UpstreamTLS != nil {
			return fmt.Errorf("upstream_tls needs upstream_proto https")
		}
	case "https":
		if t := r.UpstreamTLS; t != nil {
			if t.ServerName != "" && !ValidHost(t.ServerName) {
				return fmt.Errorf("invalid upstream_tls server_name %q", t.ServerName)
			}
			if t.CAPEM != "" {
				if len(t.CAPEM) > 64<<10 {
					return fmt.Errorf("upstream_tls ca_pem is larger than 64 KB")
				}
				if !validCAPEM(t.CAPEM) {
					return fmt.Errorf("upstream_tls ca_pem holds no valid certificate")
				}
			}
		}
	default:
		return fmt.Errorf("upstream_proto must be http, https or h2c")
	}
	return nil
}

func validCAPEM(s string) bool {
	rest, n := []byte(s), 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return n > 0
		}
		if b.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
}

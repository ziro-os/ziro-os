package cmd

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

// CLI flags for the traffic-management settings of a route. Scalars bind straight to the route;
// the rest are parsed here into the route's structures.

type trafficFlags struct {
	headerMatch, query, cookie                        []string
	connectTimeout, requestTimeout, idleTimeout       string
	retryOn                                           []string
	outlierConsecutive, outlierMaxPct                 int
	outlierEjectFor, outlierSlowStart                 string
	mirror, rewrite                                   string
	corsOrigins, corsMethods, corsHeaders, corsExpose []string
	corsCredentials                                   bool
	corsMaxAge                                        int
	upstreamCAFile, upstreamServerName                string
}

func registerTrafficFlags(f *pflag.FlagSet, r *GatewayRoute, t *trafficFlags) {
	f.StringVar(&r.PathRegex, "path-regex", "", "Also require the path to match this RE2 expression")
	f.StringArrayVar(&t.headerMatch, "header-match", nil, "Header condition: Name (present), Name=value, Name^=prefix or Name~=regex (repeatable)")
	f.StringArrayVar(&t.query, "query", nil, "Query parameter condition: name, name=value, name^=prefix or name~=regex (repeatable)")
	f.StringArrayVar(&t.cookie, "cookie", nil, "Cookie condition: name, name=value, name^=prefix or name~=regex (repeatable)")

	f.StringVar(&t.connectTimeout, "connect-timeout", "", "Time allowed to reach an upstream (default 5s)")
	f.StringVar(&t.requestTimeout, "request-timeout", "", "Limit for the whole exchange, streaming included (default none)")
	f.StringVar(&t.idleTimeout, "idle-timeout", "", "Longest silence from the upstream while streaming (default none)")
	f.StringSliceVar(&t.retryOn, "retry-on", nil, "Also retry after: 5xx, timeout, reset (idempotent requests without a body; needs --retries)")
	f.IntVar(&r.RetryBudget, "retry-budget", 0, "Retries may be at most this percent of requests (default 20)")

	f.IntVar(&t.outlierConsecutive, "outlier-failures", 0, "Eject an upstream after this many failures in a row (default 5 once any outlier flag is set)")
	f.StringVar(&t.outlierEjectFor, "outlier-eject-for", "", "First ejection time, doubling per repeat (default 30s)")
	f.IntVar(&t.outlierMaxPct, "outlier-max-percent", 0, "Never eject more than this percent of upstreams (default 50)")
	f.StringVar(&t.outlierSlowStart, "outlier-slow-start", "", "Ramp traffic back to a recovered upstream over this time")
	f.IntVar(&r.MaxConcurrent, "max-concurrent", 0, "Requests in flight on the route; over it gets 503 (0 = unlimited)")
	f.IntVar(&r.MaxUpstreamConns, "max-upstream-conns", 0, "Requests in flight per upstream (0 = unlimited)")

	f.StringVar(&r.HashKey, "hash-key", "", "With --lb hash: ip, header:Name, cookie:Name or query:name")
	f.StringVar(&r.RateKey, "rate-key", "", "What --rate counts per: ip (default), header:Name, cookie:Name or query:name")
	f.IntVar(&r.RateBurst, "rate-burst", 0, "Burst allowed above --rate (default: the rate, at least 10)")

	f.StringVar(&t.mirror, "mirror", "", "Copy traffic to an app or ip:port and discard the answer: target[@percent]")
	f.StringVar(&t.rewrite, "rewrite", "", "Rewrite the path: 'pattern=>replacement' (RE2, $1 for groups)")
	f.StringArrayVar(&t.corsOrigins, "cors-origin", nil, "Allow this origin (https://app.example.com, or *); answers preflights (repeatable)")
	f.StringSliceVar(&t.corsMethods, "cors-methods", nil, "CORS allowed methods (default GET, HEAD, POST)")
	f.StringSliceVar(&t.corsHeaders, "cors-headers", nil, "CORS allowed request headers (default: whatever the preflight asks for)")
	f.StringSliceVar(&t.corsExpose, "cors-expose", nil, "CORS response headers scripts may read")
	f.BoolVar(&t.corsCredentials, "cors-credentials", false, "CORS: allow cookies and credentials (needs explicit origins)")
	f.IntVar(&t.corsMaxAge, "cors-max-age", 0, "CORS: seconds a preflight may be cached (default 600)")
	f.BoolVar(&r.SecurityHeaders, "security-headers", false, "Add nosniff, frame and referrer headers the app does not set")

	f.StringVar(&r.UpstreamProto, "upstream-proto", "", "Speak http (default), https or h2c to the upstreams")
	f.StringVar(&t.upstreamCAFile, "upstream-ca-file", "", "CA certificate (PEM) that signs the https upstreams (default: system roots)")
	f.StringVar(&t.upstreamServerName, "upstream-server-name", "", "Name to verify on https upstreams (default: their address)")
}

// parseMatcher reads name, name=value, name^=prefix or name~=regex.
func parseMatcher(s string) (GatewayMatcher, error) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return GatewayMatcher{Name: s, Op: "present"}, s2err(s == "", s)
	}
	name, op := s[:i], "eq"
	if i > 0 && (s[i-1] == '^' || s[i-1] == '~') {
		name, op = s[:i-1], map[byte]string{'^': "prefix", '~': "regex"}[s[i-1]]
	}
	return GatewayMatcher{Name: name, Op: op, Value: s[i+1:]}, s2err(name == "", s)
}

func s2err(bad bool, s string) error {
	if bad {
		return fmt.Errorf("invalid condition %q (want name, name=value, name^=prefix or name~=regex)", s)
	}
	return nil
}

func parseMatchers(list []string) ([]GatewayMatcher, error) {
	var out []GatewayMatcher
	for _, e := range list {
		m, err := parseMatcher(e)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// applyTrafficFlags fills the route's composite traffic settings from the flags.
func applyTrafficFlags(r *GatewayRoute, t trafficFlags) error {
	var err error
	if r.HeaderMatchers, err = parseMatchers(t.headerMatch); err != nil {
		return err
	}
	if r.QueryMatchers, err = parseMatchers(t.query); err != nil {
		return err
	}
	if r.CookieMatchers, err = parseMatchers(t.cookie); err != nil {
		return err
	}
	if t.connectTimeout != "" || t.requestTimeout != "" || t.idleTimeout != "" {
		r.Timeouts = &GatewayTimeouts{Connect: t.connectTimeout, Request: t.requestTimeout, Idle: t.idleTimeout}
	}
	r.RetryOn = t.retryOn
	if t.outlierConsecutive != 0 || t.outlierMaxPct != 0 || t.outlierEjectFor != "" || t.outlierSlowStart != "" {
		r.Outlier = &GatewayOutlier{Consecutive: t.outlierConsecutive, MaxEjectPercent: t.outlierMaxPct,
			EjectFor: t.outlierEjectFor, SlowStart: t.outlierSlowStart}
	}
	if t.mirror != "" {
		target, pct := t.mirror, 0
		if i := strings.LastIndex(target, "@"); i > 0 {
			if pct, err = strconv.Atoi(target[i+1:]); err != nil {
				return fmt.Errorf("--mirror wants target[@percent]")
			}
			target = target[:i]
		}
		m := &GatewayMirror{Percent: pct}
		if _, perr := netip.ParseAddrPort(target); perr == nil {
			m.Address = target
		} else {
			m.App = target
		}
		r.Mirror = m
	}
	if t.rewrite != "" {
		pat, rep, ok := strings.Cut(t.rewrite, "=>")
		if !ok || pat == "" {
			return fmt.Errorf("--rewrite wants 'pattern=>replacement'")
		}
		r.Rewrite = &GatewayRewrite{Pattern: pat, Replace: rep}
	}
	if len(t.corsOrigins) > 0 {
		r.CORS = &GatewayCORS{Origins: t.corsOrigins, Methods: t.corsMethods, Headers: t.corsHeaders, Expose: t.corsExpose,
			Credentials: t.corsCredentials, MaxAge: t.corsMaxAge}
	} else if len(t.corsMethods)+len(t.corsHeaders)+len(t.corsExpose) > 0 || t.corsCredentials || t.corsMaxAge != 0 {
		return fmt.Errorf("--cors-* flags need at least one --cors-origin")
	}
	if t.upstreamCAFile != "" || t.upstreamServerName != "" {
		u := &GatewayUpstreamTLS{ServerName: t.upstreamServerName}
		if t.upstreamCAFile != "" {
			b, err := os.ReadFile(t.upstreamCAFile)
			if err != nil {
				return err
			}
			u.CAPEM = string(b)
		}
		r.UpstreamTLS = u
	}
	return nil
}

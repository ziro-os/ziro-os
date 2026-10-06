// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

package schema

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// GatewayRoute is one routing rule as the operator wrote it. The v1 fields (Host, PathPrefix,
// App) still work; Normalize turns them into their v2 form (Hosts, To).
type GatewayRoute struct {
	Name string `json:"name"`
	// Kind: "http" (default), "tcp" (raw TCP on Listen) or "tls" (TLS passthrough on :443,
	// routed by SNI; the upstream terminates TLS).
	Kind string `json:"kind,omitempty"`

	Host       string            `json:"host,omitempty"`  // v1: one host (Hosts[0] after Normalize)
	Hosts      []string          `json:"hosts,omitempty"` // exact names or "*.example.com" (one label)
	PathPrefix string            `json:"path_prefix,omitempty"`
	PathExact  bool              `json:"path_exact,omitempty"`
	Methods    []string          `json:"methods,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"` // request header must equal this value
	Listen     int               `json:"listen,omitempty"`  // tcp routes

	App string            `json:"app,omitempty"` // v1: one app (To[0] after Normalize)
	To  []GatewayUpstream `json:"to,omitempty"`
	LB  string            `json:"lb,omitempty"` // round_robin (default), least_conn, ip_hash, cookie

	Health *GatewayHealth `json:"health,omitempty"`

	Redirect     string          `json:"redirect,omitempty"`      // redirect instead of proxying; "{uri}" = request URI
	RedirectCode int             `json:"redirect_code,omitempty"` // 301, 302, 307, 308 (default)
	Respond      *GatewayRespond `json:"respond,omitempty"`       // a fixed response instead of proxying

	StripPrefix     string       `json:"strip_prefix,omitempty"`
	RequestHeaders  *HeaderRules `json:"request_headers,omitempty"`
	ResponseHeaders *HeaderRules `json:"response_headers,omitempty"`
	Retries         int          `json:"retries,omitempty"` // extra attempts on another upstream after a dial error (idempotent requests)
	Timeout         string       `json:"timeout,omitempty"` // upstream response header timeout (default 60s)
	Compress        bool         `json:"compress,omitempty"`

	// TLS: "auto" (ACME HTTP-01, default), "dns01" (a certificate issued through ACME DNS-01, which
	// can be a wildcard; needs a DNS provider), "off", "internal" (the gateway's own CA) or "cert:<name>".
	TLS        string            `json:"tls,omitempty"`
	AllowCIDRs []string          `json:"allow_cidrs,omitempty"`
	RateRPS    int               `json:"rate_rps,omitempty"`    // per client IP (requests, or connections for tcp/tls); 0 = unlimited
	MaxBodyMB  int               `json:"max_body_mb,omitempty"` // 0 = 10
	BasicAuth  map[string]string `json:"basic_auth,omitempty"`  // user -> bcrypt hash
}

// GatewayUpstream is a route target: an app (cluster app or local `apps` instance) or an
// IP:port, with a relative weight (canary releases).
type GatewayUpstream struct {
	App     string `json:"app,omitempty"`
	Address string `json:"address,omitempty"`
	Weight  int    `json:"weight,omitempty"` // default 1
}

type GatewayHealth struct {
	Path     string `json:"path"`
	Interval string `json:"interval,omitempty"` // default 10s
	Expect   int    `json:"expect,omitempty"`   // status code; default any 2xx/3xx
}

type GatewayRespond struct {
	Status int    `json:"status"`
	Body   string `json:"body,omitempty"`
}

type HeaderRules struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// GatewayACME configures certificate issuance (Let's Encrypt by default, or a private ACME CA).
type GatewayACME struct {
	Email     string `json:"email,omitempty"`
	Directory string `json:"directory,omitempty"`
}

// GatewayDomain is the base domain of deployed apps: an app without a host of its own is
// published at <app>.<Name> through the gateway.
type GatewayDomain struct {
	Name string `json:"name,omitempty"`
	// WildcardCert serves the apps with one wildcard certificate (*.Name) issued through ACME
	// DNS-01 instead of one HTTP-01 certificate per host. Public names only.
	WildcardCert bool `json:"wildcard_cert,omitempty"`
}

// Host is the hostname app is published at ("" when no domain is set).
func (d GatewayDomain) Host(app string) string {
	if d.Name == "" {
		return ""
	}
	return app + "." + d.Name
}

// privateSuffixes are names no public CA will certify.
var privateSuffixes = []string{".local", ".internal", ".lan", ".localhost", ".test", ".home.arpa", ".corp", ".intranet"}

// PrivateDomain reports whether name can't get an ACME certificate: it has no dot, or ends in a
// reserved or private suffix.
func PrivateDomain(name string) bool {
	if !strings.Contains(name, ".") {
		return true
	}
	for _, s := range privateSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// TLS is the route TLS mode for apps under the domain: the gateway's own CA for private names;
// for public ones the wildcard certificate when asked for (ACME DNS-01), else ACME HTTP-01.
func (d GatewayDomain) TLS() string {
	switch {
	case PrivateDomain(d.Name):
		return "internal"
	case d.WildcardCert:
		return "dns01"
	}
	return "auto"
}

// GatewayCert is an uploaded certificate (PEM chain + key).
type GatewayCert struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// GatewayConfig is what a gateway serves: routes with their resolved targets.
type GatewayConfig struct {
	ACME   GatewayACME            `json:"acme"`
	Routes []GatewayRouteState    `json:"routes"`
	Certs  map[string]GatewayCert `json:"certs,omitempty"` // "cert:<name>" routes
	// InternalCA signs certificates for "internal" routes (PEM cert + key); empty = the gateway
	// keeps its own CA in gatewayCertDir.
	InternalCA *GatewayCert `json:"internal_ca,omitempty"`
}

type GatewayRouteState struct {
	GatewayRoute
	Upstreams []string        `json:"upstreams"`         // ip:port of every target (v1 gateways read only this)
	Targets   []GatewayTarget `json:"targets,omitempty"` // with weights
}

type GatewayTarget struct {
	Addr   string `json:"addr"`
	Weight int    `json:"weight"`
}

var (
	HostRe       = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	HeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)
	MethodRe     = regexp.MustCompile(`^[A-Z]{3,10}$`)
	BcryptRe     = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

func (r *GatewayRoute) Normalize() {
	if r.Kind == "" {
		r.Kind = "http"
	}
	if len(r.Hosts) == 0 && r.Host != "" {
		r.Hosts = []string{r.Host}
	}
	for i, h := range r.Hosts {
		r.Hosts[i] = strings.ToLower(strings.TrimSuffix(h, "."))
	}
	if len(r.Hosts) > 0 {
		r.Host = r.Hosts[0]
	}
	if len(r.To) == 0 && r.App != "" {
		r.To = []GatewayUpstream{{App: r.App}}
	}
	if r.App == "" && len(r.To) > 0 {
		r.App = r.To[0].App
	}
	for i := range r.To {
		if r.To[i].Weight == 0 {
			r.To[i].Weight = 1
		}
	}
	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(m)
	}
	if r.PathPrefix == "" {
		r.PathPrefix = "/"
	}
	if r.TLS == "" && r.Kind == "http" {
		r.TLS = "auto"
	}
	if r.LB == "" {
		r.LB = "round_robin"
	}
	if r.Redirect != "" && r.RedirectCode == 0 {
		r.RedirectCode = 308
	}
}

func ValidHost(h string) bool {
	return len(h) <= 253 && (HostRe.MatchString(h) || strings.HasPrefix(h, "*.") && HostRe.MatchString(h[2:]))
}

// validateRoute checks a route at every trust boundary: the CLI, the API, the master and the
// gateway reloading its config. Nothing unchecked steers the proxy.
func (r *GatewayRoute) Validate() error {
	if err := ValidName(r.Name); err != nil {
		return err
	}
	switch r.Kind {
	case "http", "tls":
		if len(r.Hosts) == 0 || len(r.Hosts) > 32 {
			return fmt.Errorf("a %s route needs 1-32 hosts", r.Kind)
		}
	case "tcp":
		if r.Listen < 1 || r.Listen > 65535 || r.Listen == 80 || r.Listen == 443 {
			return fmt.Errorf("a tcp route needs --listen 1-65535 (not 80 or 443)")
		}
	default:
		return fmt.Errorf("kind must be http, tcp or tls")
	}
	for _, h := range r.Hosts {
		if !ValidHost(h) {
			return fmt.Errorf("invalid host %q", h)
		}
	}
	if !strings.HasPrefix(r.PathPrefix, "/") || len(r.PathPrefix) > 256 ||
		strings.ContainsAny(r.PathPrefix, " \t\r\n?#") || strings.Contains(r.PathPrefix, "..") {
		return fmt.Errorf("invalid path prefix %q", r.PathPrefix)
	}
	if r.StripPrefix != "" && (!strings.HasPrefix(r.StripPrefix, "/") || len(r.StripPrefix) > 256 || strings.ContainsAny(r.StripPrefix, " \t\r\n?#")) {
		return fmt.Errorf("invalid strip prefix %q", r.StripPrefix)
	}
	for _, m := range r.Methods {
		if !MethodRe.MatchString(m) {
			return fmt.Errorf("invalid method %q", m)
		}
	}
	if len(r.Headers) > 16 {
		return fmt.Errorf("too many header matchers")
	}
	for k, v := range r.Headers {
		if !HeaderNameRe.MatchString(k) || len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid header matcher %q", k)
		}
	}
	for _, hr := range []*HeaderRules{r.RequestHeaders, r.ResponseHeaders} {
		if hr == nil {
			continue
		}
		if len(hr.Set)+len(hr.Remove) > 32 {
			return fmt.Errorf("too many header rules")
		}
		for k, v := range hr.Set {
			if !HeaderNameRe.MatchString(k) || len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
				return fmt.Errorf("invalid header rule %q", k)
			}
		}
		for _, k := range hr.Remove {
			if !HeaderNameRe.MatchString(k) {
				return fmt.Errorf("invalid header name %q", k)
			}
		}
	}
	handlers := 0
	if r.Redirect != "" {
		handlers++
		if len(r.Redirect) > 2048 || strings.ContainsAny(r.Redirect, " \t\r\n\x00") ||
			!strings.HasPrefix(r.Redirect, "https://") && !strings.HasPrefix(r.Redirect, "http://") && !strings.HasPrefix(r.Redirect, "/") {
			return fmt.Errorf("redirect must be an http(s):// URL or a path")
		}
		if r.RedirectCode != 301 && r.RedirectCode != 302 && r.RedirectCode != 307 && r.RedirectCode != 308 {
			return fmt.Errorf("redirect code must be 301, 302, 307 or 308")
		}
	}
	if r.Respond != nil {
		handlers++
		if r.Respond.Status < 200 || r.Respond.Status > 599 || len(r.Respond.Body) > 64<<10 {
			return fmt.Errorf("respond needs a status 200-599 and a body up to 64 KB")
		}
	}
	if len(r.To) > 0 {
		handlers++
	}
	if handlers != 1 || r.Kind != "http" && len(r.To) == 0 {
		return fmt.Errorf("a route needs exactly one of: upstreams (--app/--to), --redirect, --respond")
	}
	if len(r.To) > 32 {
		return fmt.Errorf("too many upstreams (max 32)")
	}
	for _, u := range r.To {
		switch {
		case u.App != "" && u.Address == "":
			if err := ValidName(u.App); err != nil {
				return err
			}
		case u.Address != "" && u.App == "":
			if _, err := netip.ParseAddrPort(u.Address); err != nil {
				return fmt.Errorf("invalid upstream address %q (want IP:port)", u.Address)
			}
		default:
			return fmt.Errorf("an upstream is an app or an address")
		}
		if u.Weight < 1 || u.Weight > 1000 {
			return fmt.Errorf("upstream weight must be 1-1000")
		}
	}
	switch r.LB {
	case "round_robin", "least_conn", "ip_hash", "cookie":
	default:
		return fmt.Errorf("lb must be round_robin, least_conn, ip_hash or cookie")
	}
	if r.LB == "cookie" && (r.Kind != "http" || r.TLS == "off") {
		return fmt.Errorf("cookie stickiness needs an HTTPS route (the cookie is Secure); use --lb ip_hash")
	}
	if h := r.Health; h != nil {
		if !strings.HasPrefix(h.Path, "/") || len(h.Path) > 256 || strings.ContainsAny(h.Path, " \t\r\n") {
			return fmt.Errorf("invalid health check path %q", h.Path)
		}
		if h.Interval != "" {
			if d, err := time.ParseDuration(h.Interval); err != nil || d < time.Second || d > time.Hour {
				return fmt.Errorf("health interval must be 1s-1h")
			}
		}
		if h.Expect != 0 && (h.Expect < 100 || h.Expect > 599) {
			return fmt.Errorf("health expect must be a status code")
		}
	}
	if r.Retries < 0 || r.Retries > 5 {
		return fmt.Errorf("retries must be 0-5")
	}
	if r.Timeout != "" {
		if d, err := time.ParseDuration(r.Timeout); err != nil || d < time.Second || d > time.Hour {
			return fmt.Errorf("timeout must be 1s-1h")
		}
	}
	switch {
	case r.Kind != "http":
	case r.TLS == "auto", r.TLS == "dns01", r.TLS == "off", r.TLS == "internal":
	case strings.HasPrefix(r.TLS, "cert:") && ValidName(strings.TrimPrefix(r.TLS, "cert:")) == nil:
	default:
		return fmt.Errorf("tls must be auto, dns01, off, internal or cert:<name>")
	}
	if r.TLS == "auto" {
		for _, h := range r.Hosts {
			if strings.HasPrefix(h, "*.") {
				return fmt.Errorf("ACME (HTTP-01) can't issue wildcard certificates: use --tls dns01 (with a DNS provider), cert:<name> or internal for %s", h)
			}
		}
	}
	if len(r.AllowCIDRs) > 64 {
		return fmt.Errorf("too many allow CIDRs")
	}
	for _, c := range r.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("invalid CIDR %q", c)
		}
	}
	if r.RateRPS < 0 || r.RateRPS > 100000 || r.MaxBodyMB < 0 || r.MaxBodyMB > 10240 {
		return fmt.Errorf("rate must be 0-100000 rps and max body 0-10240 MB")
	}
	if len(r.BasicAuth) > 64 {
		return fmt.Errorf("too many basic auth users")
	}
	for u, h := range r.BasicAuth {
		if ValidName(u) != nil || !BcryptRe.MatchString(h) {
			return fmt.Errorf("basic auth user %q needs a bcrypt hash", u)
		}
	}
	return nil
}

// RouteApps lists the apps a route sends traffic to.
func RouteApps(r GatewayRoute) []string {
	var out []string
	if r.App != "" {
		out = append(out, r.App)
	}
	for _, u := range r.To {
		if u.App != "" && u.App != r.App {
			out = append(out, u.App)
		}
	}
	return out
}

package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// zirogate: the L4/L7 gateway. Routes (hosts, path, method and header matchers -> apps or
// addresses) live in a route store: cluster state on a cluster (the master resolves them to
// running replicas and hands the result to gateway nodes in their heartbeat), or
// /etc/ziro/gateway/routes.json on a standalone host. `ziroctl gateway serve` hot-reloads the
// resolved config: TLS (ACME, uploaded certificates or an internal CA), HTTP/1.1, HTTP/2 and
// HTTP/3, load balancing with active and passive health checks, header rules, redirects,
// rate limits, basic auth, TCP and TLS-SNI passthrough, Prometheus metrics, JSON access log.
// The data plane is gateway_proxy.go; stores, the API and `expose` are gateway_store.go.

var (
	gatewayConfigPath = "/run/ziro/gateway/config.json"
	gatewayCertDir    = "/var/lib/ziro/gateway/certs"
)

const (
	gatewayDownFor     = 10 * time.Second // an upstream that failed a dial is skipped this long
	gatewayDefaultBody = 10               // MB
	gatewayMaxTargets  = 64
)

// GatewayRoute is one routing rule as the operator wrote it. The v1 fields (Host, PathPrefix,
// App) still work; normalize turns them into their v2 form (Hosts, To).
type GatewayRoute struct {
	Name string `json:"name"`
	// Kind: "http" (default), "tcp" (raw TCP on Listen) or "tls" (TLS passthrough on :443,
	// routed by SNI; the upstream terminates TLS).
	Kind string `json:"kind,omitempty"`

	Host       string            `json:"host,omitempty"`  // v1: one host (Hosts[0] after normalize)
	Hosts      []string          `json:"hosts,omitempty"` // exact names or "*.example.com" (one label)
	PathPrefix string            `json:"path_prefix,omitempty"`
	PathExact  bool              `json:"path_exact,omitempty"`
	Methods    []string          `json:"methods,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"` // request header must equal this value
	Listen     int               `json:"listen,omitempty"`  // tcp routes

	App string            `json:"app,omitempty"` // v1: one app (To[0] after normalize)
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

	// TLS: "auto" (ACME, default), "off", "internal" (the gateway's own CA) or "cert:<name>".
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
	hostRe       = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)
	methodRe     = regexp.MustCompile(`^[A-Z]{3,10}$`)
	bcryptRe     = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

func (r *GatewayRoute) normalize() {
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

func validHost(h string) bool {
	return len(h) <= 253 && (hostRe.MatchString(h) || strings.HasPrefix(h, "*.") && hostRe.MatchString(h[2:]))
}

// validateRoute checks a route at every trust boundary: the CLI, the API, the master and the
// gateway reloading its config. Nothing unchecked steers the proxy.
func validateRoute(r *GatewayRoute) error {
	if err := validName(r.Name); err != nil {
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
		if !validHost(h) {
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
		if !methodRe.MatchString(m) {
			return fmt.Errorf("invalid method %q", m)
		}
	}
	if len(r.Headers) > 16 {
		return fmt.Errorf("too many header matchers")
	}
	for k, v := range r.Headers {
		if !headerNameRe.MatchString(k) || len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
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
			if !headerNameRe.MatchString(k) || len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
				return fmt.Errorf("invalid header rule %q", k)
			}
		}
		for _, k := range hr.Remove {
			if !headerNameRe.MatchString(k) {
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
			if err := validName(u.App); err != nil {
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
	case r.TLS == "auto", r.TLS == "off", r.TLS == "internal":
	case strings.HasPrefix(r.TLS, "cert:") && validName(strings.TrimPrefix(r.TLS, "cert:")) == nil:
	default:
		return fmt.Errorf("tls must be auto, off, internal or cert:<name>")
	}
	if r.TLS == "auto" {
		for _, h := range r.Hosts {
			if strings.HasPrefix(h, "*.") {
				return fmt.Errorf("ACME (HTTP-01) can't issue wildcard certificates: use --tls cert:<name> or internal for %s", h)
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
		if validName(u) != nil || !bcryptRe.MatchString(h) {
			return fmt.Errorf("basic auth user %q needs a bcrypt hash", u)
		}
	}
	return nil
}

// routeApps lists the apps a route sends traffic to.
func routeApps(r GatewayRoute) []string {
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

// gatewaySources returns the gateway nodes' mesh IPs when some route targets app: routing an
// app is the operator's consent to expose it, so gateways pass its network policy.
func gatewaySources(st *ClusterState, app string) []string {
	routed := false
	for _, r := range st.Routes {
		for _, a := range routeApps(r) {
			routed = routed || a == app
		}
	}
	if !routed {
		return nil
	}
	var ips []string
	for _, n := range st.Nodes {
		if n.Gateway && n.MeshIP != "" {
			ips = append(ips, n.MeshIP)
		}
	}
	return ips
}

// clusterAppTargets resolves a cluster app to the running replicas' addresses (the same health
// signal as discovery): pod IPs and the container port on a pod network, mesh IPs and the host
// port otherwise.
func clusterAppTargets(st *ClusterState, eps, pods map[string][]string, app string) []string {
	a := st.app(app)
	if a == nil {
		return nil
	}
	port, proto, _ := strings.Cut(hostPortKey(a.Port), "/")
	if port == "" || proto != "tcp" {
		return nil
	}
	ips := eps[app]
	if len(pods[app]) > 0 {
		ips, port = pods[app], portMapRe.FindStringSubmatch(a.Port)[2]
	}
	var out []string
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, port))
	}
	return out
}

// resolveTargets expands a route's upstreams into weighted addresses. An app's weight is
// spread over its replicas, so a 90/10 canary stays 90/10 however many replicas each has.
func resolveTargets(r GatewayRoute, appAddrs func(app string) []string) GatewayRouteState {
	rs := GatewayRouteState{GatewayRoute: r, Upstreams: []string{}}
	for _, u := range r.To {
		addrs := []string{u.Address}
		if u.App != "" {
			addrs = appAddrs(u.App)
		}
		for _, a := range addrs {
			w := u.Weight * 1000 / max(len(addrs), 1)
			rs.Targets = append(rs.Targets, GatewayTarget{Addr: a, Weight: max(w, 1)})
			rs.Upstreams = append(rs.Upstreams, a)
		}
	}
	return rs
}

// gatewayConfigFor resolves the cluster's routes for gateway nodes.
func gatewayConfigFor(st *ClusterState) *GatewayConfig {
	cfg := &GatewayConfig{ACME: st.GatewayACME, Routes: []GatewayRouteState{}}
	eps, pods := appEndpoints(st), podEndpoints(st)
	for _, r := range st.Routes {
		r.normalize()
		cfg.Routes = append(cfg.Routes, resolveTargets(r, func(app string) []string {
			return clusterAppTargets(st, eps, pods, app)
		}))
		if strings.HasPrefix(r.TLS, "cert:") {
			name := strings.TrimPrefix(r.TLS, "cert:")
			if c := st.Secrets[gatewayCertSecret(name)]; c != nil {
				if cfg.Certs == nil {
					cfg.Certs = map[string]GatewayCert{}
				}
				cfg.Certs[name] = GatewayCert{Cert: c["cert"], Key: c["key"]}
			}
		}
	}
	if ca := st.Secrets[gatewayInternalCASecret]; ca != nil {
		cfg.InternalCA = &GatewayCert{Cert: ca["cert"], Key: ca["key"]}
	}
	return cfg
}

func gatewayCertSecret(name string) string { return "gateway-cert-" + name }

const gatewayInternalCASecret = "gateway-internal-ca"

// syncGatewayConfig runs in the agent: it (re)writes the config and starts or stops the
// gateway service as this node gains or loses the gateway label.
func syncGatewayConfig(cfg *GatewayConfig) error {
	if cfg == nil {
		if fileExists(gatewayConfigPath) {
			stopClusterServices("gateway")
			return os.Remove(gatewayConfigPath)
		}
		return nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	first := !fileExists(gatewayConfigPath)
	if cur, err := os.ReadFile(gatewayConfigPath); err != nil || string(cur) != string(data) {
		if err := os.MkdirAll(dirOf(gatewayConfigPath), 0700); err != nil {
			return err
		}
		if err := writeFileAtomic(gatewayConfigPath, data, 0600); err != nil {
			return err
		}
	}
	if first {
		startClusterServices("gateway")
	}
	return nil
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "."
}

// describeRoute is a one-line summary for listings.
func describeRoute(r GatewayRouteState) (match, target string) {
	switch r.Kind {
	case "tcp":
		match = "tcp :" + strconv.Itoa(r.Listen)
	case "tls":
		match = "tls " + strings.Join(r.Hosts, ",")
	default:
		match = strings.Join(r.Hosts, ",") + r.PathPrefix
		if len(r.Methods) > 0 {
			match = strings.Join(r.Methods, ",") + " " + match
		}
	}
	switch {
	case r.Redirect != "":
		target = fmt.Sprintf("redirect %d %s", r.RedirectCode, r.Redirect)
	case r.Respond != nil:
		target = fmt.Sprintf("respond %d", r.Respond.Status)
	default:
		var ts []string
		for _, u := range r.To {
			t := u.App
			if t == "" {
				t = u.Address
			}
			if u.Weight != 1 {
				t += fmt.Sprintf("(w%d)", u.Weight)
			}
			ts = append(ts, t)
		}
		target = strings.Join(ts, ",")
	}
	return match, target
}

func sortRoutes(rs []GatewayRoute) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
}

package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// zirogate: the cluster's L7 ingress. Routes (host + path prefix -> app) live in cluster state;
// the master resolves them to running upstreams on the mesh and hands the result to nodes
// labelled gateway in their heartbeat. The agent writes it to gatewayConfigPath and the
// `gateway` service (ziroctl gateway serve) hot-reloads it: TLS via ACME, per-route CIDR
// allowlists, per-client rate limits, body limits, passive health checks, JSON access log.

var (
	gatewayConfigPath = "/run/ziro/gateway/config.json"
	gatewayCertDir    = "/var/lib/ziro/gateway/certs"
)

const (
	gatewayDownFor     = 10 * time.Second // an upstream that failed a dial is skipped this long
	gatewayDefaultBody = 10               // MB
)

// GatewayRoute is one routing rule (stored on the master).
type GatewayRoute struct {
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	PathPrefix string   `json:"path_prefix,omitempty"` // default "/"
	App        string   `json:"app"`
	TLS        string   `json:"tls,omitempty"` // "auto" (ACME, default) or "off"
	AllowCIDRs []string `json:"allow_cidrs,omitempty"`
	RateRPS    int      `json:"rate_rps,omitempty"`    // per client IP; 0 = unlimited
	MaxBodyMB  int      `json:"max_body_mb,omitempty"` // 0 = 10
}

// GatewayACME configures certificate issuance (Let's Encrypt by default, or a private ACME CA).
type GatewayACME struct {
	Email     string `json:"email,omitempty"`
	Directory string `json:"directory,omitempty"`
}

// GatewayConfig is what a gateway node serves: routes with their current upstreams.
type GatewayConfig struct {
	ACME   GatewayACME         `json:"acme"`
	Routes []GatewayRouteState `json:"routes"`
}

type GatewayRouteState struct {
	GatewayRoute
	Upstreams []string `json:"upstreams"` // mesh-ip:port of running replicas
}

var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (r *GatewayRoute) normalize() {
	r.Host = strings.ToLower(strings.TrimSuffix(r.Host, "."))
	if r.PathPrefix == "" {
		r.PathPrefix = "/"
	}
	if r.TLS == "" {
		r.TLS = "auto"
	}
}

func validateRoute(r *GatewayRoute) error {
	if err := validName(r.Name); err != nil {
		return err
	}
	if len(r.Host) > 253 || !hostRe.MatchString(r.Host) {
		return fmt.Errorf("invalid host %q", r.Host)
	}
	if !strings.HasPrefix(r.PathPrefix, "/") || len(r.PathPrefix) > 256 ||
		strings.ContainsAny(r.PathPrefix, " \t\r\n?#") || strings.Contains(r.PathPrefix, "..") {
		return fmt.Errorf("invalid path prefix %q", r.PathPrefix)
	}
	if err := validName(r.App); err != nil {
		return err
	}
	if r.TLS != "auto" && r.TLS != "off" {
		return fmt.Errorf("tls must be auto or off")
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
	return nil
}

// gatewaySources returns the gateway nodes' mesh IPs when some route targets app: routing an
// app is the operator's consent to expose it, so gateways pass its network policy.
func gatewaySources(st *ClusterState, app string) []string {
	routed := false
	for _, r := range st.Routes {
		routed = routed || r.App == app
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

// gatewayConfigFor resolves routes to running upstreams (same health signal as discovery).
func gatewayConfigFor(st *ClusterState) *GatewayConfig {
	cfg := &GatewayConfig{ACME: st.GatewayACME, Routes: []GatewayRouteState{}}
	eps, pods := appEndpoints(st), podEndpoints(st)
	for _, r := range st.Routes {
		rs := GatewayRouteState{GatewayRoute: r, Upstreams: []string{}}
		if a := st.app(r.App); a != nil {
			if port, proto, _ := strings.Cut(hostPortKey(a.Port), "/"); port != "" && proto == "tcp" {
				ips := eps[r.App]
				if len(pods[r.App]) > 0 { // pod network: straight to the replicas' container port
					ips, port = pods[r.App], portMapRe.FindStringSubmatch(a.Port)[2]
				}
				for _, ip := range ips {
					rs.Upstreams = append(rs.Upstreams, net.JoinHostPort(ip, port))
				}
			}
		}
		cfg.Routes = append(cfg.Routes, rs)
	}
	return cfg
}

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

// ---- proxy ----

// tokenBucket allows rate requests/second with a burst of max(rate, 10) per client.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	clients map[string]*bucketState
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newTokenBucket(rps int) *tokenBucket {
	return &tokenBucket{rate: float64(rps), burst: math.Max(float64(rps), 10), clients: map[string]*bucketState{}}
}

func (b *tokenBucket) allow(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.clients[key]
	if s == nil {
		if len(b.clients) >= 100000 { // bound memory under a spoofed-source flood: evict full buckets
			for k, v := range b.clients {
				if v.tokens+now.Sub(v.last).Seconds()*b.rate >= b.burst {
					delete(b.clients, k)
				}
			}
		}
		s = &bucketState{tokens: b.burst, last: now}
		b.clients[key] = s
	}
	s.tokens = math.Min(b.burst, s.tokens+now.Sub(s.last).Seconds()*b.rate)
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

type gwRoute struct {
	GatewayRouteState
	allow   []netip.Prefix
	limiter *tokenBucket
	next    atomic.Uint64
}

func (r *gwRoute) matches(path string) bool {
	p := r.PathPrefix
	return p == "/" || path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/")
}

type gatewayServer struct {
	mu     sync.RWMutex
	routes map[string][]*gwRoute // host -> longest prefix first
	down   sync.Map              // upstream -> time.Time (skip until)
	proxy  *httputil.ReverseProxy
	log    func(v any)
}

type gwCtxKey struct{}

type gwCtx struct {
	upstream string
	tls      bool
}

func newGatewayServer() *gatewayServer {
	g := &gatewayServer{routes: map[string][]*gwRoute{}}
	g.log = func(v any) {
		if b, err := json.Marshal(v); err == nil {
			fmt.Println(string(b))
		}
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			c := pr.In.Context().Value(gwCtxKey{}).(*gwCtx)
			pr.SetURL(&url.URL{Scheme: "http", Host: c.upstream})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded() // replaces any client-supplied X-Forwarded-* headers
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		ModifyResponse: func(resp *http.Response) error {
			if c := resp.Request.Context().Value(gwCtxKey{}).(*gwCtx); c.tls && resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=31536000")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			c := r.Context().Value(gwCtxKey{}).(*gwCtx)
			var ne net.Error
			var oe *net.OpError
			if errors.As(err, &oe) && oe.Op == "dial" || errors.As(err, &ne) && ne.Timeout() && r.Context().Err() == nil {
				g.down.Store(c.upstream, time.Now().Add(gatewayDownFor))
			}
			status := http.StatusBadGateway
			if errors.Is(err, context.Canceled) {
				status = 499 // client went away
			}
			w.WriteHeader(status)
		},
	}
	return g
}

// load swaps in a new route table. Everything is re-validated: the file is written by the
// root agent, but nothing unchecked should steer the proxy.
func (g *gatewayServer) load(cfg *GatewayConfig) error {
	routes := map[string][]*gwRoute{}
	for _, rs := range cfg.Routes {
		rs.normalize()
		if err := validateRoute(&rs.GatewayRoute); err != nil {
			return fmt.Errorf("route %q: %w", rs.Name, err)
		}
		for _, u := range rs.Upstreams {
			if _, err := netip.ParseAddrPort(u); err != nil {
				return fmt.Errorf("route %q: invalid upstream %q", rs.Name, u)
			}
		}
		r := &gwRoute{GatewayRouteState: rs}
		for _, c := range rs.AllowCIDRs {
			p, _ := netip.ParsePrefix(c)
			r.allow = append(r.allow, p.Masked())
		}
		if rs.RateRPS > 0 {
			r.limiter = newTokenBucket(rs.RateRPS)
		}
		routes[rs.Host] = append(routes[rs.Host], r)
	}
	for _, rs := range routes {
		sort.SliceStable(rs, func(i, j int) bool { return len(rs[i].PathPrefix) > len(rs[j].PathPrefix) })
	}
	g.mu.Lock()
	g.routes = routes
	g.mu.Unlock()
	return nil
}

func (g *gatewayServer) match(host, path string) *gwRoute {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, r := range g.routes[host] {
		if r.matches(path) {
			return r
		}
	}
	return nil
}

func (g *gatewayServer) acmeHost(host string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, r := range g.routes[host] {
		if r.TLS == "auto" {
			return true
		}
	}
	return false
}

// pick round-robins over upstreams not marked down; if all are down, it tries anyway
// (better a probe than a guaranteed 503).
func (g *gatewayServer) pick(r *gwRoute, now time.Time) string {
	n := len(r.Upstreams)
	if n == 0 {
		return ""
	}
	start := r.next.Add(1)
	for i := 0; i < n; i++ {
		u := r.Upstreams[(start+uint64(i))%uint64(n)]
		if until, ok := g.down.Load(u); !ok || now.After(until.(time.Time)) {
			return u
		}
	}
	return r.Upstreams[start%uint64(n)]
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush/Hijack (streaming, WebSocket upgrades).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (g *gatewayServer) handler(isTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		upstream := ""
		defer func() {
			g.log(map[string]any{"ts": start.UTC().Format(time.RFC3339Nano), "client": ip, "host": host,
				"method": r.Method, "path": r.URL.Path, "status": sw.status, "bytes": sw.bytes,
				"ms": time.Since(start).Milliseconds(), "upstream": upstream})
		}()

		rt := g.match(host, r.URL.Path)
		switch {
		case rt == nil:
			http.Error(sw, "no route", http.StatusNotFound)
			return
		case !isTLS && rt.TLS == "auto":
			http.Redirect(sw, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		if len(rt.allow) > 0 {
			addr, err := netip.ParseAddr(ip)
			ok := false
			for _, p := range rt.allow {
				ok = ok || err == nil && p.Contains(addr.Unmap())
			}
			if !ok {
				http.Error(sw, "forbidden", http.StatusForbidden)
				return
			}
		}
		if rt.limiter != nil && !rt.limiter.allow(ip, start) {
			sw.Header().Set("Retry-After", "1")
			http.Error(sw, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		limit := int64(rt.MaxBodyMB)
		if limit == 0 {
			limit = gatewayDefaultBody
		}
		if r.ContentLength > limit<<20 {
			http.Error(sw, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(sw, r.Body, limit<<20)
		if upstream = g.pick(rt, start); upstream == "" {
			http.Error(sw, "no healthy upstream", http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), gwCtxKey{}, &gwCtx{upstream: upstream, tls: isTLS})
		g.proxy.ServeHTTP(sw, r.WithContext(ctx))
	})
}

// reload loads the config file if it changed since *last; a bad file keeps the last good
// table. It returns the newly loaded config, or nil.
func (g *gatewayServer) reload(path string, last *time.Time) *GatewayConfig {
	fi, err := os.Stat(path)
	if err != nil || fi.ModTime().Equal(*last) {
		return nil
	}
	*last = fi.ModTime()
	var cfg GatewayConfig
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	if err == nil {
		err = g.load(&cfg)
	}
	if err != nil {
		fmt.Printf("[gateway] config rejected, keeping previous routes: %v\n", err)
		return nil
	}
	fmt.Printf("[gateway] loaded %d routes\n", len(cfg.Routes))
	return &cfg
}

var (
	gwHTTPAddr  string
	gwHTTPSAddr string
)

var gatewayServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the gateway (started by the gateway service on gateway nodes)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		g := newGatewayServer()
		var last time.Time
		// After a reboot ziro-init may start this before the agent has rewritten the config
		// (it lives on tmpfs): wait for it, so the ACME account is built from real settings.
		cfg := g.reload(gatewayConfigPath, &last)
		for cfg == nil {
			time.Sleep(time.Second)
			cfg = g.reload(gatewayConfigPath, &last)
		}
		go func() {
			for range time.Tick(2 * time.Second) {
				g.reload(gatewayConfigPath, &last)
			}
		}()

		if err := os.MkdirAll(gatewayCertDir, 0700); err != nil {
			return err
		}
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(gatewayCertDir),
			HostPolicy: func(_ context.Context, host string) error {
				if !g.acmeHost(host) {
					return fmt.Errorf("no tls route for %q", host)
				}
				return nil
			},
		}
		// The ACME account (email, directory) is read at start; `gateway acme` asks for a restart.
		if cfg != nil {
			m.Email = cfg.ACME.Email
			if cfg.ACME.Directory != "" {
				m.Client = &acme.Client{DirectoryURL: cfg.ACME.Directory}
			}
		}
		var fw []FirewallRule
		for _, a := range []string{gwHTTPAddr, gwHTTPSAddr} {
			if p := portOf(a); p > 0 {
				fw = append(fw, FirewallRule{Port: p, Protocol: "tcp", Comment: "Ziro gateway"})
			}
		}
		allowFirewall(fw, "")

		mk := func(addr string, h http.Handler) *http.Server {
			return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout: 5 * time.Minute, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
		}
		httpSrv := mk(gwHTTPAddr, m.HTTPHandler(g.handler(false)))
		httpsSrv := mk(gwHTTPSAddr, g.handler(true))
		httpsSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate,
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto}}
		errc := make(chan error, 2)
		go func() { errc <- httpSrv.ListenAndServe() }()
		go func() { errc <- httpsSrv.ListenAndServeTLS("", "") }()
		fmt.Printf("[gateway] serving http %s, https %s\n", gwHTTPAddr, gwHTTPSAddr)
		return <-errc
	},
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// ---- CLI (master) ----

var gatewayCmd = &cobra.Command{
	Use:     "gateway",
	Aliases: []string{"zirogate"},
	Short:   "zirogate: cluster ingress (TLS, host/path routing, rate limits) on gateway nodes",
	Long: `Expose cluster apps through gateway nodes:

  ziroctl gateway node enable master-1
  ziroctl gateway acme --email ops@example.com
  ziroctl gateway route add web --host www.example.com --app web
  ziroctl gateway route add api --host www.example.com --path /api --app api --rate 50 --allow-cidr 10.0.0.0/8
  ziroctl gateway route ls

The target app needs a tcp --port. Routing to an app admits the gateway nodes through the
cluster network policy. TLS certificates come from ACME (HTTP-01), so DNS for the host must
point at the gateway nodes and tcp/80 must be reachable; use --tls off for plain HTTP.`,
}

var (
	gwRouteFlag GatewayRoute
	gwACMEFlag  GatewayACME
)

var gatewayRouteCmd = &cobra.Command{Use: "route", Short: "Manage gateway routes (master only)"}

var gatewayRouteAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Create or replace a route: host (+ path prefix) -> app",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		r := gwRouteFlag
		r.Name = args[0]
		r.normalize()
		if err := validateRoute(&r); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			a := st.app(r.App)
			if a == nil {
				return fmt.Errorf("app %q not found", r.App)
			}
			if _, proto, _ := strings.Cut(hostPortKey(a.Port), "/"); proto != "tcp" {
				return fmt.Errorf("app %q needs a tcp --port to be routed", r.App)
			}
			kept := st.Routes[:0]
			for _, x := range st.Routes {
				if x.Name == r.Name {
					continue
				}
				if x.Host == r.Host && x.PathPrefix == r.PathPrefix {
					return fmt.Errorf("route %q already serves %s%s", x.Name, x.Host, x.PathPrefix)
				}
				kept = append(kept, x)
			}
			st.Routes = append(kept, r)
			sort.Slice(st.Routes, func(i, j int) bool { return st.Routes[i].Name < st.Routes[j].Name })
			gw := 0
			for _, n := range st.Nodes {
				if n.Gateway {
					gw++
				}
			}
			fmt.Printf("✓ route %s: %s%s -> %s (tls %s)\n", r.Name, r.Host, r.PathPrefix, r.App, r.TLS)
			if gw == 0 {
				fmt.Println("  no gateway nodes yet: ziroctl gateway node enable <node>")
			}
			return nil
		})
	},
}

var gatewayRouteRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Remove a route", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			for i, r := range st.Routes {
				if r.Name == args[0] {
					st.Routes = append(st.Routes[:i], st.Routes[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("route %q not found", args[0])
		})
	},
}

var gatewayRouteLsCmd = &cobra.Command{
	Use: "ls", Short: "List routes with their live upstreams",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		cfg := gatewayConfigFor(st)
		return printResult(cfg.Routes, func() {
			fmt.Printf("%-14s %-32s %-12s %-5s %-6s %s\n", "NAME", "HOST+PATH", "APP", "TLS", "RATE", "UPSTREAMS")
			fmt.Println(strings.Repeat("-", 100))
			for _, r := range cfg.Routes {
				rate := "-"
				if r.RateRPS > 0 {
					rate = strconv.Itoa(r.RateRPS) + "/s"
				}
				ups := strings.Join(r.Upstreams, ",")
				if ups == "" {
					ups = "(none running)"
				}
				fmt.Printf("%-14s %-32s %-12s %-5s %-6s %s\n", r.Name, r.Host+r.PathPrefix, r.App, r.TLS, rate, ups)
			}
		})
	},
}

var gatewayNodeCmd = &cobra.Command{Use: "node", Short: "Choose which nodes run the gateway (master only)"}

func gatewayNodeSet(on bool) *cobra.Command {
	use, verb := "disable <node>", "Stop running the gateway on a node"
	if on {
		use, verb = "enable <node>", "Run the gateway on a node (serves tcp/80 and tcp/443)"
	}
	return &cobra.Command{Use: use, Short: verb, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return nodeOp(args[0], func(st *ClusterState, n *ClusterNode) error {
				n.Gateway = on
				fmt.Printf("✓ %s gateway: %v (applied on its next heartbeat)\n", n.ID, on)
				return nil
			})
		}}
}

var gatewayACMECmd = &cobra.Command{
	Use:   "acme",
	Short: "Set the ACME account email and optional directory URL (default Let's Encrypt)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if d := gwACMEFlag.Directory; d != "" && !strings.HasPrefix(d, "https://") {
			return fmt.Errorf("the ACME directory must be an https:// URL")
		}
		if e := gwACMEFlag.Email; e != "" && (!strings.Contains(e, "@") || strings.ContainsAny(e, " \t\r\n") || len(e) > 254) {
			return fmt.Errorf("invalid email %q", e)
		}
		return withState(func(st *ClusterState) error {
			st.GatewayACME = gwACMEFlag
			fmt.Println("✓ ACME settings saved; restart the gateway service on gateway nodes to use a new account")
			return nil
		})
	},
}

func init() {
	f := gatewayRouteAddCmd.Flags()
	f.StringVar(&gwRouteFlag.Host, "host", "", "Hostname clients use (e.g. www.example.com)")
	f.StringVar(&gwRouteFlag.PathPrefix, "path", "/", "Path prefix (longest match wins; matched on / boundaries)")
	f.StringVar(&gwRouteFlag.App, "app", "", "Cluster app to route to (needs a tcp --port)")
	f.StringVar(&gwRouteFlag.TLS, "tls", "auto", "auto (ACME certificate, HTTP redirects to HTTPS) or off")
	f.StringSliceVar(&gwRouteFlag.AllowCIDRs, "allow-cidr", nil, "Only clients from these CIDRs (repeatable)")
	f.IntVar(&gwRouteFlag.RateRPS, "rate", 0, "Requests per second per client IP (0 = unlimited)")
	f.IntVar(&gwRouteFlag.MaxBodyMB, "max-body-mb", 0, "Request body limit in MB (default 10)")
	_ = gatewayRouteAddCmd.MarkFlagRequired("host")
	_ = gatewayRouteAddCmd.MarkFlagRequired("app")
	gatewayACMECmd.Flags().StringVar(&gwACMEFlag.Email, "email", "", "ACME account contact email")
	gatewayACMECmd.Flags().StringVar(&gwACMEFlag.Directory, "directory", "", "ACME directory URL (private CA or LE staging)")
	gatewayServeCmd.Flags().StringVar(&gwHTTPAddr, "http", ":80", "HTTP listen address")
	gatewayServeCmd.Flags().StringVar(&gwHTTPSAddr, "https", ":443", "HTTPS listen address")

	gatewayRouteCmd.AddCommand(gatewayRouteAddCmd, gatewayRouteRmCmd, gatewayRouteLsCmd)
	gatewayNodeCmd.AddCommand(gatewayNodeSet(true), gatewayNodeSet(false))
	gatewayCmd.AddCommand(gatewayRouteCmd, gatewayNodeCmd, gatewayACMECmd, gatewayServeCmd)
	rootCmd.AddCommand(gatewayCmd)
}

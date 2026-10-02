package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

// Route stores: the cluster (master state; gateway nodes get resolved routes by heartbeat) or a
// standalone host (/etc/ziro/gateway). Both are managed by the same CLI and API.

var (
	gatewayLocalDir  = "/etc/ziro/gateway"
	gatewayAdminAddr = "127.0.0.1:2019"
)

// gatewayData is what a store holds.
type gatewayData struct {
	Routes []GatewayRoute `json:"routes"`
	ACME   GatewayACME    `json:"acme"`
}

type routeStore interface {
	name() string
	read() (*gatewayData, error)
	update(fn func(d *gatewayData) error) error
	config() (*GatewayConfig, error) // resolved, as a gateway serves it
	putCert(name string, c GatewayCert) error
	rmCert(name string) error
	certNames() ([]string, error)
	internalCA() (string, error) // PEM of the CA for "internal" routes
	appTargetsKnown(app string) error
}

// gatewayStore picks the store for this host: a cluster master edits cluster routes; a host
// outside any cluster edits its own.
func gatewayStore() (routeStore, error) {
	if cfg, err := loadClusterConfig(); err == nil {
		if cfg.Role != "master" {
			return nil, fmt.Errorf("this host is a cluster worker: manage gateway routes on the master (%s)", cfg.MasterAddr)
		}
		return clusterRouteStore{}, nil
	}
	return localRouteStore{dir: gatewayLocalDir}, nil
}

// ---- cluster store ----

type clusterRouteStore struct{}

func (clusterRouteStore) name() string { return "cluster" }

func (clusterRouteStore) read() (*gatewayData, error) {
	st, err := readState()
	if err != nil {
		return nil, err
	}
	return &gatewayData{Routes: st.Routes, ACME: st.GatewayACME}, nil
}

func (clusterRouteStore) update(fn func(d *gatewayData) error) error {
	return withState(func(st *ClusterState) error {
		d := &gatewayData{Routes: append([]GatewayRoute(nil), st.Routes...), ACME: st.GatewayACME}
		if err := fn(d); err != nil {
			return err
		}
		st.Routes, st.GatewayACME = d.Routes, d.ACME
		for _, r := range d.Routes {
			if r.TLS == "internal" && st.Secrets[gatewayInternalCASecret] == nil {
				c, k, err := newInternalCA()
				if err != nil {
					return err
				}
				if st.Secrets == nil {
					st.Secrets = map[string]map[string]string{}
				}
				st.Secrets[gatewayInternalCASecret] = map[string]string{"cert": string(c), "key": string(k)}
			}
		}
		return nil
	})
}

func (clusterRouteStore) config() (*GatewayConfig, error) {
	st, err := readState()
	if err != nil {
		return nil, err
	}
	return gatewayConfigFor(st), nil
}

// Certificates are cluster secrets (sealed at rest, replicated) and reach only gateway nodes.
func (clusterRouteStore) putCert(name string, c GatewayCert) error {
	return withState(func(st *ClusterState) error {
		if st.Secrets == nil {
			st.Secrets = map[string]map[string]string{}
		}
		st.Secrets[gatewayCertSecret(name)] = map[string]string{"cert": c.Cert, "key": c.Key}
		return nil
	})
}

func (clusterRouteStore) rmCert(name string) error {
	return withState(func(st *ClusterState) error {
		for _, r := range st.Routes {
			if r.TLS == "cert:"+name {
				return fmt.Errorf("route %s uses certificate %s", r.Name, name)
			}
		}
		if st.Secrets[gatewayCertSecret(name)] == nil {
			return fmt.Errorf("no certificate %q", name)
		}
		delete(st.Secrets, gatewayCertSecret(name))
		return nil
	})
}

func (clusterRouteStore) certNames() ([]string, error) {
	st, err := readState()
	if err != nil {
		return nil, err
	}
	var out []string
	for k := range st.Secrets {
		if n, ok := strings.CutPrefix(k, "gateway-cert-"); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func (clusterRouteStore) internalCA() (string, error) {
	st, err := readState()
	if err != nil {
		return "", err
	}
	if ca := st.Secrets[gatewayInternalCASecret]; ca != nil {
		return ca["cert"], nil
	}
	return "", errors.New("no internal CA yet: it is created with the first --tls internal route")
}

func (clusterRouteStore) appTargetsKnown(app string) error {
	st, err := readState()
	if err != nil {
		return err
	}
	a := st.app(app)
	if a == nil {
		return fmt.Errorf("cluster app %q not found", app)
	}
	if _, proto, _ := strings.Cut(hostPortKey(a.Port), "/"); proto != "tcp" {
		return fmt.Errorf("app %q needs a tcp --port to be routed (--mesh-only keeps it off public interfaces)", app)
	}
	return nil
}

// ---- local (standalone) store ----

type localRouteStore struct{ dir string }

func (s localRouteStore) name() string     { return "local" }
func (s localRouteStore) file() string     { return filepath.Join(s.dir, "routes.json") }
func (s localRouteStore) certDir() string  { return filepath.Join(gatewayCertDir, "custom") }
func (s localRouteStore) lockPath() string { return filepath.Join(s.dir, ".lock") }

func (s localRouteStore) read() (*gatewayData, error) {
	d := &gatewayData{}
	b, err := os.ReadFile(s.file())
	if os.IsNotExist(err) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	return d, json.Unmarshal(b, d)
}

// update edits the store under an exclusive lock (the CLI and the API server may race).
func (s localRouteStore) update(fn func(d *gatewayData) error) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	lf, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	d, err := s.read()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.file(), b, 0600); err != nil {
		return err
	}
	return syncLocalGatewayService(len(d.Routes) > 0)
}

// syncLocalGatewayService runs the gateway service while the host has routes (it reloads its
// routes by itself within a second).
var syncLocalGatewayService = func(on bool) error {
	if on {
		startClusterServices("gateway")
	} else {
		stopClusterServices("gateway")
		syncGatewayFirewall(nil) // close the ports it opened
	}
	return nil
}

// config resolves local routes: an app is a local `apps` instance, reached at its published
// address (an unspecified bind is reached on loopback).
func (s localRouteStore) config() (*GatewayConfig, error) {
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	cfg := &GatewayConfig{ACME: d.ACME, Routes: []GatewayRouteState{}}
	for _, r := range d.Routes {
		r.Normalize()
		cfg.Routes = append(cfg.Routes, resolveTargets(r, localAppTargets))
		if name, ok := strings.CutPrefix(r.TLS, "cert:"); ok {
			if c, err := s.readCert(name); err == nil {
				if cfg.Certs == nil {
					cfg.Certs = map[string]GatewayCert{}
				}
				cfg.Certs[name] = c
			}
		}
	}
	return cfg, nil
}

func localAppTargets(app string) []string {
	in, err := loadAppInstance(app)
	if err != nil || in.Publish == "" {
		return nil
	}
	ap, err := netip.ParseAddrPort(in.Publish)
	if err != nil {
		return nil
	}
	if ap.Addr().IsUnspecified() {
		ap = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port())
	}
	return []string{ap.String()}
}

func (s localRouteStore) readCert(name string) (GatewayCert, error) {
	c, err := os.ReadFile(filepath.Join(s.certDir(), name+".crt"))
	if err != nil {
		return GatewayCert{}, err
	}
	k, err := os.ReadFile(filepath.Join(s.certDir(), name+".key"))
	return GatewayCert{Cert: string(c), Key: string(k)}, err
}

func (s localRouteStore) putCert(name string, c GatewayCert) error {
	if err := os.MkdirAll(s.certDir(), 0700); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.certDir(), name+".key"), []byte(c.Key), 0600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.certDir(), name+".crt"), []byte(c.Cert), 0644)
}

func (s localRouteStore) rmCert(name string) error {
	d, err := s.read()
	if err != nil {
		return err
	}
	for _, r := range d.Routes {
		if r.TLS == "cert:"+name {
			return fmt.Errorf("route %s uses certificate %s", r.Name, name)
		}
	}
	if err := os.Remove(filepath.Join(s.certDir(), name+".crt")); err != nil {
		return fmt.Errorf("no certificate %q", name)
	}
	return os.Remove(filepath.Join(s.certDir(), name+".key"))
}

func (s localRouteStore) certNames() ([]string, error) {
	ents, _ := os.ReadDir(s.certDir())
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".crt"); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s localRouteStore) internalCA() (string, error) {
	c, _, err := localInternalCA()
	return string(c), err
}

func (s localRouteStore) appTargetsKnown(app string) error {
	if len(localAppTargets(app)) == 0 {
		return fmt.Errorf("no local app %q with a published port (ziroctl apps deploy ... ; or --to <ip:port>)", app)
	}
	return nil
}

// ---- route edits (shared by the CLI and the API) ----

// putRoute validates r and creates or replaces it in the store.
func putRoute(s routeStore, r GatewayRoute) (GatewayRoute, error) {
	r.Normalize()
	if err := validateRoute(&r); err != nil {
		return r, err
	}
	for _, app := range routeApps(r) {
		if err := s.appTargetsKnown(app); err != nil {
			return r, err
		}
	}
	err := s.update(func(d *gatewayData) error {
		kept := d.Routes[:0]
		for _, x := range d.Routes {
			if x.Name == r.Name {
				continue
			}
			x.Normalize()
			if err := routesConflict(x, r); err != nil {
				return err
			}
			kept = append(kept, x)
		}
		if strings.HasPrefix(r.TLS, "cert:") {
			names, _ := s.certNames()
			found := false
			for _, n := range names {
				found = found || "cert:"+n == r.TLS
			}
			if !found {
				return fmt.Errorf("certificate %s is not uploaded (ziroctl gateway cert add ...)", strings.TrimPrefix(r.TLS, "cert:"))
			}
		}
		d.Routes = append(kept, r)
		sortRoutes(d.Routes)
		return nil
	})
	return r, err
}

// routesConflict refuses two routes that would match exactly the same traffic.
func routesConflict(a, b GatewayRoute) error {
	switch {
	case a.Kind == "tcp" && b.Kind == "tcp" && a.Listen == b.Listen:
		return fmt.Errorf("route %q already listens on %d", a.Name, a.Listen)
	case a.Kind == "tls" && b.Kind == "tls":
		for _, h := range a.Hosts {
			for _, k := range b.Hosts {
				if h == k {
					return fmt.Errorf("route %q already passes through %s", a.Name, h)
				}
			}
		}
	case a.Kind == "http" && b.Kind == "http" && a.PathPrefix == b.PathPrefix && a.PathExact == b.PathExact &&
		strings.Join(a.Methods, ",") == strings.Join(b.Methods, ",") && fmt.Sprint(a.Headers) == fmt.Sprint(b.Headers):
		for _, h := range a.Hosts {
			for _, k := range b.Hosts {
				if h == k {
					return fmt.Errorf("route %q already serves %s%s", a.Name, h, a.PathPrefix)
				}
			}
		}
	case (a.Kind == "tls") != (b.Kind == "tls") && a.Kind != "tcp" && b.Kind != "tcp":
		for _, h := range a.Hosts {
			for _, k := range b.Hosts {
				if h == k {
					return fmt.Errorf("%s is both an HTTPS route (%s) and a passthrough route", h, a.Name)
				}
			}
		}
	}
	return nil
}

func deleteRoute(s routeStore, name string) error {
	return s.update(func(d *gatewayData) error {
		for i, r := range d.Routes {
			if r.Name == name {
				d.Routes = append(d.Routes[:i], d.Routes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("route %q not found", name)
	})
}

// validateCert checks an uploaded certificate before it is stored.
func validateCert(c GatewayCert) error {
	kp, err := tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
	if err != nil {
		return fmt.Errorf("certificate and key don't form a pair: %w", err)
	}
	if kp.Leaf != nil && time.Now().After(kp.Leaf.NotAfter) {
		return errors.New("certificate has expired")
	}
	return nil
}

// ---- serve ----

var (
	gwHTTPAddr  string
	gwHTTPSAddr string
	gwHTTP3     bool
)

// gatewaySource returns the config to serve: the agent-written file on cluster gateway nodes,
// the local store otherwise.
func gatewaySource() (*GatewayConfig, error) {
	if _, err := loadClusterConfig(); err == nil {
		var cfg GatewayConfig
		b, err := os.ReadFile(gatewayConfigPath)
		if err != nil {
			return nil, err
		}
		return &cfg, json.Unmarshal(b, &cfg)
	}
	return localRouteStore{dir: gatewayLocalDir}.config()
}

// gwFirewallComment marks the firewall rules the gateway owns (opened and closed as routes change).
const gwFirewallComment = "Ziro gateway"

func syncGatewayFirewall(rules []FirewallRule) {
	fw := loadFirewallConfig()
	want := map[string]FirewallRule{}
	for _, r := range rules {
		r.Comment = gwFirewallComment
		want[fmt.Sprintf("%d/%s", r.Port, r.Protocol)] = r
	}
	changed := false
	kept := fw.AllowedPorts[:0]
	for _, r := range fw.AllowedPorts {
		k := fmt.Sprintf("%d/%s", r.Port, r.Protocol)
		if r.Comment == gwFirewallComment && r.Source == "" {
			if _, ok := want[k]; !ok {
				changed = true
				continue
			}
			delete(want, k)
		}
		kept = append(kept, r)
	}
	for _, r := range want {
		kept = append(kept, r)
		changed = true
	}
	if !changed {
		return
	}
	fw.AllowedPorts = kept
	if err := saveFirewallConfig(fw); err != nil {
		fmt.Printf("[gateway] firewall config: %v\n", err)
		return
	}
	if fw.Enabled {
		_ = applyFirewallRules(fw)
	}
}

var gatewayServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the gateway (the gateway service)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		g := newGatewayServer()
		var last []byte
		reload := func() bool {
			cfg, err := gatewaySource()
			if err != nil {
				return false
			}
			b, _ := json.Marshal(cfg)
			if string(b) == string(last) {
				return true
			}
			if err := g.load(cfg); err != nil {
				fmt.Printf("[gateway] config rejected, keeping previous routes: %v\n", err)
				return last != nil
			}
			last = b
			g.syncL4Listeners()
			rules := []FirewallRule{}
			for _, a := range []string{gwHTTPAddr, gwHTTPSAddr} {
				if p := portOf(a); p > 0 {
					rules = append(rules, FirewallRule{Port: p, Protocol: "tcp"})
				}
			}
			if gwHTTP3 {
				rules = append(rules, FirewallRule{Port: portOf(gwHTTPSAddr), Protocol: "udp"})
			}
			g.mu.RLock()
			for p := range g.tcp {
				rules = append(rules, FirewallRule{Port: p, Protocol: "tcp"})
			}
			g.mu.RUnlock()
			syncGatewayFirewall(rules)
			fmt.Printf("[gateway] loaded %d routes\n", len(cfg.Routes))
			return true
		}
		// After a reboot the agent may not have rewritten the config yet (tmpfs): wait for it,
		// so the ACME account is built from real settings.
		for !reload() {
			time.Sleep(time.Second)
		}
		go func() {
			for range time.Tick(time.Second) {
				reload()
			}
		}()

		if err := os.MkdirAll(gatewayCertDir, 0700); err != nil {
			return err
		}
		g.mu.RLock()
		cfg := g.cfg
		g.mu.RUnlock()
		g.acmeMgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(gatewayCertDir, "acme")),
			HostPolicy: func(_ context.Context, host string) error {
				if !g.acmeHost(host) {
					return fmt.Errorf("no ACME route for %q", host)
				}
				return nil
			},
			Email: cfg.ACME.Email,
		}
		// The ACME account (email, directory) is read at start; `gateway acme` restarts the service.
		if cfg.ACME.Directory != "" {
			g.acmeMgr.Client = &acme.Client{DirectoryURL: cfg.ACME.Directory}
		}

		mk := func(addr string, h http.Handler) *http.Server {
			return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout: 5 * time.Minute, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: g.getCertificate,
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto}}
		httpSrv := mk(gwHTTPAddr, g.acmeMgr.HTTPHandler(g.handler(false)))
		httpsSrv := mk(gwHTTPSAddr, g.handler(true))
		httpsSrv.TLSConfig = tlsCfg

		errc := make(chan error, 4)
		go func() { errc <- httpSrv.ListenAndServe() }()
		ln, err := net.Listen("tcp", gwHTTPSAddr)
		if err != nil {
			return err
		}
		https := &chanListener{ch: make(chan net.Conn, 128), addr: ln.Addr(), done: make(chan struct{})}
		go g.splitTLS(ln, https)
		go func() { errc <- httpsSrv.ServeTLS(https, "", "") }()
		if gwHTTP3 {
			g.h3 = &http3.Server{Addr: gwHTTPSAddr, Handler: g.handler(true), TLSConfig: http3.ConfigureTLSConfig(tlsCfg)}
			go func() {
				if err := g.h3.ListenAndServe(); err != nil {
					fmt.Printf("[gateway] HTTP/3 disabled: %v\n", err)
					g.h3 = nil
				}
			}()
		}
		admin := &http.Server{Addr: gatewayAdminAddr, Handler: g.adminHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := admin.ListenAndServe(); err != nil {
				fmt.Printf("[gateway] admin endpoint: %v\n", err)
			}
		}()
		fmt.Printf("[gateway] serving http %s, https %s (h2%s), admin %s\n", gwHTTPAddr, gwHTTPSAddr,
			map[bool]string{true: ", h3", false: ""}[gwHTTP3], gatewayAdminAddr)
		return <-errc
	},
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// gatewayStatus reads the running gateway's status (this host), or reports the resolved routes
// when the gateway runs elsewhere (cluster gateway nodes).
func gatewayStatus(s routeStore) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+gatewayAdminAddr+"/status", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		defer resp.Body.Close()
		var st GatewayStatus
		if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&st) == nil {
			return st, nil
		}
	}
	cfg, err := s.config()
	if err != nil {
		return nil, err
	}
	return cfg.Routes, nil
}

// ---- CLI ----

var gatewayCmd = &cobra.Command{
	Use:     "gateway",
	Aliases: []string{"zirogate"},
	Short:   "zirogate: L4/L7 gateway (TLS, HTTP/2+3, routing, load balancing) for apps and services",
	Long: `Expose apps and services through the gateway. On a cluster master, routes are served by the
gateway nodes; on a standalone host, by this host.

  ziroctl gateway expose web --host www.example.com              # one command: route + TLS (ACME)
  ziroctl gateway route add api --host api.example.com --path /v1 --app api --strip-prefix /v1 \
      --lb least_conn --health /healthz --rate 100 --compress
  ziroctl gateway route add canary --host www.example.com --app web:90 --app web-next:10
  ziroctl gateway route add db --tcp --listen 5432 --app postgres --allow-cidr 10.0.0.0/8
  ziroctl gateway route add mail --passthrough --host mail.example.com --to 10.0.0.9:443
  ziroctl gateway route add old --host old.example.com --redirect https://www.example.com{uri}
  ziroctl gateway route ls
  ziroctl gateway status          # upstream health, requests per route (this host's gateway)

Hosts need DNS pointing at the gateway and tcp/80 reachable for ACME certificates; use
--tls internal (the gateway's own CA: ziroctl gateway ca) or --tls cert:<name> otherwise.`,
}

type routeFlags struct {
	r                                  GatewayRoute
	tcp, passthrough                   bool
	apps, to, headers, setReq, setResp []string
	rmReq, rmResp, basicAuth           []string
	respond                            string
	health                             string
}

var gwF routeFlags

// routeFromFlags builds a route from the CLI flags (basic-auth passwords are hashed here and
// never stored in clear).
func routeFromFlags(name string, f routeFlags) (GatewayRoute, error) {
	r := f.r
	r.Name = name
	switch {
	case f.tcp && f.passthrough:
		return r, errors.New("--tcp and --passthrough exclude each other")
	case f.tcp:
		r.Kind = "tcp"
	case f.passthrough:
		r.Kind = "tls"
	}
	parseUp := func(s string, app bool) (GatewayUpstream, error) {
		u := GatewayUpstream{Weight: 1}
		target, w := s, ""
		if app {
			target, w, _ = strings.Cut(s, ":")
		} else if i := strings.LastIndex(s, "@"); i > 0 { // address@weight (an address has colons)
			target, w = s[:i], s[i+1:]
		}
		if w != "" {
			n, err := strconv.Atoi(w)
			if err != nil {
				return u, fmt.Errorf("invalid weight in %q", s)
			}
			u.Weight = n
		}
		if app {
			u.App = target
		} else {
			u.Address = target
		}
		return u, nil
	}
	for _, a := range f.apps {
		u, err := parseUp(a, true)
		if err != nil {
			return r, err
		}
		r.To = append(r.To, u)
	}
	for _, a := range f.to {
		u, err := parseUp(a, false)
		if err != nil {
			return r, err
		}
		r.To = append(r.To, u)
	}
	kv := func(list []string) (map[string]string, error) {
		if len(list) == 0 {
			return nil, nil
		}
		m := map[string]string{}
		for _, e := range list {
			k, v, ok := strings.Cut(e, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("invalid header %q (want Name=value)", e)
			}
			m[k] = v
		}
		return m, nil
	}
	var err error
	if r.Headers, err = kv(f.headers); err != nil {
		return r, err
	}
	setReq, err := kv(f.setReq)
	if err != nil {
		return r, err
	}
	setResp, err := kv(f.setResp)
	if err != nil {
		return r, err
	}
	if setReq != nil || f.rmReq != nil {
		r.RequestHeaders = &HeaderRules{Set: setReq, Remove: f.rmReq}
	}
	if setResp != nil || f.rmResp != nil {
		r.ResponseHeaders = &HeaderRules{Set: setResp, Remove: f.rmResp}
	}
	if f.respond != "" {
		code, body, _ := strings.Cut(f.respond, ":")
		n, err := strconv.Atoi(code)
		if err != nil {
			return r, fmt.Errorf("--respond wants status[:body]")
		}
		r.Respond = &GatewayRespond{Status: n, Body: body}
	}
	if f.health != "" {
		path, interval, _ := strings.Cut(f.health, "@")
		r.Health = &GatewayHealth{Path: path, Interval: interval}
	}
	for _, e := range f.basicAuth {
		user, pass, ok := strings.Cut(e, ":")
		if !ok || user == "" || len(pass) < 8 {
			return r, fmt.Errorf("--basic-auth wants user:password (password 8+ characters)")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return r, err
		}
		if r.BasicAuth == nil {
			r.BasicAuth = map[string]string{}
		}
		r.BasicAuth[user] = string(h)
	}
	return r, nil
}

var gatewayRouteCmd = &cobra.Command{Use: "route", Short: "Manage gateway routes"}

var gatewayRouteAddCmd = &cobra.Command{
	Use:     "add <name>",
	Aliases: []string{"set"},
	Short:   "Create or replace a route",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		r, err := routeFromFlags(args[0], gwF)
		if err != nil {
			return err
		}
		if r, err = putRoute(s, r); err != nil {
			return err
		}
		match, target := describeRoute(GatewayRouteState{GatewayRoute: r})
		fmt.Printf("✓ route %s: %s -> %s (%s gateway)\n", r.Name, match, target, s.name())
		if c, ok := s.(clusterRouteStore); ok {
			_ = c
			if st, err := readState(); err == nil {
				gw := 0
				for _, n := range st.Nodes {
					if n.Gateway {
						gw++
					}
				}
				if gw == 0 {
					fmt.Println("  no gateway nodes yet: ziroctl gateway node enable <node>")
				}
			}
		}
		return nil
	},
}

var (
	exposeHost, exposePath, exposeTLS, exposeName string
)

var gatewayExposeCmd = &cobra.Command{
	Use:   "expose <app|ip:port> --host <host>",
	Short: "Publish an app or a service on a hostname in one command (HTTPS by default)",
	Example: `  ziroctl gateway expose web --host www.example.com
  ziroctl gateway expose 10.0.0.7:8080 --host grafana.internal --tls internal`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		r, err := exposeRoute(args[0], exposeHost, exposePath, exposeTLS, exposeName)
		if err != nil {
			return err
		}
		if r, err = putRoute(s, r); err != nil {
			return err
		}
		scheme := "https"
		if r.TLS == "off" {
			scheme = "http"
		}
		fmt.Printf("✓ %s is live at %s://%s%s (route %s)\n", args[0], scheme, r.Host, r.PathPrefix, r.Name)
		return nil
	},
}

// exposeRoute is the route `expose` (and `apps deploy --expose`) creates.
func exposeRoute(target, host, path, tlsMode, name string) (GatewayRoute, error) {
	if host == "" {
		return GatewayRoute{}, errors.New("--host is required")
	}
	r := GatewayRoute{Hosts: []string{host}, PathPrefix: path, TLS: tlsMode}
	if _, err := netip.ParseAddrPort(target); err == nil {
		r.To = []GatewayUpstream{{Address: target}}
	} else {
		r.To = []GatewayUpstream{{App: target}}
	}
	if name == "" {
		name = target
		if r.To[0].Address != "" {
			name = strings.NewReplacer(".", "-", ":", "-", "[", "", "]", "").Replace(target)
		}
	}
	r.Name = name
	return r, nil
}

var gatewayRouteRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Remove a route", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := deleteRoute(s, args[0]); err != nil {
			return err
		}
		fmt.Printf("✓ route %s removed\n", args[0])
		return nil
	},
}

var gatewayRouteLsCmd = &cobra.Command{
	Use: "ls", Aliases: []string{"list"}, Short: "List routes with their resolved upstreams",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		cfg, err := s.config()
		if err != nil {
			return err
		}
		return printResult(cfg.Routes, func() {
			fmt.Printf("%-14s %-36s %-24s %-12s %s\n", "NAME", "MATCH", "TO", "TLS", "UPSTREAMS")
			for _, r := range cfg.Routes {
				match, target := describeRoute(r)
				ups := strings.Join(r.Upstreams, ",")
				if ups == "" && r.Redirect == "" && r.Respond == nil {
					ups = "(none running)"
				}
				tlsMode := r.TLS
				if r.Kind != "http" {
					tlsMode = "-"
				}
				fmt.Printf("%-14s %-36s %-24s %-12s %s\n", r.Name, match, target, tlsMode, ups)
			}
		})
	},
}

var gatewayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Upstream health, active connections and requests per route",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		st, err := gatewayStatus(s)
		if err != nil {
			return err
		}
		return printResult(st, func() {
			gs, ok := st.(GatewayStatus)
			if !ok {
				fmt.Println("The gateway doesn't run on this host; resolved routes:")
				b, _ := json.MarshalIndent(st, "", "  ")
				fmt.Println(string(b))
				return
			}
			for _, r := range gs.Routes {
				fmt.Printf("%s (%s) %s\n", r.Name, r.Kind, r.Match)
				for _, u := range r.Upstreams {
					state := "healthy"
					if !u.Healthy {
						state = "DOWN"
					}
					fmt.Printf("  %-24s share %3d%%  %-8s active %d\n", u.Addr, u.Share, state, u.Active)
				}
				if len(r.Requests) > 0 {
					fmt.Printf("  requests: %v\n", r.Requests)
				}
			}
		})
	},
}

var gatewayCertCmd = &cobra.Command{Use: "cert", Short: "Uploaded TLS certificates (for --tls cert:<name>)"}

var certFile, keyFile string

var gatewayCertAddCmd = &cobra.Command{
	Use: "add <name> --cert chain.pem --key key.pem", Short: "Upload a certificate (wildcards, private CAs)", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(args[0]); err != nil {
			return err
		}
		c, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		k, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		gc := GatewayCert{Cert: string(c), Key: string(k)}
		if err := validateCert(gc); err != nil {
			return err
		}
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := s.putCert(args[0], gc); err != nil {
			return err
		}
		fmt.Printf("✓ certificate %s stored; use it: --tls cert:%s\n", args[0], args[0])
		return nil
	},
}

var gatewayCertRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Remove a certificate (refused while a route uses it)", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		return s.rmCert(args[0])
	},
}

var gatewayCertLsCmd = &cobra.Command{
	Use: "ls", Short: "List uploaded certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		names, err := s.certNames()
		if err != nil {
			return err
		}
		return printResult(names, func() {
			for _, n := range names {
				fmt.Println(n)
			}
		})
	},
}

var gatewayCACmd = &cobra.Command{
	Use:   "ca",
	Short: "Print the internal CA certificate (trust it on clients of --tls internal routes)",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		pem, err := s.internalCA()
		if err != nil {
			return err
		}
		fmt.Print(pem)
		return nil
	},
}

var gatewayNodeCmd = &cobra.Command{Use: "node", Short: "Choose which cluster nodes run the gateway (master only)"}

func gatewayNodeSet(on bool) *cobra.Command {
	use, verb := "disable <node>", "Stop running the gateway on a node"
	if on {
		use, verb = "enable <node>", "Run the gateway on a node (serves tcp/80 and tcp+udp/443)"
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

var gwACMEFlag GatewayACME

func validateACME(a GatewayACME) error {
	if d := a.Directory; d != "" && !strings.HasPrefix(d, "https://") {
		return fmt.Errorf("the ACME directory must be an https:// URL")
	}
	if e := a.Email; e != "" && (!strings.Contains(e, "@") || strings.ContainsAny(e, " \t\r\n") || len(e) > 254) {
		return fmt.Errorf("invalid email %q", e)
	}
	return nil
}

var gatewayACMECmd = &cobra.Command{
	Use:   "acme",
	Short: "Set the ACME account email and optional directory URL (default Let's Encrypt)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateACME(gwACMEFlag); err != nil {
			return err
		}
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := s.update(func(d *gatewayData) error { d.ACME = gwACMEFlag; return nil }); err != nil {
			return err
		}
		fmt.Println("✓ ACME settings saved; restart the gateway service to use a new account")
		return nil
	},
}

func init() {
	f := gatewayRouteAddCmd.Flags()
	f.StringSliceVar(&gwF.r.Hosts, "host", nil, "Hostname(s); *.example.com matches one label (repeatable)")
	f.StringVar(&gwF.r.PathPrefix, "path", "/", "Path prefix (longest match wins; matched on / boundaries)")
	f.BoolVar(&gwF.r.PathExact, "exact", false, "Match the path exactly instead of as a prefix")
	f.StringSliceVar(&gwF.r.Methods, "method", nil, "Only these methods (repeatable)")
	f.StringArrayVar(&gwF.headers, "header", nil, "Only requests with this header value: Name=value (repeatable)")
	f.StringArrayVar(&gwF.apps, "app", nil, "App to route to, optionally app:weight (repeatable: canary)")
	f.StringArrayVar(&gwF.to, "to", nil, "Address to route to, ip:port[@weight] (repeatable)")
	f.StringVar(&gwF.r.LB, "lb", "round_robin", "round_robin, least_conn, ip_hash or cookie (sticky)")
	f.StringVar(&gwF.health, "health", "", "Active health check path[@interval], e.g. /healthz@5s")
	f.StringVar(&gwF.r.StripPrefix, "strip-prefix", "", "Remove this prefix before forwarding")
	f.StringArrayVar(&gwF.setReq, "set-header", nil, "Set a request header: Name=value (repeatable)")
	f.StringArrayVar(&gwF.rmReq, "remove-header", nil, "Remove a request header (repeatable)")
	f.StringArrayVar(&gwF.setResp, "set-response-header", nil, "Set a response header: Name=value (repeatable)")
	f.StringArrayVar(&gwF.rmResp, "remove-response-header", nil, "Remove a response header (repeatable)")
	f.IntVar(&gwF.r.Retries, "retries", 0, "Retry another upstream after a dial error (idempotent requests, 0-5)")
	f.StringVar(&gwF.r.Timeout, "timeout", "", "Upstream response timeout (default 60s)")
	f.BoolVar(&gwF.r.Compress, "compress", false, "gzip compressible responses")
	f.StringVar(&gwF.r.Redirect, "redirect", "", "Redirect instead of proxying; {uri} is the request URI")
	f.IntVar(&gwF.r.RedirectCode, "redirect-code", 0, "301, 302, 307 or 308 (default)")
	f.StringVar(&gwF.respond, "respond", "", "Answer with a fixed response: status[:body]")
	f.StringVar(&gwF.r.TLS, "tls", "auto", "auto (ACME), off, internal (gateway CA) or cert:<name>")
	f.StringSliceVar(&gwF.r.AllowCIDRs, "allow-cidr", nil, "Only clients from these CIDRs (repeatable)")
	f.IntVar(&gwF.r.RateRPS, "rate", 0, "Requests (or connections) per second per client IP (0 = unlimited)")
	f.IntVar(&gwF.r.MaxBodyMB, "max-body-mb", 0, "Request body limit in MB (default 10)")
	f.StringArrayVar(&gwF.basicAuth, "basic-auth", nil, "Require HTTP basic auth: user:password (stored as bcrypt; repeatable)")
	f.BoolVar(&gwF.tcp, "tcp", false, "A TCP route on --listen (databases, any TCP service)")
	f.IntVar(&gwF.r.Listen, "listen", 0, "Port for a --tcp route")
	f.BoolVar(&gwF.passthrough, "passthrough", false, "TLS passthrough on :443 routed by SNI (the upstream terminates TLS)")

	ef := gatewayExposeCmd.Flags()
	ef.StringVar(&exposeHost, "host", "", "Hostname to publish on")
	ef.StringVar(&exposePath, "path", "/", "Path prefix")
	ef.StringVar(&exposeTLS, "tls", "auto", "auto (ACME), off, internal or cert:<name>")
	ef.StringVar(&exposeName, "name", "", "Route name (default: the app name)")

	gatewayCertAddCmd.Flags().StringVar(&certFile, "cert", "", "PEM certificate chain")
	gatewayCertAddCmd.Flags().StringVar(&keyFile, "key", "", "PEM private key")
	_ = gatewayCertAddCmd.MarkFlagRequired("cert")
	_ = gatewayCertAddCmd.MarkFlagRequired("key")
	gatewayACMECmd.Flags().StringVar(&gwACMEFlag.Email, "email", "", "ACME account contact email")
	gatewayACMECmd.Flags().StringVar(&gwACMEFlag.Directory, "directory", "", "ACME directory URL (private CA or LE staging)")
	gatewayServeCmd.Flags().StringVar(&gwHTTPAddr, "http", ":80", "HTTP listen address")
	gatewayServeCmd.Flags().StringVar(&gwHTTPSAddr, "https", ":443", "HTTPS listen address (TCP, and UDP for HTTP/3)")
	gatewayServeCmd.Flags().BoolVar(&gwHTTP3, "http3", true, "Serve HTTP/3 (QUIC) on the HTTPS port")

	gatewayRouteCmd.AddCommand(gatewayRouteAddCmd, gatewayRouteRmCmd, gatewayRouteLsCmd)
	gatewayCertCmd.AddCommand(gatewayCertAddCmd, gatewayCertRmCmd, gatewayCertLsCmd)
	gatewayNodeCmd.AddCommand(gatewayNodeSet(true), gatewayNodeSet(false))
	gatewayCmd.AddCommand(gatewayRouteCmd, gatewayExposeCmd, gatewayStatusCmd, gatewayCertCmd, gatewayCACmd,
		gatewayNodeCmd, gatewayACMECmd, gatewayServeCmd)
	rootCmd.AddCommand(gatewayCmd)
}

// ---- API ----

// registerGatewayRoutes: the gateway's management API (like Caddy's admin API, behind the API
// server's tokens). Reading needs any token; changing routes or certificates needs admin.
// Changes are live within a second; nothing is restarted.
// registerGatewayRoutes: reading routes and status is for any token; changing what the gateway
// serves or its certificates is admin.
func registerGatewayRoutes(a *apiRouter) {
	// store answers the error itself and returns nil when the gateway's store can't be opened.
	store := func(w http.ResponseWriter) routeStore {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return nil
		}
		return s
	}
	put := func(w http.ResponseWriter, r *http.Request, name string) {
		s := store(w)
		if s == nil {
			return
		}
		var rt GatewayRoute
		if err := decodeStrict(w, r, &rt, 1<<20); err != nil {
			apiReply(w, err, nil)
			return
		}
		if name != "" {
			rt.Name = name
		}
		rt, err := putRoute(s, rt)
		apiReply(w, err, rt)
	}
	a.get("/api/v1/gateway/routes", "viewer", func(w http.ResponseWriter, r *http.Request) {
		if s := store(w); s != nil {
			cfg, err := s.config()
			if err != nil {
				apiReply(w, err, nil)
				return
			}
			apiReply(w, nil, cfg.Routes)
		}
	})
	a.post("/api/v1/gateway/routes", "admin", func(w http.ResponseWriter, r *http.Request) { put(w, r, "") })
	a.get("/api/v1/gateway/routes/{name}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s := store(w)
		if s == nil {
			return
		}
		cfg, err := s.config()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		for _, rt := range cfg.Routes {
			if rt.Name == r.PathValue("name") {
				apiReply(w, nil, rt)
				return
			}
		}
		apiReply(w, errNotFound("route not found"), nil)
	})
	a.put("/api/v1/gateway/routes/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		if err := validName(r.PathValue("name")); err != nil {
			apiReply(w, err, nil)
			return
		}
		put(w, r, r.PathValue("name"))
	})
	a.delete("/api/v1/gateway/routes/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if s := store(w); s != nil {
			err := validName(name)
			if err == nil {
				err = deleteRoute(s, name)
			}
			apiReply(w, err, APIMessage{Status: "ok", Message: "route " + name + " removed"})
		}
	})
	a.get("/api/v1/gateway/status", "viewer", func(w http.ResponseWriter, r *http.Request) {
		if s := store(w); s != nil {
			st, err := gatewayStatus(s)
			apiReply(w, err, st)
		}
	})
	a.get("/api/v1/gateway/ca", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s := store(w)
		if s == nil {
			return
		}
		pem, err := s.internalCA()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = io.WriteString(w, pem)
	})
	a.get("/api/v1/gateway/certs", "viewer", func(w http.ResponseWriter, r *http.Request) {
		if s := store(w); s != nil {
			names, err := s.certNames()
			apiReply(w, err, names)
		}
	})
	a.post("/api/v1/gateway/certs", "admin", func(w http.ResponseWriter, r *http.Request) { // {"name","cert","key"}
		s := store(w)
		if s == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
			GatewayCert
		}
		if err := decodeStrict(w, r, &req, 1<<20); err != nil {
			apiReply(w, err, nil)
			return
		}
		err := validName(req.Name)
		if err == nil {
			err = validateCert(req.GatewayCert)
		}
		if err == nil {
			err = s.putCert(req.Name, req.GatewayCert)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "certificate " + req.Name + " stored"})
	})
	a.delete("/api/v1/gateway/certs/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if s := store(w); s != nil {
			err := validName(name)
			if err == nil {
				err = s.rmCert(name)
			}
			apiReply(w, err, APIMessage{Status: "ok", Message: "certificate " + name + " removed"})
		}
	})
}

package cmd

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/metrics"
	"sort"
	"strings"
	"time"
)

// Server-level metrics and the probe endpoints.

var gatewayStart = time.Now()

// gwCertExpiry is when a certificate the gateway serves from its own store expires.
type gwCertExpiry struct {
	name string
	at   time.Time
}

// certExpiries lists the uploaded certificates and the internal CA. ACME certificates renew
// themselves and are not listed.
func (g *gatewayServer) certExpiries() []gwCertExpiry {
	g.certMu.Lock()
	defer g.certMu.Unlock()
	var out []gwCertExpiry
	for name, c := range g.certs {
		if c.Leaf != nil {
			out = append(out, gwCertExpiry{"cert:" + name, c.Leaf.NotAfter})
		}
	}
	if g.ca != nil && g.ca.Leaf != nil {
		out = append(out, gwCertExpiry{"internal-ca", g.ca.Leaf.NotAfter})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

var runtimeSamples = []metrics.Sample{
	{Name: "/sched/goroutines:goroutines"},
	{Name: "/memory/classes/heap/objects:bytes"},
	{Name: "/memory/classes/total:bytes"},
	{Name: "/gc/cycles/total:gc-cycles"},
}

// writeServerMetrics appends what is not a per-route series: connections, TLS, configuration,
// upstream state, certificates and the Go runtime.
func (g *gatewayServer) writeServerMetrics(w io.Writer) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	family := func(name, help, typ string) {
		fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	m := g.metrics
	family("zirogate_build_info", "Gateway build.", "gauge")
	fmt.Fprintf(bw, "zirogate_build_info{version=%q,commit=%q} 1\n", Version, GitCommit)
	family("zirogate_ready", "1 when the gateway serves traffic: configuration loaded and not draining.", "gauge")
	fmt.Fprintf(bw, "zirogate_ready %d\n", b2i(g.isReady()))
	family("zirogate_uptime_seconds", "Seconds since the gateway started.", "gauge")
	fmt.Fprintf(bw, "zirogate_uptime_seconds %g\n", time.Since(gatewayStart).Seconds())

	family("zirogate_connections", "Open client connections.", "gauge")
	fmt.Fprintf(bw, "zirogate_connections{kind=\"http\"} %d\nzirogate_connections{kind=\"tcp\"} %d\n", max(m.conns.Load(), 0), max(m.l4conns.Load(), 0))
	family("zirogate_tls_handshakes_total", "Completed TLS handshakes with clients, by protocol version.", "counter")
	for i, v := range [...]string{"1.0", "1.1", "1.2", "1.3"} {
		if n := m.tlsVersion[i].Load(); n > 0 {
			fmt.Fprintf(bw, "zirogate_tls_handshakes_total{version=%q} %d\n", v, n)
		}
	}
	family("zirogate_http3_handshakes_total", "Completed QUIC handshakes with clients.", "counter")
	fmt.Fprintf(bw, "zirogate_http3_handshakes_total %d\n", m.h3Handshakes.Load())

	family("zirogate_config_reload_total", "Configuration reloads by result.", "counter")
	fmt.Fprintf(bw, "zirogate_config_reload_total{result=\"ok\"} %d\nzirogate_config_reload_total{result=\"rejected\"} %d\n", m.reloadOK.Load(), m.reloadFailed.Load())
	family("zirogate_config_last_success_timestamp_seconds", "When the configuration last loaded.", "gauge")
	fmt.Fprintf(bw, "zirogate_config_last_success_timestamp_seconds %d\n", m.lastReloadOK.Load())

	t := g.tbl.Load()
	now := time.Now().UnixNano()
	family("zirogate_route_info", "Routes served (value 1).", "gauge")
	for _, r := range t.all {
		fmt.Fprintf(bw, "zirogate_route_info{route=%q,kind=%q} 1\n", r.Name, r.Kind)
	}
	family("zirogate_upstream_available", "1 when an upstream takes traffic: not ejected and passing its health check.", "gauge")
	for _, r := range t.all {
		for _, tg := range r.targets {
			fmt.Fprintf(bw, "zirogate_upstream_available{route=%q,upstream=%q} %d\n", r.Name, tg.addr, b2i(tg.usable(now)))
		}
	}
	family("zirogate_upstream_active_requests", "Requests in flight to an upstream.", "gauge")
	for _, r := range t.all {
		for _, tg := range r.targets {
			fmt.Fprintf(bw, "zirogate_upstream_active_requests{route=%q,upstream=%q} %d\n", r.Name, tg.addr, max(tg.up.active.Load(), 0))
		}
	}
	family("zirogate_bans_active", "Clients banned automatically and still in force.", "gauge")
	fmt.Fprintf(bw, "zirogate_bans_active %d\n", max(g.bans.active.Load(), 0))
	family("zirogate_cert_expiry_seconds", "Seconds until a certificate in the gateway's store expires.", "gauge")
	for _, c := range g.certExpiries() {
		fmt.Fprintf(bw, "zirogate_cert_expiry_seconds{name=%q} %d\n", c.name, int64(time.Until(c.at).Seconds()))
	}

	metrics.Read(runtimeSamples)
	for _, s := range runtimeSamples {
		name := "zirogate_go_" + strings.NewReplacer("/", "_", ":", "_", "-", "_").Replace(strings.TrimPrefix(s.Name, "/"))
		switch s.Value.Kind() {
		case metrics.KindUint64:
			family(name, "Go runtime: "+s.Name, "gauge")
			fmt.Fprintf(bw, "%s %d\n", name, s.Value.Uint64())
		}
	}
}

// isReady: a configuration is loaded and the gateway is not draining.
func (g *gatewayServer) isReady() bool {
	return g.ready.Load() && !g.draining.Load()
}

// trackConn counts open client connections of an http.Server.
func (g *gatewayServer) trackConn(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		g.metrics.conns.Add(1)
	case http.StateClosed, http.StateHijacked:
		g.metrics.conns.Add(-1)
	}
}

// countHandshake is the VerifyConnection hook: it runs once per completed TLS handshake.
func (g *gatewayServer) countHandshake(cs tls.ConnectionState) error {
	switch cs.Version {
	case tls.VersionTLS10:
		g.metrics.tlsVersion[0].Add(1)
	case tls.VersionTLS11:
		g.metrics.tlsVersion[1].Add(1)
	case tls.VersionTLS12:
		g.metrics.tlsVersion[2].Add(1)
	case tls.VersionTLS13:
		if cs.NegotiatedProtocol == "h3" {
			g.metrics.h3Handshakes.Add(1)
		} else {
			g.metrics.tlsVersion[3].Add(1)
		}
	}
	return nil
}

// metricsAuth wraps a handler so that it demands a bearer token (the dedicated metrics listener,
// which is reachable from the network, unlike the loopback admin port).
func metricsAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="zirogate"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gatewayMetricsText is the scrape of the gateway running on this host ("" when there is none),
// so one endpoint serves host, cluster and gateway series.
func gatewayMetricsText() string {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+gatewayAdminAddr+"/metrics", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(b), "# HELP") {
		return ""
	}
	return string(b)
}

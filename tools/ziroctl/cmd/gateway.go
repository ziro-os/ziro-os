package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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
		r.Normalize()
		var serve bool
		if r, serve = resolveDNSCertRoute(st.DNSCloud, r, func(n string) bool { return st.Secrets[gatewayCertSecret(n)] != nil }); !serve {
			continue // a DNS-01 route waits for its certificate
		}
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
			syncGatewayFirewall(nil) // this node no longer serves: close the gateway's ports
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

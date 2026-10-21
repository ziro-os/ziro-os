package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// TestGatewayServeEndToEnd runs the real `gateway serve` command: listeners, the WAF, probes,
// metrics, the bearer-protected metrics listener, and a SIGTERM that drains an in-flight request.
func TestGatewayServeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldCert, oldAdmin, oldTok, oldFW, oldCluster := gatewayLocalDir, gatewayCertDir, gatewayAdminAddr, gatewayAdminTokenPath, firewallConfigFile, clusterDir
	oldHTTP, oldHTTPS, oldH3, oldM, oldMT := gwHTTPAddr, gwHTTPSAddr, gwHTTP3, gwMetricsAddr, gwMetricsTokenFile
	oldStdout := os.Stdout
	defer func() {
		gatewayLocalDir, gatewayCertDir, gatewayAdminAddr, gatewayAdminTokenPath, firewallConfigFile, clusterDir = oldDir, oldCert, oldAdmin, oldTok, oldFW, oldCluster
		gwHTTPAddr, gwHTTPSAddr, gwHTTP3, gwMetricsAddr, gwMetricsTokenFile = oldHTTP, oldHTTPS, oldH3, oldM, oldMT
		os.Stdout = oldStdout
	}()
	logFile, _ := os.Create(filepath.Join(dir, "gateway.log"))
	os.Stdout = logFile

	gatewayLocalDir = filepath.Join(dir, "gw")
	gatewayCertDir = filepath.Join(dir, "certs")
	gatewayAdminTokenPath = filepath.Join(dir, "admin.token")
	clusterDir = filepath.Join(dir, "no-cluster")
	firewallConfigFile = filepath.Join(dir, "firewall.json")
	os.WriteFile(firewallConfigFile, []byte(`{"enabled":false,"default_input":"DROP","allowed_ports":[],"blocked_ips":[]}`), 0600)
	httpAddr, httpsAddr, adminAddr, metricsAddr := freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t)
	gwHTTPAddr, gwHTTPSAddr, gwHTTP3, gatewayAdminAddr = httpAddr, httpsAddr, false, adminAddr
	gwMetricsAddr, gwMetricsTokenFile = metricsAddr, filepath.Join(dir, "metrics.token")
	os.WriteFile(gwMetricsTokenFile, []byte("0123456789abcdef-token\n"), 0600)

	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(700 * time.Millisecond)
		}
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	})
	os.MkdirAll(gatewayLocalDir, 0700)
	routes, _ := json.Marshal(gatewayData{
		Routes:   []GatewayRoute{{Name: "app", Hosts: []string{"app.test"}, TLS: "off", To: []GatewayUpstream{{Address: up, Weight: 1}}, Kind: "http", PathPrefix: "/", LB: "round_robin"}},
		Settings: GatewaySettings{WAF: &GatewayWAF{Mode: "block"}},
	})
	os.WriteFile(filepath.Join(gatewayLocalDir, "routes.json"), routes, 0600)

	errc := make(chan error, 1)
	go func() { errc <- gatewayServeCmd.RunE(gatewayServeCmd, nil) }()

	get := func(addr, host, path string, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		if host != "" {
			req.Host = host
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, _ := get(adminAddr, "", "/readyz", nil); c == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway never became ready")
		}
		select {
		case err := <-errc:
			t.Fatalf("serve returned early: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c, b := get(adminAddr, "", "/healthz", nil); c != 200 || !strings.HasPrefix(b, "ok") {
		t.Errorf("healthz: %d %q", c, b)
	}
	if c, b := get(httpAddr, "app.test", "/page", nil); c != 200 || b != "hello /page" {
		t.Errorf("proxied request: %d %q", c, b)
	}
	if c, _ := get(httpAddr, "app.test", "/x?q=<script>alert(1)</script>", nil); c != 403 {
		t.Errorf("the WAF let an attack through: %d", c)
	}
	if c, _ := get(httpAddr, "unknown.test", "/", nil); c != 404 {
		t.Errorf("unknown host: %d", c)
	}
	_, m := get(adminAddr, "", "/metrics", nil)
	for _, want := range []string{`zirogate_ready 1`, `zirogate_build_info{`, `zirogate_requests_total{route="app",code="200"} 1`,
		`zirogate_denied_total{route="app",reason="waf"} 1`, `zirogate_waf_matches_total{route="app",group="xss",action="block"} 1`,
		`zirogate_config_reload_total{result="ok"} 1`, `zirogate_upstream_available{route="app",upstream="` + up + `"} 1`,
		`zirogate_upstream_responses_total{route="app",class="2xx"} 1`, `zirogate_upstream_request_duration_seconds_count{route="app"} 1`,
		`zirogate_connections{kind="http"}`, `zirogate_go_sched_goroutines_goroutines`, `zirogate_uptime_seconds`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	// The network-facing metrics listener demands the bearer token.
	if c, _ := get(metricsAddr, "", "/metrics", nil); c != http.StatusUnauthorized {
		t.Errorf("metrics without a token: %d", c)
	}
	if c, b := get(metricsAddr, "", "/metrics", map[string]string{"Authorization": "Bearer 0123456789abcdef-token"}); c != 200 || !strings.Contains(b, "zirogate_ready 1") {
		t.Errorf("metrics with the token: %d", c)
	}
	if tok, err := os.ReadFile(gatewayAdminTokenPath); err != nil || len(tok) < 32 {
		t.Errorf("admin token: %v", err)
	}
	if fi, _ := os.Stat(gatewayAdminTokenPath); fi != nil && fi.Mode().Perm() != 0600 {
		t.Errorf("admin token mode %v", fi.Mode().Perm())
	}

	// SIGTERM while a request is in flight: it completes, then the gateway exits cleanly.
	slow := make(chan string, 1)
	go func() { _, b := get(httpAddr, "app.test", "/slow", nil); slow <- b }()
	time.Sleep(200 * time.Millisecond)
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case b := <-slow:
		if b != "hello /slow" {
			t.Errorf("in-flight request during shutdown: %q", b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request never finished")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after SIGTERM")
	}
	if c, _ := get(httpAddr, "app.test", "/", nil); c != 0 {
		t.Errorf("still accepting after shutdown: %d", c)
	}
	logFile.Sync()
	out, _ := os.ReadFile(logFile.Name())
	if !strings.Contains(string(out), `"route":"app"`) || !strings.Contains(string(out), `"waf":"block:ZW-941100`) {
		t.Errorf("access log:\n%s", out)
	}
}

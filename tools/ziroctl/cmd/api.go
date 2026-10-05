package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const (
	apiTokenFile     = "/etc/ziro/api.token"
	apiLegacyRevoked = "/etc/ziro/api.token.revoked"
	apiTLSKey        = "/etc/ziro/tls/server.key"
	apiTLSCert       = "/etc/ziro/tls/server.crt"
	apiPIDFile       = "/run/ziro-api.pid"
	apiAddrFile      = "/run/ziro-api.addr" // scheme://host:port of the running server
)

var (
	apiPort      int
	apiBindHost  string
	apiUseTLS    bool
	apiCorsHost  string
	apiStartTime time.Time
)

type apiCallerKey struct{}

var apiCmd = &cobra.Command{
	Use:     "api",
	Aliases: []string{"server", "controlplane"},
	Short:   "Run the REST API that manages this host",
	Example: `  ziroctl api start --bind 0.0.0.0
  ziroctl api token create ci --role operator`,
}

var apiStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the REST API server",
	Example: `  ziroctl api start
  ziroctl api start --bind 0.0.0.0 --port 8443`,
	Run: func(cmd *cobra.Command, args []string) {
		startAPIServer()
	},
}

var apiStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show whether the API server runs and where",
	Example: `  ziroctl api status`,
	Run: func(cmd *cobra.Command, args []string) {
		addr := apiServerAddr()
		_ = printResult(map[string]any{"running": addr != "", "address": addr}, func() {
			if addr == "" {
				fmt.Println("ziro-api is not running (ziroctl service start ziro-api)")
				return
			}
			fmt.Printf("ziro-api running at %s (health: %s/api/v1/health)\n", addr, addr)
			fmt.Println("tokens: ziroctl api token create <name> --role viewer|deployer|operator|admin")
		})
	},
}

var apiTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage API tokens",
	Example: `  ziroctl api token create grafana --role viewer --ttl 720h
  ziroctl api token ls`,
	Run: func(cmd *cobra.Command, args []string) {
		token := getOrCreateAPIToken()
		if token == "" {
			fmt.Println("No bootstrap token: scoped tokens are in use. Create one with: ziroctl api token create <name> --role admin")
			return
		}
		fmt.Printf("Bootstrap admin token: %s\n", token)
		fmt.Println("Create scoped tokens (ziroctl api token create), then retire this one: ziroctl api token revoke legacy")
	},
}

var apiGenCertsCmd = &cobra.Command{
	Use:     "generate-certs",
	Short:   "Issue a new self-signed TLS certificate for the API",
	Example: `  ziroctl api generate-certs`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := ensureTLSCertificates(); err != nil {
			fmt.Printf("Failed to generate TLS certs: %v\n", err)
			return
		}
		fmt.Println("✓ TLS certificates generated at /etc/ziro/tls/ (server.crt, server.key)")
	},
}

// apiServerAddr is the running server's scheme://host:port ("" when it isn't running).
func apiServerAddr() string {
	b, err := os.ReadFile(apiAddrFile)
	if err != nil {
		return ""
	}
	if data, err := os.ReadFile(apiPIDFile); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 && isPIDRunning(pid) {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func isAPIServerRunning() bool { return apiServerAddr() != "" }

func getOrCreateAPIToken() string {
	if envTok := os.Getenv("ZIRO_API_TOKEN"); envTok != "" {
		return envTok
	}
	if data, err := os.ReadFile(apiTokenFile); err == nil {
		tok := strings.TrimSpace(string(data))
		if tok != "" {
			return tok
		}
	}
	// A first start with no scoped tokens gets one admin token to bootstrap with; once scoped
	// tokens exist, or after `api token revoke legacy`, none is created.
	if ts, _ := loadAPITokens(); len(ts) > 0 || fileExists(apiLegacyRevoked) {
		return ""
	}
	// Generate new 32-byte hex token
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	newTok := "ziro_sec_" + hex.EncodeToString(b)
	_ = os.MkdirAll("/etc/ziro", 0700)
	_ = os.WriteFile(apiTokenFile, []byte(newTok+"\n"), 0600)
	return newTok
}

// apiCertIPs are the addresses the API certificate covers: loopback and every host address.
func apiCertIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, a := range hostAddresses() {
		ips = append(ips, net.ParseIP(a.IP))
	}
	return ips
}

// tlsCertCurrent reports whether the certificate at path is ECDSA, valid for more than 30 days
// and covers every address in ips.
func tlsCertCurrent(path string, ips []net.IP, now time.Time) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || c.PublicKeyAlgorithm != x509.ECDSA || now.Add(30*24*time.Hour).After(c.NotAfter) {
		return false
	}
	for _, ip := range ips {
		if c.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

// apiCertFingerprint is the SHA-256 of the API certificate ("sha256:<hex>"; "" if unreadable), what
// `zirocd trust` shows so a client can compare it before trusting a self-signed certificate.
func apiCertFingerprint() string {
	b, err := os.ReadFile(apiTLSCert)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ensureTLSCertificates (re)issues the API's self-signed certificate (ECDSA P-256, one year)
// when it is missing, expires within 30 days, or no longer covers the host's addresses.
func ensureTLSCertificates() error {
	ips := apiCertIPs()
	if fileExists(apiTLSKey) && tlsCertCurrent(apiTLSCert, ips, time.Now()) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(apiTLSCert), 0700); err != nil {
		return err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Ziro OS"}, CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              []string{"localhost", host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(apiTLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		return err
	}
	return writeFileAtomic(apiTLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}

// certReloader serves the API certificate, renewing and reloading it at most hourly, so a
// long-running server never presents an expired certificate.
type certReloader struct {
	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert == nil || time.Since(c.checked) > time.Hour {
		c.checked = time.Now()
		if err := ensureTLSCertificates(); err != nil && c.cert != nil {
			fmt.Printf("[api] certificate renewal: %v\n", err)
			return c.cert, nil
		}
		kp, err := tls.LoadX509KeyPair(apiTLSCert, apiTLSKey)
		if err != nil {
			if c.cert != nil {
				return c.cert, nil
			}
			return nil, err
		}
		c.cert = &kp
	}
	return c.cert, nil
}

// Simple in-memory sliding window rate limiter
type rateLimiter struct {
	mu      sync.Mutex
	clients map[string][]time.Time
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		clients: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)

	var valid []time.Time
	for _, t := range rl.clients[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.limit {
		rl.clients[ip] = valid
		return false
	}
	rl.clients[ip] = append(valid, now)

	// Evict idle clients so the map cannot grow without bound.
	if len(rl.clients) > 1024 {
		for k, ts := range rl.clients {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(rl.clients, k)
			}
		}
	}
	return true
}

// cachedSecurityScan avoids re-hashing binaries on every API request.
var (
	scanMu     sync.Mutex
	scanCache  SecurityScanReport
	scanCached time.Time
)

func cachedSecurityScan() SecurityScanReport {
	scanMu.Lock()
	defer scanMu.Unlock()
	if time.Since(scanCached) > 30*time.Second {
		scanCache = runSecurityScan()
		scanCached = time.Now()
	}
	return scanCache
}

func startAPIServer() {
	apiStartTime = time.Now()
	token := getOrCreateAPIToken()

	// Write PID
	_ = os.WriteFile(apiPIDFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	defer os.Remove(apiPIDFile)

	handler := newAPIHandler(apiRoutes(), apiServerConfig{legacyToken: token, cors: apiCorsHost,
		perIP: newRateLimiter(120, time.Minute), perToken: newRateLimiter(600, time.Minute)})

	addr := fmt.Sprintf("%s:%d", apiBindHost, apiPort)
	fmt.Printf("ziro-api listening on %s (TLS %v, TLS 1.2 minimum); %d routes, docs: sdk/openapi.yaml\n", addr, apiUseTLS, len(apiRoutes().routes))
	if apiUseTLS {
		if fp := apiCertFingerprint(); fp != "" {
			fmt.Printf("certificate %s (trust it from a client with: zirocd trust https://<this host>:<port>)\n", fp)
		}
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  apiReadTimeout,
		WriteTimeout: apiWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	scheme := "http"
	if apiUseTLS {
		scheme = "https"
		if err := ensureTLSCertificates(); err != nil {
			fmt.Printf("TLS certificate error: %v\n", err)
			return
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: (&certReloader{}).get}
	}
	_ = writeFileAtomic(apiAddrFile, []byte(scheme+"://"+addr+"\n"), 0644)
	defer os.Remove(apiAddrFile)
	var err error
	if apiUseTLS {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		fmt.Printf("API server error: %v\n", err)
	}
}

// The server's default limits for a request and its answer. A route that moves a lot of data
// (a source upload, a streamed build log) lifts them for itself with http.ResponseController:
// a write deadline that fires in the middle of a TLS record leaves a partial record, which the
// client reports as "tls: bad record MAC", so a long answer must not run into the default.
const (
	apiReadTimeout  = 10 * time.Second
	apiWriteTimeout = 15 * time.Second
)

func init() {
	apiStartCmd.Flags().IntVarP(&apiPort, "port", "p", 8443, "REST API listening port")
	apiStartCmd.Flags().StringVar(&apiBindHost, "bind", "127.0.0.1", "Network address to bind (use 0.0.0.0 to expose remotely; also 'ziroctl firewall allow 8443')")
	apiStartCmd.Flags().BoolVar(&apiUseTLS, "tls", true, "Enable TLS / HTTPS encryption")
	apiStartCmd.Flags().StringVar(&apiCorsHost, "cors", "", "Allowed CORS origin for Web GUI (disabled when empty)")

	apiCmd.AddCommand(apiStartCmd)
	apiCmd.AddCommand(apiStatusCmd)
	apiCmd.AddCommand(apiTokenCmd)
	apiCmd.AddCommand(apiGenCertsCmd)
	rootCmd.AddCommand(apiCmd)
}

// registerCoreRoutes: health, host status, services, metrics, cluster and security summaries.
func registerCoreRoutes(a *apiRouter) {
	// Prometheus metrics (a viewer token is enough).
	a.get("/api/v1/metrics", "viewer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(collectMetrics()))
	})
	a.get("/api/v1/health", "public", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, map[string]any{"status": "healthy", "version": Version, "os": "Ziro OS",
			"uptime": time.Since(apiStartTime).Round(time.Second).String(), "arch": hostArch()})
	})
	a.get("/api/v1/system", "viewer", func(w http.ResponseWriter, r *http.Request) {
		sys := inspectSystem()
		platform, hypervisor := detectCloudPlatform()
		apiReply(w, nil, map[string]any{"system": sys, "platform": platform, "hypervisor": hypervisor,
			"cpus": runtime.NumCPU(), "summary": collectHostSummary()})
	})

	a.get("/api/v1/services", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, listAllServices())
	})
	a.get("/api/v1/services/{name}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		st, err := getServiceStatus(r.PathValue("name"))
		if err != nil {
			err = errNotFound(err.Error())
		}
		apiReply(w, err, st)
	})
	// Logs: the last ?lines= (default 100, at most 5000) of the service's log file.
	a.get("/api/v1/services/{name}/logs", "operator", func(w http.ResponseWriter, r *http.Request) {
		def, err := loadServiceDef(r.PathValue("name"))
		if err != nil {
			apiReply(w, errNotFound(err.Error()), nil)
			return
		}
		lines, err := tailFile(def.LogFile, queryInt(r, "lines", 100, 5000))
		apiReply(w, err, map[string]any{"service": def.Name, "lines": lines})
	})
	// Start, stop, restart, enable or disable a trusted (root-owned) service definition.
	a.post("/api/v1/services/{name}/{action}", "operator", func(w http.ResponseWriter, r *http.Request) {
		name, action := r.PathValue("name"), r.PathValue("action")
		if _, err := loadServiceDef(name); err != nil {
			apiReply(w, errNotFound(err.Error()), nil)
			return
		}
		var err error
		switch action {
		case "start":
			err = startService(name)
		case "stop":
			err = stopService(name)
		case "restart":
			err = restartService(name)
		case "enable":
			err = enableService(name)
		case "disable":
			err = disableService(name)
		default:
			apiReply(w, errNotFound("unknown action "+action), nil)
			return
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "service " + name + ": " + action + " done"})
	})

	a.get("/api/v1/wireguard", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, wireguardStatus())
	})
	a.get("/api/v1/cluster", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, clusterView())
	})
	a.get("/api/v1/security", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, cachedSecurityScan())
	})
}

// queryInt reads a positive integer query parameter, bounded by max.
func queryInt(r *http.Request, key string, def, max int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil && v > 0 {
		return min(v, max)
	}
	return def
}

// tailFile returns the last n lines of a file (reading at most the last 4 MiB).
func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := max(0, fi.Size()-4<<20)
	b := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // partial first line
	}
	return lines[max(0, len(lines)-n):], nil
}

// clusterView is the redacted cluster summary (no join or node tokens).
func clusterView() map[string]any {
	cfg, err := loadClusterConfig()
	if err != nil {
		return map[string]any{"role": "standalone"}
	}
	view := map[string]any{"cluster_id": cfg.ClusterID, "role": cfg.Role, "node_id": cfg.NodeID, "master": cfg.MasterAddr}
	if cfg.Role == "master" {
		if st, err := readState(); err == nil {
			apps := []map[string]any{}
			for _, a := range st.Apps {
				apps = append(apps, map[string]any{"name": a.Name, "image": a.Image, "replicas": a.Replicas, "port": a.Port,
					"status": st.appStatus(a), "resources": a.Resources})
			}
			view["nodes"], view["apps"], view["placements"] = st.Nodes, apps, st.Replicas
		}
	}
	return view
}

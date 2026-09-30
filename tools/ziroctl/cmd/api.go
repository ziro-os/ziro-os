package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const (
	apiTokenFile = "/etc/ziro/api.token"
	apiTLSKey    = "/etc/ziro/tls/server.key"
	apiTLSCert   = "/etc/ziro/tls/server.crt"
	apiPIDFile   = "/run/ziro-api.pid"
)

var (
	apiPort      int
	apiBindHost  string
	apiUseTLS    bool
	apiCorsHost  string
	apiStartTime time.Time
)

type apiCallerKey struct{}

type APIMessage struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

var apiCmd = &cobra.Command{
	Use:     "api",
	Aliases: []string{"server", "controlplane"},
	Short:   "Manage Ziro-OS Control Plane REST API server",
}

var apiStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Ziro-OS Control Plane REST API server (secured with TLS and token auth)",
	Run: func(cmd *cobra.Command, args []string) {
		startAPIServer()
	},
}

var apiStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status and connectivity of Ziro REST API server",
	Run: func(cmd *cobra.Command, args []string) {
		if isAPIServerRunning() {
			fmt.Printf("● Ziro REST API Server: \033[1;32mACTIVE (Running)\033[0m\n")
			fmt.Printf("   Port:     %d (HTTPS / TLS 1.2+)\n", apiPort)
			fmt.Printf("   Endpoint: https://127.0.0.1:%d/api/v1/health\n", apiPort)
			fmt.Printf("   Auth:     Bearer Token (see 'ziroctl api token')\n")
		} else {
			fmt.Printf("● Ziro REST API Server: \033[1;33mSTANDBY (Stopped)\033[0m\n")
			fmt.Println("   Start via: 'ziroctl api start' or 'ziroctl service start ziro-api'")
		}
	},
}

var apiTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Display or generate the REST API Bearer Authentication Token",
	Run: func(cmd *cobra.Command, args []string) {
		token := getOrCreateAPIToken()
		fmt.Printf("Ziro API Bearer Token: %s\n", token)
		fmt.Println("Usage with curl:")
		fmt.Printf("  curl -k -H \"Authorization: Bearer %s\" https://127.0.0.1:%d/api/v1/system\n", token, apiPort)
	},
}

var apiGenCertsCmd = &cobra.Command{
	Use:   "generate-certs",
	Short: "Generate self-signed TLS/SSL certificates for HTTPS encryption",
	Run: func(cmd *cobra.Command, args []string) {
		if err := ensureTLSCertificates(); err != nil {
			fmt.Printf("Failed to generate TLS certs: %v\n", err)
			return
		}
		fmt.Println("✓ TLS certificates generated at /etc/ziro/tls/ (server.crt, server.key)")
	},
}

func isAPIServerRunning() bool {
	// Check PID file
	if fileExists(apiPIDFile) {
		if data, err := os.ReadFile(apiPIDFile); err == nil {
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 && isPIDRunning(pid) {
				return true
			}
		}
	}

	// Check local port probe
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", apiPort), 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

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
	// Generate new 32-byte hex token
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	newTok := "ziro_sec_" + hex.EncodeToString(b)
	_ = os.MkdirAll("/etc/ziro", 0700)
	_ = os.WriteFile(apiTokenFile, []byte(newTok+"\n"), 0600)
	return newTok
}

func ensureTLSCertificates() error {
	if fileExists(apiTLSCert) && fileExists(apiTLSKey) {
		return nil
	}
	_ = os.MkdirAll("/etc/ziro/tls", 0700)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ziro-OS Cloud Control Plane"},
			CommonName:   "ziro-host",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "ziro-host"},
	}

	// Add local interfaces IPs
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok {
						template.IPAddresses = append(template.IPAddresses, ipnet.IP)
					}
				}
			}
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(apiTLSCert)
	if err != nil {
		return err
	}
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile(apiTLSKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
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

	mux := http.NewServeMux()
	limiter := newRateLimiter(120, 1*time.Minute)

	// API Middleware: Auth, Rate Limit, CORS, Security Headers
	wrapHandler := func(isPublic bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Security Headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			// CORS
			origin := r.Header.Get("Origin")
			if origin != "" && apiCorsHost != "" {
				w.Header().Set("Access-Control-Allow-Origin", apiCorsHost)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				if r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusOK)
					return
				}
			}

			// Rate Limiting
			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}
			if !limiter.allow(clientIP) {
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "Rate limit exceeded (120 req/min)"})
				return
			}

			// Authentication (scoped tokens or the pre-RBAC admin token) and role check.
			if !isPublic {
				authHeader := r.Header.Get("Authorization")
				name, role, ok := apiIdentity(trimBearer(authHeader), token, time.Now())
				if !ok || !strings.HasPrefix(authHeader, "Bearer ") {
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "Unauthorized: Invalid or missing Bearer token"})
					return
				}
				if !apiAllowed(role, r.Method) {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "Forbidden: the " + role + " role cannot " + r.Method})
					return
				}
				r = r.WithContext(context.WithValue(r.Context(), apiCallerKey{}, "api-token:"+name+"("+role+")"))
			}

			h(w, r)
		}
	}

	// Prometheus metrics (any token; a viewer token is enough).
	mux.HandleFunc("/api/v1/metrics", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(collectMetrics()))
	}))

	// 1. Health
	mux.HandleFunc("/api/v1/health", wrapHandler(true, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "healthy",
			"version":  Version,
			"os":       "Ziro-OS",
			"uptime":   time.Since(apiStartTime).Round(time.Second).String(),
			"arch":     runtime.GOARCH,
			"features": []string{"containers", "clustering", "wireguard", "firewall", "sentinel", "compose"},
		})
	}))

	// 2. System status
	mux.HandleFunc("/api/v1/system", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		sys := inspectSystem()
		platform, hypervisor := detectCloudPlatform()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"system":     sys,
			"platform":   platform,
			"hypervisor": hypervisor,
			"cpus":       runtime.NumCPU(),
		})
	}))

	// 3. Services list & management
	mux.HandleFunc("/api/v1/services", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			services := listAllServices()
			_ = json.NewEncoder(w).Encode(services)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/v1/services/", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		// Path: /api/v1/services/{name}/{action}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/services/"), "/")
		if len(parts) >= 2 && r.Method == "POST" {
			name := parts[0]
			action := parts[1]
			// Only existing, trusted service definitions: the name never reaches anything else.
			if _, err := loadServiceDef(name); err != nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: err.Error()})
				return
			}
			var err error
			switch action {
			case "start", "stop", "restart":
				err = runServiceCLI(serviceActions[action], name)
			case "enable":
				err = enableService(name)
			case "disable":
				err = disableService(name)
			default:
				http.Error(w, "Unknown action", http.StatusBadRequest)
				return
			}
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			caller, _ := r.Context().Value(apiCallerKey{}).(string)
			if aerr := auditLog(caller, "api:"+ip, "service "+action, name, err); aerr != nil {
				fmt.Printf("[api] audit log: %v\n", aerr)
			}
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(APIMessage{Status: "ok", Message: fmt.Sprintf("Service %s %sed", name, action)})
			return
		}
		http.Error(w, "Invalid path", http.StatusBadRequest)
	}))

	// 4. Containers
	mux.HandleFunc("/api/v1/containers", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			out, err := exec.Command("nerdctl", "ps", "-a", "--format", "json").Output()
			if err != nil || len(out) == 0 {
				_ = json.NewEncoder(w).Encode([]string{})
				return
			}
			w.Write(out)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	// 5. Firewall
	mux.HandleFunc("/api/v1/firewall", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		cfg := loadFirewallConfig()
		_ = json.NewEncoder(w).Encode(cfg)
	}))

	// 6. WireGuard
	mux.HandleFunc("/api/v1/wireguard", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		out, _ := exec.Command("wg", "show").Output()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": len(out) > 0,
			"raw":    string(out),
		})
	}))

	// 7. Cluster
	mux.HandleFunc("/api/v1/cluster", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		// Never expose join/node tokens: return an explicit, redacted view.
		cfg, err := loadClusterConfig()
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"role": "standalone"})
			return
		}
		view := map[string]interface{}{
			"cluster_id": cfg.ClusterID, "role": cfg.Role, "node_id": cfg.NodeID, "master": cfg.MasterAddr,
		}
		if cfg.Role == "master" {
			if st, err := readState(); err == nil {
				apps := []map[string]interface{}{}
				for _, a := range st.Apps {
					apps = append(apps, map[string]interface{}{
						"name": a.Name, "image": a.Image, "replicas": a.Replicas, "port": a.Port, "status": st.appStatus(a),
					})
				}
				view["nodes"], view["apps"], view["placements"] = st.Nodes, apps, st.Replicas
			}
		}
		_ = json.NewEncoder(w).Encode(view)
	}))

	// 8. Security Scan
	mux.HandleFunc("/api/v1/security", wrapHandler(false, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(cachedSecurityScan())
	}))

	addr := fmt.Sprintf("%s:%d", apiBindHost, apiPort)
	fmt.Println("================================================================")
	fmt.Printf(" 🚀 Ziro-OS Control Plane REST API Server started!\n")
	fmt.Println("================================================================")
	fmt.Printf(" Listening on: %s (TLS 1.3 / HTTPS: %v)\n", addr, apiUseTLS)
	fmt.Println(" Bearer Token: run 'ziroctl api token' (never logged)")
	fmt.Println(" Control Endpoints:")
	fmt.Println("   • GET  /api/v1/health       - Server & OS liveness check")
	fmt.Println("   • GET  /api/v1/system       - System metrics & cloud metadata")
	fmt.Println("   • GET  /api/v1/services     - Services list & status")
	fmt.Println("   • POST /api/v1/services/... - Start, stop, restart services")
	fmt.Println("   • GET  /api/v1/containers   - OCI containers inspection")
	fmt.Println("   • GET  /api/v1/firewall     - Firewall status & active rules")
	fmt.Println("   • GET  /api/v1/wireguard    - WireGuard mesh VPN status")
	fmt.Println("   • GET  /api/v1/cluster      - Cluster nodes & deployments")
	fmt.Println("   • GET  /api/v1/security     - Security scan & AI threat report")
	fmt.Println("================================================================")

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if apiUseTLS {
		if err := ensureTLSCertificates(); err != nil {
			fmt.Printf("TLS certificate error: %v\n", err)
			return
		}
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if err := server.ListenAndServeTLS(apiTLSCert, apiTLSKey); err != nil {
			fmt.Printf("TLS Server error: %v\n", err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("HTTP Server error: %v\n", err)
		}
	}
}

func init() {
	apiStartCmd.Flags().IntVarP(&apiPort, "port", "p", 8443, "REST API listening port")
	apiStartCmd.Flags().StringVar(&apiBindHost, "bind", "127.0.0.1", "Network address to bind (use 0.0.0.0 to expose remotely; also 'ziroctl firewall allow 8443')")
	apiStartCmd.Flags().BoolVar(&apiUseTLS, "tls", true, "Enable TLS / HTTPS encryption")
	apiStartCmd.Flags().StringVar(&apiCorsHost, "cors", "", "Allowed CORS origin for Web GUI (disabled when empty)")

	apiStatusCmd.Flags().IntVarP(&apiPort, "port", "p", 8443, "REST API listening port")
	apiTokenCmd.Flags().IntVarP(&apiPort, "port", "p", 8443, "REST API listening port")

	apiCmd.AddCommand(apiStartCmd)
	apiCmd.AddCommand(apiStatusCmd)
	apiCmd.AddCommand(apiTokenCmd)
	apiCmd.AddCommand(apiGenCertsCmd)
	rootCmd.AddCommand(apiCmd)
}

// serviceActions maps the request's action to a constant, so the request never supplies argv text.
var serviceActions = map[string]string{"start": "start", "stop": "stop", "restart": "restart"}

// runServiceCLI applies a service action through the ziroctl CLI (fixed binary, argv, no shell).
// The network-facing API never spawns daemons itself: the CLI re-validates the name and the
// root-owned definition exactly as for a local operator, and the daemon is not tied to the API.
func runServiceCLI(action, name string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.Command(self, "service", action, name).CombinedOutput()
	if err != nil {
		msg := strings.TrimPrefix(strings.TrimSpace(string(out)), "Error: ")
		return fmt.Errorf("%s", strings.TrimSpace(strings.SplitN(msg, "\n", 2)[0]))
	}
	return nil
}

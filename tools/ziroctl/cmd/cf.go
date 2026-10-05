package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Cloudflare Tunnel (the cloudflared module): publish services on this host through Cloudflare
// without a public IP or open inbound port. cloudflared dials out to Cloudflare's edge, which
// serves the hostnames and can put Zero Trust Access in front of them.
//
//   - Named tunnel: one per host, remotely managed (ingress lives at Cloudflare). Created with
//     an API token (`cf login`), or adopted from a dashboard token (`cf up --token-file`).
//   - Quick tunnel: a random trycloudflare.com URL, no account, for temporary use.
//
// The binary comes from the signed module catalog (sha256-pinned); `cf update` upgrades it.
// Secrets: the API token is sealed to the TPM when there is one, otherwise a 0600 file in a 0700
// root directory; the tunnel token is only in a root-only env file that ziro-init hands to
// cloudflared, which runs as its own unprivileged user. Neither is ever in argv.

const (
	cfModule     = "cloudflared"
	cfUser       = "cloudflared"
	cfService    = "cloudflared"
	cfQuickSvc   = "cloudflared-quick"
	cfMetrics    = "127.0.0.1:20241"
	cfQuickMet   = "127.0.0.1:20242"
	cfCatchAll   = "http_status:404"
	cfDefaultURL = "http://127.0.0.1:80" // the gateway
)

var (
	cfDir    = "/etc/ziro/cloudflared"
	cfBinary = "/var/lib/ziro/plugins/cloudflared/cloudflared"
)

func cfLoginPath() string  { return filepath.Join(cfDir, "api.json") }
func cfTunnelPath() string { return filepath.Join(cfDir, "tunnel.json") }
func cfEnvPath() string    { return filepath.Join(cfDir, "tunnel.env") }

// cfLogin is the saved API token, wrapped like the cluster data key (file or tpm provider).
type cfLogin struct {
	Account     string `json:"account"`
	AccountName string `json:"account_name"`
	Provider    string `json:"provider"`
	Blob        []byte `json:"blob"`
}

type cfTunnelState struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Account string `json:"account"`
}

var (
	hostRe  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	quickRe = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
)

// ---- secrets and state ----

func saveCFLogin(token string, acc cfAccount) error {
	c := keyProviderConfig{Provider: "file"}
	if _, err := os.Stat(tpmDevice); err == nil {
		c.Provider = "tpm"
	}
	blob, err := wrapDEK(c, []byte(token))
	if err != nil && c.Provider == "tpm" { // a TPM that can't seal (busy, locked out): still 0600 root-only
		c.Provider = "file"
		blob, err = wrapDEK(c, []byte(token))
	}
	if err != nil {
		return err
	}
	b, _ := json.Marshal(cfLogin{Account: acc.ID, AccountName: acc.Name, Provider: c.Provider, Blob: blob})
	return cfWrite(cfLoginPath(), b)
}

// cfWrite writes a root-only file in the root-only cloudflared directory.
func cfWrite(path string, b []byte) error {
	if err := os.MkdirAll(cfDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(cfDir, 0700); err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0600)
}

func loadCFLogin() (*cfLogin, error) {
	b, err := os.ReadFile(cfLoginPath())
	if os.IsNotExist(err) {
		return nil, errors.New("not logged in: ziroctl cf login")
	}
	if err != nil {
		return nil, err
	}
	var l cfLogin
	return &l, json.Unmarshal(b, &l)
}

// cfAPI returns a client for the saved account.
func cfAPI() (*cfClient, *cfLogin, error) {
	l, err := loadCFLogin()
	if err != nil {
		return nil, nil, err
	}
	tok, err := unwrapDEK(wrappedDEK{Provider: l.Provider, Blob: l.Blob}, keyProviderConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("unseal the Cloudflare API token (%s): %w", l.Provider, err)
	}
	return &cfClient{token: string(tok), account: l.Account}, l, nil
}

func loadCFTunnel() (*cfTunnelState, error) {
	b, err := os.ReadFile(cfTunnelPath())
	if os.IsNotExist(err) {
		return nil, errors.New("no tunnel on this host: ziroctl cf up")
	}
	if err != nil {
		return nil, err
	}
	var t cfTunnelState
	return &t, json.Unmarshal(b, &t)
}

// readCFSecret reads a token from a file, env (an environment value), a no-echo prompt or piped
// stdin, in that order. Never from argv.
func readCFSecret(file, env, prompt string) (string, error) {
	var s string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		s = string(b)
	case env != "":
		s = env
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		s = string(b)
	default:
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err != nil {
			return "", err
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", errors.New("empty or malformed token")
	}
	return s, nil
}

// tunnelIDFromToken reads the tunnel id from a connector token (base64 JSON {a, t, s}).
func tunnelIDFromToken(tok string) (account, id string, err error) {
	b, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(tok)
	}
	var t struct{ A, T, S string }
	if err != nil || json.Unmarshal(b, &t) != nil || t.T == "" || t.S == "" {
		return "", "", errors.New("not a Cloudflare tunnel token (copy it from Zero Trust › Networks › Tunnels)")
	}
	return t.A, t.T, nil
}

// ---- services ----

func ensureCFUser() error {
	if _, err := user.Lookup(cfUser); err == nil {
		return nil
	}
	for _, c := range [][]string{
		{"addgroup", "-S", cfUser},
		{"adduser", "-S", "-D", "-H", "-h", "/var/empty", "-s", "/sbin/nologin", "-G", cfUser, "-g", "Cloudflare Tunnel", cfUser},
	} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil && !strings.Contains(string(out), "in use") {
			return fmt.Errorf("%s: %v: %s", c[0], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func cfServiceDef(name, args, env string) ServiceDef {
	return ServiceDef{Name: name, Description: "Cloudflare Tunnel connector", Exec: cfBinary, Args: args,
		PIDFile: "/run/ziro-" + name + ".pid", LogFile: "/var/log/" + name + ".log", User: cfUser, EnvFile: env,
		Resources: &Resources{Memory: "128Mi", PIDs: 256}, Restart: "always", Autostart: true}
}

// cfRun writes the service definition and (re)starts it.
func cfRun(def ServiceDef) error {
	if err := ensureCFUser(); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(servicesDir, def.Name+".conf"), []byte(supervisedConf(def)), 0644); err != nil {
		return err
	}
	if d, err := loadServiceDef(def.Name); err == nil && getServicePID(d) > 0 {
		return restartSupervised(def.Name)
	}
	return startService(def.Name)
}

// cfStop stops a cloudflared service and removes it, so it doesn't start at boot.
func cfStop(name string) error {
	if _, err := loadServiceDef(name); err != nil {
		return nil
	}
	if err := stopService(name); err != nil {
		return err
	}
	return os.Remove(filepath.Join(servicesDir, name+".conf"))
}

func cfRunning(name string) bool {
	d, err := loadServiceDef(name)
	return err == nil && getServicePID(d) > 0
}

// cfReady reports how many edge connections the connector holds (0 = not ready).
func cfReady(metrics string) int {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + metrics + "/ready")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var r struct {
		ReadyConnections int `json:"readyConnections"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil {
		return 0
	}
	return r.ReadyConnections
}

func cfWaitReady(metrics string, d time.Duration) int {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Second) {
		if n := cfReady(metrics); n > 0 {
			return n
		}
	}
	return 0
}

// cfQuickURL returns the newest trycloudflare URL in the quick tunnel's log.
func cfQuickURL() string {
	f, err := os.Open("/var/log/" + cfQuickSvc + ".log")
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 64<<10 {
		_, _ = f.Seek(-64<<10, io.SeekEnd)
	}
	b, _ := io.ReadAll(f)
	m := quickRe.FindAll(b, -1)
	if len(m) == 0 {
		return ""
	}
	return string(m[len(m)-1])
}

// cfVersion returns the installed cloudflared version ("" when unknown).
func cfVersion() string {
	out, err := exec.Command(cfBinary, "--version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) >= 3 {
		return f[2] // "cloudflared version 2026.9.3 (built ...)"
	}
	return ""
}

// ---- input checks ----

// cfOrigin turns "8080" or a URL into the origin cloudflared forwards to.
func cfOrigin(s string) (string, error) {
	if p, err := strconv.Atoi(s); err == nil && p > 0 && p < 65536 {
		return "http://127.0.0.1:" + s, nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("%q: want a port or a URL like http://127.0.0.1:8080", s)
	}
	switch u.Scheme {
	case "http", "https", "tcp", "ssh", "rdp":
		return s, nil
	}
	return "", fmt.Errorf("%q: scheme must be http, https, tcp, ssh or rdp", s)
}

func cfHostname(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(s), ".")
	if !hostRe.MatchString(h) || len(h) > 253 {
		return "", fmt.Errorf("%q is not a hostname", s)
	}
	return h, nil
}

// cfAccessList checks --access: emails and @domains.
func cfAccessList(s string) ([]string, error) {
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.ToLower(strings.TrimSpace(a))
		if d, ok := strings.CutPrefix(a, "@"); ok {
			if _, err := cfHostname(d); err != nil {
				return nil, fmt.Errorf("--access %q: not a domain", a)
			}
		} else if name, dom, ok := strings.Cut(a, "@"); !ok || name == "" || !hostRe.MatchString(dom) {
			return nil, fmt.Errorf("--access %q: want an email or @domain", a)
		}
		out = append(out, a)
	}
	return out, nil
}

// withRoute returns rules with host -> origin added (or replaced), and the catch-all last.
func withRoute(rules []cfIngress, host, origin string) []cfIngress {
	out := withoutRoute(rules, host)
	return append(out, cfIngress{Hostname: host, Service: origin}, cfIngress{Service: cfCatchAll})
}

// withoutRoute returns rules without host and without the catch-all.
func withoutRoute(rules []cfIngress, host string) []cfIngress {
	var out []cfIngress
	for _, r := range rules {
		if r.Hostname != host && r.Hostname != "" {
			out = append(out, r)
		}
	}
	return out
}

// ---- gateway integration ----

var cfTrust struct {
	sync.Mutex
	at time.Time
	on bool
}

// cfTunnelActive reports whether this host runs a tunnel (checked at most every 10 seconds).
func cfTunnelActive() bool {
	cfTrust.Lock()
	defer cfTrust.Unlock()
	if time.Since(cfTrust.at) > 10*time.Second {
		_, a := os.Stat(filepath.Join(servicesDir, cfService+".conf"))
		_, b := os.Stat(filepath.Join(servicesDir, cfQuickSvc+".conf"))
		cfTrust.on, cfTrust.at = a == nil || b == nil, time.Now()
	}
	return cfTrust.on
}

// cfTunnelRequest handles a request cloudflared forwarded to the gateway: it comes from loopback
// with the visitor's address in CF-Connecting-IP, so rate limits, allow-lists and logs see the
// real client. Returns true when the visitor used HTTPS at Cloudflare's edge (no redirect loop to
// https). Elsewhere the header is dropped so clients can't spoof it to upstreams.
// ponytail: any local process can also send from loopback; a listener only cloudflared uses
// closes that.
func cfTunnelRequest(req *http.Request) bool {
	h := req.Header.Get("CF-Connecting-IP")
	if h == "" {
		return false
	}
	ip, port, _ := net.SplitHostPort(req.RemoteAddr)
	peer, err1 := netip.ParseAddr(ip)
	visitor, err2 := netip.ParseAddr(h)
	if err1 != nil || err2 != nil || !peer.IsLoopback() || !cfTunnelActive() {
		req.Header.Del("CF-Connecting-IP")
		return false
	}
	req.RemoteAddr = net.JoinHostPort(visitor.String(), port)
	return strings.Contains(req.Header.Get("CF-Visitor"), `"https"`)
}

// ---- commands ----

var cfCmd = &cobra.Command{
	Use:     "cf",
	Aliases: []string{"cloudflare"},
	Short:   "Cloudflare Tunnel: publish services without a public IP",
	Long: `Publish services on this host through Cloudflare Tunnel: no public IP, no open inbound port,
and optional Zero Trust Access in front. Needs the cloudflared module:

  ziroctl module enable cloudflared`,
	Example: `  ziroctl cf login
  ziroctl cf up
  ziroctl cf route add app.example.com --access @example.com
  ziroctl cf quick 8080`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Daemons started here inherit our environment: keep secrets and cloudflared settings out.
		if v := os.Getenv("CF_API_TOKEN"); v != "" {
			cfEnvToken = v
		}
		for _, kv := range os.Environ() {
			if k, _, _ := strings.Cut(kv, "="); k == "CF_API_TOKEN" || strings.HasPrefix(k, "TUNNEL_") {
				_ = os.Unsetenv(k)
			}
		}
		st := enabledModules()[cfModule]
		if st != nil && (st.Status == "enabled" || cmd == cfDownCmd) { // disable runs `cf down`
			return nil
		}
		return errors.New("cloudflared is not enabled: ziroctl module enable cloudflared")
	},
}

var (
	cfEnvToken  string // $CF_API_TOKEN, taken out of the environment
	cfTokenFile string
	cfAccountID string
	cfDelete    bool
	cfAccess    string
	cfDetach    bool
	cfStopQuick bool
	cfCheck     bool
	cfCron      bool
)

var cfLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Save a Cloudflare API token for managing tunnels",
	Long: `Save a Cloudflare API token. It is read from --token-file, $CF_API_TOKEN or a prompt (never the
command line), checked against Cloudflare, and stored sealed to the TPM when the host has one,
otherwise root-only.

Token permissions: Account › Cloudflare Tunnel: Edit and Zone › DNS: Edit; add
Account › Access: Apps and Policies: Edit to use --access.`,
	Example: `  ziroctl cf login
  ziroctl cf login --token-file /root/cf-token --account 0123abcd`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		tok, err := readCFSecret(cfTokenFile, cfEnvToken, "Cloudflare API token: ")
		if err != nil {
			return err
		}
		accs, err := (&cfClient{token: tok}).accounts()
		if err != nil {
			return err
		}
		var acc *cfAccount
		for i, a := range accs {
			if cfAccountID == "" && len(accs) == 1 || a.ID == cfAccountID {
				acc = &accs[i]
			}
		}
		if acc == nil {
			var ids []string
			for _, a := range accs {
				ids = append(ids, a.ID+" ("+a.Name+")")
			}
			if len(ids) == 0 {
				return errors.New("the token can't see any account (give it Account › Cloudflare Tunnel: Edit)")
			}
			return fmt.Errorf("choose an account with --account: %s", strings.Join(ids, ", "))
		}
		if err := saveCFLogin(tok, *acc); err != nil {
			return err
		}
		l, _ := loadCFLogin()
		fmt.Printf("✓ Logged in to %s (token stored: %s)\n", acc.Name, l.Provider)
		return nil
	},
}

var cfLogoutCmd = &cobra.Command{
	Use:     "logout",
	Short:   "Remove the saved API token",
	Example: `  ziroctl cf logout`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := os.Remove(cfLoginPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("✓ API token removed (a running tunnel keeps running)")
		return nil
	},
}

var cfUpCmd = &cobra.Command{
	Use:   "up [name]",
	Short: "Create or adopt this host's tunnel and start it",
	Long: `Start this host's tunnel. With a saved API token it creates the tunnel (named after the host
unless you give a name) or adopts an existing one of that name. With --token-file it runs a tunnel
created in the Cloudflare dashboard; no API token is needed. Without either, it restarts the
tunnel this host already has.`,
	Example: `  ziroctl cf up
  ziroctl cf up --token-file /root/tunnel-token`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var st cfTunnelState
		var tok string
		switch {
		case cfTokenFile != "":
			t, err := readCFSecret(cfTokenFile, "", "")
			if err != nil {
				return err
			}
			acc, id, err := tunnelIDFromToken(t)
			if err != nil {
				return err
			}
			st, tok = cfTunnelState{ID: id, Account: acc}, t
		case len(args) == 0 && fileExists(cfEnvPath()) && fileExists(cfTunnelPath()):
			cur, err := loadCFTunnel()
			if err != nil {
				return err
			}
			st = *cur
		default:
			c, l, err := cfAPI()
			if err != nil {
				return err
			}
			name, _ := os.Hostname()
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" || len(name) > 64 || strings.ContainsAny(name, " \t\r\n/") {
				return fmt.Errorf("bad tunnel name %q", name)
			}
			t, err := c.findTunnel(name)
			if err != nil {
				return err
			}
			if t == nil {
				if t, err = c.createTunnel(name); err != nil {
					return err
				}
				fmt.Printf("✓ Created tunnel %s (%s)\n", t.Name, t.ID)
			}
			if tok, err = c.tunnelToken(t.ID); err != nil {
				return err
			}
			st = cfTunnelState{ID: t.ID, Name: t.Name, Account: l.Account}
		}
		if tok != "" {
			b, _ := json.Marshal(st)
			if err := cfWrite(cfTunnelPath(), b); err != nil {
				return err
			}
			if err := cfWrite(cfEnvPath(), []byte("TUNNEL_TOKEN="+tok+"\n")); err != nil {
				return err
			}
		}
		def := cfServiceDef(cfService, "tunnel --no-autoupdate --metrics "+cfMetrics+" run", cfEnvPath())
		if err := cfRun(def); err != nil {
			return err
		}
		if n := cfWaitReady(cfMetrics, 20*time.Second); n > 0 {
			fmt.Printf("✓ Tunnel %s is up (%d edge connections)\n", st.ID, n)
		} else {
			fmt.Printf("… Tunnel %s started but not connected yet: ziroctl cf status, log /var/log/%s.log\n", st.ID, cfService)
		}
		fmt.Println("  Publish a hostname: ziroctl cf route add app.example.com")
		return nil
	},
}

var cfDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the tunnel; --delete also removes it at Cloudflare",
	Example: `  ziroctl cf down
  ziroctl cf down --delete`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cfStop(cfService); err != nil {
			return err
		}
		_ = cfStop(cfQuickSvc)
		if !cfDelete {
			fmt.Println("✓ Tunnel stopped (ziroctl cf up starts it again)")
			return nil
		}
		st, err := loadCFTunnel()
		if err != nil {
			return err
		}
		c, _, err := cfAPI()
		if err != nil {
			return err
		}
		if rules, err := c.ingress(st.ID); err == nil { // DNS records and Access apps ziroctl made for it
			for _, r := range withoutRoute(rules, "") {
				if err := cfUnpublish(c, st, r.Hostname); err != nil {
					fmt.Printf("  %s: %v\n", r.Hostname, err)
				}
			}
		}
		if err := c.deleteTunnel(st.ID); err != nil {
			return err
		}
		_ = os.Remove(cfEnvPath())
		_ = os.Remove(cfTunnelPath())
		fmt.Printf("✓ Tunnel %s deleted\n", st.ID)
		return nil
	},
}

var cfRouteCmd = &cobra.Command{
	Use:     "route",
	Aliases: []string{"routes"},
	Short:   "Publish hostnames through the tunnel",
	Example: `  ziroctl cf route add app.example.com
  ziroctl cf route ls`,
}

// cfRouteAPI returns a client for the account that owns this host's tunnel.
func cfRouteAPI() (*cfClient, *cfTunnelState, error) {
	st, err := loadCFTunnel()
	if err != nil {
		return nil, nil, err
	}
	c, l, err := cfAPI()
	if err != nil {
		return nil, nil, err
	}
	if st.Account != "" && st.Account != l.Account {
		return nil, nil, errors.New("the saved API token is for another account than this tunnel")
	}
	return c, st, nil
}

var cfRouteAddCmd = &cobra.Command{
	Use:   "add <hostname> [origin]",
	Short: "Publish a hostname; the origin defaults to the gateway",
	Long: `Publish a hostname: Cloudflare serves it (TLS at the edge) and the tunnel forwards it to the
origin, by default the gateway on this host (http://127.0.0.1:80), which routes it by Host as
usual. The origin can also be a port or a URL (http, https, tcp, ssh, rdp). The hostname must be
in a zone of the account. --access puts Cloudflare Access in front: only these emails and
@domains get in.`,
	Example: `  ziroctl cf route add app.example.com
  ziroctl cf route add grafana.example.com 3000 --access alice@example.com,@example.com`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := cfHostname(args[0])
		if err != nil {
			return err
		}
		origin := cfDefaultURL
		if len(args) == 2 {
			if origin, err = cfOrigin(args[1]); err != nil {
				return err
			}
		}
		var allow []string
		if cfAccess != "" {
			if allow, err = cfAccessList(cfAccess); err != nil {
				return err
			}
		}
		c, st, err := cfRouteAPI()
		if err != nil {
			return err
		}
		zone, err := c.zoneFor(host)
		if err != nil {
			return err
		}
		target := st.ID + ".cfargotunnel.com"
		rec, err := c.dnsRecord(zone.ID, host)
		if err != nil {
			return err
		}
		if rec != nil && rec.Content != target {
			return fmt.Errorf("%s already has a DNS record (%s %s): remove it first", host, rec.Type, rec.Content)
		}
		if allow != nil { // Access first: the hostname never serves unprotected
			if app, err := c.accessApp(host); err != nil {
				return err
			} else if app == nil {
				if err := c.createAccessApp(host, allow); err != nil {
					return err
				}
			}
		}
		rules, err := c.ingress(st.ID)
		if err != nil {
			return err
		}
		if err := c.putIngress(st.ID, withRoute(rules, host, origin)); err != nil {
			return err
		}
		if rec == nil {
			if err := c.createCNAME(zone.ID, host, target); err != nil {
				return err
			}
		}
		fmt.Printf("✓ https://%s → %s\n", host, origin)
		if allow != nil {
			fmt.Printf("  Access: %s\n", strings.Join(allow, ", "))
		}
		return nil
	},
}

// cfUnpublish removes the CNAME (if it points at this tunnel) and the Access app ziroctl made.
func cfUnpublish(c *cfClient, st *cfTunnelState, host string) error {
	if zone, err := c.zoneFor(host); err == nil {
		if rec, err := c.dnsRecord(zone.ID, host); err == nil && rec != nil && rec.Content == st.ID+".cfargotunnel.com" {
			if err := c.deleteDNS(zone.ID, rec.ID); err != nil {
				return err
			}
		}
	}
	if app, err := c.accessApp(host); err == nil && app != nil {
		return c.deleteAccessApp(app.ID)
	}
	return nil
}

var cfRouteRmCmd = &cobra.Command{
	Use:     "rm <hostname>",
	Short:   "Unpublish a hostname",
	Example: `  ziroctl cf route rm app.example.com`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := cfHostname(args[0])
		if err != nil {
			return err
		}
		c, st, err := cfRouteAPI()
		if err != nil {
			return err
		}
		rules, err := c.ingress(st.ID)
		if err != nil {
			return err
		}
		if err := c.putIngress(st.ID, append(withoutRoute(rules, host), cfIngress{Service: cfCatchAll})); err != nil {
			return err
		}
		if err := cfUnpublish(c, st, host); err != nil {
			return err
		}
		fmt.Printf("✓ %s unpublished\n", host)
		return nil
	},
}

var cfRouteLsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "List published hostnames",
	Example: `  ziroctl cf route ls`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, st, err := cfRouteAPI()
		if err != nil {
			return err
		}
		rules, err := c.ingress(st.ID)
		if err != nil {
			return err
		}
		routes := withoutRoute(rules, "")
		return printResult(routes, func() {
			if len(routes) == 0 {
				fmt.Println("No hostnames: ziroctl cf route add app.example.com")
				return
			}
			for _, r := range routes {
				fmt.Printf("%-40s → %s\n", r.Hostname, r.Service)
			}
		})
	},
}

var cfQuickCmd = &cobra.Command{
	Use:   "quick [origin]",
	Short: "Temporary public URL on trycloudflare.com, no account",
	Long: `Get a random https://….trycloudflare.com URL for a local service, with no account or DNS. For
tests and demos: the URL changes on every start, has no uptime guarantee, and anyone with it can
reach the service. The origin is a port or URL (default: the gateway). Runs until Ctrl-C, or in
the background with --detach (stop it with --stop).`,
	Example: `  ziroctl cf quick 8080
  ziroctl cf quick http://127.0.0.1:3000 --detach
  ziroctl cf quick --stop`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cfStopQuick {
			if err := cfStop(cfQuickSvc); err != nil {
				return err
			}
			fmt.Println("✓ Quick tunnel stopped")
			return nil
		}
		origin := cfDefaultURL
		if len(args) == 1 {
			var err error
			if origin, err = cfOrigin(args[0]); err != nil {
				return err
			}
		}
		qargs := "tunnel --no-autoupdate --metrics " + cfQuickMet + " --url " + origin
		if cfDetach {
			if err := cfRun(cfServiceDef(cfQuickSvc, qargs, "")); err != nil {
				return err
			}
			for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
				if u := cfQuickURL(); u != "" && cfReady(cfQuickMet) > 0 {
					fmt.Printf("⚠ Temporary public URL: %s → %s\n  Stop it: ziroctl cf quick --stop\n", u, origin)
					return nil
				}
			}
			return fmt.Errorf("no URL after 30s: see /var/log/%s.log", cfQuickSvc)
		}
		return cfQuickForeground(strings.Fields(qargs), origin)
	},
}

// cfQuickForeground runs a quick tunnel as the cloudflared user until Ctrl-C.
func cfQuickForeground(args []string, origin string) error {
	if err := ensureCFUser(); err != nil {
		return err
	}
	u, err := user.Lookup(cfUser)
	if err != nil {
		return err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	c := exec.Command(cfBinary, args...)
	c.Env = []string{"HOME=/var/empty", "PATH=/usr/bin:/bin"}
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	stderr, err := c.StderrPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}
	signal.Ignore(os.Interrupt) // Ctrl-C reaches cloudflared too; wait for it to exit
	sc := bufio.NewScanner(stderr)
	shown := false
	for sc.Scan() {
		if verbose {
			fmt.Fprintln(os.Stderr, sc.Text())
		}
		if m := quickRe.FindString(sc.Text()); m != "" && !shown {
			shown = true
			fmt.Printf("⚠ Temporary public URL: %s → %s\n  Anyone with the link can reach it. Ctrl-C stops it.\n", m, origin)
		}
	}
	if err := c.Wait(); err != nil && !shown {
		return fmt.Errorf("cloudflared: %w (rerun with -v for its log)", err)
	}
	fmt.Println("✓ Quick tunnel stopped")
	return nil
}

type cfStatus struct {
	Version     string `json:"version"`
	Account     string `json:"account,omitempty"`
	TokenStore  string `json:"token_store,omitempty"`
	TunnelID    string `json:"tunnel_id,omitempty"`
	TunnelName  string `json:"tunnel_name,omitempty"`
	Running     bool   `json:"running"`
	Connections int    `json:"connections"`
	QuickURL    string `json:"quick_url,omitempty"`
}

var cfStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show the tunnel, its connections and version",
	Example: `  ziroctl cf status`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := cfStatus{Version: cfVersion(), Running: cfRunning(cfService)}
		if l, err := loadCFLogin(); err == nil {
			s.Account, s.TokenStore = l.AccountName, l.Provider
		}
		if t, err := loadCFTunnel(); err == nil {
			s.TunnelID, s.TunnelName = t.ID, t.Name
		}
		if s.Running {
			s.Connections = cfReady(cfMetrics)
		}
		if cfRunning(cfQuickSvc) {
			s.QuickURL = cfQuickURL()
		}
		return printResult(s, func() {
			fmt.Printf("cloudflared  %s\n", or(s.Version, "not installed"))
			if s.Account != "" {
				fmt.Printf("account      %s (API token: %s)\n", s.Account, s.TokenStore)
			} else {
				fmt.Println("account      not logged in (ziroctl cf login)")
			}
			switch {
			case s.TunnelID == "":
				fmt.Println("tunnel       none (ziroctl cf up)")
			case s.Running:
				fmt.Printf("tunnel       %s %s, running, %d edge connections\n", s.TunnelName, s.TunnelID, s.Connections)
			default:
				fmt.Printf("tunnel       %s %s, stopped\n", s.TunnelName, s.TunnelID)
			}
			if s.QuickURL != "" {
				fmt.Printf("quick        %s\n", s.QuickURL)
			}
		})
	},
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var cfUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Upgrade cloudflared from the signed catalog",
	Long: `Upgrade cloudflared to the version the signed catalog pins, restart the tunnel and check it
reconnects; if it doesn't within 30s, the previous binary is put back. A daily job runs this
with --cron unless the module was enabled with --set auto_update=false.`,
	Example: `  ziroctl cf update
  ziroctl cf update --check`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st := enabledModules()[cfModule]
		if cfCron {
			if st.Settings["auto_update"] == "false" {
				return nil
			}
			time.Sleep(time.Duration(time.Now().UnixNano() % int64(30*time.Minute))) // spread hosts out
		}
		repos, err := catalogRepos("module")
		if err != nil {
			return err
		}
		for _, r := range repos {
			if r.Official {
				if _, err := refreshRepo(r); err != nil {
					return fmt.Errorf("refresh catalog %s: %w", r.Name, err)
				}
			}
		}
		all, err := loadManifests()
		if err != nil {
			return err
		}
		cur, _ := installedManifest(all, cfModule)
		next, ok := all[cfModule]
		if !ok {
			return errors.New("cloudflared is no longer in the catalog")
		}
		avail := next.Version != cur.Version
		if cfCheck {
			return printResult(map[string]any{"current": cur.Version, "available": next.Version, "update": avail}, func() {
				if avail {
					fmt.Printf("cloudflared %s → %s available: ziroctl cf update\n", cur.Version, next.Version)
				} else {
					fmt.Printf("= cloudflared is up to date (%s)\n", cur.Version)
				}
			})
		}
		if !avail {
			if !cfCron {
				fmt.Printf("= cloudflared is up to date (%s)\n", cur.Version)
			}
			return nil
		}
		prev := cfBinary + ".prev"
		if b, err := os.ReadFile(cfBinary); err == nil {
			_ = writeFileAtomic(prev, b, 0755)
		}
		if err := upgradeModule(cfModule, false); err != nil {
			return err
		}
		return cfRestartChecked(prev, next.Version)
	},
}

// cfRestartChecked restarts running connectors onto the new binary and puts prev back when the
// named tunnel doesn't reconnect.
// ponytail: after a rollback the next boot fetches the pinned binary again (one more try); a
// held version would need state in the module.
func cfRestartChecked(prev, version string) error {
	for _, s := range []string{cfService, cfQuickSvc} {
		if cfRunning(s) {
			_ = restartSupervised(s)
		}
	}
	if !cfRunning(cfService) || cfWaitReady(cfMetrics, 30*time.Second) > 0 {
		_ = os.Remove(prev)
		_ = auditLog("ziroctl", "cf", "cf update", "cloudflared "+version, nil)
		fmt.Printf("✓ cloudflared %s\n", version)
		return nil
	}
	b, err := os.ReadFile(prev)
	if err == nil {
		err = writeFileAtomic(cfBinary, b, 0755)
	}
	if err == nil {
		err = restartSupervised(cfService)
	}
	msg := fmt.Sprintf("cloudflared %s did not reconnect; previous version restored", version)
	if err != nil {
		msg = fmt.Sprintf("cloudflared %s did not reconnect and the rollback failed: %v", version, err)
	}
	alertf("high", "cloudflared", msg, nil)
	return errors.New(msg)
}

func init() {
	cfLoginCmd.Flags().StringVar(&cfTokenFile, "token-file", "", "Read the API token from this file")
	cfLoginCmd.Flags().StringVar(&cfAccountID, "account", "", "Account ID, when the token sees several")
	cfUpCmd.Flags().StringVar(&cfTokenFile, "token-file", "", "Run a dashboard tunnel with the token in this file")
	cfDownCmd.Flags().BoolVar(&cfDelete, "delete", false, "Also delete the tunnel and its DNS records at Cloudflare")
	cfRouteAddCmd.Flags().StringVar(&cfAccess, "access", "", "Only these emails and @domains get in (Cloudflare Access)")
	cfQuickCmd.Flags().BoolVarP(&cfDetach, "detach", "d", false, "Run in the background")
	cfQuickCmd.Flags().BoolVar(&cfStopQuick, "stop", false, "Stop the background quick tunnel")
	cfUpdateCmd.Flags().BoolVar(&cfCheck, "check", false, "Only report whether an update is available")
	cfUpdateCmd.Flags().BoolVar(&cfCron, "cron", false, "For the daily job: jitter, honour auto_update")
	_ = cfUpdateCmd.Flags().MarkHidden("cron")
	cfRouteCmd.AddCommand(cfRouteAddCmd, cfRouteRmCmd, cfRouteLsCmd)
	cfCmd.AddCommand(cfLoginCmd, cfLogoutCmd, cfUpCmd, cfDownCmd, cfRouteCmd, cfQuickCmd, cfStatusCmd, cfUpdateCmd)
	rootCmd.AddCommand(cfCmd)
}

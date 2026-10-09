package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"golang.org/x/sys/unix"
)

// Tailscale (the tailscale module, RFC 0003): join this host to a tailnet. Everything here is
// built to need as little trust as possible.
//
//   - The binaries come from the signed module catalog (sha256-pinned, re-verified at boot) and
//     are upgraded daily with `tailscale update`, which puts the old ones back if the node does
//     not come back healthy.
//   - tailscaled runs as its own unprivileged user with exactly CAP_NET_ADMIN and CAP_NET_RAW
//     (service caps), no_new_privs, and a cgroup limit. Its state (the node key) is in a 0700
//     directory it owns; its control socket is in a 0750 directory, so only root and it use it.
//   - An auth key is read from a file, stdin or a hidden prompt, never from argv, handed to the
//     tailscale CLI as a 0600 file that is removed when it returns, and never stored.
//   - Nothing is open by default: the tailnet's DNS and routes are not accepted, there is no
//     SSH, exit node or subnet router, and no port is reachable from the tailnet until
//     `tailscale allow` opens it for the tailscale0 interface only.

const (
	tsModule      = "tailscale"
	tsUser        = "tailscale"
	tsService     = "tailscaled"
	tsIface       = "tailscale0"
	tsDefaultPort = 41642 // not tailscaled's 41641: that is zirocd's
)

var (
	tsPluginDir = filepath.Join(schema.PluginRoot, tsModule)
	tsDaemon    = filepath.Join(tsPluginDir, "tailscaled")
	tsCLI       = filepath.Join(tsPluginDir, "tailscale")
	tsStateDir  = "/var/lib/ziro/tailscale"
	tsConfDir   = "/etc/ziro/tailscale"
	tsRunDir    = "/run/tailscale"
	tsSocket    = filepath.Join(tsRunDir, "tailscaled.sock")
	tsEnvFile   = filepath.Join(tsConfDir, "tailscaled.env")
	tsTunDev    = "/dev/net/tun"
	tsTmpRoot   = "/run" // the 0600 key file for `tailscale up` lives in a 0700 directory here

	// CGNAT range tailnet addresses come from (RFC 6598).
	tsRange = netip.MustParsePrefix("100.64.0.0/10")
)

// ports other Ziro components use: tailscaled must not take them.
var tsReservedPorts = map[int]string{41641: "zirocd", 51820: "WireGuard", 51821: "the cluster mesh"}

// tsKeyRe is a Tailscale auth key (tskey-auth-…) or OAuth client secret (tskey-client-…), with
// the optional ?ephemeral=…&preauthorized=… parameters.
var tsKeyRe = regexp.MustCompile(`^tskey-[A-Za-z0-9_-]{4,64}(\?[A-Za-z0-9_=&.-]{1,128})?$`)
var tsTagRe = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,62}$`)
var tsHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// tsPort is the UDP port tailscaled listens on (module setting "port").
func tsPort() (int, error) {
	v := ""
	if st := enabledModules()[tsModule]; st != nil {
		v = st.Settings["port"]
	}
	if v == "" {
		return tsDefaultPort, nil
	}
	p, err := strconv.Atoi(v)
	if err != nil || p < 1024 || p > 65535 {
		return 0, fmt.Errorf("tailscale port %q: want 1024-65535", v)
	}
	if who := tsReservedPorts[p]; who != "" {
		return 0, fmt.Errorf("tailscale port %d is used by %s", p, who)
	}
	return p, nil
}

// tsDaemonDef is the tailscaled service: its own user and exactly the capabilities it needs.
func tsDaemonDef() (ServiceDef, error) {
	port, err := tsPort()
	if err != nil {
		return ServiceDef{}, err
	}
	return ServiceDef{
		Name:        tsService,
		Description: "Tailscale node",
		Exec:        tsDaemon,
		Args: fmt.Sprintf("--state=%s --socket=%s --port=%d --tun=%s --statedir=%s",
			filepath.Join(tsStateDir, "tailscaled.state"), tsSocket, port, tsIface, tsStateDir),
		PIDFile:   "/run/ziro-tailscaled.pid",
		LogFile:   "/var/log/tailscaled.log",
		User:      tsUser,
		Caps:      []string{"net_admin", "net_raw"},
		EnvFile:   tsEnvFile,
		Resources: &Resources{Memory: "256Mi", PIDs: 256},
		Restart:   "always", Autostart: true,
	}, nil
}

// tsEnvContent is tailscaled's environment: a Go heap that stays small, and no log upload to
// Tailscale unless the operator turned telemetry on (module setting "telemetry").
func tsEnvContent(telemetry bool) string {
	s := "GOGC=25\nGOMEMLIMIT=192MiB\n"
	if !telemetry {
		s += "TS_NO_LOGS_NO_SUPPORT=true\n"
	}
	return s
}

func tsTelemetry() bool {
	st := enabledModules()[tsModule]
	return st != nil && st.Settings["telemetry"] == "on"
}

// tsSetup makes the module ready and (re)starts tailscaled. It is the module's post_start: it
// runs on enable and at every boot, so it must be idempotent.
func tsSetup() error {
	for _, f := range []string{tsDaemon, tsCLI} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("%s is missing: ziroctl module enable %s", f, tsModule)
		}
	}
	if err := ensureServiceUser(tsUser, "Tailscale"); err != nil {
		return err
	}
	u, err := user.Lookup(tsUser)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, d := range []struct {
		path string
		mode os.FileMode
		own  bool // owned by the service user
	}{{tsStateDir, 0o700, true}, {tsRunDir, 0o750, true}, {tsConfDir, 0o700, false}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		o, g := 0, 0
		if d.own {
			o, g = uid, gid
		}
		if err := os.Chown(d.path, o, g); err != nil {
			return err
		}
	}
	if err := traversable(tsDaemon); err != nil {
		return err
	}
	if err := ensureTunDevice(gid); err != nil {
		return err
	}
	if err := writeFileAtomic(tsEnvFile, []byte(tsEnvContent(tsTelemetry())), 0o600); err != nil {
		return err
	}
	def, err := tsDaemonDef()
	if err != nil {
		return err
	}
	if err := def.ValidateCaps(); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(servicesDir, def.Name+".conf"), []byte(supervisedConf(def)), 0o644); err != nil {
		return err
	}
	if d, err := loadServiceDef(def.Name); err == nil && getServicePID(d) > 0 {
		return restartSupervised(def.Name)
	}
	return startService(def.Name)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ensureTunDevice makes sure /dev/net/tun exists and the service user can open it.
func ensureTunDevice(gid int) error {
	if fi, err := os.Stat(tsTunDev); err == nil {
		if fi.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("%s is not a character device", tsTunDev)
		}
		return nil // devtmpfs made it (0666 root)
	}
	if err := os.MkdirAll(filepath.Dir(tsTunDev), 0o755); err != nil {
		return err
	}
	if err := unix.Mknod(tsTunDev, unix.S_IFCHR|0o660, int(unix.Mkdev(10, 200))); err != nil {
		return fmt.Errorf("create %s (does the kernel have TUN?): %w", tsTunDev, err)
	}
	return os.Chown(tsTunDev, 0, gid) // root:tailscale 0660: only the daemon (and root) may open it
}

// tsTeardown stops tailscaled and removes its service so it does not start at boot (the module's
// stop command, run on disable). The node key stays in the state directory until a purge.
func tsTeardown() error {
	if _, err := loadServiceDef(tsService); err != nil {
		return nil
	}
	if err := stopService(tsService); err != nil {
		return err
	}
	return os.Remove(filepath.Join(servicesDir, tsService+".conf"))
}

func tsRunning() bool {
	d, err := loadServiceDef(tsService)
	return err == nil && getServicePID(d) > 0
}

// ---- the tailscale CLI ----

// tsEnv is the environment for the tailscale CLI: nothing of ours leaks in, nothing of the
// operator's TS_* settings changes its behaviour.
func tsEnv() []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=/", "LANG=C"}
}

// tsExec runs the tailscale CLI against tailscaled's socket. Its arguments never contain a secret.
func tsExec(ctx context.Context, args []string, stdout, stderr *os.File) error {
	// deepcode ignore CommandInjection: tsCLI is a fixed root-owned path from the signed module; args are argv, no shell
	cmd := exec.CommandContext(ctx, tsCLI, append([]string{"--socket=" + tsSocket}, args...)...)
	cmd.Env = tsEnv()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Stdin = nil
	return cmd.Run()
}

func tsOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, tsCLI, append([]string{"--socket=" + tsSocket}, args...)...)
	cmd.Env = tsEnv()
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

// tsKeyFile writes an auth key for `tailscale up --auth-key=file:…`: a 0600 file in a 0700
// directory that exists only while the CLI runs. A key on the command line would show in
// /proc/<pid>/cmdline for every local user.
func tsKeyFile(key string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp(tsTmpRoot, "ziro-ts-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// tsReadKey reads an auth key from a file, stdin or a no-echo prompt (never argv) and checks its
// shape.
func tsReadKey(file string, stdin, prompt bool) (string, error) {
	n := b2i(file != "") + b2i(stdin) + b2i(prompt)
	switch {
	case n == 0:
		return "", nil
	case n > 1:
		return "", errors.New("use only one of --auth-key-file, --auth-key-stdin, --auth-key-prompt")
	}
	k, err := readCFSecret(file, "", "Tailscale auth key: ")
	if err != nil {
		return "", err
	}
	if !tsKeyRe.MatchString(k) {
		return "", errors.New("that is not a Tailscale auth key (tskey-auth-… or an OAuth client secret tskey-client-…)")
	}
	return k, nil
}

// tsUpArgs builds the `tailscale up` command line. The defaults are the closed ones; --reset
// returns every flag not given here to its default, so the node is exactly what this says.
func tsUpArgs(o tsUpOptions, keyFile string) ([]string, error) {
	if o.Hostname != "" && !tsHostRe.MatchString(o.Hostname) {
		return nil, fmt.Errorf("invalid --hostname %q", o.Hostname)
	}
	if strings.HasPrefix(o.KeyKind, "tskey-client-") && len(o.Tags) == 0 {
		return nil, errors.New("an OAuth client secret needs --tag (the node is owned by a tag)")
	}
	for _, t := range o.Tags {
		if !tsTagRe.MatchString(t) {
			return nil, fmt.Errorf("invalid --tag %q (want tag:name)", t)
		}
	}
	args := []string{"up", "--reset",
		"--accept-dns=false", // smart DNS owns /etc/resolv.conf
		"--accept-routes=" + strconv.FormatBool(o.AcceptRoutes),
		"--ssh=false", // sshd keeps port 22 and its hardening
		"--shields-up=false",
		"--advertise-exit-node=false",
		"--timeout=" + o.Timeout.String(),
	}
	if o.Hostname != "" {
		args = append(args, "--hostname="+o.Hostname)
	}
	if len(o.Tags) > 0 {
		args = append(args, "--advertise-tags="+strings.Join(o.Tags, ","))
	}
	if o.LoginServer != "" {
		u, err := tsLoginServer(o.LoginServer)
		if err != nil {
			return nil, err
		}
		args = append(args, "--login-server="+u)
	}
	if keyFile != "" {
		args = append(args, "--auth-key=file:"+keyFile)
	}
	return args, nil
}

// tsLoginServer accepts only an https URL (a Headscale server) without credentials, path, query
// or fragment.
func tsLoginServer(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("--login-server %q: want an https URL like https://headscale.example.com", s)
	}
	return u.Scheme + "://" + u.Host, nil
}

type tsUpOptions struct {
	Hostname     string
	Tags         []string
	LoginServer  string
	AcceptRoutes bool
	Timeout      time.Duration
	KeyKind      string // the key's prefix, only to check that an OAuth secret has tags
}

// tsRangeConflict names a route that already uses the tailnet range on another interface (the
// router mesh uses 100.64.0.0/10 too): joining would break one of the two.
func tsRangeConflict(routes []RouteStatus) string {
	for _, r := range routes {
		p, err := netip.ParsePrefix(r.Dest)
		if err != nil || r.Iface == tsIface || p.Bits() == 0 {
			continue
		}
		if p.Overlaps(tsRange) {
			return fmt.Sprintf("%s on %s", r.Dest, r.Iface)
		}
	}
	return ""
}

// ---- status ----

type tsStatusJSON struct {
	Version        string
	BackendState   string
	AuthURL        string
	Health         []string
	Self           tsNode
	Peer           map[string]tsNode
	CurrentTailnet struct {
		Name string
	}
}

type tsNode struct {
	HostName     string
	DNSName      string
	Online       bool
	TailscaleIPs []string
	CurAddr      string
	Relay        string
	ExitNode     bool
}

// TailscaleStatus is what `ziroctl tailscale status` reports.
type TailscaleStatus struct {
	State    string   `json:"state"` // Running, NeedsLogin, Stopped, Starting, …
	Version  string   `json:"version,omitempty"`
	Tailnet  string   `json:"tailnet,omitempty"`
	Name     string   `json:"name,omitempty"`
	IPs      []string `json:"ips,omitempty"`
	LoginURL string   `json:"login_url,omitempty"`
	Peers    int      `json:"peers"`
	Online   int      `json:"peers_online"`
	Direct   int      `json:"peers_direct"`
	Relayed  int      `json:"peers_relayed"`
	Health   []string `json:"health,omitempty"`
	Port     int      `json:"port,omitempty"`
}

func parseTSStatus(b []byte) (TailscaleStatus, error) {
	var j tsStatusJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return TailscaleStatus{}, fmt.Errorf("tailscale status: %w", err)
	}
	st := TailscaleStatus{State: j.BackendState, Version: j.Version, Tailnet: j.CurrentTailnet.Name,
		Name: strings.TrimSuffix(j.Self.DNSName, "."), IPs: j.Self.TailscaleIPs, LoginURL: j.AuthURL, Peers: len(j.Peer), Health: j.Health}
	for _, p := range j.Peer {
		if !p.Online {
			continue
		}
		st.Online++
		switch {
		case p.CurAddr != "":
			st.Direct++
		case p.Relay != "":
			st.Relayed++
		}
	}
	return st, nil
}

func tsStatus(ctx context.Context) (TailscaleStatus, error) {
	if !tsRunning() {
		return TailscaleStatus{}, errors.New("tailscaled is not running: ziroctl service start tailscaled")
	}
	b, err := tsOutput(ctx, "status", "--json")
	if err != nil {
		return TailscaleStatus{}, err
	}
	st, err := parseTSStatus(b)
	if p, perr := tsPort(); perr == nil {
		st.Port = p
	}
	return st, err
}

// tsHealthy is the update's check: tailscaled answers, and a node that was joined is still joined.
func tsHealthy(was string, wait time.Duration) bool {
	for end := time.Now().Add(wait); ; time.Sleep(time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := tsStatus(ctx)
		cancel()
		if err == nil && (was != "Running" || st.State == "Running") {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// tsDoctorCheck is the doctor row: only when the module is enabled.
func tsDoctorCheck() (doctorCheck, bool) {
	if st := enabledModules()[tsModule]; st == nil || st.Status != "enabled" {
		return doctorCheck{}, false
	}
	c := doctorCheck{Name: "Tailscale"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := tsStatus(ctx)
	switch {
	case err != nil:
		c.Details, c.Fix = err.Error(), "ziroctl service start tailscaled"
	case st.State == "Running":
		c.Passed, c.Details = true, fmt.Sprintf("%s (%s), %d of %d peers online", st.Name, strings.Join(st.IPs, " "), st.Online, st.Peers)
	case st.State == "NeedsLogin" || st.State == "Stopped":
		c.Passed, c.Details, c.Fix = true, "not joined to a tailnet", "ziroctl tailscale up"
	default:
		c.Details = st.State
	}
	if c.Passed && len(st.Health) > 0 {
		c.Passed, c.Details = false, strings.Join(st.Health, "; ")
	}
	return c, true
}

// ---- commands ----

var (
	tsKeyFileFlag  string
	tsKeyStdin     bool
	tsKeyPrompt    bool
	tsHostname     string
	tsTags         []string
	tsLogin        string
	tsAcceptRoutes bool
	tsOpenPort     bool
	tsForce        bool
	tsUpTimeout    time.Duration
	tsCheck        bool
	tsCron         bool
)

var tailscaleCmd = &cobra.Command{
	Use:   "tailscale",
	Short: "Join this host to a Tailscale network",
	Long: `Reach this host (and let it reach your other devices) over a Tailscale network. Needs the
tailscale module, which downloads Tailscale on demand:

  ziroctl module enable tailscale
  ziroctl tailscale up

Closed by default: the tailnet's DNS and routes are not accepted, there is no SSH, exit node or
subnet router, and no port is reachable from the tailnet until you open it:

  ziroctl tailscale allow ssh`,
	Example: `  ziroctl tailscale up
  ziroctl tailscale up --auth-key-file /root/ts.key --tag tag:server
  ziroctl tailscale allow ssh
  ziroctl tailscale status`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Daemons started from here inherit our environment: keep TS_* settings out.
		for _, kv := range os.Environ() {
			if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "TS_") || strings.HasPrefix(k, "TAILSCALE_") {
				_ = os.Unsetenv(k)
			}
		}
		if cmd == tsSetupCmd || cmd == tsTeardownCmd { // the module's own hooks: it is installing or disabling
			return nil
		}
		if st := enabledModules()[tsModule]; st != nil && st.Status == "enabled" {
			return nil
		}
		return errors.New("tailscale is not enabled: ziroctl module enable tailscale")
	},
}

var tsUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Join a tailnet with a login link or an auth key",
	Long: `Joins this host to your tailnet. With no key it prints a login link to open in a browser.
For an unattended join, give an auth key (or an OAuth client secret with --tag) from a file,
stdin or a hidden prompt. The key is never put on a command line or stored: it is handed to
Tailscale as a 0600 file that is removed when the command ends.`,
	Example: `  ziroctl tailscale up
  ziroctl tailscale up --auth-key-file /root/ts.key --tag tag:server --hostname web1
  echo "$KEY" | ziroctl tailscale up --auth-key-stdin
  ziroctl tailscale up --login-server https://headscale.example.com`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := tsReadKey(tsKeyFileFlag, tsKeyStdin, tsKeyPrompt)
		if err != nil {
			return err
		}
		if !tsRunning() {
			if err := tsSetup(); err != nil {
				return err
			}
		}
		if c := tsRangeConflict(readRoutes()); c != "" && !tsForce {
			return fmt.Errorf("%s already uses 100.64.0.0/10, the range Tailscale assigns addresses from (the router mesh?); use --force to join anyway", c)
		}
		opts := tsUpOptions{Hostname: tsHostname, Tags: tsTags, LoginServer: tsLogin, AcceptRoutes: tsAcceptRoutes, Timeout: tsUpTimeout}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := tsJoin(ctx, opts, key, os.Stdout, os.Stderr); err != nil {
			return err
		}
		if tsOpenPort {
			if p, err := tsPort(); err == nil {
				if _, err := firewallAllow(fmt.Sprintf("%d/udp", p), "Tailscale direct connections"); err != nil {
					fmt.Fprintf(os.Stderr, "warning: firewall: %v\n", err)
				}
			}
		}
		_ = auditLog("ziroctl", "tailscale", "tailscale up", opts.Hostname, nil)
		st, err := tsStatus(ctx)
		if err != nil {
			return nil
		}
		fmt.Printf("✓ %s: %s %s\n", st.State, st.Name, strings.Join(st.IPs, " "))
		fmt.Println("  Nothing on this host is reachable from the tailnet yet: ziroctl tailscale allow ssh")
		return nil
	},
}

// tsJoin runs `tailscale up` with the key (if any) in a 0600 file that exists only while the CLI
// runs; the key is never in its arguments or environment.
func tsJoin(ctx context.Context, opts tsUpOptions, key string, stdout, stderr *os.File) error {
	opts.KeyKind, _, _ = strings.Cut(key, "?")
	keyPath := ""
	if key != "" {
		p, cleanup, err := tsKeyFile(key)
		if err != nil {
			return err
		}
		defer cleanup()
		keyPath = p
	}
	args, err := tsUpArgs(opts, keyPath)
	if err != nil {
		return err
	}
	if err := tsExec(ctx, args, stdout, stderr); err != nil {
		return fmt.Errorf("tailscale up: %w", err)
	}
	return nil
}

var tsStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show this node, its addresses and how peers connect",
	Example: "  ziroctl tailscale status",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := tsStatus(cmd.Context())
		if err != nil {
			return err
		}
		return printResult(st, func() {
			fmt.Printf("State:    %s\n", st.State)
			if st.Name != "" {
				fmt.Printf("Node:     %s  %s\n", st.Name, strings.Join(st.IPs, " "))
			}
			if st.Tailnet != "" {
				fmt.Printf("Tailnet:  %s\n", st.Tailnet)
			}
			if st.LoginURL != "" {
				fmt.Printf("Login:    %s\n", st.LoginURL)
			}
			fmt.Printf("Peers:    %d online of %d (%d direct, %d relayed)\n", st.Online, st.Peers, st.Direct, st.Relayed)
			fmt.Printf("Version:  %s (udp port %d)\n", st.Version, st.Port)
			for _, h := range st.Health {
				fmt.Printf("Warning:  %s\n", h)
			}
		})
	},
}

var tsIPCmd = &cobra.Command{
	Use:     "ip",
	Short:   "Print this node's tailnet addresses",
	Example: "  ziroctl tailscale ip",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := tsStatus(cmd.Context())
		if err != nil {
			return err
		}
		for _, ip := range st.IPs {
			fmt.Println(ip)
		}
		return nil
	},
}

var tsPingCmd = &cobra.Command{
	Use:     "ping <peer>",
	Short:   "Check how this node reaches a peer",
	Example: "  ziroctl tailscale ping laptop",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !tsPeerRe.MatchString(args[0]) {
			return fmt.Errorf("invalid peer %q (a device name or tailnet address)", args[0])
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		return tsExec(ctx, []string{"ping", "--c=3", "--timeout=5s", args[0]}, os.Stdout, os.Stderr)
	},
}

var tsPeerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,100}$`)

var tsDownCmd = &cobra.Command{
	Use:     "down",
	Short:   "Disconnect from the tailnet and keep this node's identity",
	Example: "  ziroctl tailscale down",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := tsExec(ctx, []string{"down"}, os.Stdout, os.Stderr); err != nil {
			return err
		}
		_ = auditLog("ziroctl", "tailscale", "tailscale down", "", nil)
		fmt.Println("✓ disconnected (ziroctl tailscale up reconnects)")
		return nil
	},
}

var tsLogoutCmd = &cobra.Command{
	Use:     "logout",
	Short:   "Leave the tailnet and remove this node from it",
	Example: "  ziroctl tailscale logout",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := tsExec(ctx, []string{"logout"}, os.Stdout, os.Stderr); err != nil {
			return err
		}
		_ = auditLog("ziroctl", "tailscale", "tailscale logout", "", nil)
		fmt.Println("✓ logged out: this node is removed from your tailnet")
		return nil
	},
}

// tsAllowSpec turns "ssh" or "<port>[/proto]" into a firewall port spec.
func tsAllowSpec(s string) (string, error) {
	if s == "ssh" {
		return "22/tcp", nil
	}
	if p, _ := parsePortProto(s); p <= 0 || p > 65535 {
		return "", fmt.Errorf("invalid port %q (ssh, or 8080, 5432/tcp)", s)
	}
	return s, nil
}

var tsAllowCmd = &cobra.Command{
	Use:   "allow <ssh|port[/proto]>",
	Short: "Open a port to the tailnet only",
	Long: `Opens a port for traffic that arrives over the tailnet (the tailscale0 interface) and nowhere
else. The tailnet's own access rules still apply on top of this.`,
	Example: `  ziroctl tailscale allow ssh
  ziroctl tailscale allow 5432/tcp`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		spec, err := tsAllowSpec(args[0])
		if err != nil {
			return err
		}
		added, err := firewallAllowOn(spec, "Tailscale", tsIface)
		if err != nil {
			return err
		}
		if !added {
			fmt.Printf("%s is already open to the tailnet\n", spec)
			return nil
		}
		fmt.Printf("✓ %s is open to the tailnet (tailscale0 only)\n", spec)
		if !loadFirewallConfig().Enabled {
			fmt.Println("  note: the firewall is off, so every port is already open: ziroctl firewall enable")
		}
		return nil
	},
}

var tsDenyCmd = &cobra.Command{
	Use:     "deny <ssh|port[/proto]>",
	Short:   "Close a port opened to the tailnet",
	Example: "  ziroctl tailscale deny ssh",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		spec, err := tsAllowSpec(args[0])
		if err != nil {
			return err
		}
		if err := firewallDenyOn(spec, tsIface); err != nil {
			return err
		}
		fmt.Printf("✓ %s is closed to the tailnet\n", spec)
		return nil
	},
}

var tsLsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "List the ports open to the tailnet",
	Example: "  ziroctl tailscale ls",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var rules []FirewallRule
		for _, r := range loadFirewallConfig().AllowedPorts {
			if r.Iface == tsIface {
				rules = append(rules, r)
			}
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].Port < rules[j].Port })
		return printResult(rules, func() {
			if len(rules) == 0 {
				fmt.Println("nothing is open to the tailnet (ziroctl tailscale allow ssh)")
				return
			}
			for _, r := range rules {
				fmt.Printf("%d/%s\n", r.Port, r.Protocol)
			}
		})
	},
}

var tsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Upgrade Tailscale from the signed catalog",
	Long: `Upgrade Tailscale to the version the signed catalog pins (the newest stable release, checked
and pinned daily), restart it and check the node is still connected; if it isn't within 30s, the
previous binaries are put back. A daily job runs this with --cron unless the module was enabled
with --set auto_update=false.`,
	Example: `  ziroctl tailscale update
  ziroctl tailscale update --check`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		was := ""
		if st, err := tsStatus(cmd.Context()); err == nil {
			was = st.State
		}
		return updateModuleBinaries(binaryUpdate{
			Module: tsModule, Title: "Tailscale", Binaries: []string{tsDaemon, tsCLI},
			AuditSource: "tailscale", AuditAction: "tailscale update", Check: tsCheck, Cron: tsCron,
			AutoSetting: "auto_update", AlertOnError: "tailscale",
			Restart: func() bool {
				if tsRunning() {
					_ = restartSupervised(tsService)
				}
				return !tsRunning() || tsHealthy(was, 30*time.Second)
			},
		})
	},
}

var tsSetupCmd = &cobra.Command{
	Use:    "setup",
	Short:  "Prepare and start tailscaled (the module's start hook)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   func(cmd *cobra.Command, args []string) error { return tsSetup() },
}

var tsTeardownCmd = &cobra.Command{
	Use:    "teardown",
	Short:  "Stop tailscaled (the module's stop hook)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   func(cmd *cobra.Command, args []string) error { return tsTeardown() },
}

func init() {
	f := tsUpCmd.Flags()
	f.StringVar(&tsKeyFileFlag, "auth-key-file", "", "Read the auth key from this file")
	f.BoolVar(&tsKeyStdin, "auth-key-stdin", false, "Read the auth key from stdin")
	f.BoolVar(&tsKeyPrompt, "auth-key-prompt", false, "Ask for the auth key (hidden)")
	f.StringVar(&tsHostname, "hostname", "", "Name of this node in the tailnet (default: the host name)")
	f.StringArrayVar(&tsTags, "tag", nil, "Tag for this node, e.g. tag:server (repeatable)")
	f.StringVar(&tsLogin, "login-server", "", "Use this control server (Headscale), an https URL")
	f.BoolVar(&tsAcceptRoutes, "accept-routes", false, "Use the subnet routes other nodes advertise")
	f.BoolVar(&tsOpenPort, "open-port", false, "Open the UDP port so peers can connect directly (public hosts)")
	f.BoolVar(&tsForce, "force", false, "Join even if 100.64.0.0/10 is already in use here")
	f.DurationVar(&tsUpTimeout, "timeout", 5*time.Minute, "How long to wait for the node to come up")
	tsUpdateCmd.Flags().BoolVar(&tsCheck, "check", false, "Only report whether an update is available")
	tsUpdateCmd.Flags().BoolVar(&tsCron, "cron", false, "For the daily job: jitter, honour auto_update")
	_ = tsUpdateCmd.Flags().MarkHidden("cron")
	tailscaleCmd.AddCommand(tsUpCmd, tsStatusCmd, tsIPCmd, tsPingCmd, tsDownCmd, tsLogoutCmd, tsAllowCmd, tsDenyCmd, tsLsCmd, tsUpdateCmd, tsSetupCmd, tsTeardownCmd)
	rootCmd.AddCommand(tailscaleCmd)
}

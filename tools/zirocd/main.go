// zirocd is the Ziro client daemon and CLI: it joins a device to Ziro router networks
// (ziroctl router) over WireGuard, on Linux, macOS and Windows.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/release"
	"github.com/ziro-os/zirocd/daemon"
	"github.com/ziro-os/zirocd/update"
)

var Version = "dev" // set by -ldflags "-X main.Version=..."

var (
	jsonOut  bool
	stateDir = daemon.DefaultStateDir()
	upKey    string
	upName   string
	upRoutes []string
	upDNS    bool
	upAuto   string
)

func main() {
	root := &cobra.Command{
		Use:           "zirocd",
		Short:         "Ziro client: join devices to Ziro router networks",
		SilenceUsage:  true,
		SilenceErrors: true,
		Example: `  sudo zirocd service install
  sudo zirocd up --key zr1_...
  zirocd status`,
	}
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON")

	daemonCmd := &cobra.Command{Use: "daemon", Short: "Run the daemon in the foreground", Hidden: true, RunE: runDaemon}
	daemonCmd.Flags().StringVar(&stateDir, "state-dir", daemon.DefaultStateDir(), "where keys and state are kept")

	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Join a network, or reconnect",
		Example: `  sudo zirocd up --key zr1_...
  sudo zirocd up --key zr1_... --name build-01 --advertise-routes 10.0.0.0/16
  sudo zirocd up                      # reconnect after zirocd down`,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := daemon.UpRequest{Key: upKey, Name: upName, AutoUpdate: upAuto}
			if cmd.Flags().Changed("advertise-routes") {
				req.Routes = upRoutes
			}
			if cmd.Flags().Changed("accept-dns") {
				req.AcceptDNS = &upDNS
			}
			if req.Key == "" {
				req.Key = os.Getenv("ZIROCD_KEY") // keeps the key out of shell history and ps
			}
			var s daemon.Status
			if err := call(http.MethodPost, "/up", req, &s); err != nil {
				return err
			}
			for i := 0; i < 40 && s.State == "connecting"; i++ { // wait for the first netmap
				time.Sleep(500 * time.Millisecond)
				if err := call(http.MethodGet, "/status", nil, &s); err != nil {
					return err
				}
			}
			return show(s, func() {
				switch s.State {
				case "pending":
					fmt.Println("⧗ waiting for an admin to approve this device: ziroctl router member approve <network> <name>")
				case "connected":
					fmt.Printf("✓ connected: %s.%s  %s\n", s.Name, s.Domain, s.IPv4)
				default:
					fmt.Printf("⚠ %s: %s (zirocd status)\n", s.State, orDash(s.Error))
				}
			})
		},
	}
	upCmd.Flags().StringVar(&upKey, "key", "", "router key (zr1_...); or set ZIROCD_KEY")
	upCmd.Flags().StringVar(&upName, "name", "", "device name in the network (default: hostname)")
	upCmd.Flags().StringSliceVar(&upRoutes, "advertise-routes", nil, "subnets to offer (an admin approves each)")
	upCmd.Flags().BoolVar(&upDNS, "accept-dns", true, "resolve <device>.<network>.ziro")
	upCmd.Flags().StringVar(&upAuto, "auto-update", "", "on, notify or off")

	downCmd := &cobra.Command{Use: "down", Short: "Disconnect and keep this device's identity", Example: "  sudo zirocd down",
		RunE: func(cmd *cobra.Command, args []string) error { return call(http.MethodPost, "/down", nil, nil) }}
	logoutCmd := &cobra.Command{Use: "logout", Short: "Disconnect and delete this device's keys", Example: "  sudo zirocd logout",
		RunE: func(cmd *cobra.Command, args []string) error { return call(http.MethodPost, "/logout", nil, nil) }}

	statusCmd := &cobra.Command{Use: "status", Short: "Show the connection and peers", Example: "  zirocd status\n  zirocd status --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			var s daemon.Status
			if err := call(http.MethodGet, "/status", nil, &s); err != nil {
				return err
			}
			return show(s, func() { printStatus(s) })
		}}

	pingCmd := &cobra.Command{Use: "ping <device>", Short: "Ping a peer by name or address", Args: cobra.ExactArgs(1),
		Example: "  zirocd ping db-1",
		RunE: func(cmd *cobra.Command, args []string) error {
			var s daemon.Status
			if err := call(http.MethodGet, "/status", nil, &s); err != nil {
				return err
			}
			ip := args[0]
			for _, p := range s.Peers {
				if p.Name == args[0] && len(p.Addresses) > 0 {
					ip = strings.SplitN(p.Addresses[0], "/", 2)[0]
				}
			}
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("no peer %q (zirocd status)", args[0])
			}
			n := "-c"
			if runtime.GOOS == "windows" {
				n = "-n"
			}
			c := exec.Command("ping", n, "4", ip)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			return c.Run()
		}}

	updateCmd := &cobra.Command{Use: "update", Short: "Install the newest signed zirocd now", Example: "  sudo zirocd update",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := call(http.MethodPost, "/update", nil, &out); err != nil {
				return err
			}
			if out["version"] == "" {
				fmt.Println("✓ zirocd is up to date")
			} else {
				fmt.Printf("✓ installed zirocd %s; the service restarts on it\n", out["version"])
			}
			return nil
		}}

	versionCmd := &cobra.Command{Use: "version", Short: "Print the version", Example: "  zirocd version",
		Run: func(cmd *cobra.Command, args []string) { fmt.Println(Version) }}

	serviceCmd := &cobra.Command{Use: "service", Short: "Install or remove the background service", Example: "  sudo zirocd service install"}
	serviceCmd.AddCommand(
		&cobra.Command{Use: "install", Short: "Run zirocd at boot", Example: "  sudo zirocd service install",
			RunE: func(cmd *cobra.Command, args []string) error {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if err := installService(exe); err != nil {
					return err
				}
				fmt.Println("✓ zirocd service installed and started. Next: sudo zirocd up --key zr1_...")
				return nil
			}},
		&cobra.Command{Use: "uninstall", Short: "Stop and remove the service", Example: "  sudo zirocd service uninstall",
			RunE: func(cmd *cobra.Command, args []string) error { return uninstallService() }},
	)

	root.AddCommand(daemonCmd, upCmd, downCmd, logoutCmd, statusCmd, pingCmd, updateCmd, versionCmd, serviceCmd)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func show(v any, text func()) error {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	text()
	return nil
}

func printStatus(s daemon.Status) {
	fmt.Printf("State:    %s\n", s.State)
	if s.Error != "" {
		fmt.Printf("Error:    %s\n", s.Error)
	}
	if s.Name != "" {
		fmt.Printf("Device:   %s.%s  %s %s\n", s.Name, s.Domain, s.IPv4, s.IPv6)
	}
	if s.Interface != "" {
		fmt.Printf("Tunnel:   %s (filtered %d packets)\n", s.Interface, s.Dropped)
	}
	fmt.Printf("Version:  %s", s.Version)
	if s.Update != "" {
		fmt.Printf(" (update %s available: sudo zirocd update)", s.Update)
	}
	fmt.Println()
	if len(s.Peers) == 0 {
		return
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tADDRESS\tENDPOINT\tHANDSHAKE\tRX\tTX")
	for _, p := range s.Peers {
		hs := "-"
		if p.LastHandshake > 0 {
			hs = time.Since(time.Unix(p.LastHandshake, 0)).Round(time.Second).String() + " ago"
		}
		addr := ""
		if len(p.Addresses) > 0 {
			addr = p.Addresses[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\n", p.Name, addr, orDash(p.Endpoint), hs, p.RxBytes, p.TxBytes)
	}
	tw.Flush()
}

// call talks to the daemon over its control socket.
func call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	hc := &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return daemon.Dial() },
	}}
	req, _ := http.NewRequest(method, "http://zirocd"+path, body)
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "Access is denied") {
			return errors.New("permission denied: run as root (sudo) or as an Administrator")
		}
		return fmt.Errorf("zirocd is not running (sudo zirocd service install): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return errors.New(e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// runDaemon is the service: control API, data plane and the updater.
func runDaemon(cmd *cobra.Command, args []string) error {
	if ok, err := runAsService(); ok {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveDaemon(ctx)
}

func serveDaemon(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src := release.NewSource("zirocd/" + Version)
	upd := &update.Updater{Current: Version, Exe: exe, Dir: stateDir, Source: src}
	if rolled, err := upd.Startup(); err != nil {
		fmt.Fprintf(os.Stderr, "zirocd: %v\n", err)
	} else if rolled {
		fmt.Fprintln(os.Stderr, "zirocd: the new version failed twice; rolled back, restarting")
		os.Exit(3)
	}
	d := daemon.New(stateDir, Version)
	d.OnHealthy = upd.Healthy
	if err := d.Start(); err != nil {
		return err
	}
	defer d.Close()
	ln, err := daemon.Listen()
	if err != nil {
		return err
	}
	restart := func() {
		fmt.Fprintln(os.Stderr, "zirocd: updated; restarting")
		d.Close()
		os.Exit(3) // the service manager starts the new binary
	}
	updateNow := func(ctx context.Context) (string, error) {
		v, err := upd.Target(ctx, d.PinnedVersion())
		if err != nil || v == "" {
			return "", err
		}
		if err := upd.Install(ctx, v); err != nil {
			return "", err
		}
		go func() { time.Sleep(time.Second); restart() }()
		return v, nil
	}
	srv := &http.Server{Handler: d.Handler(updateNow), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go upd.Loop(ctx, d.AutoUpdate, d.PinnedVersion, d.SetUpdateAvailable, restart)
	fmt.Fprintf(os.Stderr, "zirocd %s running (state %s)\n", Version, stateDir)
	<-ctx.Done()
	_ = srv.Close()
	return nil
}

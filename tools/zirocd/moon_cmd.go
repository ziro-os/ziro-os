package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ziro-os/zirocd/moon"
)

// `zirocd moon`: run this host as a moon (a regional relay). The token comes from a file or the
// environment, never argv (visible to every user in ps).
func moonCmd() *cobra.Command {
	var o moon.Options
	var tokenFile string
	c := &cobra.Command{
		Use:   "moon",
		Short: "Run a moon: a regional relay for router devices (any Linux host or container)",
		Long: `A moon relays WireGuard ciphertext between devices that have no direct path. Add it on a
master first (ziroctl router moon add <name> --public <host:port>), then start it here with the
token, once. After that it needs only --dir. It listens on tcp (TLS) and udp (relay + STUN).`,
		Example: `  ZIROCD_MOON_TOKEN=zm1_... zirocd moon --dir /var/lib/zirocd-moon
  zirocd moon --dir /var/lib/zirocd-moon --token-file /run/secrets/moon-token --metrics-listen 127.0.0.1:9102
  zirocd moon --dir /var/lib/zirocd-moon      # already registered`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Token = os.Getenv("ZIROCD_MOON_TOKEN")
			if tokenFile != "" {
				b, err := os.ReadFile(tokenFile)
				if err != nil {
					return err
				}
				o.Token = strings.TrimSpace(string(b))
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return moon.Run(ctx, o)
		},
	}
	f := c.Flags()
	f.StringVar(&o.Dir, "dir", "/var/lib/zirocd-moon", "where the moon keeps its key and certificate")
	f.StringVar(&tokenFile, "token-file", "", "file holding the zm1_ token (or set ZIROCD_MOON_TOKEN)")
	f.StringVar(&o.Listen, "listen", "", "TLS listen address (default :8443; saved)")
	f.IntVar(&o.STUNPort, "stun-port", 0, "UDP port for relayed datagrams and STUN (default 3478; saved)")
	f.IntVar(&o.RateMbps, "rate-mbps", 0, "per-device relayed bandwidth (default 1000; saved)")
	f.IntVar(&o.MaxMbps, "max-mbps", 0, "relay-wide relayed bandwidth (default 10000; saved)")
	f.StringVar(&o.MetricsListen, "metrics-listen", "", "serve /healthz, /readyz and /metrics here, e.g. 127.0.0.1:9102 (saved)")
	f.BoolVar(&o.RegisterOnly, "register-only", false, "register, save, and exit (ziroctl router moon join)")
	return c
}

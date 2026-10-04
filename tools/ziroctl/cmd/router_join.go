package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// `ziroctl router join|leave|status`: the Ziro OS way to run zirocd. It opens the firewall for
// WireGuard, runs zirocd as a ziro-init service and hands it the key through the environment
// (never argv). The zr0 interface is trusted by the host firewall: zirocd's own filter has
// already applied the network's ACL to every packet that appears on it.

const (
	zirocdBin      = "/usr/bin/zirocd"
	zirocdSock     = "/run/zirocd.sock"
	zirocdIface    = "zr0"
	zirocdUDPPort  = 41641
	routerKeyEnvVr = "ZIROCD_KEY"
)

var (
	rjKeyFile string
	rjKey     string
	rjName    string
	rjRoutes  []string
)

// routerJoinKey reads the key from --key-file, $ZIROCD_KEY or --key (in that order).
func routerJoinKey() (string, error) {
	k := rjKey
	if v := os.Getenv(routerKeyEnvVr); v != "" {
		k = v
	}
	if rjKeyFile != "" {
		b, err := os.ReadFile(rjKeyFile)
		if err != nil {
			return "", err
		}
		k = strings.TrimSpace(string(b))
	}
	if k == "" {
		return "", errors.New("no key: --key-file <file>, ZIROCD_KEY=zr1_... or --key")
	}
	if _, err := zr.ParseInvite(k); err != nil {
		return "", err
	}
	return k, nil
}

func zirocd(env []string, args ...string) error {
	c := exec.Command(zirocdBin, args...)
	c.Env = append(os.Environ(), env...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

var routerJoinCmd = &cobra.Command{
	Use:   "join",
	Short: "Join this host to a router network with zirocd",
	Example: `  ziroctl router join --key-file /root/office.key
  ZIROCD_KEY=zr1_... ziroctl router join --name build-01 --advertise-routes 10.200.0.0/16`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := routerJoinKey()
		if err != nil {
			return err
		}
		if _, err := os.Stat(zirocdBin); err != nil {
			return fmt.Errorf("%s missing: this image predates zirocd (ziroctl upgrade)", zirocdBin)
		}
		if _, err := validRoutes(rjRoutes); err != nil {
			return err
		}
		allowFirewall([]FirewallRule{{Port: zirocdUDPPort, Protocol: "udp", Comment: "Ziro router (zirocd WireGuard)"}}, zirocdIface)
		startClusterServices("zirocd")
		for i := 0; i < 50; i++ {
			if _, err := os.Stat(zirocdSock); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		up := []string{"up"}
		if rjName != "" {
			up = append(up, "--name", rjName)
		}
		if cmd.Flags().Changed("advertise-routes") {
			up = append(up, "--advertise-routes", strings.Join(rjRoutes, ","))
		}
		if jsonOutput {
			up = append(up, "--json")
		}
		return zirocd([]string{routerKeyEnvVr + "=" + key}, up...)
	},
}

var routerLeaveCmd = &cobra.Command{
	Use: "leave", Short: "Leave the router network and stop zirocd", Example: "  ziroctl router leave",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := zirocd(nil, "logout"); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ zirocd logout: %v\n", err)
		}
		stopClusterServices("zirocd")
		fmt.Println("✓ left the router network; zirocd stopped")
		return nil
	},
}

var routerStatusCmd = &cobra.Command{
	Use: "status", Short: "Show this host's router connection and peers", Example: "  ziroctl router status\n  ziroctl router status --json",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		a := []string{"status"}
		if jsonOutput {
			a = append(a, "--json")
		}
		return zirocd(nil, a...)
	},
}

func init() {
	routerJoinCmd.Flags().StringVar(&rjKeyFile, "key-file", "", "file holding the zr1_ key")
	routerJoinCmd.Flags().StringVar(&rjKey, "key", "", "zr1_ key (prefer --key-file or ZIROCD_KEY: argv is visible to other users)")
	routerJoinCmd.Flags().StringVar(&rjName, "name", "", "device name (default: hostname)")
	routerJoinCmd.Flags().StringSliceVar(&rjRoutes, "advertise-routes", nil, "subnets to route for the network (an admin approves each)")
	routerCmd.AddCommand(routerJoinCmd, routerLeaveCmd, routerStatusCmd)
}

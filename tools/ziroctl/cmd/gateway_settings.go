package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// Gateway-wide settings: trusted proxies, PROXY protocol, drain time. They live in the same
// store as the routes and reach every gateway node the same way.

func readGatewaySettings(s routeStore) (GatewaySettings, error) {
	d, err := s.read()
	if err != nil {
		return GatewaySettings{}, err
	}
	return d.Settings, nil
}

func nonBlank(list []string) []string {
	var out []string
	for _, c := range list {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// activeSettings is what gateways receive: the settings without the bans that have run out.
func activeSettings(s GatewaySettings, now time.Time) GatewaySettings {
	var live []GatewayBan
	for _, b := range s.Bans {
		if !b.Expired(now) {
			live = append(live, b)
		}
	}
	s.Bans = live
	return s
}

// putGatewaySettings validates and stores the settings.
func putGatewaySettings(s routeStore, set GatewaySettings) (GatewaySettings, error) {
	set.TrustedProxies = nonBlank(set.TrustedProxies)
	set.DenyCIDRs = nonBlank(set.DenyCIDRs)
	if err := set.Validate(); err != nil {
		return set, err
	}
	if err := checkWAFExclusions(set.WAF); err != nil {
		return set, err
	}
	return set, s.update(func(d *gatewayData) error { d.Settings = set; return nil })
}

var gwSettingsFlags struct {
	trusted       []string
	proxyProtocol bool
	drain         int
	waf           wafFlags
	deny          []string
	autoBan       bool
	abStrikes     int
	abWindow      string
	abDuration    string
	abMax         string
	abKernel      bool
	wafAutoUpdate bool
}

var gatewaySettingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Show the gateway-wide settings",
	Example: `  ziroctl gateway settings
  ziroctl gateway settings set --trusted-proxy 10.0.0.0/8 --proxy-protocol`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		set, err := readGatewaySettings(s)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(set, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

var gatewaySettingsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Change the gateway-wide settings",
	Long: `Only the flags you give are changed. Trusted proxies are the load balancers and CDNs in front of the gateway. Only a connection
from a trusted proxy may say who the real client is (X-Forwarded-For, or a PROXY protocol header),
so allow lists, rate limits and ip_hash apply to the client and not to the load balancer.
An empty --trusted-proxy clears the list.`,
	Example: `  ziroctl gateway settings set --trusted-proxy 10.0.0.0/8 --trusted-proxy 192.168.1.5
  ziroctl gateway settings set --proxy-protocol
  ziroctl gateway settings set --drain-seconds 40`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		set, err := readGatewaySettings(s)
		if err != nil {
			return err
		}
		f := cmd.Flags()
		if f.Changed("trusted-proxy") {
			set.TrustedProxies = gwSettingsFlags.trusted
		}
		if f.Changed("proxy-protocol") {
			set.ProxyProtocol = gwSettingsFlags.proxyProtocol
		}
		if f.Changed("drain-seconds") {
			set.DrainSeconds = gwSettingsFlags.drain
		}
		if gwSettingsFlags.waf.any() {
			if set.WAF, err = gwSettingsFlags.waf.build(); err != nil {
				return err
			}
		}
		if f.Changed("deny-cidr") {
			set.DenyCIDRs = nonBlank(gwSettingsFlags.deny)
		}
		if f.Changed("auto-ban") && !gwSettingsFlags.autoBan {
			set.AutoBan = nil
		} else if gwSettingsFlags.autoBan || f.Changed("auto-ban-strikes") || f.Changed("auto-ban-window") ||
			f.Changed("auto-ban-duration") || f.Changed("auto-ban-max") || f.Changed("auto-ban-kernel") {
			ab := set.AutoBan
			if ab == nil {
				ab = &GatewayAutoBan{}
			}
			if f.Changed("auto-ban-strikes") {
				ab.Strikes = gwSettingsFlags.abStrikes
			}
			if f.Changed("auto-ban-window") {
				ab.Window = gwSettingsFlags.abWindow
			}
			if f.Changed("auto-ban-duration") {
				ab.Duration = gwSettingsFlags.abDuration
			}
			if f.Changed("auto-ban-max") {
				ab.Max = gwSettingsFlags.abMax
			}
			if f.Changed("auto-ban-kernel") {
				ab.Kernel = gwSettingsFlags.abKernel
			}
			set.AutoBan = ab
		}
		if _, err := putGatewaySettings(s, set); err != nil {
			return err
		}
		fmt.Println("✓ gateway settings saved (applied within a second on gateway nodes)")
		return nil
	},
}

// registerGatewaySettingsRoutes: /api/v1/gateway/settings.
func registerGatewaySettingsRoutes(a *apiRouter) {
	a.get("/api/v1/gateway/settings", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		set, err := readGatewaySettings(s)
		apiReply(w, err, set)
	})
	a.put("/api/v1/gateway/settings", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		var set GatewaySettings
		if err := decodeStrict(w, r, &set, 1<<16); err != nil {
			apiReply(w, err, nil)
			return
		}
		set, err = putGatewaySettings(s, set)
		apiReply(w, err, set)
	})
}

// addBasicAuth hashes a "user:password" entry into the route (the password is never stored).
func addBasicAuth(r *GatewayRoute, entry, flag string) error {
	user, pass, ok := strings.Cut(entry, ":")
	if !ok || user == "" || len(pass) < 8 {
		return fmt.Errorf("%s wants user:password (password 8+ characters)", flag)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if r.BasicAuth == nil {
		r.BasicAuth = map[string]string{}
	}
	r.BasicAuth[user] = string(h)
	return nil
}

// readBasicAuthFile reads user:password lines (blank lines and # comments skipped). Like an SSH
// key, the file must not be readable by others: it holds passwords in clear.
func readBasicAuthFile(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by others: chmod 600 %s", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no user:password lines", path)
	}
	return out, nil
}

func init() {
	f := gatewaySettingsSetCmd.Flags()
	f.StringSliceVar(&gwSettingsFlags.trusted, "trusted-proxy", nil, "Load balancer or CDN address or CIDR in front of the gateway (repeatable; empty clears)")
	f.BoolVar(&gwSettingsFlags.proxyProtocol, "proxy-protocol", false, "Accept PROXY protocol v1/v2 from trusted proxies (--proxy-protocol=false turns it off)")
	f.IntVar(&gwSettingsFlags.drain, "drain-seconds", 0, "How long a stopping gateway waits for in-flight requests (default 25, max 60)")
	f.BoolVar(&gwSettingsFlags.wafAutoUpdate, "waf-auto-update", true, "Fetch new WAF rules about once a day (default on)")
	registerWAFFlags(f, &gwSettingsFlags.waf, "routes that have none of their own")
	f.StringSliceVar(&gwSettingsFlags.deny, "deny-cidr", nil, "Refuse these addresses or CIDRs on every route (repeatable; empty clears)")
	f.BoolVar(&gwSettingsFlags.autoBan, "auto-ban", false, "Ban clients that keep getting blocked by the WAF or failing basic auth (--auto-ban=false turns it off)")
	f.IntVar(&gwSettingsFlags.abStrikes, "auto-ban-strikes", 0, "Blocked requests within the window that earn a ban (default 5)")
	f.StringVar(&gwSettingsFlags.abWindow, "auto-ban-window", "", "Window for counting strikes (default 1m)")
	f.StringVar(&gwSettingsFlags.abDuration, "auto-ban-duration", "", "First ban; doubles for repeat offenders (default 10m)")
	f.StringVar(&gwSettingsFlags.abMax, "auto-ban-max", "", "Longest ban (default 24h)")
	f.BoolVar(&gwSettingsFlags.abKernel, "auto-ban-kernel", false, "Also ban in the host firewall: every port, not just the gateway's")
	gatewaySettingsCmd.AddCommand(gatewaySettingsSetCmd)
	gatewayCmd.AddCommand(gatewaySettingsCmd)
}

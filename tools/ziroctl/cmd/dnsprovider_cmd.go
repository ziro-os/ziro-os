package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ---- views ----

// DNSCloudView is what `dns cloud ls` and GET /api/v1/dns/cloud show. Tokens never appear.
type DNSCloudView struct {
	Owner     string            `json:"owner"` // the ownership comment on the records it manages
	Providers []DNSProviderConf `json:"providers"`
	Records   []DNSCloudRecord  `json:"records"`
	Addresses []string          `json:"addresses,omitempty"`
	Status    *DNSSyncStatus    `json:"status,omitempty"` // the last sync recorded on this host
}

func dnsCloudView(s routeStore) (DNSCloudView, error) {
	d, err := s.read()
	if err != nil {
		return DNSCloudView{}, err
	}
	v := DNSCloudView{Owner: dnsMarker(), Providers: d.DNSCloud.Providers, Records: d.DNSCloud.Records, Addresses: d.DNSCloud.Addresses}
	if v.Providers == nil {
		v.Providers = []DNSProviderConf{}
	}
	if v.Records == nil {
		v.Records = []DNSCloudRecord{}
	}
	if st, ok := readDNSStatus(); ok {
		v.Status = &st
	}
	return v, nil
}

func printDNSPlan(p DNSPlan) {
	sym := map[string]string{"create": "+", "update": "~", "delete": "-", "skip": "!"}
	for _, it := range p.Items {
		line := fmt.Sprintf("  %s %-7s %-34s %-5s %s", sym[it.Action], it.Action, it.Name, it.Type, it.Content)
		switch {
		case it.Action == "update" && it.Was != "":
			line += "  (was " + it.Was + ")"
		case it.Action == "skip":
			line += "  — " + it.Reason
		}
		if it.Provider != "" && it.Action != "skip" {
			line += "  [" + it.Provider + "]"
		}
		if it.Error != "" {
			line += "  FAILED: " + it.Error
		}
		fmt.Println(line)
	}
	for _, w := range p.Warnings {
		fmt.Println("  ! " + w)
	}
}

func printDNSSummary(p DNSPlan, applied bool) {
	if p.Changes() == 0 {
		fmt.Printf("✓ the provider already matches (%d records managed by ziro)\n", p.Owned)
		return
	}
	verb := "would change"
	if applied {
		verb = "changed"
	}
	fmt.Printf("%s: %d created, %d updated, %d deleted\n", verb, p.count("create"), p.count("update"), p.count("delete"))
}

// ---- CLI ----

var (
	dnsProvName, dnsProvTokenFile string
	dnsProvZones                  []string
	dnsRecProvider                string
	dnsRecTTL                     int
	dnsRecProxied                 bool
	dnsSyncForce                  bool
	dnsAddrClear                  bool
)

var dnsProviderCmd = &cobra.Command{
	Use:     "provider",
	Short:   "Public DNS providers that publish the gateway's names",
	Example: "  ziroctl dns provider add cloudflare --token-file cf.token\n  ziroctl dns provider ls",
	Long: `Connect a public DNS provider (Cloudflare) so the records for the gateway's base domain and
route hosts are created, updated and removed there automatically, instead of by hand.

Create the API token at the provider with the least it needs: Cloudflare ‹ My Profile ‹ API Tokens ‹
Zone › DNS › Edit and Zone › Zone › Read, limited to the zones to manage. The token is read from a
file, a hidden prompt or stdin (never argv), checked, and stored root-only (sealed in the TPM when the
host has one). In a cluster it is a cluster secret, sealed at rest like the others, so a new leader
keeps syncing.`,
}

var dnsProviderAddCmd = &cobra.Command{
	Use:   "add cloudflare",
	Short: "Connect a DNS provider",
	Example: `  ziroctl dns provider add cloudflare --token-file cf.token
  ziroctl dns provider add cloudflare --name acme --zones example.com,example.org --token-file acme.token`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		tok, err := readCFSecret(dnsProvTokenFile, "", "DNS provider API token: ")
		if err != nil {
			return err
		}
		name := dnsProvName
		if name == "" {
			name = args[0]
		}
		conf, zones, err := dnsProviderAdd(s, name, args[0], tok, dnsProvZones)
		if err != nil {
			return err
		}
		var names []string
		for _, z := range zones {
			names = append(names, z.Name)
		}
		clusterAudit("cli", "dns provider add", conf.Name, nil)
		fmt.Printf("✓ provider %s (%s) manages %d zone(s): %s\n", conf.Name, conf.Kind, len(zones), strings.Join(names, ", "))
		fmt.Println("  See what it would change with: ziroctl dns cloud plan")
		return nil
	},
}

var dnsProviderLsCmd = &cobra.Command{
	Use: "ls", Short: "List DNS providers", Args: cobra.NoArgs, Example: "  ziroctl dns provider ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		v, err := dnsCloudView(s)
		if err != nil {
			return err
		}
		return printResult(v.Providers, func() {
			if len(v.Providers) == 0 {
				fmt.Println("No DNS provider. Add one with: ziroctl dns provider add cloudflare --token-file …")
				return
			}
			for _, p := range v.Providers {
				zones := "all zones the token sees"
				if len(p.Zones) > 0 {
					zones = strings.Join(p.Zones, ", ")
				}
				fmt.Printf("%-16s %-11s %s\n", p.Name, p.Kind, zones)
			}
		})
	},
}

var dnsProviderRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Disconnect a DNS provider", Args: cobra.ExactArgs(1), Example: "  ziroctl dns provider rm cloudflare",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := dnsProviderRm(s, args[0]); err != nil {
			return err
		}
		clusterAudit("cli", "dns provider rm", args[0], nil)
		fmt.Printf("✓ provider %s removed with its token. Records it created stay at the provider.\n", args[0])
		return nil
	},
}

var dnsCloudCmd = &cobra.Command{
	Use:     "cloud",
	Short:   "Records published at the public DNS provider",
	Example: "  ziroctl dns cloud plan\n  ziroctl dns cloud sync",
	Long: `The gateway's names are published automatically: a wildcard for the base domain, a record for
every route host it does not cover, and the explicit records added here. Each record is created
with a "ziro:<cluster id>" comment, and only records with that comment are ever changed or
deleted, so records you made yourself are never touched.

The module dns-cloudflare runs the sync (ziroctl module enable dns-cloudflare): every 5 minutes and
within seconds of a route or domain change. In a cluster only the leader writes.`,
}

var dnsCloudAddCmd = &cobra.Command{
	Use:   "add <name> <A|AAAA|CNAME|TXT> <content>",
	Short: "Keep an explicit record at the provider",
	Example: `  ziroctl dns cloud add www.example.com CNAME app.example.com
  ziroctl dns cloud add tunnel.example.com CNAME 1234.cfargotunnel.com --proxied`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := dnsRecordAdd(s, DNSCloudRecord{Provider: dnsRecProvider, Name: args[0], Type: args[1], Content: args[2], TTL: dnsRecTTL, Proxied: dnsRecProxied}); err != nil {
			return err
		}
		fmt.Println("✓ saved; the sync creates it at the provider (ziroctl dns cloud plan shows when)")
		return nil
	},
}

var dnsCloudRmCmd = &cobra.Command{
	Use: "rm <name> [type]", Short: "Stop keeping an explicit record", Args: cobra.RangeArgs(1, 2),
	Example: "  ziroctl dns cloud rm www.example.com CNAME",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		typ := ""
		if len(args) > 1 {
			typ = args[1]
		}
		n, err := dnsRecordRm(s, args[0], typ)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %d record(s) removed; the sync deletes them at the provider\n", n)
		return nil
	},
}

var dnsCloudLsCmd = &cobra.Command{
	Use: "ls", Short: "Show providers, explicit records and the last sync", Args: cobra.NoArgs, Example: "  ziroctl dns cloud ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		v, err := dnsCloudView(s)
		if err != nil {
			return err
		}
		return printResult(v, func() {
			fmt.Printf("Owner marker: %s\n", v.Owner)
			if len(v.Providers) == 0 {
				fmt.Println("No DNS provider. Add one with: ziroctl dns provider add cloudflare --token-file …")
				return
			}
			for _, p := range v.Providers {
				fmt.Printf("Provider %s (%s)\n", p.Name, p.Kind)
			}
			if len(v.Addresses) > 0 {
				fmt.Println("Published addresses:", strings.Join(v.Addresses, ", "))
			}
			for _, r := range v.Records {
				px := ""
				if r.Proxied {
					px = " (proxied)"
				}
				fmt.Printf("  %-34s %-5s %s%s\n", r.Name, r.Type, r.Content, px)
			}
			printDNSStatus(v.Status)
		})
	},
}

func printDNSStatus(st *DNSSyncStatus) {
	if st == nil {
		fmt.Println("No sync recorded on this host (in a cluster the leader syncs).")
		return
	}
	state := "ok"
	if !st.OK {
		state = "FAILED"
	}
	fmt.Printf("Last sync %s: %s (%d created, %d updated, %d deleted, %d skipped)\n", st.Time, state, st.Created, st.Updated, st.Deleted, st.Skipped)
	for _, e := range st.Errors {
		fmt.Println("  ! " + e)
	}
}

var dnsCloudStatusCmd = &cobra.Command{
	Use: "status", Short: "Show the last sync on this host", Args: cobra.NoArgs, Example: "  ziroctl dns cloud status",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, ok := readDNSStatus()
		if !ok {
			return printResult(map[string]any{"synced": false}, func() { printDNSStatus(nil) })
		}
		return printResult(st, func() { printDNSStatus(&st) })
	},
}

var dnsCloudPlanCmd = &cobra.Command{
	Use: "plan", Short: "Show what a sync would change, without changing anything", Args: cobra.NoArgs,
	Example: "  ziroctl dns cloud plan",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		plan, err := dnsSyncOnce(s, false, true)
		if err != nil {
			return err
		}
		return printResult(plan, func() { printDNSPlan(plan); printDNSSummary(plan, false) })
	},
}

var dnsCloudSyncCmd = &cobra.Command{
	Use: "sync", Short: "Reconcile the provider now", Args: cobra.NoArgs,
	Long: `Reconcile the provider with the gateway now. In a cluster, run it on the leader; the sync
service does this by itself, and two writers would race.`,
	Example: "  ziroctl dns cloud sync\n  ziroctl dns cloud sync --force",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if s.name() == "cluster" && !socketIsLeader() {
			return errors.New("this master is not the Raft leader; the leader's sync service does this (or run the command there)")
		}
		plan, err := dnsSyncOnce(s, dnsSyncForce, false)
		if jsonOutput || plan.Items != nil {
			_ = printResult(plan, func() { printDNSPlan(plan); printDNSSummary(plan, err == nil) })
		}
		return err
	},
}

var dnsCloudAddressesCmd = &cobra.Command{
	Use:   "addresses [ip...]",
	Short: "Publish these addresses for the gateway's names",
	Long: `By default the records point at the gateway nodes' own addresses. Behind a NAT or a load
balancer, publish the address clients reach instead. --clear goes back to the default.`,
	Example: "  ziroctl dns cloud addresses 203.0.113.10\n  ziroctl dns cloud addresses --clear",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if len(args) == 0 && !dnsAddrClear {
			v, err := dnsCloudView(s)
			if err != nil {
				return err
			}
			return printResult(v.Addresses, func() {
				if len(v.Addresses) == 0 {
					fmt.Println("The gateway nodes' own addresses are published.")
				}
				for _, a := range v.Addresses {
					fmt.Println(a)
				}
			})
		}
		if dnsAddrClear {
			args = nil
		}
		if err := dnsAddressesSet(s, args); err != nil {
			return err
		}
		fmt.Println("✓ saved")
		return nil
	},
}

// dnsSyncServeCmd is the service of the dns-cloudflare module.
var dnsSyncServeCmd = &cobra.Command{
	Use:    "dns-sync",
	Short:  "Run the DNS provider sync (started by the dns-cloudflare module)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		clustered := false
		if cfg, err := loadClusterConfig(); err == nil && cfg.Role != "" {
			clustered = true
		}
		l := &dnsLoop{
			store: gatewayStore,
			leader: func() bool {
				return !clustered || socketIsLeader()
			},
			sync: func(s routeStore) (DNSPlan, error) {
				plan, err := dnsSyncOnce(s, false, false)
				for _, it := range plan.Items {
					if it.Action != "skip" && it.Error == "" {
						fmt.Printf("[dns] %s %s %s %s\n", it.Action, it.Name, it.Type, it.Content)
					}
				}
				return plan, err
			},
			now: time.Now,
			announce: func(err error) {
				fmt.Printf("[dns] sync failed: %v\n", err)
				alertf("high", "dns", "DNS provider sync failed", map[string]any{"error": err.Error()})
			},
		}
		fmt.Printf("[dns] provider sync running (every %s and on route changes)\n", dnsSyncEvery)
		for range time.Tick(dnsPollEvery) {
			l.tick()
		}
		return nil
	},
}

// dnsDoctorCheck is the doctor row for the DNS provider: tokens readable, last sync recent and ok.
func dnsDoctorCheck(now time.Time) (doctorCheck, bool) {
	s, err := gatewayStore()
	if err != nil {
		return doctorCheck{}, false
	}
	d, err := s.read()
	if err != nil || len(d.DNSCloud.Providers) == 0 {
		return doctorCheck{}, false
	}
	c := doctorCheck{Name: "DNS provider", Fix: "run one sync", fix: func() error {
		if s.name() == "cluster" && !socketIsLeader() {
			return errors.New("not the Raft leader: run 'ziroctl doctor --fix' there")
		}
		_, err := dnsSyncOnce(s, false, false)
		return err
	}}
	for _, p := range d.DNSCloud.Providers {
		if _, err := dnsTokenGet(s, p.Name); err != nil {
			c.Details, c.Fix = err.Error(), "ziroctl dns provider add "+p.Kind+" --name "+p.Name+" --token-file …"
			c.fix = nil
			return c, true
		}
	}
	st, ok := readDNSStatus()
	last, _ := time.Parse(time.RFC3339, st.Time)
	switch {
	case !ok && s.name() == "cluster":
		c.Passed, c.Details = true, "no sync recorded on this master (the leader syncs)"
	case !ok:
		c.Details = "no sync has run yet (ziroctl module enable dns-cloudflare, or ziroctl dns cloud sync)"
	case !st.OK:
		c.Details = "last sync failed: " + strings.Join(st.Errors, "; ")
	case now.Sub(last) > 3*dnsSyncEvery:
		c.Details = fmt.Sprintf("last sync %s ago (the sync service should run every %s)", now.Sub(last).Round(time.Second), dnsSyncEvery)
	default:
		c.Passed, c.Details = true, fmt.Sprintf("%d provider(s), last sync %s ago", len(d.DNSCloud.Providers), now.Sub(last).Round(time.Second))
	}
	return c, true
}

func init() {
	dnsProviderAddCmd.Flags().StringVar(&dnsProvName, "name", "", "Name for this provider (default: its kind)")
	dnsProviderAddCmd.Flags().StringVar(&dnsProvTokenFile, "token-file", "", "Read the API token from this file (else a hidden prompt, or stdin)")
	dnsProviderAddCmd.Flags().StringSliceVar(&dnsProvZones, "zones", nil, "Manage only these zones (default: every zone the token sees)")
	dnsProviderCmd.AddCommand(dnsProviderAddCmd, dnsProviderLsCmd, dnsProviderRmCmd)

	dnsCloudAddCmd.Flags().StringVar(&dnsRecProvider, "provider", "", "Provider to create it at (default: the one hosting the zone)")
	dnsCloudAddCmd.Flags().IntVar(&dnsRecTTL, "ttl", 0, "TTL in seconds (default 300; 1 = automatic)")
	dnsCloudAddCmd.Flags().BoolVar(&dnsRecProxied, "proxied", false, "Proxy it through the provider (Cloudflare)")
	dnsCloudSyncCmd.Flags().BoolVar(&dnsSyncForce, "force", false, "Allow deleting most of the records this cluster owns")
	dnsCloudAddressesCmd.Flags().BoolVar(&dnsAddrClear, "clear", false, "Publish the gateway nodes' own addresses again")
	dnsCloudCmd.AddCommand(dnsCloudAddCmd, dnsCloudRmCmd, dnsCloudLsCmd, dnsCloudStatusCmd, dnsCloudPlanCmd, dnsCloudSyncCmd, dnsCloudAddressesCmd)

	dnsCmd.AddCommand(dnsProviderCmd, dnsCloudCmd)
	gatewayCmd.AddCommand(dnsSyncServeCmd)
}

// ---- API ----

// registerDNSCloudRoutes: /api/v1/dns/cloud. Everything that reaches the provider or changes what
// is published is admin; reading the configuration is for any token (no token value is ever returned).
func registerDNSCloudRoutes(a *apiRouter) {
	done := func(msg string) APIMessage { return APIMessage{Status: "ok", Message: msg} }
	a.get("/api/v1/dns/cloud", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		v, err := dnsCloudView(s)
		apiReply(w, err, v)
	})
	a.get("/api/v1/dns/cloud/plan", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		plan, err := dnsSyncOnce(s, false, true)
		apiReply(w, err, plan)
	})
	a.post("/api/v1/dns/cloud/sync", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Force bool `json:"force"`
		}
		if r.ContentLength != 0 && !decodeBody(w, r, &req) {
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		if s.name() == "cluster" && !socketIsLeader() {
			apiReply(w, errors.New("this master is not the Raft leader; the leader's sync service does this"), nil)
			return
		}
		plan, err := dnsSyncOnce(s, req.Force, false)
		if err != nil && plan.Items == nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, err, plan)
	})
	a.put("/api/v1/dns/cloud/providers/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind  string   `json:"kind"`
			Token string   `json:"token"`
			Zones []string `json:"zones"`
		}
		if err := decodeStrict(w, r, &req, 16<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		if req.Kind == "" {
			req.Kind = dnsKindCloudflare
		}
		tok := strings.TrimSpace(req.Token)
		if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
			apiReply(w, errors.New("token: the provider's API token (one line)"), nil)
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		conf, zones, err := dnsProviderAdd(s, r.PathValue("name"), req.Kind, tok, req.Zones)
		if err == nil {
			clusterAudit("api", "dns provider add", conf.Name, nil)
		}
		apiReply(w, err, map[string]any{"provider": conf, "zones": zones})
	})
	a.delete("/api/v1/dns/cloud/providers/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		err = dnsProviderRm(s, r.PathValue("name"))
		if err == nil {
			clusterAudit("api", "dns provider rm", r.PathValue("name"), nil)
		}
		apiReply(w, err, done("provider removed; records it created stay at the provider"))
	})
	a.post("/api/v1/dns/cloud/records", "admin", func(w http.ResponseWriter, r *http.Request) {
		var rec DNSCloudRecord
		if err := decodeStrict(w, r, &rec, 16<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, dnsRecordAdd(s, rec), done("saved; the sync creates it at the provider"))
	})
	a.delete("/api/v1/dns/cloud/records", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			apiReply(w, errors.New("name: the record name (and optionally type) to stop keeping"), nil)
			return
		}
		n, err := dnsRecordRm(s, name, r.URL.Query().Get("type"))
		apiReply(w, err, done(fmt.Sprintf("%d record(s) removed; the sync deletes them at the provider", n)))
	})
	a.put("/api/v1/dns/cloud/addresses", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Addresses []string `json:"addresses"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, dnsAddressesSet(s, req.Addresses), done("saved"))
	})
}

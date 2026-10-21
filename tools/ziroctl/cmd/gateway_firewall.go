package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Operator surface of the gateway firewall: WAF flags shared by routes and gateway settings, the
// ban list, and the rule catalog.

var gatewayAdminTokenPath = "/run/ziro/gateway/admin.token"

// ---- WAF flags ----

type wafFlags struct {
	mode             string
	level, threshold int
	bodyKB           int
	exclude, rules   []string
	skipBody         bool
}

func registerWAFFlags(f *pflag.FlagSet, w *wafFlags, what string) {
	f.StringVar(&w.mode, "waf", "", "Web application firewall for "+what+": off, detect (log only) or block")
	f.IntVar(&w.level, "waf-level", 0, "WAF rule level 1-3: 2 and 3 add broader rules and more false positives (default 1)")
	f.IntVar(&w.threshold, "waf-threshold", 0, "Anomaly score that blocks a request (default 5; a critical rule scores 5)")
	f.StringSliceVar(&w.exclude, "waf-exclude", nil, "Turn off a rule (ZW-942100) or a group (sqli, xss, lfi, rce, java, xxe, ssrf, protocol, scanner)")
	f.IntVar(&w.bodyKB, "waf-body-kb", 0, "Request body bytes the WAF inspects (default 8, max 256)")
	f.BoolVar(&w.skipBody, "waf-skip-body", false, "Inspect the URL and headers only")
	f.StringArrayVar(&w.rules, "waf-rule", nil, `Custom rule as JSON: {"id":"x","target":"path","op":"prefix","value":"/admin","action":"score","score":3} (repeatable)`)
}

func (w wafFlags) any() bool {
	return w.mode != "" || w.level != 0 || w.threshold != 0 || w.bodyKB != 0 || len(w.exclude) > 0 || w.skipBody || len(w.rules) > 0
}

// build returns the WAF configuration the flags describe, or nil when none was given.
func (w wafFlags) build() (*GatewayWAF, error) {
	if !w.any() {
		return nil, nil
	}
	if w.mode == "" {
		return nil, fmt.Errorf("the --waf-* flags need --waf off|detect|block")
	}
	out := &GatewayWAF{Mode: w.mode, Level: w.level, Threshold: w.threshold, InspectBodyKB: w.bodyKB, Exclude: w.exclude, SkipBody: w.skipBody}
	for _, js := range w.rules {
		dec := json.NewDecoder(strings.NewReader(js))
		dec.DisallowUnknownFields()
		var r GatewayWAFRule
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("--waf-rule: %v", err)
		}
		out.Rules = append(out.Rules, r)
	}
	return out, out.Validate()
}

// checkWAFExclusions refuses exclusions that name no rule or group (a typo would silently leave
// a rule on). The gateway itself ignores unknown names, so old configs keep loading.
func checkWAFExclusions(w *GatewayWAF) error {
	if w == nil {
		return nil
	}
	for _, ex := range w.Exclude {
		if !wafKnownExclusion(ex) {
			return fmt.Errorf("unknown WAF rule or group %q (see: ziroctl gateway waf rules)", ex)
		}
	}
	return nil
}

// ---- bans ----

// addGatewayBan bans an address or network on every gateway node, for d (0 = until removed).
func addGatewayBan(s routeStore, addr string, d time.Duration, reason string) (GatewayBan, error) {
	p, err := parseNet(addr)
	if err != nil {
		return GatewayBan{}, err
	}
	b := GatewayBan{Addr: canonNet(p), Reason: reason}
	if d > 0 {
		b.Until = time.Now().Add(d).UTC().Format(time.RFC3339)
	}
	if err := b.Validate(); err != nil {
		return b, err
	}
	return b, s.update(func(d *gatewayData) error {
		kept := activeSettings(d.Settings, time.Now()).Bans
		out := kept[:0:0]
		for _, x := range kept {
			if x.Addr != b.Addr {
				out = append(out, x)
			}
		}
		d.Settings.Bans = append(out, b)
		return d.Settings.Validate()
	})
}

// canonNet writes a single address without a prefix length.
func canonNet(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// removeGatewayBan lifts a manual ban (and an automatic one on this host's gateway).
func removeGatewayBan(s routeStore, addr string) (manual, auto bool, err error) {
	p, err := parseNet(addr)
	if err != nil {
		return false, false, err
	}
	err = s.update(func(d *gatewayData) error {
		out := d.Settings.Bans[:0:0]
		for _, x := range d.Settings.Bans {
			if q, perr := parseNet(x.Addr); perr == nil && q == p {
				manual = true
				continue
			}
			out = append(out, x)
		}
		d.Settings.Bans = out
		return nil
	})
	if err == nil && p.IsSingleIP() {
		auto = gatewayAdminDo(http.MethodDelete, "/bans/"+p.Addr().String(), nil) == nil
	}
	return manual, auto, err
}

type gatewayBans struct {
	Manual []GatewayBan `json:"manual"`
	Auto   []BanStatus  `json:"auto"` // on the gateway running on this host
}

func listGatewayBans(s routeStore) (gatewayBans, error) {
	d, err := s.read()
	if err != nil {
		return gatewayBans{}, err
	}
	out := gatewayBans{Manual: activeSettings(d.Settings, time.Now()).Bans, Auto: []BanStatus{}}
	if out.Manual == nil {
		out.Manual = []GatewayBan{}
	}
	var auto []BanStatus
	if b, err := gatewayAdminRequest(http.MethodGet, "/bans", nil); err == nil && json.Unmarshal(b, &auto) == nil && auto != nil {
		out.Auto = auto
	}
	return out, nil
}

// gatewayAdminRequest talks to the gateway running on this host over its loopback endpoint,
// proving it is root by the token the gateway wrote at start.
func gatewayAdminRequest(method, path string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://"+gatewayAdminAddr+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if tok, err := os.ReadFile(gatewayAdminTokenPath); err == nil {
		req.Header.Set("X-Gateway-Admin", strings.TrimSpace(string(tok)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gateway: %s", strings.TrimSpace(string(b)))
	}
	return b, nil
}

func gatewayAdminDo(method, path string, body []byte) error {
	_, err := gatewayAdminRequest(method, path, body)
	return err
}

// newAdminToken creates the secret that lets root processes on this host change the running
// gateway (lifting a ban). Other local users cannot read it.
func newAdminToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b[:])
	if err := os.MkdirAll(dirOf(gatewayAdminTokenPath), 0700); err != nil {
		return "", err
	}
	return tok, writeFileAtomic(gatewayAdminTokenPath, []byte(tok), 0600)
}

func (g *gatewayServer) adminAuthorized(r *http.Request) bool {
	return g.adminToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gateway-Admin")), []byte(g.adminToken)) == 1
}

// adminBanRoutes adds the ban endpoints to the loopback admin mux.
func (g *gatewayServer) adminBanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /bans", func(w http.ResponseWriter, r *http.Request) {
		list := g.bans.list(time.Now())
		if list == nil {
			list = []BanStatus{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("DELETE /bans/{addr}", func(w http.ResponseWriter, r *http.Request) {
		if !g.adminAuthorized(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a, err := netip.ParseAddr(r.PathValue("addr"))
		if err != nil || !g.bans.unban(a) {
			http.Error(w, "not banned", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// ---- CLI ----

var gatewayBanCmd = &cobra.Command{Use: "ban", Short: "Ban clients from the gateway",
	Long: `Bans apply to every route on every gateway node. A ban lasts until it is removed, or for --for.
The gateway also bans clients by itself when settings enable it (gateway settings set --auto-ban).`,
	Example: "  ziroctl gateway ban add 203.0.113.0/24 --for 24h --reason scraper\n  ziroctl gateway ban ls"}

var gwBanFor time.Duration
var gwBanReason string

var gatewayBanAddCmd = &cobra.Command{
	Use: "add <address|cidr>", Short: "Ban an address or network",
	Example: "  ziroctl gateway ban add 203.0.113.7 --for 1h",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		b, err := addGatewayBan(s, args[0], gwBanFor, gwBanReason)
		if err != nil {
			return err
		}
		_ = auditLog("cli", "cli", "gateway ban add", b.Addr, nil)
		until := "until removed"
		if b.Until != "" {
			until = "until " + b.Until
		}
		fmt.Printf("✓ %s banned %s (applied within a second on gateway nodes)\n", b.Addr, until)
		return nil
	},
}

var gatewayBanRmCmd = &cobra.Command{
	Use: "rm <address|cidr>", Short: "Lift a ban",
	Example: "  ziroctl gateway ban rm 203.0.113.7",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		manual, auto, err := removeGatewayBan(s, args[0])
		if err != nil {
			return err
		}
		if !manual && !auto {
			return fmt.Errorf("%s is not banned", args[0])
		}
		_ = auditLog("cli", "cli", "gateway ban rm", args[0], nil)
		fmt.Printf("✓ %s unbanned\n", args[0])
		return nil
	},
}

var gatewayBanLsCmd = &cobra.Command{
	Use: "ls", Short: "List bans", Example: "  ziroctl gateway ban ls", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		bans, err := listGatewayBans(s)
		if err != nil {
			return err
		}
		fmt.Printf("%-40s %-22s %-7s %s\n", "ADDRESS", "UNTIL", "SOURCE", "REASON")
		for _, b := range bans.Manual {
			until := b.Until
			if until == "" {
				until = "removed by hand"
			}
			fmt.Printf("%-40s %-22s %-7s %s\n", b.Addr, until, "manual", b.Reason)
		}
		for _, b := range bans.Auto {
			fmt.Printf("%-40s %-22s %-7s %s\n", b.Addr, b.Until, "auto", b.Reason)
		}
		return nil
	},
}

var gatewayWAFCmd = &cobra.Command{
	Use:   "waf",
	Short: "Inspect and update the WAF rules",
	Long: `The WAF rules are a signed pack published in the ziro-os/pkgs repository. Gateways use the built-in
rules until a pack is installed, and then switch to the pack within a second, without a restart.
New rules are fetched about once a day; "waf update" fetches them now.`,
	Example: "  ziroctl gateway waf rules\n  ziroctl gateway waf update",
}

var (
	wafRulesGroup                  string
	wafUpdateCheck, wafUpdateForce bool
	wafTestBenignFile              string
)

var gatewayWAFRulesCmd = &cobra.Command{
	Use: "rules", Short: "List the WAF rules in use", Example: "  ziroctl gateway waf rules --group sqli", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := wafLoadPack(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
		p := wafEng().pack
		fmt.Printf("Rules: %s %s (%s)\n\n", p.Name, p.Version, p.Source)
		fmt.Printf("%-10s %-9s %-5s %-5s %-7s %s\n", "ID", "GROUP", "LEVEL", "SCORE", "STAGE", "DESCRIPTION")
		rules := wafRuleCatalog()
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
		for _, r := range rules {
			if wafRulesGroup == "" || r.Group == wafRulesGroup {
				fmt.Printf("%-10s %-9s %-5d %-5d %-7s %s\n", r.ID, r.Group, r.Level, r.Score, r.Stage, r.Msg)
			}
		}
		return nil
	},
}

func printWAFChange(res *wafUpdateResult) {
	for _, l := range []struct {
		what string
		ids  []string
	}{{"added", res.Added}, {"changed", res.Updated}, {"removed", res.Removed}} {
		if len(l.ids) > 0 {
			fmt.Printf("  %s: %s\n", l.what, strings.Join(l.ids, " "))
		}
	}
}

var gatewayWAFUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Fetch the newest signed WAF rules and use them",
	Long: `Downloads the rules catalog, checks its signature and every rule (each rule's own test samples must
pass), and installs it. Running gateways switch to the new rules within a second. On a cluster master every
gateway node fetches the rules too. A pack that fails any check is not installed and the rules in use stay.`,
	Example: "  ziroctl gateway waf update\n  ziroctl gateway waf update --check",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := wafUpdate(wafUpdateCheck, wafUpdateForce)
		_ = auditLog("cli", "cli", "gateway waf update", wafRepoName, err)
		if err != nil {
			return err
		}
		switch {
		case res.Held != "":
			fmt.Printf("Held back: %s\n", res.Held)
		case wafUpdateCheck:
			fmt.Printf("In use: %s %s (%s). On offer: %s\n", res.Pack.Name, res.Pack.Version, res.Pack.Source, res.Available)
		case !res.Changed:
			fmt.Printf("✓ WAF rules are up to date: %s %s, %d rules\n", res.Pack.Name, res.Pack.Version, res.Rules)
		default:
			fmt.Printf("✓ WAF rules updated to %s %s: %d rules\n", res.Pack.Name, res.Pack.Version, res.Rules)
			printWAFChange(res)
			if err := bumpWAFEpoch(); err != nil {
				return fmt.Errorf("the local gateway has the rules, but the cluster could not be told to fetch them: %w", err)
			}
		}
		return nil
	},
}

var gatewayWAFRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Return to the WAF rules used before the last update",
	Long: `Reinstalls the previous pack. The pack you rolled back from is not installed again by the daily
update; a newer pack is.`,
	Example: "  ziroctl gateway waf rollback",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := wafRollback()
		_ = auditLog("cli", "cli", "gateway waf rollback", wafRepoName, err)
		if err != nil {
			return err
		}
		fmt.Printf("✓ WAF rules rolled back to %s %s: %d rules\n", res.Pack.Name, res.Pack.Version, res.Rules)
		printWAFChange(res)
		return bumpWAFEpoch()
	},
}

var gatewayWAFStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show which WAF rules are installed",
	Example: "  ziroctl gateway waf status",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st := wafStatusNow()
		if jsonOutput {
			fmt.Println(jsonString(st))
			return nil
		}
		fmt.Printf("In use:    %s %s (%s), %d rules\n", st.InUse.Name, st.InUse.Version, st.InUse.Source, st.Rules)
		if st.Cached != nil {
			fmt.Printf("Installed: serial %d, signed index valid until %s\n", st.Cached.Serial, st.Cached.Expires)
		} else {
			fmt.Println("Installed: no downloaded pack (run: ziroctl gateway waf update)")
		}
		if len(st.Staged) > 0 {
			fmt.Printf("Staged:    %s (logged, not scored)\n", strings.Join(st.Staged, " "))
		}
		if len(st.Disabled) > 0 {
			fmt.Printf("Off:       %s\n", strings.Join(st.Disabled, " "))
		}
		fmt.Printf("Rollback:  %v\n", st.Previous)
		if st.Held != 0 {
			fmt.Printf("Held:      serial %d was rolled back and is not installed again\n", st.Held)
		}
		if st.Error != "" {
			fmt.Printf("Problem:   %s\n", st.Error)
		}
		return nil
	},
}

var gatewayWAFTestCmd = &cobra.Command{
	Use:   "test <rules.json>",
	Short: "Check a WAF rules file and its samples",
	Long: `Parses a rules file strictly, compiles every rule and runs the match and nomatch samples each rule
carries. With --benign it also checks that none of a list of legitimate requests (one target per line,
optionally followed by a tab and a User-Agent) would be blocked at level 1 or 2. The rules repository runs this
on every pull request.`,
	Example: "  ziroctl gateway waf test waf/zirogate-crs/rules.json --benign waf/zirogate-crs/benign.txt",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return wafTestFile(args[0], wafTestBenignFile, os.Stdout)
	},
}

var gatewayWAFExportCmd = &cobra.Command{
	Use:     "export",
	Short:   "Print the built-in WAF rules as a rules file",
	Example: "  ziroctl gateway waf export > rules.json",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := os.Stdout.Write(wafBuiltinJSON)
		return err
	},
}

// ---- API ----

func registerGatewayFirewallRoutes(a *apiRouter) {
	a.get("/api/v1/gateway/waf/rules", "viewer", func(w http.ResponseWriter, r *http.Request) {
		_, _ = wafLoadPack()
		apiReply(w, nil, wafRuleCatalog())
	})
	a.get("/api/v1/gateway/waf/pack", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, wafStatusNow())
	})
	a.post("/api/v1/gateway/waf/update", "admin", func(w http.ResponseWriter, r *http.Request) {
		res, err := wafUpdate(false, false)
		if err == nil && res.Changed {
			err = bumpWAFEpoch()
		}
		apiReply(w, err, res)
	})
	a.post("/api/v1/gateway/waf/rollback", "admin", func(w http.ResponseWriter, r *http.Request) {
		res, err := wafRollback()
		if err == nil {
			err = bumpWAFEpoch()
		}
		apiReply(w, err, res)
	})
	a.get("/api/v1/gateway/bans", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		bans, err := listGatewayBans(s)
		apiReply(w, err, bans)
	})
	a.post("/api/v1/gateway/bans", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		var req struct {
			Addr   string `json:"addr"`
			For    string `json:"for"` // a duration; empty = until removed
			Reason string `json:"reason"`
		}
		if err := decodeStrict(w, r, &req, 1<<14); err != nil {
			apiReply(w, err, nil)
			return
		}
		var d time.Duration
		if req.For != "" {
			if d, err = time.ParseDuration(req.For); err != nil || d <= 0 || d > 365*24*time.Hour {
				apiReply(w, fmt.Errorf("for must be a duration up to 8760h"), nil)
				return
			}
		}
		b, err := addGatewayBan(s, req.Addr, d, req.Reason)
		apiReply(w, err, b)
	})
	a.delete("/api/v1/gateway/bans/{addr}", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		manual, auto, err := removeGatewayBan(s, r.PathValue("addr"))
		if err == nil && !manual && !auto {
			err = errNotFound("not banned")
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: r.PathValue("addr") + " unbanned"})
	})
}

func init() {
	gatewayBanAddCmd.Flags().DurationVar(&gwBanFor, "for", 0, "Ban for this long (default: until removed)")
	gatewayBanAddCmd.Flags().StringVar(&gwBanReason, "reason", "", "Why (shown in the ban list)")
	gatewayBanCmd.AddCommand(gatewayBanAddCmd, gatewayBanRmCmd, gatewayBanLsCmd)
	gatewayWAFRulesCmd.Flags().StringVar(&wafRulesGroup, "group", "", "Only this group")
	gatewayWAFUpdateCmd.Flags().BoolVar(&wafUpdateCheck, "check", false, "Only report whether a newer pack is available")
	gatewayWAFUpdateCmd.Flags().BoolVar(&wafUpdateForce, "force", false, "Install even if the pack is not newer, or was rolled back")
	gatewayWAFTestCmd.Flags().StringVar(&wafTestBenignFile, "benign", "", "A file of legitimate requests that must not be blocked")
	gatewayWAFCmd.AddCommand(gatewayWAFRulesCmd, gatewayWAFUpdateCmd, gatewayWAFStatusCmd, gatewayWAFRollbackCmd, gatewayWAFTestCmd, gatewayWAFExportCmd)
	gatewayCmd.AddCommand(gatewayBanCmd, gatewayWAFCmd)
}

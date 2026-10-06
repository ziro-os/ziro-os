package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// renewDNSCerts issues the named certificates (all when none are named) now. Without force only the
// ones that are due. It must run on the leader: two hosts issuing for one name would race over the
// challenge records.
func renewDNSCerts(s routeStore, names []string, force bool, now time.Time) ([]string, error) {
	if s.name() == "cluster" && !socketIsLeader() {
		return nil, errors.New("this master is not the Raft leader; the leader's sync service renews certificates (or run the command there)")
	}
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	if len(d.DNSCloud.Certs) == 0 {
		return nil, errors.New("no DNS-01 certificate: ziroctl dns cert add … (or ziroctl gateway domain set <domain> --wildcard-cert)")
	}
	var issued, errs []string
	state := readDNSCertStatus()
	for _, c := range d.DNSCloud.Certs {
		if len(names) > 0 && !slices.Contains(names, c.Name) {
			continue
		}
		if due, _ := dnsCertDue(s, c, now); !due && !force {
			continue
		}
		st := state[c.Name]
		st.LastAttempt = now.UTC().Format(time.RFC3339)
		if err := issueAndStore(s, c); err != nil {
			st.Failures++
			st.LastError, st.NextAttempt = sanitizeLabel(err.Error(), 400), now.Add(dnsCertBackoff(st.Failures)).UTC().Format(time.RFC3339)
			errs = append(errs, fmt.Sprintf("%s: %v", c.Name, err))
		} else {
			st = dnsCertState{LastAttempt: st.LastAttempt, LastIssued: st.LastAttempt}
			issued = append(issued, c.Name)
		}
		state[c.Name] = st
	}
	writeDNSCertStatus(state)
	if len(names) > 0 && len(issued)+len(errs) == 0 {
		for _, n := range names {
			if d.DNSCloud.cert(n) == nil {
				return nil, fmt.Errorf("no DNS-01 certificate %q", n)
			}
		}
	}
	if len(errs) > 0 {
		return issued, errors.New(strings.Join(errs, "; "))
	}
	return issued, nil
}

// certAlertSeverity: a failing renewal is high; critical when the certificate in use is about to
// expire (or there is none), because then clients start to see errors.
func certAlertSeverity(s routeStore, c DNSCert, now time.Time) string {
	if g, err := s.getCert(c.Name); err == nil {
		if na, err := certExpiry(g.Cert); err == nil && na.Sub(now) > 7*24*time.Hour {
			return "high"
		}
	}
	return "critical"
}

// dnsCertDoctorCheck is the doctor row for the DNS-01 certificates.
func dnsCertDoctorCheck(now time.Time) (doctorCheck, bool) {
	s, err := gatewayStore()
	if err != nil {
		return doctorCheck{}, false
	}
	views, err := dnsCertViews(s, now)
	if err != nil || len(views) == 0 {
		return doctorCheck{}, false
	}
	c := doctorCheck{Name: "DNS-01 certificates", Passed: true, Fix: "issue the missing or expiring ones now", fix: func() error {
		_, err := renewDNSCerts(s, nil, false, time.Now())
		return err
	}}
	var parts []string
	for _, v := range views {
		switch {
		case !v.Issued:
			c.Passed = false
			parts = append(parts, v.Name+" not issued yet")
		case v.DaysLeft < 14:
			c.Passed = false
			parts = append(parts, fmt.Sprintf("%s expires in %d days", v.Name, v.DaysLeft))
		default:
			parts = append(parts, fmt.Sprintf("%s %dd left", v.Name, v.DaysLeft))
		}
		if v.LastError != "" {
			c.Passed = false
			parts[len(parts)-1] += ": last attempt failed: " + v.LastError
		}
	}
	c.Details = strings.Join(parts, "; ")
	return c, true
}

// ---- CLI ----

var (
	dnsCertFlagName, dnsCertProvider string
	dnsCertForce                     bool
)

var dnsCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Wildcard certificates through ACME DNS-01",
	Long: `ACME DNS-01 proves you control a name with a TXT record at your DNS provider, so it can issue
wildcard certificates and needs no inbound port 80 or 443 for validation. The gateway gets the
certificate, serves it to routes with --tls dns01, and renews it 30 days before it expires. Needs a DNS
provider (ziroctl dns provider add). The module dns-cloudflare does the issuing and renewing; in a
cluster only the leader does.

Use a staging CA while trying it: ziroctl gateway acme --directory https://acme-staging-v02.api.letsencrypt.org/directory`,
	Example: "  ziroctl dns cert add '*.example.com' example.com\n  ziroctl dns cert ls",
}

var dnsCertAddCmd = &cobra.Command{
	Use:   "add <name>...",
	Short: "Keep a certificate for these names issued",
	Example: `  ziroctl dns cert add '*.example.com'
  ziroctl dns cert add '*.apps.example.com' apps.example.com --name dns01-apps`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		c, err := dnsCertAdd(s, args, dnsCertFlagName, dnsCertProvider)
		if err != nil {
			return err
		}
		fmt.Printf("✓ certificate %s for %s; the sync service issues it within a minute (ziroctl dns cert ls)\n", c.Name, strings.Join(c.Domains, ", "))
		fmt.Println("  Use it with: ziroctl gateway route add … --tls dns01")
		return nil
	},
}

var dnsCertLsCmd = &cobra.Command{
	Use: "ls", Short: "List DNS-01 certificates and their expiry", Args: cobra.NoArgs, Example: "  ziroctl dns cert ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		views, err := dnsCertViews(s, time.Now())
		if err != nil {
			return err
		}
		return printResult(views, func() {
			if len(views) == 0 {
				fmt.Println("No DNS-01 certificate. Add one with: ziroctl dns cert add '*.example.com'")
			}
			for _, v := range views {
				state := "not issued yet"
				if v.Issued {
					state = fmt.Sprintf("expires %s (%d days)", v.NotAfter[:10], v.DaysLeft)
				}
				fmt.Printf("%-28s %-32s %s\n", v.Name, strings.Join(v.Domains, ","), state)
				if v.LastError != "" {
					fmt.Printf("    ! last attempt failed: %s (next try %s)\n", v.LastError, v.NextAttempt)
				}
			}
		})
	},
}

var dnsCertRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Stop keeping a certificate and delete it", Args: cobra.ExactArgs(1), Example: "  ziroctl dns cert rm dns01-wild-example-com",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if err := dnsCertRm(s, args[0]); err != nil {
			return err
		}
		fmt.Printf("✓ certificate %s removed\n", args[0])
		return nil
	},
}

var dnsCertRenewCmd = &cobra.Command{
	Use: "renew [name]", Short: "Issue or renew certificates now", Args: cobra.MaximumNArgs(1),
	Long:    "Issues the certificates that are missing or due now (all of them with --force). Run it on the leader; the sync service does this by itself.",
	Example: "  ziroctl dns cert renew\n  ziroctl dns cert renew dns01-wild-example-com --force",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		issued, err := renewDNSCerts(s, args, dnsCertForce, time.Now())
		for _, n := range issued {
			fmt.Printf("✓ issued %s\n", n)
		}
		if err == nil && len(issued) == 0 {
			fmt.Println("Nothing is due (--force issues anyway)")
		}
		return err
	},
}

func init() {
	dnsCertAddCmd.Flags().StringVar(&dnsCertFlagName, "name", "", "Store name (dns01-…; default from the first name)")
	dnsCertAddCmd.Flags().StringVar(&dnsCertProvider, "provider", "", "DNS provider that holds the zone (default: the first that does)")
	dnsCertRenewCmd.Flags().BoolVar(&dnsCertForce, "force", false, "Issue even when the certificate is not due")
	dnsCertCmd.AddCommand(dnsCertAddCmd, dnsCertLsCmd, dnsCertRmCmd, dnsCertRenewCmd)
	dnsCmd.AddCommand(dnsCertCmd)
}

// ---- API ----

func registerDNSCertRoutes(a *apiRouter) {
	a.get("/api/v1/dns/cloud/certs", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		v, err := dnsCertViews(s, time.Now())
		apiReply(w, err, v)
	})
	a.post("/api/v1/dns/cloud/certs", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domains  []string `json:"domains"`
			Name     string   `json:"name"`
			Provider string   `json:"provider"`
		}
		if err := decodeStrict(w, r, &req, 16<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		c, err := dnsCertAdd(s, req.Domains, req.Name, req.Provider)
		apiReply(w, err, c)
	})
	a.delete("/api/v1/dns/cloud/certs", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			apiReply(w, errors.New("name: the certificate to remove (ziroctl dns cert ls)"), nil)
			return
		}
		apiReply(w, dnsCertRm(s, name), APIMessage{Status: "ok", Message: "certificate removed"})
	})
	a.post("/api/v1/dns/cloud/certs/renew", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name  string `json:"name"`
			Force bool   `json:"force"`
		}
		if r.ContentLength != 0 && !decodeBody(w, r, &req) {
			return
		}
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		var names []string
		if req.Name != "" {
			names = []string{req.Name}
		}
		issued, err := renewDNSCerts(s, names, req.Force, time.Now())
		if err != nil && len(issued) == 0 {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, err, map[string]any{"issued": issued})
	})
}

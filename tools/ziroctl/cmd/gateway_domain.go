package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// The gateway's base domain: every deployed app that has no host of its own is published at
// <app>.<domain> (a gateway route, TLS by the domain's kind). Setting the domain also gives the
// built-in DNS a wildcard record for it, pointing at the gateway, so the hosts of the cluster (or
// the standalone host) resolve the apps; for everyone else the records to create at the DNS
// provider are printed.

// domainInfo is what `gateway domain` and the API report.
type domainInfo struct {
	Domain    string   `json:"domain"`
	TLS       string   `json:"tls,omitempty"`
	Example   string   `json:"example,omitempty"`   // the URL an app would get
	Addresses []string `json:"addresses,omitempty"` // where the gateway answers
	Records   []string `json:"records,omitempty"`   // what to create at a public DNS provider
	Managed   []string `json:"managed,omitempty"`   // DNS providers that create them automatically
	DNS       string   `json:"dns,omitempty"`       // what was done in the built-in DNS
}

// gatewayDomain is the configured base domain (the zero value when none or unreadable).
func gatewayDomain() GatewayDomain {
	s, err := gatewayStore()
	if err != nil {
		return GatewayDomain{}
	}
	d, err := s.read()
	if err != nil {
		return GatewayDomain{}
	}
	return d.Domain
}

// gatewayAddrs are the addresses the gateway answers on: the gateway nodes of a cluster, or this
// host's primary address.
func gatewayAddrs(s routeStore) []string {
	if s.name() == "cluster" {
		st, err := readState()
		if err != nil {
			return nil
		}
		var out []string
		for _, n := range st.Nodes {
			if n.Gateway && n.IP != "" {
				out = append(out, n.IP)
			}
		}
		return out
	}
	if a := hostAddrs(); len(a) > 0 { // in role order: the primary interface first
		return []string{a[0].IP}
	}
	return nil
}

// hostAddrs is a seam for tests.
var hostAddrs = hostAddresses

func wildcardName(domain string) string { return "*." + domain }

// syncWildcardDNS makes the built-in DNS answer *.domain with addrs (none: removes the record).
// It reports what it did.
func syncWildcardDNS(s routeStore, domain string, addrs []string) (string, error) {
	name := wildcardName(domain)
	recs := make([]DNSRecord, 0, len(addrs))
	for _, a := range addrs {
		recs = append(recs, DNSRecord{Name: name, Type: "A", Value: a, TTL: 300})
	}
	for _, r := range recs {
		if _, _, err := parseRecord(r); err != nil {
			return "", err
		}
	}
	if s.name() == "cluster" {
		err := withState(func(st *ClusterState) error {
			kept := st.DNSRecords[:0]
			for _, r := range st.DNSRecords {
				if fqdn(r.Name) != fqdn(name) {
					kept = append(kept, r)
				}
			}
			st.DNSRecords = append(kept, recs...)
			return nil
		})
		return "cluster DNS: " + name + " (every node resolves it after its next heartbeat)", err
	}
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) { // no dns.json yet is fine
		return "", err
	}
	if err := removeDNSRecords(cfg, name, "A"); err != nil && !strings.Contains(err.Error(), "no ") {
		return "", err
	}
	cfg.Records = append(cfg.Records, recs...)
	if err := saveDNSConfig(cfg); err != nil {
		return "", err
	}
	if !dnsEnabled() {
		return "local DNS: " + name + " saved; turn the resolver on with: ziroctl dns enable", nil
	}
	return "local DNS: " + name + " (reloaded within 2s)", nil
}

func describeDomain(s routeStore, d GatewayDomain) domainInfo {
	info := domainInfo{Domain: d.Name, Addresses: gatewayAddrs(s)}
	if d.Name == "" {
		return info
	}
	info.TLS, info.Example = d.TLS(), "https://"+d.Host("<app>")
	for _, a := range info.Addresses {
		info.Records = append(info.Records, fmt.Sprintf("%s. A %s", wildcardName(d.Name), a))
	}
	if gd, err := s.read(); err == nil {
		for _, p := range gd.DNSCloud.Providers {
			info.Managed = append(info.Managed, p.Name)
		}
	}
	return info
}

// setGatewayDomain stores the domain (name "" removes it) and updates the built-in DNS.
func setGatewayDomain(name string) (domainInfo, error) { return setGatewayDomainOpts(name, false) }

// setGatewayDomainOpts is setGatewayDomain with the choice of serving the apps with one wildcard
// certificate (*.name) issued through ACME DNS-01. That needs a DNS provider and a public name. The
// certificate belongs to the domain: changing or removing the domain drops it.
func setGatewayDomainOpts(name string, wildcard bool) (domainInfo, error) {
	s, err := gatewayStore()
	if err != nil {
		return domainInfo{}, err
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name != "" && (strings.HasPrefix(name, "*") || !validHost(name) || len(name) > 200) {
		return domainInfo{}, fmt.Errorf("invalid domain %q (a name like apps.example.com)", name)
	}
	if wildcard && (name == "" || schema.PrivateDomain(name)) {
		return domainInfo{}, errors.New("a wildcard certificate needs a public base domain (a private name uses the gateway's own CA)")
	}
	var old GatewayDomain
	var dropped []string
	if err := s.update(func(d *gatewayData) error {
		old, d.Domain = d.Domain, GatewayDomain{Name: name, WildcardCert: wildcard}
		kept := d.DNSCloud.Certs[:0]
		for _, c := range d.DNSCloud.Certs { // the previous domain's certificate goes
			if c.Source == dnsCertSourceDom {
				dropped = append(dropped, c.Name)
				continue
			}
			kept = append(kept, c)
		}
		d.DNSCloud.Certs = kept
		if wildcard {
			if _, err := addDNSCertTo(d, []string{wildcardName(name)}, "", "", dnsCertSourceDom); err != nil {
				return err
			}
		}
		bumpDNS(d)
		return nil
	}); err != nil {
		return domainInfo{}, err
	}
	for _, n := range dropped {
		if !wildcard || n != dnsCertName([]string{wildcardName(name)}) { // an unchanged certificate is kept
			_ = s.rmCert(n)
			dnsCertForget(n)
		}
	}
	info := describeDomain(s, GatewayDomain{Name: name, WildcardCert: wildcard})
	var derr error
	if old.Name != "" && old.Name != name { // the old wildcard is no longer ours
		_, derr = syncWildcardDNS(s, old.Name, nil)
	}
	if name != "" && derr == nil {
		if len(info.Addresses) == 0 {
			info.DNS = "no gateway address yet (ziroctl gateway node enable <node>): no DNS record was added"
		} else {
			info.DNS, derr = syncWildcardDNS(s, name, info.Addresses)
		}
	}
	return info, derr
}

// exposeFor is the hostname and TLS mode an app is published with: its own --expose, else
// <app>.<gateway domain>, else none.
func exposeFor(d *Deployment) (host, tlsMode string) {
	if d.Expose != "" {
		return d.Expose, d.ExposeTLS
	}
	if dom := gatewayDomain(); dom.Name != "" {
		return dom.Host(d.Name), dom.TLS()
	}
	return "", ""
}

var gatewayDomainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Publish deployed apps under a base domain",
	Long: `With a base domain, every deployed app without its own --expose host is published at
<app>.<domain> through the gateway: a route is created when the app is released. Public names get
ACME certificates; private ones (.local, .internal, .lan, no dot) use the gateway's own CA
(ziroctl gateway ca). Setting the domain also adds a wildcard record to the built-in DNS pointing
at the gateway, and prints the records to create at your DNS provider.`,
	Example: `  ziroctl gateway domain set apps.example.com
  ziroctl gateway domain
  ziroctl gateway domain rm`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		d, err := s.read()
		if err != nil {
			return err
		}
		return printDomain(describeDomain(s, d.Domain))
	},
}

func printDomain(info domainInfo) error {
	return printResult(info, func() {
		if info.Domain == "" {
			fmt.Println("No base domain. Set one with: ziroctl gateway domain set apps.example.com")
			return
		}
		fmt.Printf("Apps are published at %s (TLS %s)\n", info.Example, info.TLS)
		if info.DNS != "" {
			fmt.Println("✓", info.DNS)
		}
		if len(info.Records) == 0 {
			fmt.Println("! No gateway address yet: enable a gateway node (ziroctl gateway node enable <node>)")
			return
		}
		// A private name (.local, .internal, ...) is never published to a public provider.
		if len(info.Managed) > 0 && info.TLS != "internal" {
			fmt.Printf("✓ DNS records are created automatically at %s (ziroctl dns cloud plan shows what)\n", strings.Join(info.Managed, ", "))
			fmt.Println("Apps already deployed pick the domain up on their next release: ziroctl deploy redeploy <app>")
			return
		}
		fmt.Println("DNS records to create at your DNS provider (or use these addresses behind a load balancer):")
		for _, r := range info.Records {
			fmt.Println("  " + r)
		}
		if info.TLS == "internal" {
			fmt.Println("Private name: clients trust the gateway CA from: ziroctl gateway ca")
		}
		if info.TLS == "dns01" {
			fmt.Println("Apps are served with the wildcard certificate *." + info.Domain + " (ACME DNS-01); its status: ziroctl dns cert ls")
		}
		fmt.Println("Apps already deployed pick the domain up on their next release: ziroctl deploy redeploy <app>")
	})
}

var gwDomainWildcard bool

var gatewayDomainSetCmd = &cobra.Command{
	Use:   "set <domain>",
	Short: "Set the base domain for deployed apps",
	Long: `Publish deployed apps at <app>.<domain>. With --wildcard-cert they are all served with one
wildcard certificate (*.<domain>) that the gateway gets through ACME DNS-01 and renews 30 days
before it expires, instead of one HTTP-01 certificate per app. That needs a DNS provider
(ziroctl dns provider add) and the dns-cloudflare module, which does the issuing, and a public
name. Until the certificate is issued the apps are not served.`,
	Example: `  ziroctl gateway domain set apps.example.com
  ziroctl gateway domain set apps.example.com --wildcard-cert`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := setGatewayDomainOpts(args[0], gwDomainWildcard)
		if err != nil {
			return err
		}
		return printDomain(info)
	},
}

var gatewayDomainRmCmd = &cobra.Command{
	Use:     "rm",
	Short:   "Stop publishing apps under a base domain",
	Example: `  ziroctl gateway domain rm`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := setGatewayDomain(""); err != nil {
			return err
		}
		fmt.Println("✓ base domain removed; routes already created stay (ziroctl gateway route ls)")
		return nil
	},
}

func init() {
	gatewayDomainSetCmd.Flags().BoolVar(&gwDomainWildcard, "wildcard-cert", false, "Serve the apps with one wildcard certificate issued through ACME DNS-01")
	gatewayDomainCmd.AddCommand(gatewayDomainSetCmd, gatewayDomainRmCmd)
	gatewayCmd.AddCommand(gatewayDomainCmd)
}

// registerGatewayDomainRoutes: /api/v1/gateway/domain.
func registerGatewayDomainRoutes(a *apiRouter) {
	a.get("/api/v1/gateway/domain", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := gatewayStore()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		d, err := s.read()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, describeDomain(s, d.Domain))
	})
	a.put("/api/v1/gateway/domain", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name         string `json:"name"`
			WildcardCert bool   `json:"wildcard_cert"`
		}
		if err := decodeStrict(w, r, &req, 4<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		if req.Name == "" {
			apiReply(w, errors.New("name: the base domain, e.g. apps.example.com (DELETE removes it)"), nil)
			return
		}
		info, err := setGatewayDomainOpts(req.Name, req.WildcardCert)
		apiReply(w, err, info)
	})
	a.delete("/api/v1/gateway/domain", "admin", func(w http.ResponseWriter, r *http.Request) {
		_, err := setGatewayDomain("")
		apiReply(w, err, map[string]string{"domain": ""})
	})
}

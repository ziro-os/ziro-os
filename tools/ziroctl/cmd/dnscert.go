package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// DNS-01 certificates: certificates the gateway gets through ACME DNS-01, which proves control of a
// name with a TXT record at the DNS provider (dnsprovider.go) instead of by answering on :80/:443.
// That makes wildcard certificates possible and needs no inbound port for validation. The issuer is
// gateway_acme_dns.go; this file is the configuration: which certificates exist and which routes use
// them (a route with `tls: dns01` is served the certificate that covers its hosts).
//
// ponytail: HTTP-01 through autocert stays the default (`tls: auto`); DNS-01 is opt-in per route or
// per base domain, so a host with no DNS provider changes nothing.

// DNSCert is a certificate to keep issued through DNS-01.
type DNSCert struct {
	Name     string   `json:"name"`               // the certificate store name (dns01-…)
	Domains  []string `json:"domains"`            // names on the certificate: "example.com", "*.example.com"
	Provider string   `json:"provider,omitempty"` // DNS provider that holds the zone ("": the first that does)
	Source   string   `json:"source,omitempty"`   // "domain": made by `gateway domain set --wildcard-cert`
}

const (
	maxDNSCerts       = 20
	maxDNSCertDomains = 10
	dnsCertSourceDom  = "domain"
)

// dnsCertSlug turns a name into the part of a store name that identifies it.
func dnsCertSlug(d string) string {
	slug := strings.ReplaceAll(strings.TrimPrefix(d, "*."), ".", "-")
	if strings.HasPrefix(d, "*.") {
		slug = "wild-" + slug
	}
	return slug
}

// dnsCertName is the store name for a certificate: dns01-<first name>.
func dnsCertName(domains []string) string {
	name := "dns01-" + dnsCertSlug(domains[0])
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	return name
}

// cleanDNSCertDomains validates and normalises the names for a certificate: public DNS names, a
// wildcard only as the first label, no private suffixes (no public CA certifies them).
func cleanDNSCertDomains(in []string) ([]string, error) {
	var out []string
	for _, d := range in {
		d = normDNSName(d)
		if d == "" {
			continue
		}
		base := strings.TrimPrefix(d, "*.")
		if !hostRe.MatchString(base) || len(d) > 253 {
			return nil, fmt.Errorf("invalid certificate name %q (a DNS name like example.com or *.example.com)", d)
		}
		if schema.PrivateDomain(base) {
			return nil, fmt.Errorf("%s is a private name: no public CA issues certificates for it (use --tls internal)", d)
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one name is needed")
	}
	if len(out) > maxDNSCertDomains {
		return nil, fmt.Errorf("at most %d names on one certificate", maxDNSCertDomains)
	}
	sort.Strings(out)
	return out, nil
}

// covers reports whether the certificate is valid for host: an exact name, or a wildcard for the
// one label in front of it.
func (c DNSCert) covers(host string) bool {
	host = normDNSName(host)
	for _, d := range c.Domains {
		if d == host {
			return true
		}
		if base, ok := strings.CutPrefix(d, "*."); ok {
			if label, ok := strings.CutSuffix(host, "."+base); ok && label != "" && !strings.Contains(label, ".") && label != "*" {
				return true
			}
		}
	}
	return false
}

// coversAll: every host is covered.
func (c DNSCert) coversAll(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !c.covers(h) {
			return false
		}
	}
	return true
}

// certFor is the first certificate that covers every host of a route.
func (c DNSCloud) certFor(hosts []string) *DNSCert {
	for i := range c.Certs {
		if c.Certs[i].coversAll(hosts) {
			return &c.Certs[i]
		}
	}
	return nil
}

func (c DNSCloud) cert(name string) *DNSCert {
	for i := range c.Certs {
		if c.Certs[i].Name == name {
			return &c.Certs[i]
		}
	}
	return nil
}

// ---- configuration edits (shared by the CLI and the API) ----

// addDNSCert records a certificate to keep issued (replacing one of the same name). The issuer
// creates it within a poll of the loop.
func addDNSCertTo(d *gatewayData, domains []string, name, provider, source string) (DNSCert, error) {
	domains, err := cleanDNSCertDomains(domains)
	if err != nil {
		return DNSCert{}, err
	}
	if len(d.DNSCloud.Providers) == 0 {
		return DNSCert{}, errors.New("no DNS provider yet: ziroctl dns provider add cloudflare --token-file …")
	}
	if provider != "" && d.DNSCloud.provider(provider) == nil {
		return DNSCert{}, fmt.Errorf("no DNS provider %q (ziroctl dns provider ls)", provider)
	}
	if name == "" {
		name = dnsCertName(domains)
	}
	if err := validName(name); err != nil || !strings.HasPrefix(name, "dns01-") {
		return DNSCert{}, fmt.Errorf("certificate name %q must be a valid name starting with dns01-", name)
	}
	c := DNSCert{Name: name, Domains: domains, Provider: provider, Source: source}
	if cur := d.DNSCloud.cert(name); cur != nil {
		*cur = c
	} else {
		if len(d.DNSCloud.Certs) >= maxDNSCerts {
			return DNSCert{}, fmt.Errorf("at most %d DNS-01 certificates", maxDNSCerts)
		}
		d.DNSCloud.Certs = append(d.DNSCloud.Certs, c)
	}
	d.DNSCloud.Epoch++
	return c, nil
}

func dnsCertAdd(s routeStore, domains []string, name, provider string) (DNSCert, error) {
	var out DNSCert
	err := s.update(func(d *gatewayData) error {
		var err error
		out, err = addDNSCertTo(d, domains, name, provider, "")
		return err
	})
	return out, err
}

// dnsCertRm drops a certificate from the configuration and deletes the stored one. A route that
// would be left without a certificate keeps it.
func dnsCertRm(s routeStore, name string) error {
	err := s.update(func(d *gatewayData) error {
		c := d.DNSCloud.cert(name)
		if c == nil {
			return fmt.Errorf("no DNS-01 certificate %q", name)
		}
		if c.Source == dnsCertSourceDom && d.Domain.WildcardCert {
			return fmt.Errorf("%s belongs to the base domain %s: ziroctl gateway domain set %s (without --wildcard-cert) drops it", name, d.Domain.Name, d.Domain.Name)
		}
		for _, r := range d.Routes {
			r.Normalize()
			if r.TLS != "dns01" || !c.coversAll(r.Hosts) {
				continue
			}
			other := false
			for _, o := range d.DNSCloud.Certs {
				other = other || (o.Name != name && o.coversAll(r.Hosts))
			}
			if !other {
				return fmt.Errorf("route %s serves %s with it: remove or change the route first", r.Name, strings.Join(r.Hosts, ", "))
			}
		}
		kept := d.DNSCloud.Certs[:0]
		for _, o := range d.DNSCloud.Certs {
			if o.Name != name {
				kept = append(kept, o)
			}
		}
		d.DNSCloud.Certs = kept
		d.DNSCloud.Epoch++
		return nil
	})
	if err != nil {
		return err
	}
	_ = s.rmCert(name) // nothing stored yet is fine
	dnsCertForget(name)
	return nil
}

// requireDNSCertFor is putRoute's check for `tls: dns01`: a configured certificate must cover the
// route's hosts, else the route could never be served.
func requireDNSCertFor(d *gatewayData, r GatewayRoute) error {
	if r.TLS != "dns01" {
		return nil
	}
	if d.DNSCloud.certFor(r.Hosts) == nil {
		return fmt.Errorf("no DNS-01 certificate covers %s: ziroctl dns cert add <name>… (or ziroctl gateway domain set <domain> --wildcard-cert)", strings.Join(r.Hosts, ", "))
	}
	return nil
}

// resolveDNSCertRoute turns a `tls: dns01` route into the stored certificate that serves it. While
// no certificate has been issued the route is left out (the gateway would only fail the handshake,
// and an older gateway node would reject the whole configuration over a TLS mode it does not know).
func resolveDNSCertRoute(c DNSCloud, r GatewayRoute, issued func(name string) bool) (GatewayRoute, bool) {
	if r.TLS != "dns01" {
		return r, true
	}
	cert := c.certFor(r.Hosts)
	if cert == nil || !issued(cert.Name) {
		return r, false
	}
	r.TLS = "cert:" + cert.Name
	return r, true
}

// ---- reading what was issued ----

// certExpiry is the NotAfter of the first certificate in a PEM chain.
func certExpiry(chainPEM string) (time.Time, error) {
	rest := []byte(chainPEM)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return time.Time{}, errors.New("no certificate in the PEM")
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return c.NotAfter, nil
	}
}

// DNSCertView is a certificate and what is known about it, for the CLI and the API.
type DNSCertView struct {
	DNSCert
	Issued      bool   `json:"issued"`
	NotAfter    string `json:"not_after,omitempty"`
	DaysLeft    int    `json:"days_left,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	LastAttempt string `json:"last_attempt,omitempty"`
	NextAttempt string `json:"next_attempt,omitempty"`
}

func dnsCertViews(s routeStore, now time.Time) ([]DNSCertView, error) {
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	status := readDNSCertStatus()
	out := []DNSCertView{}
	for _, c := range d.DNSCloud.Certs {
		v := DNSCertView{DNSCert: c}
		if g, err := s.getCert(c.Name); err == nil {
			if na, err := certExpiry(g.Cert); err == nil {
				v.Issued, v.NotAfter, v.DaysLeft = true, na.UTC().Format(time.RFC3339), int(na.Sub(now).Hours()/24)
			}
		}
		if st, ok := status[c.Name]; ok {
			v.LastError, v.LastAttempt, v.NextAttempt = st.LastError, st.LastAttempt, st.NextAttempt
		}
		out = append(out, v)
	}
	return out, nil
}

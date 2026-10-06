package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// DNS provider: publish the gateway's names at a public DNS provider instead of printing the
// records to create by hand. The desired records are derived from the gateway (base domain and
// routes) plus explicit records; dnsprovider_sync.go diffs them against the provider and applies the
// difference, touching only records it created (they carry an ownership comment).
//
// Configuration (providers, explicit records, the Epoch a route change bumps) lives with the
// gateway's data, so in a cluster it replicates with the routes. A provider's API token is a
// cluster secret in a cluster (replicated and sealed at rest, so a new leader can carry on) and a
// root-only file on a standalone host, sealed in the TPM when there is one (like `ziroctl cf login`:
// without a TPM the file is only as private as its 0600 mode). It is never in argv, the environment
// or logs.
//
// ponytail: Cloudflare is the only implementation; another provider is one more DNSProvider.

// DNSZone is a zone (a DNS domain) a provider hosts.
type DNSZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DNSRec is one record at a provider. TTL 0 or 1 means automatic. Comment carries the ownership
// marker.
type DNSRec struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"` // A, AAAA, CNAME, TXT
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied bool   `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// DNSProvider is what the reconciler needs from a DNS provider.
type DNSProvider interface {
	Zones() ([]DNSZone, error)
	List(zoneID string) ([]DNSRec, error)
	Upsert(zoneID string, r DNSRec) error // creates when r.ID is empty, else replaces that record
	Delete(zoneID, id string) error
}

// DNSProviderConf is a configured provider (its token is stored apart, sealed).
type DNSProviderConf struct {
	Name  string   `json:"name"`
	Kind  string   `json:"kind"`            // cloudflare
	Zones []string `json:"zones,omitempty"` // only these zones are managed; empty = every zone the token sees
}

// DNSCloudRecord is an explicit record to keep at a provider, besides the derived ones.
type DNSCloudRecord struct {
	Provider string `json:"provider,omitempty"` // empty: the first provider that hosts the zone
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Proxied  bool   `json:"proxied,omitempty"`
}

// DNSCloud is the declarative DNS-provider setting, stored with the gateway data.
type DNSCloud struct {
	Providers []DNSProviderConf `json:"providers,omitempty"`
	Records   []DNSCloudRecord  `json:"records,omitempty"`
	// Addresses are published for the gateway's names instead of the gateway nodes' own
	// addresses (a NAT, a load balancer).
	Addresses []string `json:"addresses,omitempty"`
	// Certs are certificates kept issued through ACME DNS-01 (dnscert.go).
	Certs []DNSCert `json:"certs,omitempty"`
	// Epoch is bumped by every route or domain change; the sync loop reconciles when it moves.
	Epoch int `json:"epoch,omitempty"`
}

const (
	dnsKindCloudflare = "cloudflare"
	dnsSecretPrefix   = "dns-provider-" // cluster secret holding a provider's token
	dnsDefaultTTL     = 300
	maxDNSRecords     = 500
)

var (
	dnsProviderDir = "/etc/ziro/dnsprovider" // standalone: the tokens (root-only)
	dnsStatusDir   = "/var/lib/ziro/dnsprovider"
)

// dnsProviderFactory builds a provider client from its configuration and token (a test seam).
var dnsProviderFactory = func(c DNSProviderConf, token string) (DNSProvider, error) {
	switch c.Kind {
	case dnsKindCloudflare:
		return newCFDNSProvider(token), nil
	}
	return nil, fmt.Errorf("unknown DNS provider kind %q (supported: %s)", c.Kind, dnsKindCloudflare)
}

// dnsOwner is the cluster (or host) these records belong to: part of every ownership comment, so
// two clusters sharing a zone never touch each other's records.
func dnsOwner() string {
	if cfg, err := loadClusterConfig(); err == nil && cfg.ClusterID != "" {
		return cfg.ClusterID
	}
	h, _ := os.Hostname()
	return "host-" + sanitizeLabel(h, 40)
}

// dnsMarker is the comment on every record the sync owns. Records with any other comment, or none,
// are never updated or deleted. (ACME challenge records use a different marker, "ziro-acme:", so the
// sync never mistakes one for its own.)
func dnsMarker() string { return "ziro:" + dnsOwner() }

// ---- tokens ----

type sealedDNSToken struct {
	Provider string `json:"provider"` // file or tpm
	Blob     []byte `json:"blob"`
}

func dnsTokenFile(name string) string { return filepath.Join(dnsProviderDir, name+".json") }

func dnsTokenPut(s routeStore, name, token string) error {
	if s.name() == "cluster" {
		return withState(func(st *ClusterState) error {
			if st.Secrets == nil {
				st.Secrets = map[string]map[string]string{}
			}
			st.Secrets[dnsSecretPrefix+name] = map[string]string{"token": token}
			return nil
		})
	}
	provider, blob, err := sealToken(token)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(sealedDNSToken{Provider: provider, Blob: blob})
	if err := os.MkdirAll(dnsProviderDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dnsProviderDir, 0700); err != nil {
		return err
	}
	return writeFileAtomic(dnsTokenFile(name), b, 0600)
}

func dnsTokenGet(s routeStore, name string) (string, error) {
	if s.name() == "cluster" {
		st, err := readState()
		if err != nil {
			return "", err
		}
		if tok := st.Secrets[dnsSecretPrefix+name]["token"]; tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("no token stored for DNS provider %q", name)
	}
	b, err := os.ReadFile(dnsTokenFile(name))
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no token stored for DNS provider %q", name)
	}
	if err != nil {
		return "", err
	}
	var t sealedDNSToken
	if err := json.Unmarshal(b, &t); err != nil {
		return "", err
	}
	tok, err := unsealToken(t.Provider, t.Blob)
	if err != nil {
		return "", fmt.Errorf("unseal the token of DNS provider %q (%s): %w", name, t.Provider, err)
	}
	return tok, nil
}

func dnsTokenRm(s routeStore, name string) error {
	if s.name() == "cluster" {
		return withState(func(st *ClusterState) error { delete(st.Secrets, dnsSecretPrefix+name); return nil })
	}
	if err := os.Remove(dnsTokenFile(name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ---- configuration edits (shared by the CLI and the API) ----

// bumpDNS marks the gateway's names as changed so the sync loop reconciles soon. It only moves when
// a provider is configured, so hosts without one never see a changed file.
func bumpDNS(d *gatewayData) {
	if len(d.DNSCloud.Providers) > 0 {
		d.DNSCloud.Epoch++
	}
}

func (c DNSCloud) provider(name string) *DNSProviderConf {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

func cleanDNSZones(zones []string) ([]string, error) {
	var out []string
	for _, z := range zones {
		z = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
		if z == "" {
			continue
		}
		if !hostRe.MatchString(z) {
			return nil, fmt.Errorf("invalid zone %q", z)
		}
		if !slices.Contains(out, z) {
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out, nil
}

// dnsProviderAdd checks the token against the provider (it must see at least one managed zone),
// stores it (see the package comment) and records the provider. Calling it again for a name replaces the token.
func dnsProviderAdd(s routeStore, name, kind, token string, zones []string) (DNSProviderConf, []DNSZone, error) {
	if err := validName(name); err != nil {
		return DNSProviderConf{}, nil, fmt.Errorf("provider name: %w", err)
	}
	if kind != dnsKindCloudflare {
		return DNSProviderConf{}, nil, fmt.Errorf("unknown DNS provider kind %q (supported: %s)", kind, dnsKindCloudflare)
	}
	zones, err := cleanDNSZones(zones)
	if err != nil {
		return DNSProviderConf{}, nil, err
	}
	conf := DNSProviderConf{Name: name, Kind: kind, Zones: zones}
	p, err := dnsProviderFactory(conf, token)
	if err != nil {
		return conf, nil, err
	}
	all, err := p.Zones()
	if err != nil {
		return conf, nil, fmt.Errorf("the token was refused: %w", err)
	}
	managed := managedZones(conf, all)
	if len(managed) == 0 {
		if len(zones) > 0 {
			return conf, nil, fmt.Errorf("the token sees none of the zones %s", strings.Join(zones, ", "))
		}
		return conf, nil, errors.New("the token sees no zones (it needs Zone › DNS › Edit and Zone › Zone › Read on the zones to manage)")
	}
	if err := dnsTokenPut(s, name, token); err != nil {
		return conf, nil, err
	}
	err = s.update(func(d *gatewayData) error {
		if cur := d.DNSCloud.provider(name); cur != nil {
			*cur = conf
		} else {
			d.DNSCloud.Providers = append(d.DNSCloud.Providers, conf)
		}
		d.DNSCloud.Epoch++
		return nil
	})
	return conf, managed, err
}

func dnsProviderRm(s routeStore, name string) error {
	err := s.update(func(d *gatewayData) error {
		if d.DNSCloud.provider(name) == nil {
			return fmt.Errorf("no DNS provider %q", name)
		}
		for _, r := range d.DNSCloud.Records {
			if r.Provider == name {
				return fmt.Errorf("record %s %s is pinned to provider %s: remove it first (ziroctl dns cloud rm)", r.Name, r.Type, name)
			}
		}
		kept := d.DNSCloud.Providers[:0]
		for _, p := range d.DNSCloud.Providers {
			if p.Name != name {
				kept = append(kept, p)
			}
		}
		d.DNSCloud.Providers = kept
		return nil
	})
	if err != nil {
		return err
	}
	return dnsTokenRm(s, name)
}

// normDNSName lower-cases a record name and drops a trailing dot.
func normDNSName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// normDNSContent makes provider and desired content comparable.
func normDNSContent(typ, c string) string {
	c = strings.TrimSpace(c)
	switch typ {
	case "CNAME":
		return normDNSName(c)
	case "A", "AAAA":
		if a, err := netip.ParseAddr(c); err == nil {
			return a.String()
		}
	}
	return c
}

// validDNSCloudRecord checks an explicit record's shape (the names are public DNS names).
func validDNSCloudRecord(r *DNSCloudRecord) error {
	r.Name, r.Type = normDNSName(r.Name), strings.ToUpper(strings.TrimSpace(r.Type))
	r.Provider = strings.TrimSpace(r.Provider)
	if !validDomain(strings.TrimPrefix(r.Name, "*.")) || len(r.Name) > 253 {
		return fmt.Errorf("invalid record name %q", r.Name)
	}
	if r.TTL < 0 || r.TTL > 86400 || (r.TTL > 1 && r.TTL < 60) {
		return fmt.Errorf("ttl must be 0 (default), 1 (automatic) or 60-86400")
	}
	// The same checks as the built-in DNS records, so one validation rules both.
	if _, _, err := parseRecord(DNSRecord{Name: r.Name, Type: r.Type, Value: r.Content}); err != nil {
		return err
	}
	if r.Proxied && r.Type == "TXT" {
		return errors.New("a TXT record cannot be proxied")
	}
	r.Content = normDNSContent(r.Type, r.Content)
	return nil
}

func dnsRecordAdd(s routeStore, r DNSCloudRecord) error {
	if err := validDNSCloudRecord(&r); err != nil {
		return err
	}
	return s.update(func(d *gatewayData) error {
		if r.Provider != "" && d.DNSCloud.provider(r.Provider) == nil {
			return fmt.Errorf("no DNS provider %q (ziroctl dns provider ls)", r.Provider)
		}
		if len(d.DNSCloud.Providers) == 0 {
			return errors.New("no DNS provider yet: ziroctl dns provider add cloudflare --token-file …")
		}
		if len(d.DNSCloud.Records) >= maxDNSRecords {
			return fmt.Errorf("at most %d explicit records", maxDNSRecords)
		}
		for _, x := range d.DNSCloud.Records {
			if x.Name == r.Name && x.Type == r.Type && x.Content == r.Content && x.Provider == r.Provider {
				return fmt.Errorf("%s %s %s is already managed", r.Name, r.Type, r.Content)
			}
		}
		d.DNSCloud.Records = append(d.DNSCloud.Records, r)
		d.DNSCloud.Epoch++
		return nil
	})
}

// dnsRecordRm removes the explicit records of that name (and type, when given); the sync then
// deletes them at the provider.
func dnsRecordRm(s routeStore, name, typ string) (int, error) {
	name, typ = normDNSName(name), strings.ToUpper(strings.TrimSpace(typ))
	n := 0
	err := s.update(func(d *gatewayData) error {
		kept := d.DNSCloud.Records[:0]
		for _, r := range d.DNSCloud.Records {
			if r.Name == name && (typ == "" || r.Type == typ) {
				n++
				continue
			}
			kept = append(kept, r)
		}
		if n == 0 {
			return fmt.Errorf("no explicit record %s", name)
		}
		d.DNSCloud.Records = kept
		d.DNSCloud.Epoch++
		return nil
	})
	return n, err
}

// dnsAddressesSet replaces the published addresses (none: back to the gateway nodes' own).
func dnsAddressesSet(s routeStore, addrs []string) error {
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil {
			return fmt.Errorf("invalid address %q", a)
		}
		if !slices.Contains(out, ip.String()) {
			out = append(out, ip.String())
		}
	}
	return s.update(func(d *gatewayData) error {
		d.DNSCloud.Addresses = out
		bumpDNS(d)
		return nil
	})
}

// ---- desired state ----

// desiredRec is a record the gateway (or the operator) wants at a provider.
type desiredRec struct {
	Provider string // "": the first provider that hosts the zone
	Name     string
	Type     string
	Content  string
	TTL      int
	Proxied  bool
}

// coveredByDomain: host is one label under the base domain, which the wildcard record answers.
func coveredByDomain(host, domain string) bool {
	if domain == "" {
		return false
	}
	label, ok := strings.CutSuffix(host, "."+domain)
	return ok && label != "" && !strings.Contains(label, ".") && label != "*"
}

// dnsDesired derives the records from the gateway data: a wildcard for the base domain, a record
// for each route host the wildcard does not cover, and the explicit records. Names that no public
// CA or resolver knows (.local, .internal, ...) stay with the built-in DNS. Problems that don't stop
// the rest are returned as warnings.
func dnsDesired(s routeStore, d *gatewayData) (recs []desiredRec, warns []string) {
	addrs := slices.Clone(d.DNSCloud.Addresses)
	if len(addrs) == 0 {
		addrs = gatewayAddrs(s)
	}
	var ips []netip.Addr
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			warns = append(warns, fmt.Sprintf("gateway address %q is not an IP: skipped", a))
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			warns = append(warns, fmt.Sprintf("publishing %s, a private address: only clients on that network can reach the gateway (set a public one: ziroctl dns cloud addresses)", ip))
		}
		ips = append(ips, ip)
	}
	seen := map[string]bool{}
	add := func(r desiredRec) {
		r.Name, r.Type = normDNSName(r.Name), strings.ToUpper(r.Type)
		if r.TTL == 0 {
			r.TTL = dnsDefaultTTL
		}
		k := fmt.Sprintf("%s|%s|%s|%s", r.Provider, r.Name, r.Type, r.Content)
		if !seen[k] {
			seen[k] = true
			recs = append(recs, r)
		}
	}
	addAddrs := func(name string) {
		for _, ip := range ips {
			typ := "A"
			if ip.Is6() && !ip.Is4In6() {
				typ = "AAAA"
			}
			add(desiredRec{Name: name, Type: typ, Content: ip.Unmap().String()})
		}
	}

	domain := d.Domain.Name
	if domain != "" && !schema.PrivateDomain(domain) {
		addAddrs(wildcardName(domain))
	}
	for _, r := range d.Routes {
		r.Normalize()
		if r.Kind == "tcp" {
			continue
		}
		for _, h := range r.Hosts {
			h = normDNSName(h)
			if h == "" || schema.PrivateDomain(strings.TrimPrefix(h, "*.")) || coveredByDomain(h, domain) {
				continue
			}
			addAddrs(h)
		}
	}
	if len(ips) == 0 && (domain != "" || len(d.Routes) > 0) {
		warns = append(warns, "no gateway address yet (ziroctl gateway node enable <node>, or ziroctl dns cloud addresses): no records for the gateway's names")
	}
	for _, r := range d.DNSCloud.Records {
		add(desiredRec{Provider: r.Provider, Name: r.Name, Type: r.Type, Content: normDNSContent(r.Type, r.Content), TTL: r.TTL, Proxied: r.Proxied})
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		return a.Name+"|"+a.Type+"|"+a.Content < b.Name+"|"+b.Type+"|"+b.Content
	})
	return recs, warns
}

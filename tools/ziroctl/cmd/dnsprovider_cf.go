package cmd

import "strings"

// cfDNSProvider is the Cloudflare DNSProvider, on the hardened cfClient (bearer token, TLS-verified
// HTTPS only, redirects refused) with retries for 429 and 5xx answers.
type cfDNSProvider struct{ c *cfClient }

// cfRetries is how many times a throttled or failing call is retried (about a minute in all).
const cfRetries = 5

func newCFDNSProvider(token string) *cfDNSProvider {
	return &cfDNSProvider{c: &cfClient{token: token, retries: cfRetries}}
}

func (p *cfDNSProvider) Zones() ([]DNSZone, error) {
	zs, err := p.c.zones()
	if err != nil {
		return nil, err
	}
	out := make([]DNSZone, 0, len(zs))
	for _, z := range zs {
		out = append(out, DNSZone{ID: z.ID, Name: strings.ToLower(z.Name)})
	}
	return out, nil
}

func (p *cfDNSProvider) List(zoneID string) ([]DNSRec, error) {
	rs, err := p.c.listDNS(zoneID)
	if err != nil {
		return nil, err
	}
	out := make([]DNSRec, 0, len(rs))
	for _, r := range rs {
		switch r.Type {
		case "A", "AAAA", "CNAME", "TXT": // the types the sync manages; the rest is never listed
		default:
			continue
		}
		content := r.Content
		if r.Type == "TXT" { // Cloudflare returns TXT content quoted
			content = strings.TrimSuffix(strings.TrimPrefix(content, `"`), `"`)
		}
		out = append(out, DNSRec{ID: r.ID, Name: normDNSName(r.Name), Type: r.Type, Content: content,
			TTL: r.TTL, Proxied: r.Proxied, Comment: r.Comment})
	}
	return out, nil
}

func (p *cfDNSProvider) Upsert(zoneID string, r DNSRec) error {
	rec := cfDNSRecord{ID: r.ID, Type: r.Type, Name: r.Name, Content: r.Content, TTL: r.TTL, Proxied: r.Proxied, Comment: r.Comment}
	if r.ID == "" {
		return p.c.createDNS(zoneID, rec)
	}
	return p.c.updateDNS(zoneID, rec)
}

func (p *cfDNSProvider) Delete(zoneID, id string) error { return p.c.deleteDNS(zoneID, id) }

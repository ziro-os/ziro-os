package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The few Cloudflare API calls `ziroctl cf` makes: accounts, tunnels and their ingress, DNS
// records and Access apps. Every response is Cloudflare's {success, errors, result} envelope.

var (
	cfAPIBase = "https://api.cloudflare.com/client/v4"
	cfHTTP    = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("refusing redirect") // the bearer token must never follow one
	}}
)

type cfClient struct {
	token, account string
	// retries > 0 retries 429 and 5xx answers (and transport errors, for idempotent requests) with
	// jittered exponential backoff; the `cf` commands leave it 0.
	retries int
	sleep   func(time.Duration) // test seam; nil: time.Sleep
}

type cfAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfTunnel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfIngress struct {
	Hostname      string         `json:"hostname,omitempty"`
	Service       string         `json:"service"`
	OriginRequest map[string]any `json:"originRequest,omitempty"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`     // 1 = automatic
	Proxied bool   `json:"proxied,omitempty"` // A/AAAA/CNAME only
	Comment string `json:"comment,omitempty"`
}

type cfAccessApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// retryWait is how long to wait before attempt+1: Retry-After when Cloudflare sent one (capped),
// else 1s doubling to 30s, plus up to 50% jitter.
func retryWait(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			return min(time.Duration(s)*time.Second, time.Minute)
		}
	}
	d := min(time.Second<<attempt, 30*time.Second)
	return d + rand.N(d/2+1)
}

func (c *cfClient) do(method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(method, cfAPIBase+path, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err = cfHTTP.Do(req)
		// A POST is retried only when Cloudflare says it did not process it (429); anything else could
		// have been applied.
		again := attempt < c.retries
		switch {
		case err != nil && again && method != http.MethodPost:
			c.wait(retryWait(nil, attempt))
			continue
		case err != nil:
			return fmt.Errorf("cloudflare: %w", err)
		case again && (resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && method != http.MethodPost)):
			w := retryWait(resp, attempt)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			c.wait(w)
			continue
		}
		break
	}
	defer resp.Body.Close()
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare %s %s: HTTP %d", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%s (%d)", e.Message, e.Code))
		}
		if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (c *cfClient) wait(d time.Duration) {
	if c.sleep != nil {
		c.sleep(d)
		return
	}
	time.Sleep(d)
}

func (c *cfClient) acct(p string) string { return "/accounts/" + url.PathEscape(c.account) + p }

func (c *cfClient) accounts() ([]cfAccount, error) {
	var a []cfAccount
	return a, c.do("GET", "/accounts?per_page=50", nil, &a)
}

// findTunnel returns the live tunnel called name (nil if there is none).
func (c *cfClient) findTunnel(name string) (*cfTunnel, error) {
	var ts []cfTunnel
	if err := c.do("GET", c.acct("/cfd_tunnel?is_deleted=false&name="+url.QueryEscape(name)), nil, &ts); err != nil {
		return nil, err
	}
	for _, t := range ts {
		if t.Name == name {
			return &t, nil
		}
	}
	return nil, nil
}

// createTunnel creates a remotely managed tunnel: its ingress lives at Cloudflare, so no config
// file on the host can drift from it.
func (c *cfClient) createTunnel(name string) (*cfTunnel, error) {
	var t cfTunnel
	return &t, c.do("POST", c.acct("/cfd_tunnel"), map[string]string{"name": name, "config_src": "cloudflare"}, &t)
}

func (c *cfClient) tunnelToken(id string) (string, error) {
	var tok string
	return tok, c.do("GET", c.acct("/cfd_tunnel/"+url.PathEscape(id)+"/token"), nil, &tok)
}

func (c *cfClient) deleteTunnel(id string) error {
	_ = c.do("DELETE", c.acct("/cfd_tunnel/"+url.PathEscape(id)+"/connections"), nil, nil) // stale connections block the delete
	return c.do("DELETE", c.acct("/cfd_tunnel/"+url.PathEscape(id)), nil, nil)
}

func (c *cfClient) ingress(id string) ([]cfIngress, error) {
	var r struct {
		Config struct {
			Ingress []cfIngress `json:"ingress"`
		} `json:"config"`
	}
	return r.Config.Ingress, c.do("GET", c.acct("/cfd_tunnel/"+url.PathEscape(id)+"/configurations"), nil, &r)
}

func (c *cfClient) putIngress(id string, rules []cfIngress) error {
	body := map[string]any{"config": map[string]any{"ingress": rules}}
	return c.do("PUT", c.acct("/cfd_tunnel/"+url.PathEscape(id)+"/configurations"), body, nil)
}

// zoneFor finds the zone that holds host: the longest of its suffixes that is a zone here.
func (c *cfClient) zoneFor(host string) (*cfZone, error) {
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		var zs []cfZone
		name := strings.Join(labels[i:], ".")
		if err := c.do("GET", "/zones?name="+url.QueryEscape(name), nil, &zs); err != nil {
			return nil, err
		}
		for _, z := range zs {
			if z.Name == name {
				return &z, nil
			}
		}
	}
	return nil, fmt.Errorf("no zone for %s in this Cloudflare account (or the token lacks Zone › DNS)", host)
}

func (c *cfClient) dnsRecord(zone, host string) (*cfDNSRecord, error) {
	var rs []cfDNSRecord
	if err := c.do("GET", "/zones/"+url.PathEscape(zone)+"/dns_records?name="+url.QueryEscape(host), nil, &rs); err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, nil
	}
	return &rs[0], nil
}

func (c *cfClient) createCNAME(zone, host, target string) error {
	rec := map[string]any{"type": "CNAME", "name": host, "content": target, "proxied": true, "comment": "ziroctl cf"}
	return c.do("POST", "/zones/"+url.PathEscape(zone)+"/dns_records", rec, nil)
}

// cfMaxPages bounds every paginated listing (100 per page).
const cfMaxPages = 100

// zones lists every zone the token can see.
func (c *cfClient) zones() ([]cfZone, error) {
	var all []cfZone
	for page := 1; page <= cfMaxPages; page++ {
		var zs []cfZone
		if err := c.do("GET", fmt.Sprintf("/zones?per_page=50&page=%d", page), nil, &zs); err != nil {
			return nil, err
		}
		all = append(all, zs...)
		if len(zs) < 50 {
			return all, nil
		}
	}
	return nil, fmt.Errorf("cloudflare: more than %d zones", 50*cfMaxPages)
}

// listDNS lists every record of a zone.
func (c *cfClient) listDNS(zone string) ([]cfDNSRecord, error) {
	var all []cfDNSRecord
	for page := 1; page <= cfMaxPages; page++ {
		var rs []cfDNSRecord
		if err := c.do("GET", fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", url.PathEscape(zone), page), nil, &rs); err != nil {
			return nil, err
		}
		all = append(all, rs...)
		if len(rs) < 100 {
			return all, nil
		}
	}
	return nil, fmt.Errorf("cloudflare: more than %d records in one zone", 100*cfMaxPages)
}

// dnsBody is a record as Cloudflare takes it on create and replace. The proxied flag is always
// sent: omitting it on a replace would silently turn proxying off.
func dnsBody(r cfDNSRecord) map[string]any {
	ttl := r.TTL
	if ttl <= 0 || r.Proxied {
		ttl = 1 // automatic; a proxied record can have no other
	}
	return map[string]any{"type": r.Type, "name": r.Name, "content": r.Content, "ttl": ttl, "proxied": r.Proxied, "comment": r.Comment}
}

func (c *cfClient) createDNS(zone string, r cfDNSRecord) error {
	return c.do("POST", "/zones/"+url.PathEscape(zone)+"/dns_records", dnsBody(r), nil)
}

func (c *cfClient) updateDNS(zone string, r cfDNSRecord) error {
	return c.do("PUT", "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(r.ID), dnsBody(r), nil)
}

func (c *cfClient) deleteDNS(zone, id string) error {
	return c.do("DELETE", "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(id), nil, nil)
}

// accessApp returns the Access app ziroctl made for host (nil if none).
func (c *cfClient) accessApp(host string) (*cfAccessApp, error) {
	var as []cfAccessApp
	if err := c.do("GET", c.acct("/access/apps?domain="+url.QueryEscape(host)), nil, &as); err != nil {
		return nil, err
	}
	for _, a := range as {
		if a.Domain == host && a.Name == cfAccessName(host) {
			return &a, nil
		}
	}
	return nil, nil
}

func cfAccessName(host string) string { return "ziro: " + host }

// createAccessApp puts host behind Cloudflare Access: only the given emails and @domains get in.
func (c *cfClient) createAccessApp(host string, allow []string) error {
	var include []map[string]any
	for _, a := range allow {
		if d, ok := strings.CutPrefix(a, "@"); ok {
			include = append(include, map[string]any{"email_domain": map[string]string{"domain": d}})
		} else {
			include = append(include, map[string]any{"email": map[string]string{"email": a}})
		}
	}
	app := map[string]any{
		"name": cfAccessName(host), "domain": host, "type": "self_hosted", "session_duration": "24h",
		"policies": []map[string]any{{"name": "ziro allow", "decision": "allow", "include": include}},
	}
	return c.do("POST", c.acct("/access/apps"), app, nil)
}

func (c *cfClient) deleteAccessApp(id string) error {
	return c.do("DELETE", c.acct("/access/apps/"+url.PathEscape(id)), nil, nil)
}

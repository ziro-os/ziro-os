package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
}

type cfAccessApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func (c *cfClient) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPIBase+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cfHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
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

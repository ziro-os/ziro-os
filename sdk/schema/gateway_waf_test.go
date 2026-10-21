package schema

import (
	"strings"
	"testing"
	"time"
)

func TestGatewayWAFValidate(t *testing.T) {
	good := GatewayWAF{Mode: WAFBlock, Level: 2, Threshold: 8, InspectBodyKB: 64, Exclude: []string{"ZW-942100", "xss"},
		Rules: []GatewayWAFRule{
			{ID: "office", Target: "ip", Op: "cidr", Value: "203.0.113.0/24", Action: "allow"},
			{ID: "scrapers", Target: "user_agent", Op: "regex", Value: "bot|crawler", Action: "score", Score: 3},
			{ID: "token", Target: "header:X-Token", Op: "eq", Value: "x", Not: true, Action: "deny"},
			{ID: "arg", Target: "arg:id", Op: "prefix", Value: "../", Action: "log"},
		}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(w *GatewayWAF){
		"mode":            func(w *GatewayWAF) { w.Mode = "paranoid" },
		"level":           func(w *GatewayWAF) { w.Level = 4 },
		"threshold":       func(w *GatewayWAF) { w.Threshold = 101 },
		"body size":       func(w *GatewayWAF) { w.InspectBodyKB = WAFMaxBodyKB + 1 },
		"exclusion":       func(w *GatewayWAF) { w.Exclude = []string{"all"} },
		"duplicate rule":  func(w *GatewayWAF) { w.Rules = append(w.Rules, w.Rules[0]) },
		"too many rules":  func(w *GatewayWAF) { w.Rules = make([]GatewayWAFRule, WAFMaxRules+1) },
		"bad target":      func(w *GatewayWAF) { w.Rules[1].Target = "response" },
		"bad op":          func(w *GatewayWAF) { w.Rules[1].Op = "like" },
		"empty value":     func(w *GatewayWAF) { w.Rules[1].Value = "" },
		"bad regex":       func(w *GatewayWAF) { w.Rules[1].Value = "(" },
		"cidr on a path":  func(w *GatewayWAF) { w.Rules[0].Target = "path" },
		"ip with prefix":  func(w *GatewayWAF) { w.Rules[0].Op = "prefix" },
		"bad action":      func(w *GatewayWAF) { w.Rules[0].Action = "drop" },
		"score on deny":   func(w *GatewayWAF) { w.Rules[2].Score = 5 },
		"score too large": func(w *GatewayWAF) { w.Rules[1].Score = 21 },
		"bad cidr":        func(w *GatewayWAF) { w.Rules[0].Value = "300.0.0.0/8" },
	}
	for name, mut := range bad {
		w := good
		w.Rules = append([]GatewayWAFRule(nil), good.Rules...)
		mut(&w)
		if err := w.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGatewaySettingsFirewall(t *testing.T) {
	ok := GatewaySettings{WAF: &GatewayWAF{Mode: WAFDetect}, DenyCIDRs: []string{"192.0.2.0/24", "2001:db8::/32", "198.51.100.1"},
		Bans:    []GatewayBan{{Addr: "203.0.113.5"}, {Addr: "203.0.113.0/24", Until: "2030-01-01T00:00:00Z", Reason: "scraper"}},
		AutoBan: &GatewayAutoBan{Strikes: 5, Window: "1m", Duration: "10m", Max: "24h", Kernel: true}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]GatewaySettings{
		"deny cidr":     {DenyCIDRs: []string{"x"}},
		"too many deny": {DenyCIDRs: make([]string, MaxGlobalDenyCIDRs+1)},
		"ban addr":      {Bans: []GatewayBan{{Addr: "x"}}},
		"ban until":     {Bans: []GatewayBan{{Addr: "10.0.0.1", Until: "tomorrow"}}},
		"ban reason":    {Bans: []GatewayBan{{Addr: "10.0.0.1", Reason: "a\nb"}}},
		"too many bans": {Bans: make([]GatewayBan, MaxManualBans+1)},
		"auto strikes":  {AutoBan: &GatewayAutoBan{Strikes: -1}},
		"auto duration": {AutoBan: &GatewayAutoBan{Duration: "0s"}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	past := GatewayBan{Addr: "10.0.0.1", Until: "2001-01-01T00:00:00Z"}
	if !past.Expired(time.Now()) || (GatewayBan{Addr: "10.0.0.1"}).Expired(time.Now()) {
		t.Error("Expired")
	}
	if (GatewayBan{Until: "garbage"}).Expired(time.Now()) != true {
		t.Error("a ban with an unreadable end date must not last forever")
	}
}

func TestGatewayRouteFirewallFields(t *testing.T) {
	r := GatewayRoute{Name: "r", Hosts: []string{"a.test"}, To: []GatewayUpstream{{Address: "10.0.0.1:80"}},
		WAF: &GatewayWAF{Mode: WAFBlock}, DenyCIDRs: []string{"192.0.2.0/24"}}
	r.Normalize()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.DenyCIDRs = make([]string, MaxRouteDenyCIDRs+1)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "deny_cidrs") {
		t.Errorf("too many deny entries: %v", err)
	}
	tcp := GatewayRoute{Name: "t", Kind: "tcp", Listen: 5432, To: []GatewayUpstream{{Address: "10.0.0.1:5432"}}, WAF: &GatewayWAF{Mode: WAFBlock}}
	tcp.Normalize()
	if err := tcp.Validate(); err == nil {
		t.Error("a WAF on a tcp route accepted")
	}
	tcp.WAF, tcp.DenyCIDRs = nil, []string{"192.0.2.0/24"}
	if err := tcp.Validate(); err != nil {
		t.Errorf("deny lists work on tcp routes: %v", err)
	}
}

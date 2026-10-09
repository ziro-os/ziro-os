package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNftRulesBoundToAnInterface(t *testing.T) {
	script, err := buildNftScript(FirewallConfig{DefaultInput: "DROP", AllowedPorts: []FirewallRule{
		{Port: 22, Protocol: "tcp"},
		{Port: 22, Protocol: "tcp", Iface: "tailscale0"},
		{Port: 53, Protocol: "udp", Iface: "tailscale0", Source: "100.64.0.0/10"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    tcp dport 22 accept\n",
		`    iifname "tailscale0" tcp dport 22 accept` + "\n",
		`    iifname "tailscale0" ip saddr 100.64.0.0/10 udp dport 53 accept` + "\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	// the interface rule is not a trusted-interface accept: nothing but the listed port matches
	if strings.Contains(script, `iifname "tailscale0" accept`) {
		t.Errorf("the interface was trusted wholesale:\n%s", script)
	}
	for _, bad := range []string{"lo", "eth0; drop", "a b", strings.Repeat("x", 16), "ts0\n"} {
		if _, err := buildNftScript(FirewallConfig{AllowedPorts: []FirewallRule{{Port: 22, Protocol: "tcp", Iface: bad}}}); err == nil {
			t.Errorf("interface %q accepted", bad)
		}
	}
}

func TestFirewallAllowOnInterface(t *testing.T) {
	old := firewallConfigFile
	firewallConfigFile = filepath.Join(t.TempDir(), "firewall.json")
	defer func() { firewallConfigFile = old }()
	if err := saveFirewallConfig(FirewallConfig{DefaultInput: "DROP"}); err != nil { // disabled: nothing is applied
		t.Fatal(err)
	}
	if added, err := firewallAllowOn("22", "tailnet ssh", "tailscale0"); !added || err != nil {
		t.Fatalf("first allow: %v %v", added, err)
	}
	if added, _ := firewallAllowOn("22/tcp", "again", "tailscale0"); added {
		t.Error("the same interface rule was added twice")
	}
	// a rule for any interface is a different rule
	if added, _ := firewallAllow("22", "ssh"); !added {
		t.Error("an any-interface rule was treated as the interface rule")
	}
	cfg := loadFirewallConfig()
	if len(cfg.AllowedPorts) != 2 || cfg.AllowedPorts[0].Iface != "tailscale0" || cfg.AllowedPorts[1].Iface != "" {
		t.Fatalf("rules: %+v", cfg.AllowedPorts)
	}
	if _, err := firewallAllowOn("22", "", "bad name"); err == nil {
		t.Error("a bad interface name was accepted")
	}
	// deny removes only the rule on that interface
	if err := firewallDenyOn("22", "tailscale0"); err != nil {
		t.Fatal(err)
	}
	cfg = loadFirewallConfig()
	if len(cfg.AllowedPorts) != 1 || cfg.AllowedPorts[0].Iface != "" {
		t.Fatalf("deny removed the wrong rule: %+v", cfg.AllowedPorts)
	}
	if err := firewallDenyOn("22", "tailscale0"); err == nil {
		t.Error("denying a rule that is not there succeeded")
	}
}

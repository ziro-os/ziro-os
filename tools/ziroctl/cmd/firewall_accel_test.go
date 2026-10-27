package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guardScript(t *testing.T, mut func(*FirewallConfig)) string {
	t.Helper()
	cfg := FirewallConfig{Enabled: true, DefaultInput: "DROP", AllowedPorts: []FirewallRule{{Port: 80, Protocol: "tcp"}}}
	mut(&cfg)
	s, err := buildGuardScript(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Without ports the guard is what it was: no raw chain rules, no synproxy.
func TestGuardWithoutSynProxyIsUnchanged(t *testing.T) {
	s := guardScript(t, func(*FirewallConfig) {})
	for _, no := range []string{"synproxy mss", "notrack", "add rule inet ziro_guard raw", "add element inet ziro_guard synproxy_ports"} {
		if strings.Contains(s, no) {
			t.Errorf("a guard without SYN proxy ports contains %q", no)
		}
	}
}

func TestGuardSynProxyRules(t *testing.T) {
	s := guardScript(t, func(c *FirewallConfig) {
		c.TrustedInterfaces = []string{"wg0"}
		c.Guard.SynProxy = []int{80, 443}
		c.Guard.Allow = []string{"198.51.100.0/24"}
	})
	for _, want := range []string{
		"add element inet ziro_guard synproxy_ports { 80, 443 }",
		"add rule inet ziro_guard raw tcp dport @synproxy_ports tcp flags & (fin|syn|rst|ack) == syn notrack",
		"add rule inet ziro_guard input tcp dport @synproxy_ports ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm",
		"add rule inet ziro_guard input tcp dport @synproxy_ports ct state invalid drop",
		"chain raw { type filter hook prerouting priority raw; policy accept; }",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// A SYN left untracked but accepted by an exemption would never be tracked: every input exemption
	// that precedes the limits must be repeated, in the same order, before the notrack rule.
	var inEx, rawEx []string
	for _, l := range strings.Split(s, "\n") {
		if r, ok := strings.CutPrefix(l, "add rule inet ziro_guard input "); ok && strings.HasSuffix(r, " accept") && !strings.HasPrefix(r, "ct state") {
			inEx = append(inEx, r)
		}
		if r, ok := strings.CutPrefix(l, "add rule inet ziro_guard raw "); ok && strings.HasSuffix(r, " accept") {
			rawEx = append(rawEx, r)
		}
	}
	if len(rawEx) == 0 || strings.Join(inEx, "\n") != strings.Join(rawEx, "\n") {
		t.Fatalf("raw exemptions differ from the input exemptions:\ninput:\n%s\nraw:\n%s", strings.Join(inEx, "\n"), strings.Join(rawEx, "\n"))
	}
	for _, must := range []string{`iifname "wg0" accept`, "ip saddr @allow4 accept", `iif "lo" accept`} {
		if !accelListHas(rawEx, must) {
			t.Errorf("the raw chain does not exempt %q", must)
		}
	}
	// notrack comes after the exemptions, the proxy after the per-source limits
	if strings.Index(s, "raw tcp dport") < strings.LastIndex(s, "raw ip6 saddr @allow6 accept") {
		t.Error("notrack precedes an exemption")
	}
	if strings.Index(s, "synproxy mss") < strings.Index(s, "update @syn4") || strings.Index(s, "synproxy mss") < strings.Index(s, "ct count over") {
		t.Error("the SYN proxy precedes the per-source limits")
	}
}

func accelListHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestSynProxyPortsAreValidated(t *testing.T) {
	for _, bad := range [][]int{{0}, {70000}, {80, 80}, {-1}, make([]int, maxSynProxyPorts+1)} {
		g := GuardConfig{SynProxy: bad}
		if err := g.withDefaults().validate(); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := (GuardConfig{SynProxy: []int{80, 443, 8443}}).withDefaults().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSynProxySysctls(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"net/netfilter", "net/ipv4"} {
		os.MkdirAll(filepath.Join(dir, p), 0o755)
	}
	if err := tuneSynProxy(dir); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"net/netfilter/nf_conntrack_tcp_loose": "0", "net/ipv4/tcp_syncookies": "1", "net/ipv4/tcp_timestamps": "1"} {
		if b, _ := os.ReadFile(filepath.Join(dir, p)); string(b) != want {
			t.Errorf("%s = %q, want %s", p, b, want)
		}
	}
	// a kernel without conntrack lacks one of the files: the others are still set and the error is reported
	os.Remove(filepath.Join(dir, "net/netfilter"))
	os.RemoveAll(filepath.Join(dir, "net/netfilter"))
	if err := tuneSynProxy(dir); err == nil {
		t.Fatal("a missing sysctl was not reported")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "net/ipv4/tcp_syncookies")); string(b) != "1" {
		t.Fatal("the other sysctls were skipped")
	}
}

func TestFlowScript(t *testing.T) {
	s, err := buildFlowScript([]string{"eth0", "nerdctl0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet ziro_flow\ndelete table inet ziro_flow", "flowtable ft { hook ingress priority 0; devices = { eth0, nerdctl0 }; }",
		"hook forward priority 0; policy accept;", "meta l4proto { tcp, udp } counter flow add @ft"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "ziro_guard") || strings.Contains(s, "inet ziro ") {
		t.Error("the flow table must not touch the firewall's own tables")
	}
	for _, bad := range [][]string{nil, {"eth0; flush ruleset"}, {"eth0", "eth0"}, {"a b"}, {"veth*"}, {"toolonginterfacename"}, {"a", "b", "c", "d", "e", "f", "g", "h", "i"}} {
		if _, err := buildFlowScript(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFlowtableIsOnlyOfferedForConfiguredInterfaces(t *testing.T) {
	cfg := FirewallConfig{Enabled: true, Flowtable: []string{"nothere0"}}
	if err := validFlowDevices(cfg.Flowtable); err != nil {
		t.Fatal(err)
	}
	// the main firewall script knows nothing of the flow table: it cannot be broken by it
	s, err := buildNftScript(cfg)
	if err != nil || strings.Contains(s, "flow") {
		t.Fatalf("the firewall script mentions flow offload: %v\n%s", err, s)
	}
}

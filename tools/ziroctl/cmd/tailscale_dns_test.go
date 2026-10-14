package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dnsStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldCfg, oldPin := dnsConfigPath, resolvPinned
	dnsConfigPath, resolvPinned = filepath.Join(dir, "dns.json"), filepath.Join(dir, "resolv.conf")
	t.Cleanup(func() { dnsConfigPath, resolvPinned = oldCfg, oldPin })
	return dnsConfigPath
}

func forwardsOf(t *testing.T) map[string]string {
	t.Helper()
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range cfg.Forwards {
		var ups []string
		for _, u := range f.Upstreams {
			ups = append(ups, u.Addr)
		}
		out[f.Domain] = strings.Join(ups, ",")
	}
	return out
}

func TestTailscaleDNSDomain(t *testing.T) {
	for in, want := range map[string]string{
		"tailfc781.ts.net":   "tailfc781.ts.net",
		"TailFC781.ts.net.":  "tailfc781.ts.net",
		" mynet.example.com": "mynet.example.com",
		"":                   "",
	} {
		if got, err := tsDNSDomain(in); err != nil || got != want {
			t.Errorf("tsDNSDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A suffix the control server reports is not trusted to be broad: forwarding example.com or a TLD would
	// send the host's own names to the tailnet resolver.
	for _, bad := range []string{"com", "ts.net", "example.com", "co", "bad name.ts.net", "a..ts.net", "-x.ts.net"} {
		if got, err := tsDNSDomain(bad); err == nil {
			t.Errorf("tsDNSDomain(%q) = %q, want an error", bad, got)
		}
	}
}

func TestTailscaleDNSForwardIsOursAndNarrow(t *testing.T) {
	dnsStub(t)

	// joined: the tailnet suffix goes to MagicDNS, nothing else changes
	if err := tsSyncDNS("tailfc781.ts.net"); err != nil {
		t.Fatal(err)
	}
	if got := forwardsOf(t); len(got) != 1 || got["tailfc781.ts.net"] != "100.100.100.100" {
		t.Fatalf("forwards = %v", got)
	}
	// idempotent: the file is not rewritten
	before, _ := os.Stat(dnsConfigPath)
	os.Chtimes(dnsConfigPath, before.ModTime().Add(-3600e9), before.ModTime().Add(-3600e9))
	old, _ := os.Stat(dnsConfigPath)
	if err := tsSyncDNS("tailfc781.ts.net"); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.Stat(dnsConfigPath); !now.ModTime().Equal(old.ModTime()) {
		t.Error("an unchanged rule rewrote the config")
	}

	// the operator's own rules are never touched, also when they look similar
	if err := editDNSQuiet(func(c *DNSConfig) {
		c.Forwards = append(c.Forwards,
			DNSForward{Domain: "corp.example", Upstreams: []DNSUpstream{{Addr: "10.0.0.53"}}},
			DNSForward{Domain: "lab.example", Upstreams: []DNSUpstream{{Addr: "100.100.100.100"}, {Addr: "10.0.0.2"}}}, // two upstreams: theirs
		)
	}); err != nil {
		t.Fatal(err)
	}

	// another tailnet replaces ours, not theirs
	if err := tsSyncDNS("othernet.ts.net"); err != nil {
		t.Fatal(err)
	}
	got := forwardsOf(t)
	if _, still := got["tailfc781.ts.net"]; still || got["othernet.ts.net"] != "100.100.100.100" || got["corp.example"] != "10.0.0.53" || len(got) != 3 {
		t.Fatalf("after switching tailnet: %v", got)
	}

	// logged out / down / disabled: ours goes, theirs stays
	if err := tsSyncDNS(""); err != nil {
		t.Fatal(err)
	}
	got = forwardsOf(t)
	if len(got) != 2 || got["corp.example"] != "10.0.0.53" || got["lab.example"] != "100.100.100.100,10.0.0.2" {
		t.Fatalf("after leaving: %v", got)
	}
	// and again with nothing of ours left is a no-op, not an error
	if err := tsSyncDNS(""); err != nil {
		t.Fatal(err)
	}
}

func TestTailscaleDNSLeavesAnOperatorsRuleForTheSameDomain(t *testing.T) {
	dnsStub(t)
	if err := editDNSQuiet(func(c *DNSConfig) {
		c.Forwards = []DNSForward{{Domain: "tailfc781.ts.net", Upstreams: []DNSUpstream{{Addr: "10.0.0.53"}}}}
	}); err != nil {
		t.Fatal(err)
	}
	err := tsSyncDNS("tailfc781.ts.net")
	if err == nil || !strings.Contains(err.Error(), "left as it is") {
		t.Fatalf("want a clear conflict, got %v", err)
	}
	if got := forwardsOf(t); got["tailfc781.ts.net"] != "10.0.0.53" || len(got) != 1 {
		t.Errorf("the operator's rule was changed: %v", got)
	}
}

func TestTailscaleApplyDNS(t *testing.T) {
	dnsStub(t)
	running := TailscaleStatus{State: "Running", MagicDNS: "tailfc781.ts.net"}

	// not joined, or no MagicDNS: no rule, no noise
	for _, st := range []TailscaleStatus{{State: "NeedsLogin", MagicDNS: "tailfc781.ts.net"}, {State: "Running"}, {State: "Stopped"}} {
		if notes := tsApplyDNS(st); len(notes) != 0 || len(forwardsOf(t)) != 0 {
			t.Errorf("%+v: notes %v, forwards %v", st, notes, forwardsOf(t))
		}
	}

	// joined while smart DNS is off: the rule is saved and the operator is told how to make it count
	notes := tsApplyDNS(running)
	if len(notes) != 1 || !strings.Contains(notes[0], "ziroctl dns enable") || forwardsOf(t)["tailfc781.ts.net"] != "100.100.100.100" {
		t.Errorf("smart DNS off: notes %v, forwards %v", notes, forwardsOf(t))
	}
	if !tsDNSActive("tailfc781.ts.net") || tsDNSActive("other.ts.net") || tsDNSActive("") {
		t.Error("tsDNSActive")
	}

	// smart DNS on: nothing to add
	if err := os.WriteFile(resolvPinned, []byte(dnsPinMarker+"\nnameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if notes := tsApplyDNS(running); len(notes) != 0 {
		t.Errorf("smart DNS on: %v", notes)
	}

	// a suffix the guard refuses is reported, and nothing is forwarded for it
	if notes := tsApplyDNS(TailscaleStatus{State: "Running", MagicDNS: "com"}); len(notes) != 1 || !strings.Contains(notes[0], "too short") {
		t.Errorf("broad suffix: %v", notes)
	}
}

func TestParseTailscaleStatusMagicDNS(t *testing.T) {
	st, err := parseTSStatus([]byte(`{"BackendState":"Running","Self":{"DNSName":"ziro-m1.tailfc781.ts.net.","TailscaleIPs":["100.108.122.67"]},
		"CurrentTailnet":{"Name":"me@example.com","MagicDNSSuffix":"tailfc781.ts.net","MagicDNSEnabled":true}}`))
	if err != nil || st.MagicDNS != "tailfc781.ts.net" {
		t.Fatalf("%+v, %v", st, err)
	}
	// MagicDNS switched off for the tailnet: the suffix is reported by control but names do not exist
	st, _ = parseTSStatus([]byte(`{"BackendState":"Running","CurrentTailnet":{"MagicDNSSuffix":"tailfc781.ts.net","MagicDNSEnabled":false}}`))
	if st.MagicDNS != "" {
		t.Errorf("MagicDNS = %q with MagicDNS disabled", st.MagicDNS)
	}
}

// editDNSQuiet edits the DNS config without the CLI's messages (tests only).
func editDNSQuiet(edit func(*DNSConfig)) error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	edit(cfg)
	return saveDNSConfig(cfg)
}

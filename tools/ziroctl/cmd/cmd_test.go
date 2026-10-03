package cmd

import (
	"bytes"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ziroctl version") {
		t.Errorf("expected version output to contain 'ziroctl version', got: %s", out)
	}
}

func TestSystemInspect(t *testing.T) {
	st := inspectSystem()
	if st.OSName == "" {
		t.Errorf("expected non-empty OSName")
	}
	if st.KernelVersion == "" {
		t.Errorf("expected non-empty KernelVersion")
	}
}

func TestSecurityAuditCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"security", "audit"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("security audit command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Ziro-OS Security") {
		t.Errorf("expected output to contain 'Ziro-OS Security', got: %s", out)
	}
}

func TestSystemCommands(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"system", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("system help command failed: %v", err)
	}

	out := buf.String()
	for _, sub := range []string{"top", "df", "prune", "reboot", "poweroff"} {
		if !strings.Contains(out, sub) {
			t.Errorf("expected system help to list '%s', got: %s", sub, out)
		}
	}
}

func TestDecodeHexIPv4(t *testing.T) {
	ip := decodeHexIPv4("01011AAC")
	if ip != "172.26.1.1" {
		t.Errorf("expected 172.26.1.1, got: %s", ip)
	}
	ip2 := decodeHexIPv4("0101A8C0")
	if ip2 != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got: %s", ip2)
	}
}

func TestServiceList(t *testing.T) {
	services := listAllServices()
	if len(services) == 0 {
		t.Errorf("expected default services to be present")
	}
	foundContainerd := false
	for _, s := range services {
		if s.Name == "containerd" {
			foundContainerd = true
			break
		}
	}
	if !foundContainerd {
		t.Errorf("expected containerd in service list")
	}
}

func TestWireguardKeygen(t *testing.T) {
	priv, pub := generateWgKeypair()
	if len(priv) == 0 || len(pub) == 0 {
		t.Errorf("expected non-empty keypair")
	}
	if priv == pub {
		t.Errorf("expected private and public keys to differ")
	}
}

func TestFirewallParsing(t *testing.T) {
	port, proto := parsePortProto("8443/tcp")
	if port != 8443 || proto != "tcp" {
		t.Errorf("expected 8443/tcp, got %d/%s", port, proto)
	}

	port2, proto2 := parsePortProto("51820/udp")
	if port2 != 51820 || proto2 != "udp" {
		t.Errorf("expected 51820/udp, got %d/%s", port2, proto2)
	}
}

func TestSecurityScan(t *testing.T) {
	rep := runSecurityScan()
	if rep.Timestamp == "" {
		t.Errorf("expected non-empty timestamp")
	}
	if rep.HardeningScore < 0 || rep.HardeningScore > 100 {
		t.Errorf("invalid hardening score: %d", rep.HardeningScore)
	}
}

func TestAPIToken(t *testing.T) {
	tok := getOrCreateAPIToken()
	if len(tok) < 16 {
		t.Errorf("expected token of at least 16 chars, got: %s", tok)
	}
}

func TestMotdCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"motd"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("motd command failed: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"CPU", "Network", "Workload"} {
		if !strings.Contains(out, want) {
			t.Errorf("motd output lacks %q: %s", want, out)
		}
	}
}

func TestMOTDAddresses(t *testing.T) {
	sum := HostSummary{Version: "1.0", Hostname: "h", Mode: "installed", MemTotal: 4 << 30, MemUsed: 1 << 30,
		Addresses: []HostAddress{{"172.26.1.108", "eth0", "primary"}, {"10.200.0.1", "ziro0", "mesh"}, {"10.201.0.1", "ziro-dns0", "pods"}},
		Attention: []Attention{{"memory pressure 12%", "ziroctl system top"}, {"firewall disabled", "ziroctl firewall enable"}}}
	var buf bytes.Buffer
	renderMOTD(&buf, sum, termStyle{unicode: true})
	out := buf.String()
	if !strings.Contains(out, "172.26.1.108 eth0 · mesh 10.200.0.1 · pods 10.201.0.1") || strings.Count(out, "10.201.0.1") != 1 ||
		!strings.Contains(out, "! memory pressure 12%  ziroctl system top") || !strings.Contains(out, "! firewall disabled    ziroctl firewall enable") ||
		!strings.Contains(out, "████░░░░░░░░░░  1.0 GiB / 4.0 GiB     25%") || strings.Contains(out, "\033") || strings.Contains(out, "LIVE") {
		t.Errorf("motd:\n%s", out)
	}
	// Live media is called out; serial-style terminals get ASCII only.
	buf.Reset()
	sum.Mode = "live"
	renderMOTD(&buf, sum, termStyle{})
	out = buf.String()
	if !strings.Contains(out, "Ziro OS 1.0  LIVE") || !strings.Contains(out, "ziroctl install") || !strings.Contains(out, "####----------") {
		t.Errorf("live/ascii motd:\n%s", out)
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("ascii motd has %q:\n%s", r, out)
		}
	}
	for name, want := range map[string]string{"eth0": "primary", "ens3": "nic", "ziro0": "mesh", "ziro-dns0": "pods",
		"veth1a2b": "", "nerdctl0": "", "cni0": "", "docker0": "", "lo": ""} {
		if got := ifaceRole(name, "eth0"); got != want {
			t.Errorf("ifaceRole(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestReadRoutes(t *testing.T) {
	old := procRoot
	procRoot = t.TempDir()
	defer func() { procRoot = old }()
	os.MkdirAll(filepath.Join(procRoot, "net"), 0755)
	os.WriteFile(filepath.Join(procRoot, "net", "route"), []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eth0\t00000000\t01011AAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"+
		"eth0\t00011AAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"), 0644)
	r := readRoutes()
	if len(r) != 2 || r[0] != (RouteStatus{"0.0.0.0/0", "172.26.1.1", "eth0", 0}) || r[1] != (RouteStatus{"172.26.1.0/24", "", "eth0", 0}) {
		t.Errorf("routes = %+v", r)
	}
}

// TestHelpText keeps the help readable: every command has a short, plain description (a verb,
// no parenthetical asides, no trailing period) and every command an operator runs has an
// example.
func TestHelpText(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" || sub.Parent().Name() == "completion" {
				continue
			}
			path := sub.CommandPath()
			s := sub.Short
			switch {
			case s == "":
				t.Errorf("%s: no Short", path)
			case len(s) > 60:
				t.Errorf("%s: Short is %d chars (max 60): %q", path, len(s), s)
			case strings.ContainsAny(s, "()") || strings.HasSuffix(s, ".") || strings.Contains(s, "Ziro-OS"):
				t.Errorf("%s: Short has asides, a period or the old name: %q", path, s)
			}
			if sub.Example == "" {
				t.Errorf("%s: no Example", path)
			}
			walk(sub)
		}
	}
	walk(rootCmd)
}

func TestProcessAlive(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("needs /proc")
	}
	if !processAlive(os.Getpid()) || processAlive(1<<22) {
		t.Error("processAlive wrong for self or a missing PID")
	}
	if up := getPIDUptime(os.Getpid()); up == "unknown" || strings.HasPrefix(up, "-") {
		t.Errorf("uptime of self = %q", up)
	}
}

func TestDoctorFix(t *testing.T) {
	doctorSettle = 0
	ran := 0
	healthy := false
	checks := func() []doctorCheck {
		return []doctorCheck{
			{Name: "ok", Passed: true},
			{Name: "svc", Passed: healthy, fix: func() error { ran++; healthy = true; return nil }},
			{Name: "advice", Passed: false, Fix: "ziroctl firewall enable"},
		}
	}
	out := applyDoctorFixes(checks(), checks)
	if ran != 1 || !out[1].Passed || !out[1].Fixed || out[0].Fixed || out[2].Passed || out[2].Fixed {
		t.Fatalf("ran %d, checks %+v", ran, out)
	}
	// A fixed row that folds into a summary on the re-check is still reported.
	folded := applyDoctorFixes([]doctorCheck{{Name: "Service crond", fix: func() error { return nil }, Fix: "start crond"}},
		func() []doctorCheck { return []doctorCheck{{Name: "Services", Passed: true}} })
	if len(folded) != 2 || !folded[1].Fixed || folded[1].Name != "Service crond" {
		t.Errorf("folded fix not reported: %+v", folded)
	}
	if again := applyDoctorFixes(out, checks); len(again) != 3 || ran != 1 {
		t.Errorf("a passing check was fixed again (ran %d)", ran)
	}
}

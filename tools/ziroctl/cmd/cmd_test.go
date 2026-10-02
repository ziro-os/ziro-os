package cmd

import (
	"bytes"
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
	for _, sub := range []string{"status", "reboot", "poweroff"} {
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
	for _, want := range []string{"Ziro OS", "Resources", "Network", "Workloads"} {
		if !strings.Contains(out, want) {
			t.Errorf("motd output lacks %q: %s", want, out)
		}
	}
}

func TestMOTDAddresses(t *testing.T) {
	var buf bytes.Buffer
	renderMOTD(&buf, HostSummary{Version: "1.0", Hostname: "h", Mode: "installed", Addresses: []HostAddress{
		{"172.26.1.108", "eth0", "primary"}, {"10.200.0.1", "ziro0", "mesh"}, {"10.201.0.1", "ziro-dns0", "pods"}},
		Attention: []string{"memory pressure 12%"}}, false)
	out := buf.String()
	if !strings.Contains(out, "172.26.1.108 (eth0)  mesh 10.200.0.1  pods 10.201.0.1") || strings.Count(out, "10.201.0.1") != 1 ||
		!strings.Contains(out, "Attention  memory pressure 12%") || strings.Contains(out, "\033") {
		t.Errorf("motd:\n%s", out)
	}
	for name, want := range map[string]string{"eth0": "primary", "ens3": "nic", "ziro0": "mesh", "ziro-dns0": "pods",
		"veth1a2b": "", "nerdctl0": "", "cni0": "", "docker0": "", "lo": ""} {
		if got := ifaceRole(name, "eth0"); got != want {
			t.Errorf("ifaceRole(%s) = %q, want %q", name, got, want)
		}
	}
}

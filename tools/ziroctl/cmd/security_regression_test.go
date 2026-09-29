package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserDataTransport(t *testing.T) {
	for _, raw := range []string{"http://example.com/bootstrap", "http://169.254.169.254/latest/user-data", "ftp://169.254.169.254/x", "https://user:password@example.com/x", "https:/missing-host"} {
		u, err := url.Parse(raw)
		if err == nil && validateUserDataURL(u) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	var contacted atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted.Store(true); fmt.Fprint(w, "unsafe") }))
	defer plain.Close()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downgrade":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		case "/redirect":
			http.Redirect(w, r, "/payload", http.StatusFound)
		default:
			fmt.Fprint(w, "authenticated payload")
		}
	}))
	defer tlsServer.Close()
	client := userDataClient()
	client.Transport = tlsServer.Client().Transport // trust only the test certificate
	if _, err := client.Get(tlsServer.URL + "/downgrade"); err == nil {
		t.Fatal("downgrade accepted")
	}
	if contacted.Load() {
		t.Fatal("HTTP destination contacted")
	}
	resp, err := client.Get(tlsServer.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "authenticated payload" {
		t.Fatalf("HTTPS redirect failed: %q", body)
	}
	if _, err := userDataClient().Get(tlsServer.URL); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestMetadataRejectsRedirectsAndProxy(t *testing.T) {
	var contacted atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted.Store(true) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := metadataClient(time.Second)
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("metadata honors environment proxy")
	}
	req, _ := http.NewRequest(http.MethodPut, source.URL, nil)
	req.Header.Set("X-aws-ec2-metadata-token", "private")
	if _, err := client.Do(req); err == nil {
		t.Fatal("metadata redirect accepted")
	}
	if contacted.Load() {
		t.Fatal("metadata token destination contacted")
	}
	if resp, err := client.Get(destination.URL); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
}

func TestClusterHealthBoundToAssignedNode(t *testing.T) {
	app := ClusteredApp{Name: "web", Replicas: 2}
	st := ClusterState{Nodes: []ClusterNode{{ID: "a", Status: "Ready", Running: []string{containerName(app, 0), containerName(app, 1), containerName(app, 1)}}, {ID: "b", Status: "Ready"}}, Replicas: []Replica{{App: "web", Index: 0, Node: "a"}, {App: "web", Index: 1, Node: "b"}}}
	if got := st.appStatus(app); got != "1/2 running" {
		t.Fatalf("forged health: %s", got)
	}
	st.Nodes[1].Running = []string{containerName(app, 1)}
	if got := st.appStatus(app); got != "2/2 running" {
		t.Fatal(got)
	}
	st.Nodes[1].Status = "NotReady"
	if got := st.appStatus(app); got != "1/2 running" {
		t.Fatal(got)
	}
	st.Replicas[1].Node = ""
	if got := st.appStatus(app); got != "1/2 running, 1 pending" {
		t.Fatal(got)
	}
	st.Replicas[0].Node = "unknown"
	if got := st.appStatus(app); got != "0/2 running, 1 pending" {
		t.Fatal(got)
	}
}

func TestSSHHardeningPrecedenceAndScopes(t *testing.T) {
	input := []byte("# PasswordAuthentication no\n  pAsSwOrDaUtHeNtIcAtIoN=yes\nPasswordAuthentication no\nPermitRootLogin \"no\"\nMaxAuthTries=2\nPort 2222\nMatch User root\nPasswordAuthentication yes\nChallengeResponseAuthentication yes\nPermitRootLogin forced-commands-only\nMaxAuthTries 1\nMatch Address 203.0.113.0/24\nX11Forwarding yes\n")
	out, err := hardenedSSHConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if !sshKeyOnlyConfig(out) {
		t.Fatalf("unsafe output: %s", out)
	}
	for _, want := range []string{"PermitRootLogin no\n", "MaxAuthTries 2\n", "Port 2222\n", "PermitRootLogin forced-commands-only\n", "MaxAuthTries 1\n", "Match User root\n"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("lost %q", want)
		}
	}
	again, err := hardenedSSHConfig(out)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("not idempotent: %v\n%s", err, again)
	}
	for _, line := range []string{"Include /etc/ssh/conf.d/*", "  iNcLuDe=/tmp/override", "\"Include\" \"/tmp/override\"", "Match all\nInclude conf.d/*", "Match all\nInclude\r/tmp/override"} {
		if _, err := hardenedSSHConfig([]byte(line)); err == nil {
			t.Errorf("accepted include %q", line)
		}
	}
	if sshKeyOnlyConfig([]byte("# PasswordAuthentication no\n")) {
		t.Fatal("comment counted")
	}
	if sshKeyOnlyConfig([]byte("Match User root\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\n")) {
		t.Fatal("missing globals counted")
	}
}

func TestCanonicalQuarantineTargets(t *testing.T) {
	for _, c := range []struct{ input, family, target string }{
		{"::ffff:203.0.113.8", "ip", "203.0.113.8"},
		{"::ffff:203.0.113.8/120", "ip", "203.0.113.0/24"},
		{"203.0.113.8/24", "ip", "203.0.113.0/24"},
		{"2001:0db8::1/32", "ip6", "2001:db8::/32"},
	} {
		family, target, err := canonicalBlockTarget(c.input)
		if err != nil || family != c.family || target != c.target {
			t.Fatalf("%s: %s %s %v", c.input, family, target, err)
		}
		script, err := buildNftScript(FirewallConfig{BlockedIPs: []BlockedIP{{IP: c.input}}})
		if err != nil || !strings.Contains(script, family+" saddr "+target+" drop") {
			t.Fatalf("wrong generated rule: %s %v", script, err)
		}
	}
	for _, input := range []string{"::ffff:203.0.113.0/64", "fe80::1%eth0", "1.2.3.4 accept"} {
		if _, _, err := canonicalBlockTarget(input); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestBackupRejectsReadableStaging(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "staging-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupStaging(f); err == nil {
		t.Fatal("readable staging accepted")
	}
	if err := f.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupStaging(f); err != nil {
		t.Fatal(err)
	}
}

func TestSSHCandidateFailurePreservesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "sshd")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := hardenSSHFile(path); err == nil {
		t.Fatal("validation failure ignored")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("failed candidate replaced original")
	}
}

func TestQuarantinePrecedesBroadAccepts(t *testing.T) {
	cfg := FirewallConfig{BlockedIPs: []BlockedIP{{IP: "203.0.113.0/24"}, {IP: "2001:db8::/32"}}, AllowedPorts: []FirewallRule{{Port: 22, Protocol: "tcp"}}}
	script, err := buildNftScript(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, drop := range []string{"ip saddr 203.0.113.0/24 drop", "ip6 saddr 2001:db8::/32 drop"} {
		for _, accept := range []string{"ct state established,related accept", "ip protocol icmp accept", "ip6 nexthdr icmpv6 accept", "tcp dport 22 accept"} {
			if strings.Index(script, drop) >= strings.Index(script, accept) {
				t.Fatalf("%s follows %s", drop, accept)
			}
		}
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "rules")
	for _, bin := range []string{"iptables", "ip6tables"} {
		body := "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$RULE_LOG\"\n"
		if err := os.WriteFile(filepath.Join(dir, bin), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RULE_LOG", log)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := applyIptables(cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	for _, pair := range []struct{ bin, ip string }{{"iptables", "203.0.113.0/24"}, {"ip6tables", "2001:db8::/32"}} {
		drop := pair.bin + " -A INPUT -s " + pair.ip + " -j DROP"
		accept := pair.bin + " -A INPUT -m conntrack"
		if strings.Index(string(data), drop) < 0 || strings.Index(string(data), drop) >= strings.Index(string(data), accept) {
			t.Fatalf("quarantine order: %s", data)
		}
	}
	if strings.Contains(string(data), "FORWARD") || strings.Contains(string(data), "-t nat") {
		t.Fatal("container rules mutated")
	}
}

func TestQuarantineBlockUnblockAliases(t *testing.T) {
	old := firewallConfigFile
	firewallConfigFile = filepath.Join(t.TempDir(), "firewall.json")
	t.Cleanup(func() { firewallConfigFile = old })
	for _, target := range []string{"203.0.113.9/24", "::ffff:203.0.113.8", "2001:0db8:0000:0000:0000:0000:0000:0001"} {
		for _, legacy := range []bool{false, true} {
			cfg := FirewallConfig{DefaultInput: "DROP"}
			if legacy {
				cfg.BlockedIPs = []BlockedIP{{IP: target}}
			}
			if err := saveFirewallConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if err := fwBlockIPCmd.RunE(fwBlockIPCmd, []string{target}); err != nil {
				t.Fatal(err)
			}
			if len(loadFirewallConfig().BlockedIPs) != 1 {
				t.Fatal("equivalent quarantine duplicated")
			}
			if err := fwUnblockIPCmd.RunE(fwUnblockIPCmd, []string{target}); err != nil {
				t.Fatal(err)
			}
			if len(loadFirewallConfig().BlockedIPs) != 0 {
				t.Fatalf("quarantine remains: %s legacy=%v", target, legacy)
			}
		}
	}
}

func TestIptablesRebuildFailsClosed(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "rules")
	for _, bin := range []string{"iptables", "ip6tables"} {
		script := "#!/bin/sh\nprintf '%s %s\\n' \"${0##*/}\" \"$*\" >> \"$RULE_LOG\"\nif [ \"$FAIL_APPEND\" = 1 ] && [ \"$1\" = '-A' ]; then exit 1; fi\n"
		if err := os.WriteFile(filepath.Join(dir, bin), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RULE_LOG", log)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := FirewallConfig{DefaultInput: "ACCEPT", BlockedIPs: []BlockedIP{{IP: "203.0.113.8"}, {IP: "2001:db8::1"}}}
	for _, fail := range []string{"0", "1"} {
		t.Setenv("FAIL_APPEND", fail)
		os.WriteFile(log, nil, 0600)
		err := applyIptables(cfg)
		if (err != nil) != (fail == "1") {
			t.Fatalf("append failure result: %v", err)
		}
		data, _ := os.ReadFile(log)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if lines[0] != "iptables -P INPUT DROP" || lines[1] != "iptables -F INPUT" {
			t.Fatalf("flush without DROP: %s", data)
		}
		if fail == "1" {
			if strings.Contains(string(data), "-P INPUT ACCEPT") {
				t.Fatalf("failed rebuild reopened input: %s", data)
			}
		} else {
			for _, bin := range []string{"iptables", "ip6tables"} {
				accept := strings.Index(string(data), bin+" -P INPUT ACCEPT")
				drop := strings.Index(string(data), bin+" -A INPUT -s ")
				flush := strings.Index(string(data), bin+" -F INPUT")
				guard := strings.Index(string(data), bin+" -P INPUT DROP")
				if guard < 0 || guard >= flush || drop < flush || accept < drop {
					t.Fatalf("unsafe replacement: %s", data)
				}
			}
		}
	}
}

func TestBackupPrivateDuringWriteAndFailureCleanup(t *testing.T) {
	dir := t.TempDir()
	old := backupPaths
	backupPaths = []string{dir}
	t.Cleanup(func() { backupPaths = old })
	started, proceed := filepath.Join(dir, "started"), filepath.Join(dir, "proceed")
	binDir := filepath.Join(dir, "bin")
	os.Mkdir(binDir, 0755)
	script := "#!/bin/sh\nprintf private; touch \"$BACKUP_STARTED\"; while [ ! -f \"$BACKUP_PROCEED\" ]; do sleep 0.02; done; exit \"$BACKUP_EXIT\"\n"
	os.WriteFile(filepath.Join(binDir, "tar"), []byte(script), 0700)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BACKUP_STARTED", started)
	t.Setenv("BACKUP_PROCEED", proceed)
	t.Setenv("BACKUP_EXIT", "0")
	out := filepath.Join(dir, "backup.tar.gz")
	done := make(chan error, 1)
	go func() { _, err := createBackup(out); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for !fileExists(started) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Unblock even on assertion failure, so no subprocess survives the test.
	defer os.WriteFile(proceed, nil, 0600)
	if !fileExists(started) {
		t.Fatal("tar never started")
	}
	partials, _ := filepath.Glob(filepath.Join(dir, ".ziro-backup-*"))
	if len(partials) != 1 {
		t.Fatalf("expected one private staging file: %v", partials)
	}
	info, err := os.Stat(partials[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe staging permissions: %v %v", info, err)
	}
	if fileExists(out) {
		t.Fatal("partial archive published")
	}
	os.WriteFile(proceed, nil, 0600)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(out)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe final permissions")
	}
	if _, err := createBackup(out); err == nil {
		t.Fatal("existing output overwritten")
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("unchanged"), 0644)
	link := filepath.Join(dir, "symlink")
	os.Symlink(target, link)
	if _, err := createBackup(link); err == nil {
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "unchanged" {
		t.Fatal("symlink target modified")
	}
	t.Setenv("BACKUP_EXIT", "1")
	failed := filepath.Join(dir, "failed.tar.gz")
	if _, err := createBackup(failed); err == nil {
		t.Fatal("tar failure ignored")
	}
	partials, _ = filepath.Glob(filepath.Join(dir, ".ziro-backup-*"))
	if fileExists(failed) || len(partials) != 0 {
		t.Fatal("failed archive left behind")
	}
}

func TestBackupChecksumAndRestoreValidation(t *testing.T) {
	t.Setenv("COPYFILE_DISABLE", "1") // BSD tar must not add macOS AppleDouble members.
	if _, err := exec.LookPath("tar"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "config")
	os.Mkdir(source, 0700)
	os.WriteFile(filepath.Join(source, "key"), []byte("private key"), 0600)
	old := backupPaths
	backupPaths = []string{source}
	t.Cleanup(func() { backupPaths = old })
	out := filepath.Join(dir, "backup.tar.gz")
	if _, err := createBackup(out); err != nil {
		t.Fatal(err)
	}
	if err := validateBackupArchive(out); err != nil {
		t.Fatal(err)
	}
	hash, _ := computeFileSHA256(out)
	manifest, _ := os.ReadFile(out + ".sha256")
	if string(manifest) != hash+"  backup.tar.gz\n" {
		t.Fatal("checksum format changed")
	}
}

func TestSSHEffectivePolicy(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("OpenSSH effective-policy validation requires sshd")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "host_key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("host key: %v %s", err, out)
	}
	path := filepath.Join(dir, "sshd_config")
	input := "HostKey " + key + "\nPasswordAuthentication yes\nChallengeResponseAuthentication yes\nPermitRootLogin no\nMaxAuthTries 2\nMatch User root\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\nX11Forwarding yes\nMatch Address 203.0.113.0/24\nPasswordAuthentication\ryes\nMaxAuthTries 1\n"
	os.WriteFile(path, []byte(input), 0600)
	if err := hardenSSHFile(path); err != nil {
		t.Fatal(err)
	}
	for _, context := range []string{"user=root,host=test,addr=203.0.113.1", "user=worker,host=test,addr=198.51.100.1", "user=worker,host=test,addr=203.0.113.1"} {
		out, err := exec.Command(sshd, "-T", "-f", path, "-C", context).CombinedOutput()
		if err != nil {
			t.Fatalf("effective policy: %v %s", err, out)
		}
		out = []byte(strings.ToLower(string(out)))
		for _, setting := range []string{"passwordauthentication no", "kbdinteractiveauthentication no", "permitemptypasswords no", "permitrootlogin no", "x11forwarding no"} {
			if !strings.Contains(string(out), setting+"\n") {
				t.Fatalf("%s: missing %s in %s", context, setting, out)
			}
		}
		if strings.Contains(context, "addr=203.") && !strings.Contains(string(out), "maxauthtries 1\n") {
			t.Fatal("stronger Match retry limit lost")
		}
	}
}

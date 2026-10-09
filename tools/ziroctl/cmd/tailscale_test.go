package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

func tsStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stubModules(t)
	oldDaemon, oldCLI, oldSock, oldTmp, oldPlug := tsDaemon, tsCLI, tsSocket, tsTmpRoot, tsPluginDir
	tsPluginDir = filepath.Join(dir, "plugins")
	tsDaemon, tsCLI = filepath.Join(tsPluginDir, "tailscaled"), filepath.Join(tsPluginDir, "tailscale")
	tsSocket, tsTmpRoot = filepath.Join(dir, "ts.sock"), dir
	t.Cleanup(func() {
		tsDaemon, tsCLI, tsSocket, tsTmpRoot, tsPluginDir = oldDaemon, oldCLI, oldSock, oldTmp, oldPlug
	})
	os.MkdirAll(tsPluginDir, 0755)
	return dir
}

// The module manifest the catalog publishes (its sha256 values are the catalog's to fill in).
func TestTailscaleManifestMatchesTheCommand(t *testing.T) {
	b, err := os.ReadFile("testdata/tailscale.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := schema.ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	if m.Name != tsModule || len(m.Packages) != 0 {
		t.Errorf("name %q, packages %v: the module installs nothing from the base image", m.Name, m.Packages)
	}
	// the artifact paths are the binaries the command runs, for both architectures
	arch := map[string]int{}
	for _, a := range m.Artifacts {
		arch[a.Arch]++
		if a.Path != filepath.Join(schema.PluginRoot, tsModule, "tailscaled") && a.Path != filepath.Join(schema.PluginRoot, tsModule, "tailscale") {
			t.Errorf("artifact path %s", a.Path)
		}
		if !strings.HasPrefix(a.URL, "https://") {
			t.Errorf("artifact %s is not https", a.URL)
		}
	}
	if arch["x86_64"] != 2 || arch["aarch64"] != 2 {
		t.Errorf("artifacts per arch: %v", arch)
	}
	// the module only wires the commands in: setup on start, teardown on stop, a daily update
	if len(m.PostStart) != 1 || !reflect.DeepEqual(m.PostStart[0].Args, []string{"tailscale", "setup"}) ||
		len(m.Stop) != 1 || !reflect.DeepEqual(m.Stop[0].Args, []string{"tailscale", "teardown"}) ||
		len(m.Cron) != 1 || !strings.Contains(m.Cron[0], "tailscale update --cron") || len(m.Services) != 0 {
		t.Errorf("lifecycle wiring: %+v", m)
	}
	// the settings the command reads
	have := map[string]string{}
	for _, s := range m.Settings {
		have[s.Name] = s.Default
	}
	if have["port"] != "41642" || have["telemetry"] != "off" || have["auto_update"] != "true" {
		t.Errorf("setting defaults: %v", have)
	}
	if m.MinMemoryMB < 512 {
		t.Errorf("min_memory_mb %d", m.MinMemoryMB)
	}
}

func TestTailscaleDaemonDefinition(t *testing.T) {
	tsStub(t)
	def, err := tsDaemonDef()
	if err != nil {
		t.Fatal(err)
	}
	if def.User != "tailscale" || !reflect.DeepEqual(def.Caps, []string{"net_admin", "net_raw"}) {
		t.Errorf("user %q caps %v: tailscaled must run unprivileged with only net_admin+net_raw", def.User, def.Caps)
	}
	if err := def.ValidateCaps(); err != nil {
		t.Error(err)
	}
	if def.Resources == nil || def.Resources.Memory == "" || def.Resources.PIDs == 0 {
		t.Errorf("no cgroup limits: %+v", def.Resources)
	}
	for _, want := range []string{"--port=41642", "--tun=tailscale0", "--socket=", "--state=", "--statedir="} {
		if !strings.Contains(def.Args, want) {
			t.Errorf("args lack %s: %s", want, def.Args)
		}
	}
	for _, bad := range []string{"--ssh", "--accept-dns", "authkey", "auth-key", "tskey"} {
		if strings.Contains(def.Args, bad) {
			t.Errorf("args contain %s: %s", bad, def.Args)
		}
	}
	if def.Restart != "always" || !def.Autostart || def.EnvFile != tsEnvFile {
		t.Errorf("def %+v", def)
	}
	// it round-trips through the conf file the supervisor reads
	conf := supervisedConf(def)
	if !strings.Contains(conf, "caps=net_admin,net_raw\n") || !strings.Contains(conf, "user=tailscale\n") {
		t.Errorf("conf:\n%s", conf)
	}
}

func TestTailscalePort(t *testing.T) {
	tsStub(t)
	if p, err := tsPort(); err != nil || p != 41642 {
		t.Fatalf("default port %d, %v", p, err)
	}
	for set, wantErr := range map[string]bool{"41642": false, "50000": false, "41641": true, "51820": true, "51821": true, "80": true, "70000": true, "x": true} {
		saveModuleState(&ModuleState{Name: tsModule, Status: "enabled", Settings: map[string]string{"port": set}})
		if _, err := tsPort(); (err != nil) != wantErr {
			t.Errorf("port %q: err %v", set, err)
		}
	}
}

func TestTailscaleEnvironmentFile(t *testing.T) {
	if got := tsEnvContent(false); !strings.Contains(got, "TS_NO_LOGS_NO_SUPPORT=true") || !strings.Contains(got, "GOMEMLIMIT=") {
		t.Errorf("default env must not upload logs and must bound the heap: %q", got)
	}
	if got := tsEnvContent(true); strings.Contains(got, "TS_NO_LOGS_NO_SUPPORT") {
		t.Errorf("telemetry on still disables logs: %q", got)
	}
	if strings.Contains(tsEnvContent(false), "TS_AUTHKEY") {
		t.Error("the env file must never hold a key")
	}
}

func TestTailscaleKeyShapeAndSources(t *testing.T) {
	for k, ok := range map[string]bool{
		"tskey-auth-kAbCdEfGhIjKl-1234567890": true, "tskey-client-kAbC123-xyz?ephemeral=false&preauthorized=true": true,
		"tskey-": false, "hello": false, "tskey-auth-a b": false, "tskey-auth-abc\n": false, "": false, "tskey-auth-x;rm": false,
	} {
		if got := tsKeyRe.MatchString(k); got != ok {
			t.Errorf("key %q: %v", k, got)
		}
	}
	if k, err := tsReadKey("", false, false); k != "" || err != nil {
		t.Errorf("no key source = interactive login: %q %v", k, err)
	}
	if _, err := tsReadKey("/x", true, false); err == nil {
		t.Error("two key sources accepted")
	}
	f := filepath.Join(t.TempDir(), "key")
	os.WriteFile(f, []byte("tskey-auth-kAbCdEfGhI-abcdefghijklmnop\n"), 0600)
	if k, err := tsReadKey(f, false, false); err != nil || !strings.HasPrefix(k, "tskey-auth-") || strings.ContainsAny(k, "\n ") {
		t.Errorf("key from file: %q %v", k, err)
	}
	os.WriteFile(f, []byte("not a key"), 0600)
	if _, err := tsReadKey(f, false, false); err == nil {
		t.Error("a malformed key was accepted")
	}
}

func TestTailscaleUpArgsAreClosedByDefault(t *testing.T) {
	args, err := tsUpArgs(tsUpOptions{Timeout: 5 * time.Minute}, "")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{"up", "--reset", "--accept-dns=false", "--accept-routes=false", "--ssh=false", "--advertise-exit-node=false", "--timeout=5m0s"} {
		if !strings.Contains(got, want) {
			t.Errorf("args lack %s: %s", want, got)
		}
	}
	for _, bad := range []string{"--auth-key", "--advertise-routes", "--exit-node=", "--operator"} {
		if strings.Contains(got, bad) {
			t.Errorf("args contain %s: %s", bad, got)
		}
	}
	args, err = tsUpArgs(tsUpOptions{Hostname: "web1", Tags: []string{"tag:server", "tag:prod"}, AcceptRoutes: true, LoginServer: "https://hs.example.com/", Timeout: time.Minute}, "/run/x/key")
	if err != nil {
		t.Fatal(err)
	}
	got = strings.Join(args, " ")
	for _, want := range []string{"--hostname=web1", "--advertise-tags=tag:server,tag:prod", "--accept-routes=true", "--login-server=https://hs.example.com", "--auth-key=file:/run/x/key"} {
		if !strings.Contains(got, want) {
			t.Errorf("args lack %s: %s", want, got)
		}
	}
	for _, bad := range []tsUpOptions{
		{Hostname: "Bad_Name"}, {Hostname: "-x"}, {Tags: []string{"server"}}, {Tags: []string{"tag:UP"}},
		{LoginServer: "http://hs.example.com"}, {LoginServer: "https://u:p@hs.example.com"}, {LoginServer: "https://hs.example.com/x?y"},
		{KeyKind: "tskey-client-abc"}, // an OAuth secret without a tag
	} {
		bad.Timeout = time.Minute
		if _, err := tsUpArgs(bad, ""); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := tsUpArgs(tsUpOptions{KeyKind: "tskey-client-abc", Tags: []string{"tag:ci"}, Timeout: time.Minute}, ""); err != nil {
		t.Errorf("an OAuth secret with a tag: %v", err)
	}
}

// The join, end to end against a fake tailscale CLI: the key reaches it only as a 0600 file inside a
// 0700 directory, never in its arguments or environment, and the file is gone afterwards.
func TestTailscaleJoinKeepsTheKeyOffTheCommandLine(t *testing.T) {
	dir := tsStub(t)
	log := filepath.Join(dir, "cli.log")
	script := `#!/bin/sh
{
  echo "ARGS: $*"
  echo "ENV: $(env | grep -c -E 'TS_|TAILSCALE|AUTHKEY')"
  for a in "$@"; do case "$a" in --auth-key=file:*) f=${a#--auth-key=file:}
    echo "KEYFILE: $f"; echo "MODE: $(stat -c %a "$f") DIRMODE: $(stat -c %a "$(dirname "$f")")"; echo "KEY: $(cat "$f")";; esac; done
} > ` + log + "\n"
	if err := os.WriteFile(tsCLI, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_AUTHKEY", "leaked-from-the-operators-environment")
	const key = "tskey-auth-kAbCdEfGhI-abcdefghijklmnop"
	if err := tsJoin(context.Background(), tsUpOptions{Hostname: "web1", Timeout: time.Minute}, key, os.Stdout, os.Stderr); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	out := string(b)
	argsLine, _, _ := strings.Cut(out, "\n")
	if strings.Contains(argsLine, key) || strings.Contains(argsLine, "tskey") {
		t.Errorf("the key is on the command line: %s", argsLine)
	}
	if !strings.Contains(argsLine, "--socket="+tsSocket) || !strings.Contains(argsLine, "--auth-key=file:") {
		t.Errorf("args: %s", argsLine)
	}
	if !strings.Contains(out, "ENV: 0\n") {
		t.Errorf("TS_* or key variables reached the CLI:\n%s", out)
	}
	if !strings.Contains(out, "MODE: 600 DIRMODE: 700") || !strings.Contains(out, "KEY: "+key) {
		t.Errorf("key file:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if f, ok := strings.CutPrefix(l, "KEYFILE: "); ok {
			if _, err := os.Stat(f); err == nil {
				t.Errorf("key file %s still exists after the join", f)
			}
			if _, err := os.Stat(filepath.Dir(f)); err == nil {
				t.Errorf("key directory %s still exists", filepath.Dir(f))
			}
		}
	}
	// no key: interactive login, no key file at all
	if err := tsJoin(context.Background(), tsUpOptions{Timeout: time.Minute}, "", os.Stdout, os.Stderr); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); strings.Contains(string(b), "auth-key") {
		t.Errorf("login without a key passed one: %s", b)
	}
	// a failing CLI is an error, and the key file is still removed
	os.WriteFile(tsCLI, []byte("#!/bin/sh\nexit 1\n"), 0755)
	if err := tsJoin(context.Background(), tsUpOptions{Timeout: time.Minute}, key, os.Stdout, os.Stderr); err == nil {
		t.Error("a failing tailscale up reported success")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "ziro-ts-*")); len(left) != 0 {
		t.Errorf("leftover key directories: %v", left)
	}
}

func TestTailscaleRangeConflict(t *testing.T) {
	routes := []RouteStatus{{Dest: "0.0.0.0/0", Iface: "eth0"}, {Dest: "172.26.1.0/24", Iface: "eth0"}, {Dest: "100.64.0.0/10", Iface: "tailscale0"}}
	if c := tsRangeConflict(routes); c != "" {
		t.Errorf("the tailnet's own route and a default route are not conflicts: %q", c)
	}
	if c := tsRangeConflict(append(routes, RouteStatus{Dest: "100.64.5.0/24", Iface: "zr0"})); !strings.Contains(c, "zr0") {
		t.Errorf("a router mesh route in the tailnet range: %q", c)
	}
	if c := tsRangeConflict(append(routes, RouteStatus{Dest: "100.128.0.0/16", Iface: "zr0"})); c != "" {
		t.Errorf("outside the range: %q", c)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	st, err := parseTSStatus([]byte(`{"Version":"1.98.5","BackendState":"Running","Health":["no UDP"],
	  "CurrentTailnet":{"Name":"me@example.com"},
	  "Self":{"HostName":"web1","DNSName":"web1.tail1234.ts.net.","Online":true,"TailscaleIPs":["100.101.102.103","fd7a:115c:a1e0::1"]},
	  "Peer":{"a":{"Online":true,"CurAddr":"198.51.100.7:41641"},"b":{"Online":true,"Relay":"fra"},"c":{"Online":false},"d":{"Online":true,"CurAddr":"203.0.113.1:41641","Relay":"fra"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "Running" || st.Name != "web1.tail1234.ts.net" || st.Tailnet != "me@example.com" || len(st.IPs) != 2 ||
		st.Peers != 4 || st.Online != 3 || st.Direct != 2 || st.Relayed != 1 || len(st.Health) != 1 {
		t.Errorf("%+v", st)
	}
	if _, err := parseTSStatus([]byte("not json")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestTailscaleAllowSpec(t *testing.T) {
	for in, want := range map[string]string{"ssh": "22/tcp", "8080": "8080", "5432/tcp": "5432/tcp", "53/udp": "53/udp"} {
		if got, err := tsAllowSpec(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "70000", "http", "22; rm", "-1"} {
		if _, err := tsAllowSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTailscaleStateIsNeverBackedUp(t *testing.T) {
	for _, p := range backupPaths {
		if strings.HasPrefix(tsStateDir, p) {
			t.Errorf("backup path %s includes the node key directory %s", p, tsStateDir)
		}
	}
}

// A new version that does not come back must not stay: the previous binaries are restored and
// the service is restarted onto them.
func TestUpdateRollsBackWhenTheServiceDoesNotComeBack(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "tailscaled"), filepath.Join(dir, "tailscale")
	os.WriteFile(a, []byte("new-daemon"), 0755)
	os.WriteFile(b, []byte("new-cli"), 0755)
	os.WriteFile(a+".prev", []byte("old-daemon"), 0755)
	os.WriteFile(b+".prev", []byte("old-cli"), 0755)
	restarts := 0
	u := binaryUpdate{Module: "x", Title: "Tailscale", Binaries: []string{a, b}, AuditSource: "tailscale", AuditAction: "tailscale update",
		Restart: func() bool { restarts++; return restarts > 1 }} // unhealthy on the new binary, healthy on the old
	if err := restartChecked(u, "9.9.9"); err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err = %v", err)
	}
	if x, _ := os.ReadFile(a); string(x) != "old-daemon" {
		t.Errorf("daemon = %q", x)
	}
	if x, _ := os.ReadFile(b); string(x) != "old-cli" {
		t.Errorf("cli = %q", x)
	}
	if restarts != 2 {
		t.Errorf("restarts = %d: the service must be restarted onto the restored binaries", restarts)
	}
	// healthy: the previous copies are dropped
	os.WriteFile(a+".prev", []byte("old"), 0755)
	if err := restartChecked(binaryUpdate{Module: "x", Title: "Tailscale", Binaries: []string{a}, AuditSource: "tailscale", AuditAction: "x",
		Restart: func() bool { return true }}, "9.9.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a + ".prev"); err == nil {
		t.Error(".prev kept after a healthy update")
	}
}

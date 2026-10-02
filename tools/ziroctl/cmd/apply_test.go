package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyHostIdempotent(t *testing.T) {
	dir := t.TempDir()
	saved := []*string{&hostnamePath, &hostsPath, &kernelHostnamePath, &sshAuthorizedKeysPath, &firewallConfigFile,
		&updateConfFile, &extraPackagesFile, &appliedHostConfig}
	olds := make([]string, len(saved))
	for i, p := range saved {
		olds[i] = *p
		*p = filepath.Join(dir, fmt.Sprintf("%d-%s", i, filepath.Base(*p)))
	}
	oldInst, oldAdd := apkInstalled, apkAdd
	installed := map[string]bool{}
	apkInstalled = func(p string) bool { return installed[p] }
	apkAdd = func(ps []string) error {
		for _, p := range ps {
			installed[p] = true
		}
		return nil
	}
	t.Cleanup(func() {
		for i, p := range saved {
			*p = olds[i]
		}
		apkInstalled, apkAdd = oldInst, oldAdd
	})
	os.WriteFile(firewallConfigFile, []byte(`{"enabled":false,"default_input":"DROP","allowed_ports":[],"blocked_ips":[]}`), 0644)
	os.WriteFile(sshAuthorizedKeysPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3n8Lr0zkRZ3jGCSgBQIzDiADudzPnJFPg+7mY0Y1RE admin-own\n"), 0600)

	key1 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops"
	key2 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBy3bS0E4dvU7a2YHzEJqSPMRxHzJdQUdnDXiLAJGd5m ci"
	host := func(keys ...string) []byte {
		return []byte("host:\n  version: 1\n  hostname: web-1\n  ssh: {keys: [" + `"` + strings.Join(keys, `", "`) + `"` + "]}\n" +
			"  firewall: {allow: [443/tcp]}\n  packages: [htop]\n  update: {auto: true}\n")
	}
	plan, err := applyHostFile(host(key1, key2), dir, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan {
		if c.Action != "update" {
			t.Errorf("first apply: %+v", c)
		}
	}
	if b, _ := os.ReadFile(hostnamePath); string(b) != "web-1\n" || !installed["htop"] || !strings.Contains(string(mustRead(updateConfFile)), `"auto":true`) {
		t.Fatalf("not applied: hostname %q htop %v update %q", mustRead(hostnamePath), installed["htop"], mustRead(updateConfFile))
	}
	// Applying the same file again changes nothing.
	plan, _ = applyHostFile(host(key1, key2), dir, true, 0)
	for _, c := range plan {
		if c.Action != "unchanged" {
			t.Errorf("second apply plans %+v", c)
		}
	}
	// A key removed from the file is removed from the host; keys it never managed stay.
	if _, err := applyHostFile(host(key1), dir, false, 0); err != nil {
		t.Fatal(err)
	}
	ak := string(mustRead(sshAuthorizedKeysPath))
	if strings.Contains(ak, "AAAAIBy3") || !strings.Contains(ak, "admin-own") || !strings.Contains(ak, "AAAAIOMq") {
		t.Errorf("authorized_keys:\n%s", ak)
	}
	if fi, _ := os.Stat(appliedHostConfig); fi == nil || fi.Mode().Perm() != 0600 {
		t.Error("applied config not recorded 0600")
	}
}

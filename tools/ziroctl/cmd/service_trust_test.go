package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceDefinitionTrust(t *testing.T) {
	// Only root-owned executables nobody else can write may run as services.
	if err := trustedExecutable("/bin/sh"); err != nil {
		t.Fatalf("/bin/sh: %v", err)
	}
	mine := filepath.Join(t.TempDir(), "tool")
	_ = os.WriteFile(mine, []byte("#!/bin/sh\n"), 0755)
	for _, bad := range []string{"sh", "/bin/../bin/sh", mine, "/nonexistent/x"} {
		if err := trustedExecutable(bad); err == nil && os.Geteuid() != 0 {
			t.Errorf("accepted %q", bad)
		}
	}
	if fi, _ := os.Stat(mine); rootOwnedFile(fi) && os.Geteuid() != 0 {
		t.Error("a file owned by the test user passed as root-owned")
	}
	for _, c := range []struct {
		def ServiceDef
		ok  bool
	}{
		{ServiceDef{PIDFile: "/run/x.pid", LogFile: "/var/log/x.log"}, true},
		{ServiceDef{}, true},
		{ServiceDef{PIDFile: "/etc/passwd"}, false},
		{ServiceDef{PIDFile: "/run/../etc/shadow"}, false},
		{ServiceDef{LogFile: "/etc/ziro/cluster/state.json"}, false},
	} {
		if err := checkServicePaths(&c.def); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c.def, err)
		}
	}
}

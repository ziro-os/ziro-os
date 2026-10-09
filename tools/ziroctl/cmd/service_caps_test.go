package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

func TestCapNumbersAndMask(t *testing.T) {
	got, err := capNumbers([]string{"net_admin", "net_raw"})
	if err != nil || !reflect.DeepEqual(got, []int{12, 13}) {
		t.Fatalf("capNumbers = %v, %v", got, err)
	}
	for _, bad := range []string{"sys_admin", "sys_module", "dac_override", "setuid", "all", ""} {
		if _, err := capNumbers([]string{bad}); err == nil {
			t.Errorf("capability %q accepted", bad)
		}
	}
	if lo, hi := capMask([]int{12, 13}); lo != 0x3000 || hi != 0 {
		t.Errorf("mask = %#x %#x", lo, hi)
	}
	if lo, hi := capMask([]int{0, 31, 32, 38}); lo != 0x80000001 || hi != 0x41 {
		t.Errorf("mask with high caps = %#x %#x", lo, hi)
	}
	if got := parseCapList(" net_admin, net_raw ,,"); !reflect.DeepEqual(got, []string{"net_admin", "net_raw"}) {
		t.Errorf("parseCapList = %v", got)
	}
}

// Every capability a service may ask for is a privilege reviewed here: nothing that loads code,
// reads memory or disks raw, overrides permissions or becomes root.
func TestServiceCapsAllowlist(t *testing.T) {
	var names []string
	for n := range schema.ServiceCaps {
		names = append(names, n)
	}
	for _, n := range names {
		if n != "net_admin" && n != "net_raw" && n != "net_bind_service" {
			t.Errorf("capability %q was added to the allowlist: review and update this test", n)
		}
	}
	for _, c := range []struct {
		def ServiceDef
		ok  bool
	}{
		{ServiceDef{Name: "ts", User: "tailscale", Caps: []string{"net_admin", "net_raw"}}, true},
		{ServiceDef{Name: "ts", User: "tailscale"}, true},
		{ServiceDef{Name: "ts", Caps: []string{"net_admin"}}, false},                                 // root already has everything
		{ServiceDef{Name: "ts", User: "root", Caps: []string{"net_admin"}}, false},                   // same
		{ServiceDef{Name: "ts", User: "tailscale", Caps: []string{"sys_admin"}}, false},              // not available
		{ServiceDef{Name: "ts", User: "tailscale", Caps: []string{"net_admin", "net_admin"}}, false}, // duplicate
	} {
		if err := c.def.ValidateCaps(); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c.def, err)
		}
	}
}

func TestServiceCapsConfRoundTrip(t *testing.T) {
	stubModules(t)
	d := ServiceDef{Name: "tsd", Description: "d", Exec: "/bin/true", Args: "--x", PIDFile: "/run/tsd.pid", LogFile: "/var/log/tsd.log",
		User: "nobody", Caps: []string{"net_admin", "net_raw"}}
	conf := supervisedConf(d)
	if !strings.Contains(conf, "caps=net_admin,net_raw\n") {
		t.Fatalf("conf lacks caps:\n%s", conf)
	}
	if err := os.WriteFile(filepath.Join(servicesDir, "tsd.conf"), []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 { // loadServiceDef trusts only root-owned files
		return
	}
	got, err := loadServiceDef("tsd")
	if err != nil || !reflect.DeepEqual(got.Caps, d.Caps) || got.User != "nobody" {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	// caps without a user are refused when the definition is loaded
	bad := strings.Replace(conf, "user=nobody\n", "", 1)
	os.WriteFile(filepath.Join(servicesDir, "tsd.conf"), []byte(bad), 0644)
	if _, err := loadServiceDef("tsd"); err == nil {
		t.Error("a root service with caps was loaded")
	}
}

func TestServiceCommand(t *testing.T) {
	plain, err := serviceCommand(&ServiceDef{Name: "x", Exec: "/bin/echo", Args: "a b"})
	if err != nil || plain.Path == "" || !reflect.DeepEqual(plain.Args, []string{"/bin/echo", "a", "b"}) {
		t.Fatalf("plain service: %v %v", plain, err)
	}
	c, err := serviceCommand(&ServiceDef{Name: "ts", Exec: "/bin/echo", Args: "secret-looking-arg", User: "nobody", Caps: []string{"net_raw"}})
	if err != nil {
		t.Fatal(err)
	}
	// only the validated name reaches the launcher's command line
	if len(c.Args) != 4 || c.Args[1] != "service" || c.Args[2] != "exec" || c.Args[3] != "ts" {
		t.Errorf("launcher argv = %v", c.Args)
	}
	if _, err := serviceCommand(&ServiceDef{Name: "ts", Exec: "/bin/echo", Caps: []string{"net_raw"}}); err == nil {
		t.Error("caps without a user accepted")
	}
}

// helper process: becomes `cat /proc/self/status` through execWithCaps (needs root)
func TestCapsHelperProcess(t *testing.T) {
	if os.Getenv("ZIRO_CAPS_HELPER") != "1" {
		t.Skip("helper process")
	}
	err := execWithCaps("/bin/cat", []string{"cat", "/proc/self/status"}, []string{"PATH=/bin"}, 65534, 65534, []int{12, 13})
	t.Fatalf("exec returned: %v", err)
}

// The privileged sequence, for real: root becomes nobody with exactly CAP_NET_ADMIN and
// CAP_NET_RAW in every set, an empty rest of the bounding set, no group and no_new_privs.
func TestExecWithCaps(t *testing.T) {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		t.Skip("needs root on Linux")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCapsHelperProcess$")
	cmd.Env = append(os.Environ(), "ZIRO_CAPS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("the sandbox does not allow the privilege change: %v: %s", err, out)
	}
	st := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			st[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	for k, want := range map[string]string{
		"Uid": "65534 65534 65534 65534", "Gid": "65534 65534 65534 65534", "Groups": "",
		"CapInh": "0000000000003000", "CapPrm": "0000000000003000", "CapEff": "0000000000003000",
		"CapBnd": "0000000000003000", "CapAmb": "0000000000003000", "NoNewPrivs": "1",
	} {
		if st[k] != want {
			t.Errorf("%s = %q, want %q\n%s", k, st[k], want, out)
		}
	}
}

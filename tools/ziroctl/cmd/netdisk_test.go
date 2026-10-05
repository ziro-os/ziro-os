package cmd

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetConfigValidate(t *testing.T) {
	good := NetConfig{Interfaces: []NetIface{
		{Name: "eth0", Mode: "static", Addresses: []string{"10.0.0.5/24", "2001:db8::5/64"}, Gateway: "10.0.0.1", Gateway6: "2001:db8::1", IPv6: "static", MTU: 9000},
		{Name: "eth1", Mode: "manual"}, {Name: "eth2", Mode: "manual"},
		{Name: "bond0", Mode: "dhcp", BondMode: "active-backup", Slaves: []string{"eth1", "eth2"}},
		{Name: "bond0.100", Mode: "static", Addresses: []string{"172.16.100.5/24"}, Parent: "bond0", VLANID: 100},
	}, Routes: []NetRoute{{To: "10.20.0.0/16", Via: "10.0.0.254"}, {To: "2001:db8:1::/48", Via: "2001:db8::fe"}}}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	bad := []NetConfig{
		{Interfaces: []NetIface{{Name: "eth0; reboot", Mode: "dhcp"}}},
		{Interfaces: []NetIface{{Name: "eth0", Mode: "static"}}},
		{Interfaces: []NetIface{{Name: "eth0", Mode: "static", Addresses: []string{"10.0.0.5"}}}},
		{Interfaces: []NetIface{{Name: "eth0", Mode: "static", Addresses: []string{"10.0.0.5/24"}, Gateway: "2001:db8::1"}}},
		{Interfaces: []NetIface{{Name: "eth0", MTU: 100000}}},
		{Interfaces: []NetIface{{Name: "v", Parent: "eth0", VLANID: 5000}}},
		{Interfaces: []NetIface{{Name: "b", BondMode: "yolo", Slaves: []string{"eth1"}}}},
		{Interfaces: []NetIface{{Name: "eth1", Mode: "dhcp"}, {Name: "b", BondMode: "802.3ad", Slaves: []string{"eth1"}}}}, // slave must be manual
		{Interfaces: []NetIface{{Name: "eth0"}, {Name: "eth0"}}},
		{Interfaces: []NetIface{{Name: "eth0", Mode: "static", Addresses: []string{"2001:db8::5/64"}, IPv6: "off"}}},
		{Routes: []NetRoute{{To: "10.0.0.0/8"}}},
		{Routes: []NetRoute{{To: "10.0.0.0/8", Via: "2001:db8::1"}}},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func planStrings(steps []netStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.String())
	}
	return out
}

func TestNetPlan(t *testing.T) {
	prev := &NetConfig{Interfaces: []NetIface{{Name: "eth0", Mode: "dhcp"}, {Name: "eth0.200", Parent: "eth0", VLANID: 200, Mode: "dhcp"}},
		Routes: []NetRoute{{To: "10.30.0.0/16", Via: "10.0.0.254"}}}
	next := &NetConfig{Interfaces: []NetIface{
		{Name: "eth0", Mode: "static", Addresses: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1", MTU: 1450},
		{Name: "eth1", Mode: "manual"}, {Name: "eth2", Mode: "manual"},
		{Name: "bond0", Mode: "dhcp", BondMode: "802.3ad", Slaves: []string{"eth1", "eth2"}, IPv6: "off"},
		{Name: "bond0.100", Mode: "static", Parent: "bond0", VLANID: 100, Addresses: []string{"172.16.100.5/24"}},
	}, Routes: []NetRoute{{To: "10.20.0.0/16", Via: "10.0.0.254", Metric: 50}}}
	got := strings.Join(planStrings(netPlan(prev, next)), "\n")
	for _, want := range []string{
		"ip route del 10.30.0.0/16 via 10.0.0.254",                  // removed route
		"ip link del eth0.200",                                      // removed VLAN
		"ip link add bond0 type bond mode 802.3ad miimon 100",       // bond before its VLAN
		"ip link set eth1 master bond0",                             // enslaved
		"ip link add link bond0 name bond0.100 type vlan id 100",    // VLAN on the bond
		"ip link set eth0 mtu 1450",                                 // MTU
		"stop DHCP on eth0\nip -4 addr flush dev eth0 scope global", // static replaces DHCP
		"ip addr replace 10.0.0.5/24 dev eth0",                      // address
		"ip -4 route replace default via 10.0.0.1 dev eth0",         // gateway
		"/proc/sys/net/ipv6/conf/bond0/disable_ipv6 = 1",            // ipv6 off
		"/proc/sys/net/ipv6/conf/eth0/accept_ra = 2",                // SLAAC while forwarding
		"start DHCP on bond0",                                       // dhcp on the bond
		"ip route replace 10.20.0.0/16 via 10.0.0.254 metric 50",    // static route
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plan lacks %q\n---\n%s", want, got)
		}
	}
	if strings.Index(got, "type bond") > strings.Index(got, "type vlan") {
		t.Error("the bond must exist before its VLAN")
	}
}

// An unconfirmed apply rolls back to the previous configuration by itself.
func TestNetApplyRollback(t *testing.T) {
	dir := t.TempDir()
	netConfigPath, netAppliedPath, netRollbackPath = filepath.Join(dir, "n.json"), filepath.Join(dir, "a.json"), filepath.Join(dir, "r.json")
	alertConfigPath, alertSpoolDir, clusterDir = filepath.Join(dir, "al.json"), filepath.Join(dir, "sp"), dir
	var ran []string
	orig := runNetStep
	runNetStep = func(s netStep) error { ran = append(ran, s.String()); return nil }
	defer func() { runNetStep = orig }()

	old := &NetConfig{Interfaces: []NetIface{{Name: "eth0", Mode: "dhcp"}}}
	saveNetConfig(netConfigPath, old)
	saveNetConfig(netAppliedPath, old)
	bad := &NetConfig{Interfaces: []NetIface{{Name: "eth0", Mode: "static", Addresses: []string{"192.0.2.9/24"}}}}
	saveNetConfig(netConfigPath, bad)

	// Arm a rollback like startNetApply does (without spawning the watcher process).
	prev, _ := loadNetConfig(netAppliedPath)
	rb := netRollback{Token: "t1", Deadline: time.Now().Add(-time.Second), Prev: prev, PrevFile: true}
	b, _ := json.Marshal(rb)
	os.WriteFile(netRollbackPath, b, 0600)
	if err := applyNetConfig(bad, false); err != nil {
		t.Fatal(err)
	}
	ran = nil
	if err := networkRollbackWatchCmd.RunE(networkRollbackWatchCmd, []string{"t1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ran, "\n"), "start DHCP on eth0") {
		t.Fatalf("rollback did not restore DHCP: %v", ran)
	}
	cur, _ := loadNetConfig(netConfigPath)
	if cur.Interfaces[0].Mode != "dhcp" || fileExists(netRollbackPath) {
		t.Fatalf("config not restored: %+v", cur)
	}
	// A confirmed change is left alone: the watcher exits when the rollback file is gone.
	if err := networkRollbackWatchCmd.RunE(networkRollbackWatchCmd, []string{"t1"}); err != nil {
		t.Fatal(err)
	}
}

func TestHostnameAndResolv(t *testing.T) {
	for _, ok := range []string{"node-1", "web01.prod.example.com"} {
		if validHostname(ok) != nil {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "-x", "x-", "a_b", "UPPER", "a..b", strings.Repeat("a", 64), "a b", "x\nnameserver 6.6.6.6"} {
		if validHostname(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	hosts := "127.0.0.1\tlocalhost\n127.0.1.1\told-name\n::1\tlocalhost\n"
	got := rewriteHosts(hosts, "web01.prod.example.com")
	if !strings.Contains(got, "127.0.1.1\tweb01.prod.example.com web01\n") || strings.Contains(got, "old-name") || !strings.Contains(got, "::1") {
		t.Fatalf("hosts:\n%s", got)
	}
	r, err := renderResolv([]string{"1.1.1.1", "2606:4700:4700::1111"}, []string{"corp.example"})
	if err != nil || !strings.Contains(r, "search corp.example\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n") {
		t.Fatalf("%v\n%s", err, r)
	}
	for _, bad := range [][]string{nil, {"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"}, {"not-an-ip"}, {"1.1.1.1\nnameserver 6.6.6.6"}} {
		if _, err := renderResolv(bad, nil); err == nil {
			t.Errorf("resolvers %q accepted", bad)
		}
	}
}

// fakeSysBlock lays out a disk "vda" of diskSz sectors with partitions (start, size).
func fakeSysBlock(t *testing.T, diskSz int64, parts ...[2]int64) {
	root := t.TempDir()
	sysBlock = filepath.Join(root, "class", "block")
	devs := filepath.Join(root, "devices", "vda")
	os.MkdirAll(sysBlock, 0755)
	os.MkdirAll(devs, 0755)
	os.WriteFile(filepath.Join(devs, "size"), []byte(itoa64(diskSz)), 0644)
	os.Symlink(devs, filepath.Join(sysBlock, "vda"))
	for i, p := range parts {
		name := "vda" + itoa64(int64(i+1))
		d := filepath.Join(devs, name)
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, "partition"), []byte(itoa64(int64(i+1))), 0644)
		os.WriteFile(filepath.Join(d, "start"), []byte(itoa64(p[0])), 0644)
		os.WriteFile(filepath.Join(d, "size"), []byte(itoa64(p[1])), 0644)
		os.Symlink(d, filepath.Join(sysBlock, name))
	}
}

func itoa64(i int64) string { return strconv.FormatInt(i, 10) }

func TestDiskGeometryAndGrowth(t *testing.T) {
	// 20 GiB disk: BIOS boot, ESP, root ending at 10 GiB -> about 10 GiB to grow.
	fakeSysBlock(t, 41943040, [2]int64{2048, 4096}, [2]int64{6144, 1048576}, [2]int64{1054720, 19916800})
	g, err := geometry("vda3")
	if err != nil || g.Disk != "vda" || g.Number != 3 || !g.Last {
		t.Fatalf("%+v %v", g, err)
	}
	if extra := g.growable(); extra != 41943040-34-(1054720+19916800) {
		t.Fatalf("growable %d", extra)
	}
	if g2, _ := geometry("vda2"); g2.Last || g2.growable() != 0 {
		t.Fatal("only the last partition may grow")
	}
	// Already filling the disk (minus the backup GPT): nothing to do.
	fakeSysBlock(t, 41943040, [2]int64{2048, 41943040 - 34 - 2048})
	if g, _ := geometry("vda1"); g.growable() != 0 {
		t.Fatal("full partition reported growable")
	}
}

func TestMountSourceAndDiskGuards(t *testing.T) {
	mi := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(mi, []byte("22 1 253:3 / / rw,relatime - ext4 /dev/vda3 rw\n30 22 0:5 / /dev rw - devtmpfs devtmpfs rw\n40 22 253:17 / /data rw - ext4 /dev/vdb1 rw\n"), 0644)
	mountInfoPath = mi
	if d, fs := mountSource("/"); d != "/dev/vda3" || fs != "ext4" {
		t.Fatalf("root: %s %s", d, fs)
	}
	if d, _ := mountSource("/dev"); d != "" {
		t.Fatal("devtmpfs is not a disk")
	}
	for _, bad := range []string{"/", "/etc", "/usr/local", "/boot/efi", "/var", "data", "/data/../etc"} {
		if validateMountPoint(bad) == nil {
			t.Errorf("mount point %s accepted", bad)
		}
	}
	for _, ok := range []string{"/data", "/srv/volumes", "/var/lib/containerd", "/mnt/backup"} {
		if err := validateMountPoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	fakeSysBlock(t, 41943040, [2]int64{2048, 41943040 - 2082})
	for _, dev := range []string{"/dev/vda", "/dev/vda1", "/dev/../vda", "vdb", "/dev/sdb; rm -rf /"} {
		if _, err := addDataDisk(dev, "/data", "", false); err == nil {
			t.Errorf("disk add %s accepted", dev)
		}
	}
}

func TestExtSuperAndHalfGrownResize(t *testing.T) {
	sb := make([]byte, 1024)
	binary.LittleEndian.PutUint16(sb[0x38:], 0xEF53)
	binary.LittleEndian.PutUint32(sb[0x18:], 2) // 4 KiB blocks
	binary.LittleEndian.PutUint32(sb[0x04:], 5)
	binary.LittleEndian.PutUint32(sb[0x150:], 1)
	if b, bs, err := parseExtSuper(sb); err != nil || b != 5 || bs != 4096 {
		t.Fatalf("32-bit: %d %d %v", b, bs, err)
	}
	binary.LittleEndian.PutUint32(sb[0x60:], 0x80) // 64bit feature: the high word counts
	if b, _, _ := parseExtSuper(sb); b != 1<<32|5 {
		t.Fatalf("64-bit: %d", b)
	}
	if _, _, err := parseExtSuper(make([]byte, 1024)); err == nil {
		t.Fatal("accepted a non-ext superblock")
	}

	// The partition already fills the disk (an older image grew it, then had no resize2fs), but
	// the filesystem is 1 GiB short: only the filesystem is grown, with no partition commands.
	fakeSysBlock(t, 41943040, [2]int64{2048, 41943040 - 34 - 2048})
	oldRun, oldSize, oldResize := diskRun, extSize, resizeFS
	t.Cleanup(func() { diskRun, extSize, resizeFS = oldRun, oldSize, oldResize })
	var ran []string
	diskRun = func(_ string, name string, args ...string) error { ran = append(ran, name); return nil }
	partBlocks := uint64(41943040-34-2048) * 512 / 4096
	extSize = func(string) (uint64, uint64, error) { return partBlocks - (1<<30)/4096, 4096, nil }
	var got uint64
	resizeFS = func(mnt string, blocks uint64) error { got = blocks; return nil }
	n, err := growPartition("/dev/vda1", "/", "ext4", false)
	if err != nil || n != (1<<30)/512 || got != partBlocks || len(ran) != 0 {
		t.Fatalf("grew %d sectors to %d blocks, ran %v: %v", n, got, ran, err)
	}
	// Filesystem matches its partition: nothing to do.
	extSize = func(string) (uint64, uint64, error) { return partBlocks, 4096, nil }
	got = 0
	if n, err := growPartition("/dev/vda1", "/", "ext4", false); n != 0 || err != nil || got != 0 {
		t.Fatalf("up-to-date fs resized: %d %v", n, err)
	}
	// Room on the disk: partition commands run, then the fs grows to the new partition size.
	fakeSysBlock(t, 41943040, [2]int64{2048, 20971520})
	extSize = func(string) (uint64, uint64, error) { return 20971520 * 512 / 4096, 4096, nil }
	diskRun = func(_ string, name string, args ...string) error {
		ran = append(ran, name)
		if name == "partx" { // the kernel now sees the grown partition
			os.WriteFile(filepath.Join(sysBlock, "vda1", "size"), []byte(itoa64(41943040-34-2048)), 0644)
		}
		return nil
	}
	if _, err := growPartition("/dev/vda1", "/", "ext4", false); err != nil || got != partBlocks || strings.Join(ran, " ") != "sfdisk sfdisk partx" {
		t.Fatalf("grow: %d blocks, ran %v: %v", got, ran, err)
	}
}

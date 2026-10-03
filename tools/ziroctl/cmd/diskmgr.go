package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Disk management: grow partitions and filesystems when the cloud/VM disk is resized (root and
// data disks, automatically at boot and every minute), and add data disks in one command.

var (
	sysBlock       = "/sys/class/block"
	mountInfoPath  = "/proc/self/mountinfo"
	disksStatePath = "/etc/ziro/disks.json"
)

const (
	minGrowSectors = 16 << 20 / 512 // grow only when at least 16 MiB is unused
	gptBackupSecs  = 34             // backup GPT header + entries at the end of the disk
)

type DataDisk struct {
	Label string `json:"label"`
	Mount string `json:"mount"`
	Added string `json:"added"`
}

func readSysInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

type partGeom struct {
	Part, Disk          string // e.g. vda3, vda
	Number              int
	Start, Size, DiskSz int64 // 512-byte sectors
	Last                bool  // no partition starts after this one
}

// geometry reads a partition's layout from sysfs.
func geometry(part string) (*partGeom, error) {
	g := &partGeom{Part: part}
	n, err := readSysInt(filepath.Join(sysBlock, part, "partition"))
	if err != nil {
		return nil, fmt.Errorf("%s is not a partition", part)
	}
	g.Number = int(n)
	if g.Start, err = readSysInt(filepath.Join(sysBlock, part, "start")); err != nil {
		return nil, err
	}
	if g.Size, err = readSysInt(filepath.Join(sysBlock, part, "size")); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(sysBlock, part))
	if err != nil {
		return nil, err
	}
	g.Disk = filepath.Base(filepath.Dir(real))
	if g.DiskSz, err = readSysInt(filepath.Join(sysBlock, g.Disk, "size")); err != nil {
		return nil, err
	}
	g.Last = true
	ents, _ := os.ReadDir(filepath.Join(sysBlock, g.Disk))
	for _, e := range ents {
		if s, err := readSysInt(filepath.Join(sysBlock, g.Disk, e.Name(), "start")); err == nil && s > g.Start {
			g.Last = false
		}
	}
	return g, nil
}

// growable returns how many sectors the partition can grow by (0 = nothing worth doing).
func (g *partGeom) growable() int64 {
	if !g.Last {
		return 0
	}
	free := g.DiskSz - gptBackupSecs - (g.Start + g.Size)
	if free < minGrowSectors {
		return 0
	}
	return free
}

// mountSource returns the device mounted at path from mountinfo ("" if none or not a block device).
func mountSource(path string) (dev, fstype string) {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// id parent maj:min root mountpoint opts ... - fstype source superopts
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		fields, tail := strings.Fields(pre), strings.Fields(post)
		if !ok || len(fields) < 5 || len(tail) < 2 || fields[4] != path {
			continue
		}
		dev, fstype = tail[1], tail[0] // the last mount on a path wins
	}
	if !strings.HasPrefix(dev, "/dev/") {
		return "", fstype
	}
	return dev, fstype
}

var diskRun = func(stdin string, name string, args ...string) error {
	c := exec.Command(name, args...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if out, err := c.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = "..." + msg[len(msg)-300:]
		}
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

// growPartition grows the last partition to the end of its disk and the filesystem on it, online.
func growPartition(dev, fstype string, dryRun bool) (int64, error) {
	part := filepath.Base(dev)
	g, err := geometry(part)
	if err != nil {
		return 0, err
	}
	extra := g.growable()
	if extra == 0 {
		return 0, nil
	}
	if fstype != "ext4" && fstype != "ext3" && fstype != "ext2" {
		return 0, fmt.Errorf("%s: %s can't be grown online by ziroctl (only ext2/3/4)", dev, fstype)
	}
	if dryRun {
		return extra, nil
	}
	disk := "/dev/" + g.Disk
	// The backup GPT must move to the new end of the disk before the partition can use the space.
	_ = diskRun("", "sfdisk", "--relocate", "gpt-bak-std", disk)
	if err := diskRun(", +\n", "sfdisk", "--force", "--no-reread", "--no-tell-kernel", "-N", strconv.Itoa(g.Number), disk); err != nil {
		return 0, err
	}
	// partx -u updates the kernel's view of a partition that is in use (BLKPG resize).
	if err := diskRun("", "partx", "-u", "--nr", strconv.Itoa(g.Number), disk); err != nil {
		return 0, err
	}
	if err := diskRun("", "resize2fs", dev); err != nil {
		return 0, err
	}
	return extra, nil
}

func loadDataDisks() []DataDisk {
	var d []DataDisk
	if b, err := os.ReadFile(disksStatePath); err == nil {
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func saveDataDisks(d []DataDisk) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(disksStatePath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(disksStatePath, b, 0644)
}

// expandAll grows the root filesystem and every data disk that has room.
func expandAll(dryRun, quiet bool) error {
	targets := []string{"/"}
	for _, d := range loadDataDisks() {
		targets = append(targets, d.Mount)
	}
	var errs []string
	for _, mnt := range targets {
		dev, fstype := mountSource(mnt)
		if dev == "" {
			if !quiet && mnt == "/" {
				fmt.Println("/ is not on a disk partition (live system): nothing to grow")
			}
			continue
		}
		extra, err := growPartition(dev, fstype, dryRun)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if extra == 0 {
			if !quiet {
				fmt.Printf("%s (%s): already uses its whole disk\n", mnt, dev)
			}
			continue
		}
		gb := float64(extra*512) / (1 << 30)
		if dryRun {
			fmt.Printf("%s (%s): would grow by %.1f GiB\n", mnt, dev, gb)
			continue
		}
		fmt.Printf("✅ %s (%s) grown by %.1f GiB\n", mnt, dev, gb)
		_ = auditLog("ziroctl", "disk", "disk expand", fmt.Sprintf("%s (%s) +%.1f GiB", mnt, dev, gb), nil)
		alertf("low", "disk", fmt.Sprintf("Filesystem %s grown by %.1f GiB", mnt, gb), map[string]any{"mount": mnt, "device": dev})
	}
	if !dryRun {
		checkDiskUsage(targets)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// checkDiskUsage alerts when a managed filesystem is 90% or more full.
func checkDiskUsage(mounts []string) {
	for _, m := range mounts {
		var st syscall.Statfs_t
		if syscall.Statfs(m, &st) != nil || st.Blocks == 0 {
			continue
		}
		used := 100 - int(uint64(st.Bavail)*100/uint64(st.Blocks))
		if used >= 90 {
			alertf("high", "disk", fmt.Sprintf("Filesystem %s is %d%% full", m, used), map[string]any{"mount": m, "used_percent": used})
		}
	}
}

var (
	diskDevRe   = regexp.MustCompile(`^/dev/(sd[a-z]{1,2}|vd[a-z]{1,2}|xvd[a-z]{1,2}|nvme[0-9]+n[0-9]+|hd[a-z])$`)
	diskLabelRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,16}$`)
	// Mounting over these would hide or break the OS.
	diskForbidden = []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"}
)

func validateMountPoint(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("mount point %q must be an absolute, clean path", p)
	}
	for _, f := range diskForbidden {
		if p == f || (f != "/" && f != "/var" && f != "/root" && strings.HasPrefix(p, f+"/")) {
			return fmt.Errorf("refusing to mount over system path %s", p)
		}
	}
	return nil
}

// addDataDisk partitions, formats, mounts and records an empty disk.
func addDataDisk(dev, mount, label string, force bool) (*DataDisk, error) {
	if !diskDevRe.MatchString(dev) {
		return nil, fmt.Errorf("%q is not a whole-disk device (e.g. /dev/vdb, /dev/sdb, /dev/nvme1n1)", dev)
	}
	if err := validateMountPoint(mount); err != nil {
		return nil, err
	}
	name := filepath.Base(dev)
	if _, err := os.Stat(filepath.Join(sysBlock, name, "size")); err != nil {
		return nil, fmt.Errorf("no such disk %s", dev)
	}
	if rootDev, _ := mountSource("/"); rootDev != "" {
		if g, err := geometry(filepath.Base(rootDev)); err == nil && g.Disk == name {
			return nil, fmt.Errorf("%s holds the root filesystem", dev)
		}
	}
	if !force {
		ents, _ := os.ReadDir(filepath.Join(sysBlock, name))
		for _, e := range ents {
			if fileExists(filepath.Join(sysBlock, name, e.Name(), "partition")) {
				return nil, fmt.Errorf("%s already has partitions (use --force to wipe them)", dev)
			}
		}
		if out, err := exec.Command("blkid", "-p", dev).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return nil, fmt.Errorf("%s holds data (%s); use --force to wipe it", dev, strings.TrimSpace(string(out)))
		}
		if ents, err := os.ReadDir(mount); err == nil && len(ents) > 0 {
			return nil, fmt.Errorf("%s is not empty (its files would be hidden); use --force", mount)
		}
	}
	existing := loadDataDisks()
	for _, d := range existing {
		if d.Mount == mount {
			return nil, fmt.Errorf("a data disk is already mounted at %s", mount)
		}
	}
	if label == "" {
		label = fmt.Sprintf("ZIRO_DATA_%d", len(existing)+1)
	}
	if !diskLabelRe.MatchString(label) {
		return nil, fmt.Errorf("invalid label %q (A-Z a-z 0-9 _ -, max 16)", label)
	}
	part := dev + "1"
	if strings.HasPrefix(name, "nvme") {
		part = dev + "p1"
	}
	steps := []struct {
		stdin string
		cmd   []string
	}{
		{"label: gpt\n,,L\n", []string{"sfdisk", "--wipe", "always", dev}},
		{"", []string{"partx", "-u", dev}},
		{"", []string{"mdev", "-s"}},
		{"", []string{"mkfs.ext4", "-q", "-F", "-L", label, "-m", "1", "-E", "lazy_itable_init=1,lazy_journal_init=1", part}},
	}
	for _, s := range steps {
		if err := diskRun(s.stdin, s.cmd[0], s.cmd[1:]...); err != nil && s.cmd[0] != "mdev" {
			return nil, err
		}
	}
	d := DataDisk{Label: label, Mount: mount, Added: time.Now().UTC().Format(time.RFC3339)}
	if err := mountDataDisk(d); err != nil {
		return nil, err
	}
	return &d, saveDataDisks(append(existing, d))
}

func mountDataDisk(d DataDisk) error {
	if dev, _ := mountSource(d.Mount); dev != "" {
		return nil // already mounted
	}
	if err := os.MkdirAll(d.Mount, 0755); err != nil {
		return err
	}
	return diskRun("", "mount", "-t", "ext4", "-o", "noatime,nodev,nosuid", "LABEL="+d.Label, d.Mount)
}

var (
	diskAuto, diskDryRun, diskQuiet, diskForce bool
	diskMount, diskLabel                       string
)

var diskExpandCmd = &cobra.Command{
	Use:   "expand",
	Short: "Grow partitions and filesystems into resized disks",
	Example: `  ziroctl disk expand --dry-run
  ziroctl disk expand`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return expandAll(diskDryRun, diskQuiet)
	},
}

var diskAddCmd = &cobra.Command{
	Use:     "add <device>",
	Short:   "Format and mount an empty disk",
	Example: `  ziroctl disk add /dev/vdb --mount /data`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if diskMount == "" {
			return errors.New("--mount is required (e.g. --mount /data)")
		}
		d, err := addDataDisk(args[0], diskMount, diskLabel, diskForce)
		if err != nil {
			return err
		}
		fmt.Printf("✅ %s formatted (ext4, label %s) and mounted at %s\n", args[0], d.Label, d.Mount)
		return nil
	},
}

var diskRemoveCmd = &cobra.Command{
	Use:     "remove <mount>",
	Short:   "Unmount a data disk and stop managing it",
	Example: `  ziroctl disk remove /data`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		disks := loadDataDisks()
		kept := disks[:0]
		var found *DataDisk
		for _, d := range disks {
			if d.Mount == args[0] {
				d := d
				found = &d
				continue
			}
			kept = append(kept, d)
		}
		if found == nil {
			return fmt.Errorf("no data disk mounted at %s", args[0])
		}
		if dev, _ := mountSource(found.Mount); dev != "" {
			if err := diskRun("", "umount", found.Mount); err != nil {
				return err
			}
		}
		if err := saveDataDisks(kept); err != nil {
			return err
		}
		fmt.Printf("✅ Unmounted %s (label %s); its data is untouched\n", found.Mount, found.Label)
		return nil
	},
}

var diskBootCmd = &cobra.Command{
	Use:    "boot",
	Hidden: true,
	Short:  "Mount data disks and grow filesystems (ziro-init)",
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, d := range loadDataDisks() {
			if err := mountDataDisk(d); err != nil {
				fmt.Printf("[disk] %s: %v\n", d.Mount, err)
			}
		}
		if err := expandAll(false, true); err != nil {
			fmt.Printf("[disk] %v\n", err)
		}
		return nil
	},
}

func init() {
	diskExpandCmd.Flags().BoolVar(&diskAuto, "auto", false, "Unattended (cron/boot)")
	diskExpandCmd.Flags().BoolVar(&diskDryRun, "dry-run", false, "Only show what would grow")
	diskExpandCmd.Flags().BoolVar(&diskQuiet, "quiet", false, "Print only changes")
	diskAddCmd.Flags().StringVar(&diskMount, "mount", "", "Mount point (e.g. /data, /var/lib/containerd)")
	diskAddCmd.Flags().StringVar(&diskLabel, "label", "", "Filesystem label (default ZIRO_DATA_<n>)")
	diskAddCmd.Flags().BoolVar(&diskForce, "force", false, "Wipe a disk that has partitions or data")
	diskCmd.AddCommand(diskExpandCmd, diskAddCmd, diskRemoveCmd, diskBootCmd)
}

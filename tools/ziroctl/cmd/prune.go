package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// `system df` shows where disk space goes; `system prune` reclaims what nothing uses: stopped
// containers that no app owns, images no container uses, rotated logs, stale temp files, the
// package cache and (only when asked) the upgrade rollback generation. App data, volumes,
// secrets and /etc are never touched. Every prune is planned first; nothing is removed without
// confirmation (or -y).

// PruneItem is one thing a prune would remove.
type PruneItem struct {
	Category string `json:"category"` // containers, images, logs, tmp, cache, rollback
	Target   string `json:"target"`
	Bytes    int64  `json:"bytes"`
}

var (
	pruneTmpAge  = 7 * 24 * time.Hour
	pruneTmpDirs = []string{"/tmp", "/var/tmp"}
	pruneLogDir  = "/var/log"
	pruneCaches  = []string{"/var/cache/apk"}
	// runNerdctl is the container runtime CLI (a variable so tests can stub it).
	runNerdctl = func(args ...string) ([]byte, error) { return exec.Command("nerdctl", args...).Output() }
)

var pruneCategories = []string{"containers", "images", "logs", "tmp", "cache", "rollback"}

// dirSize sums regular files under p (not following symlinks).
func dirSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// managedContainer is a container a Ziro app or the cluster owns (never pruned).
func managedContainer(name, labels string) bool {
	return strings.HasPrefix(name, "ziro-") || strings.Contains(labels, "ziro.cluster=") || strings.Contains(labels, "ziro.app=")
}

// openFiles is every path some process has open (stale temp files still in use are kept).
func openFiles() map[string]bool {
	out := map[string]bool{}
	fds, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*", "fd", "*"))
	for _, fd := range fds {
		if t, err := os.Readlink(fd); err == nil && strings.HasPrefix(t, "/") {
			out[t] = true
		}
	}
	return out
}

// planPrune lists what pruning the categories would remove.
func planPrune(cats map[string]bool, now time.Time) []PruneItem {
	var items []PruneItem
	if cats["containers"] || cats["images"] {
		used := map[string]bool{}
		if out, err := runNerdctl("ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Labels}}"); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				f := strings.SplitN(line, "\t", 5)
				if len(f) < 4 {
					continue
				}
				labels := ""
				if len(f) == 5 {
					labels = f[4]
				}
				stopped := !strings.HasPrefix(f[2], "Up")
				if cats["containers"] && stopped && !managedContainer(f[1], labels) {
					items = append(items, PruneItem{"containers", f[1] + " (" + f[0] + ")", 0})
					continue // its image becomes unused
				}
				for _, k := range imageKeys(f[3]) {
					used[k] = true
				}
			}
		}
		if cats["images"] {
			if out, err := runNerdctl("images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Digest}}\t{{.Size}}"); err == nil {
				for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
					f := strings.Split(line, "\t")
					if len(f) < 4 || imageInUse(used, f[0], f[1], f[2]) {
						continue
					}
					target := f[0]
					if strings.Contains(target, "<none>") {
						target = f[1] // dangling: only the ID names it
					}
					items = append(items, PruneItem{"images", target, parseHumanSize(f[3])})
				}
			}
		}
	}
	if cats["logs"] {
		matches, _ := filepath.Glob(filepath.Join(pruneLogDir, "*.log.[0-9]*")) // .1 and .N.gz
		for _, m := range matches {
			if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() {
				items = append(items, PruneItem{"logs", m, fi.Size()})
			}
		}
	}
	if cats["tmp"] {
		open := openFiles()
		for _, d := range pruneTmpDirs {
			_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
				if err != nil || !e.Type().IsRegular() || open[p] {
					return nil
				}
				if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime()) > pruneTmpAge {
					items = append(items, PruneItem{"tmp", p, fi.Size()})
				}
				return nil
			})
		}
	}
	if cats["cache"] {
		for _, c := range pruneCaches {
			entries, _ := os.ReadDir(c)
			for _, e := range entries {
				p := filepath.Join(c, e.Name())
				items = append(items, PruneItem{"cache", p, dirSize(p)})
			}
		}
	}
	if cats["rollback"] {
		p := filepath.Join("/", upgradeRelDir, "rollback")
		if fileExists(p) {
			items = append(items, PruneItem{"rollback", p, dirSize(p)})
		}
	}
	return items
}

// imageKeys are the names an image reference matches: the normalized name:tag
// (docker.io/library/mysql:8.4 for "mysql:8.4") and its digest. Containers record the full
// reference they were created from, `nerdctl images` lists the short one; both normalize alike.
func imageKeys(ref string) []string {
	r, err := parseImageRef(ref)
	if err != nil {
		return []string{ref}
	}
	var keys []string
	if r.Tag != "" {
		keys = append(keys, r.name()+":"+r.Tag)
	}
	if r.Digest != "" {
		keys = append(keys, r.Digest)
	}
	return keys
}

// imageInUse reports whether an image row (repo:tag, ID, digest) is what some container uses.
func imageInUse(used map[string]bool, ref, id, digest string) bool {
	if used[id] || used[digest] {
		return true
	}
	if strings.Contains(ref, "<none>") {
		return false
	}
	for _, k := range imageKeys(ref) {
		if used[k] {
			return true
		}
	}
	return false
}

// errPruneInUse marks an item the runtime refused because it is in use now (a container
// started since the plan): kept, not an error.
var errPruneInUse = errors.New("in use")

// nerdctlError adds the runtime's own message to a failed nerdctl command.
func nerdctlError(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		msg := strings.TrimSpace(string(ee.Stderr))
		if strings.Contains(msg, "in use") || strings.Contains(msg, "being used") || strings.Contains(msg, "is running") {
			return fmt.Errorf("%w: %s", errPruneInUse, lastLines(msg, 1))
		}
		return fmt.Errorf("%v: %s", err, lastLines(msg, 2))
	}
	return err
}

// parseHumanSize reads runtime sizes like "45.2 MiB", "1.1GB" or "800kB" (best effort, 0 if not).
func parseHumanSize(s string) int64 {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	units := []struct {
		suffix string
		mult   float64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"KB", 1e3}, {"B", 1}}
	for _, u := range units {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			if v, err := strconv.ParseFloat(num, 64); err == nil {
				return int64(v * u.mult)
			}
			return 0
		}
	}
	return 0
}

// applyPrune removes the planned items; it re-checks each one (a temp file opened since the
// plan, a container restarted) and reports what failed.
func applyPrune(items []PruneItem) (freed int64, errs []error) {
	for _, it := range items {
		var err error
		switch it.Category {
		case "containers":
			id := it.Target[strings.LastIndex(it.Target, "(")+1 : len(it.Target)-1]
			if _, err = runNerdctl("rm", id); err != nil { // refuses a running container
				err = nerdctlError(err)
			}
		case "images":
			if _, err = runNerdctl("rmi", it.Target); err != nil { // refuses an image in use
				err = nerdctlError(err)
			}
		case "logs", "tmp":
			if it.Category == "tmp" && openFiles()[it.Target] {
				continue
			}
			err = os.Remove(it.Target)
		case "cache":
			err = os.RemoveAll(it.Target)
		case "rollback":
			var lock *os.File
			if lock, err = lockUpgrade(filepath.Join("/", upgradeRelDir)); err == nil {
				err = os.RemoveAll(it.Target)
				lock.Close()
			}
		default:
			err = fmt.Errorf("unknown category %q", it.Category)
		}
		if errors.Is(err, errPruneInUse) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", it.Category, it.Target, err))
			continue
		}
		freed += it.Bytes
	}
	return freed, errs
}

// DiskUsageEntry is one row of `system df`.
type DiskUsageEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	Reclaimable int64  `json:"reclaimable"`
}

func systemDiskUsage() []DiskUsageEntry {
	plan := planPrune(map[string]bool{"images": true, "logs": true, "tmp": true, "cache": true, "rollback": true}, time.Now())
	reclaim := map[string]int64{}
	for _, it := range plan {
		reclaim[it.Category] += it.Bytes
	}
	rows := []DiskUsageEntry{
		{"images and containers", "/var/lib/containerd", dirSize("/var/lib/containerd"), reclaim["images"]},
		{"app data", "/var/lib/ziro/apps", dirSize("/var/lib/ziro/apps"), 0},
		{"logs", pruneLogDir, dirSize(pruneLogDir), reclaim["logs"]},
		{"upgrade rollback", filepath.Join("/", upgradeRelDir), dirSize(filepath.Join("/", upgradeRelDir)), reclaim["rollback"]},
		{"package cache", "/var/cache/apk", dirSize("/var/cache/apk"), reclaim["cache"]},
		{"temporary files", "/tmp /var/tmp", dirSize("/tmp") + dirSize("/var/tmp"), reclaim["tmp"]},
	}
	return rows
}

var (
	pruneYes, pruneDryRun, pruneAll bool
	pruneOnly                       []string
)

// pruneSelection is the categories chosen by flags: the safe default set, --only, or --all.
func pruneSelection(only []string, all bool) (map[string]bool, error) {
	cats := map[string]bool{"containers": true, "images": true, "logs": true, "tmp": true, "cache": true}
	if len(only) > 0 {
		cats = map[string]bool{}
		for _, c := range only {
			if !strings.Contains(" "+strings.Join(pruneCategories, " ")+" ", " "+c+" ") {
				return nil, fmt.Errorf("unknown category %q (one of %s)", c, strings.Join(pruneCategories, ", "))
			}
			cats[c] = true
		}
	}
	if all {
		cats["rollback"] = true
	}
	return cats, nil
}

var systemPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Free disk: old containers, images, logs, caches",
	Example: `  ziroctl system prune --dry-run
  ziroctl system prune --only logs,tmp --yes
  ziroctl system prune --all --yes`,
	Long: `Plans what to remove, shows it, and asks before removing anything (-y skips the question,
--dry-run only shows the plan). Default categories: containers, images, logs, tmp, cache.
--all adds the upgrade rollback generation (you can no longer roll back the last upgrade).
App data, volumes, secrets, /etc and anything a process has open are never removed.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cats, err := pruneSelection(pruneOnly, pruneAll)
		if err != nil {
			return err
		}
		items := planPrune(cats, time.Now())
		var total int64
		for _, it := range items {
			total += it.Bytes
		}
		if pruneDryRun || len(items) == 0 || (!pruneYes && !jsonOutput) {
			if err := printResult(map[string]any{"items": items, "bytes": total, "applied": false}, func() {
				printPrunePlan(items, total)
			}); err != nil || pruneDryRun || len(items) == 0 {
				return err
			}
			if !confirm("Remove these? [y/N]: ") {
				fmt.Println("Nothing was removed.")
				return nil
			}
		} else if jsonOutput && !pruneYes {
			return errors.New("--json needs -y or --dry-run (no interactive confirmation)")
		}
		freed, errs := applyPrune(items)
		if err := printResult(map[string]any{"items": items, "bytes": freed, "applied": true}, func() {
			if freed > 0 || len(errs) == 0 {
				fmt.Printf("Reclaimed %s\n", humanBytes(uint64(freed)))
			}
		}); err != nil {
			return err
		}
		return errors.Join(errs...)
	},
}

func printPrunePlan(items []PruneItem, total int64) {
	if len(items) == 0 {
		fmt.Println("Nothing to prune.")
		return
	}
	by := map[string][]PruneItem{}
	for _, it := range items {
		by[it.Category] = append(by[it.Category], it)
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var n int64
		for _, it := range by[k] {
			n += it.Bytes
		}
		fmt.Printf("%-11s %4d item(s)  %9s\n", k, len(by[k]), humanBytes(uint64(n)))
		for i, it := range by[k] {
			if i == 5 {
				fmt.Printf("            ... and %d more\n", len(by[k])-5)
				break
			}
			fmt.Printf("            %s\n", it.Target)
		}
	}
	fmt.Printf("Total: %s\n", humanBytes(uint64(total)))
}

var systemDfCmd = &cobra.Command{
	Use:     "df",
	Short:   "Show disk use by category and what prune frees",
	Example: `  ziroctl system df`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rows := systemDiskUsage()
		return printResult(rows, func() {
			fmt.Printf("%-22s %10s %12s  %s\n", "WHAT", "SIZE", "RECLAIMABLE", "PATH")
			for _, r := range rows {
				fmt.Printf("%-22s %10s %12s  %s\n", r.Name, humanBytes(uint64(r.Bytes)), humanBytes(uint64(r.Reclaimable)), r.Path)
			}
			for _, d := range collectHostSummary().Disks {
				fmt.Printf("\nfilesystem %s: %s of %s used (%d%%)", d.Path, humanBytes(d.Used), humanBytes(d.Total), d.Percent())
			}
			fmt.Println()
		})
	},
}

func init() {
	f := systemPruneCmd.Flags()
	f.BoolVarP(&pruneYes, "yes", "y", false, "Don't ask for confirmation")
	f.BoolVar(&pruneDryRun, "dry-run", false, "Only show what would be removed")
	f.BoolVar(&pruneAll, "all", false, "Also remove the upgrade rollback generation")
	f.StringSliceVar(&pruneOnly, "only", nil, "Only these categories: "+strings.Join(pruneCategories, ","))
	systemCmd.AddCommand(systemPruneCmd, systemDfCmd)
}

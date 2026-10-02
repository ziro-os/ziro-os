package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Services run in their own cgroup under /sys/fs/cgroup/ziro/<class>/<name> (created by ziro-init
// at boot, re-created here when missing). Platform services ("system": sshd, containerd and the
// built-in ziroctl daemons) are protected from the OOM killer and keep a memory reservation, so a
// host under memory pressure stays manageable; plugin services ("workloads") are bounded by
// their resources and are the first the kernel reclaims or kills.

var (
	cgroupRoot  = "/sys/fs/cgroup"
	errNoCgroup = errors.New("cgroup v2 not mounted")
)

const (
	systemOOMScoreAdj   = -900
	workloadOOMScoreAdj = 300
)

func serviceClass(name string) string {
	for _, s := range defaultServices {
		if s.Name == name {
			return "system"
		}
	}
	return "workloads"
}

// cgroupWrite writes one cgroup interface file.
func cgroupWrite(dir, file, value string) error {
	return os.WriteFile(filepath.Join(dir, file), []byte(value), 0644)
}

// ensureCgroupParents creates ziro/<class> with the memory, cpu, pids and io controllers
// delegated to its children. Parents hold no processes (cgroup v2's no-internal-process rule).
func ensureCgroupParents(class string) (string, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return "", errNoCgroup
	}
	dir := cgroupRoot
	for _, part := range []string{"ziro", class} {
		dir = filepath.Join(dir, part)
		if err := os.Mkdir(dir, 0755); err != nil && !os.IsExist(err) {
			return "", err
		}
		for _, c := range []string{"+memory", "+cpu", "+pids", "+io"} {
			_ = cgroupWrite(dir, "cgroup.subtree_control", c) // a controller the kernel lacks is skipped
		}
	}
	return dir, nil
}

// serviceCgroup prepares the service's cgroup with its limits and returns its path.
func serviceCgroup(def *ServiceDef) (string, error) {
	if err := validName(def.Name); err != nil {
		return "", err
	}
	parent, err := ensureCgroupParents(serviceClass(def.Name))
	if err != nil {
		return "", err
	}
	dir := filepath.Join(parent, def.Name)
	if err := os.Mkdir(dir, 0755); err != nil && !os.IsExist(err) {
		return "", err
	}
	// The whole service is one unit for the OOM killer: no half-killed daemon left behind.
	_ = cgroupWrite(dir, "memory.oom.group", "1")
	return dir, applyCgroupLimits(dir, def.Resources)
}

// applyCgroupLimits writes the limits ("max" when unset, so removing a limit takes effect).
func applyCgroupLimits(dir string, r *Resources) error {
	mem, high, swap := "max", "max", "max"
	if n := r.MemoryBytes(); n > 0 {
		// memory.high throttles and reclaims before memory.max kills: pressure shows up as
		// slowness and in PSI before the service dies. The limit covers swap too (zram on small
		// hosts): cgroup v2 limits swap separately, so without swap.max a service could grow
		// past its limit into swap.
		mem, high, swap = strconv.FormatInt(n, 10), strconv.FormatInt(n/10*9, 10), "0"
	}
	cpu := "max 100000"
	pids := "max"
	if r != nil {
		if r.CPUs > 0 {
			cpu = fmt.Sprintf("%d 100000", int64(r.CPUs*100000))
		}
		if r.PIDs > 0 {
			pids = strconv.Itoa(r.PIDs)
		}
	}
	var errs []error
	for f, v := range map[string]string{"memory.max": mem, "memory.high": high, "memory.swap.max": swap, "cpu.max": cpu, "pids.max": pids} {
		if err := cgroupWrite(dir, f, v); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
		}
	}
	return errors.Join(errs...)
}

// setOOMScoreAdj sets a started service's OOM priority.
func setOOMScoreAdj(pid int, class string) {
	v := workloadOOMScoreAdj
	if class == "system" {
		v = systemOOMScoreAdj
	}
	_ = os.WriteFile("/proc/"+strconv.Itoa(pid)+"/oom_score_adj", []byte(strconv.Itoa(v)), 0644)
}

// containerResourceArgs renders resources as container runtime flags. Containers without a
// memory limit get a positive OOM score, so under host memory pressure an unbounded container
// is reclaimed before the platform (containerd's own -999 would otherwise be inherited).
func containerResourceArgs(r *Resources) []string {
	var args []string
	if n := r.MemoryBytes(); n > 0 {
		// --memory-swap is memory plus swap (Docker semantics): equal to --memory means no swap,
		// so the limit holds on hosts with zram.
		args = append(args, "--memory", strconv.FormatInt(n, 10), "--memory-swap", strconv.FormatInt(n, 10))
	} else {
		args = append(args, "--oom-score-adj", strconv.Itoa(workloadOOMScoreAdj))
	}
	if r != nil && r.CPUs > 0 {
		args = append(args, "--cpus", strings.TrimRight(strings.TrimRight(strconv.FormatFloat(r.CPUs, 'f', 3, 64), "0"), "."))
	}
	if r != nil && r.PIDs > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(r.PIDs))
	}
	return args
}

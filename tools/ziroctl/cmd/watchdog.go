package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The resource watchdog runs inside the sentinel daemon. It turns the two ways a small host
// dies slowly into something controlled and reported:
//   - memory: when tasks stall on memory (PSI "full") for a sustained period, it alerts with
//     the top consumers and restarts the largest plugin service (ziro/workloads), instead of
//     letting the kernel thrash the page cache until the global OOM killer picks a victim;
//   - disk: when /var fills up, it prunes what nothing uses (images, rotated logs, stale temp
//     files, caches) and alerts with what it freed.
//   - services: every minute, an enabled service that is down is started again (ziro-init
//     restarts crashed daemons; this catches one that never came up).
// Thresholds: /etc/ziro/sentinel.json, e.g. {"memory_full_percent": 10, "disk_prune_percent": 90}.

var sentinelConfFile = "/etc/ziro/sentinel.json"

type watchdogConf struct {
	MemoryFullPercent float64 `json:"memory_full_percent"` // PSI full avg10 that counts as stalling
	MemoryForSeconds  int     `json:"memory_for_seconds"`  // ...sustained this long
	RestartWorkloads  bool    `json:"restart_workloads"`   // restart the largest plugin service
	DiskPrunePercent  int     `json:"disk_prune_percent"`  // /var usage that triggers a prune (0 = off)
}

func loadWatchdogConf() watchdogConf {
	c := watchdogConf{MemoryFullPercent: 10, MemoryForSeconds: 15, RestartWorkloads: true, DiskPrunePercent: 90}
	if b, err := os.ReadFile(sentinelConfFile); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// cgroupMemory is a cgroup's current memory use.
type cgroupMemory struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
}

// largestWorkloads lists plugin services by memory use, largest first.
func largestWorkloads() []cgroupMemory {
	var out []cgroupMemory
	dirs, _ := filepath.Glob(filepath.Join(cgroupRoot, "ziro", "workloads", "*", "memory.current"))
	for _, p := range dirs {
		out = append(out, cgroupMemory{filepath.Base(filepath.Dir(p)), readUint(p)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// watchdogState carries the counters between ticks (pure step, so it can be tested).
type watchdogState struct {
	stalledFor  time.Duration
	lastMemAct  time.Time
	lastDiskAct time.Time
}

const (
	watchdogTick     = 5 * time.Second
	memActionCooloff = 5 * time.Minute
	diskCooloff      = time.Hour
)

// memoryStep decides whether to act on memory pressure now.
func (w *watchdogState) memoryStep(c watchdogConf, full float64, now time.Time) bool {
	if full < c.MemoryFullPercent {
		w.stalledFor = 0
		return false
	}
	w.stalledFor += watchdogTick
	if w.stalledFor < time.Duration(c.MemoryForSeconds)*time.Second || now.Sub(w.lastMemAct) < memActionCooloff {
		return false
	}
	w.lastMemAct, w.stalledFor = now, 0
	return true
}

func runResourceWatchdog() {
	var st watchdogState
	tick := time.NewTicker(watchdogTick)
	defer tick.Stop()
	for n := 0; ; n++ {
		<-tick.C
		c := loadWatchdogConf()
		if _, full, ok := readPressure("memory"); ok && st.memoryStep(c, full, time.Now()) {
			top := largestWorkloads()
			details := map[string]any{"pressure_full_avg10": full, "workloads": top}
			action := "none"
			if c.RestartWorkloads && len(top) > 0 && top[0].Bytes > 0 {
				action = "restarted " + top[0].Name
				if err := restartSupervised(top[0].Name); err != nil {
					action = fmt.Sprintf("restart %s failed: %v", top[0].Name, err)
				}
			}
			details["action"] = action
			fmt.Printf("[%s] memory pressure %.0f%%: %s\n", time.Now().Format("15:04:05"), full, action)
			alertf("high", "memory", "Host is stalling on memory", details)
		}
		if n%12 == 6 { // every minute: start enabled services that are down (cooldown per service)
			for _, f := range healServices(false) {
				msg := "restarted " + f.Name
				if f.Error != "" {
					msg = "restart " + f.Name + " failed: " + f.Error
				}
				fmt.Printf("[%s] service %s was down: %s\n", time.Now().Format("15:04:05"), f.Name, msg)
				alertf("medium", "service", "Service "+f.Name+" was down", map[string]any{"service": f.Name, "action": msg})
			}
		}
		if n%12 == 0 && c.DiskPrunePercent > 0 && time.Since(st.lastDiskAct) > diskCooloff { // every minute
			used, total, ok := diskUsage("/var")
			if ok && int(used*100/max(total, 1)) >= c.DiskPrunePercent {
				st.lastDiskAct = time.Now()
				items := planPrune(map[string]bool{"images": true, "logs": true, "tmp": true, "cache": true}, time.Now())
				freed, errs := applyPrune(items)
				fmt.Printf("[%s] /var %d%% full: pruned %s\n", time.Now().Format("15:04:05"), used*100/total, humanBytes(uint64(freed)))
				alertf("high", "disk", "Disk almost full: pruned unused data", map[string]any{
					"path": "/var", "used_percent": used * 100 / total, "freed_bytes": freed, "errors": len(errs)})
			}
		}
	}
}

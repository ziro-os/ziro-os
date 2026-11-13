package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// Container health checks without systemd. nerdctl schedules each container's health check with a
// systemd timer that runs `nerdctl container healthcheck <id>`; Ziro OS has no systemd, so no check
// ever runs and `.State.Health` stays empty (a Coolify deployment with a health check enabled never
// turns healthy). This service runs the same command on the container's schedule. nerdctl itself
// records the result (the nerdctl/healthstate label), so inspect, `ps --filter health=` and the Docker
// API show it as usual.
//
// It also collects the address leases a `docker network connect` of a running container leaves
// behind when that container is removed (see docker_network.go).

const (
	healthLabel      = "nerdctl/healthcheck"
	healthStateLabel = "nerdctl/healthstate"
	// healthStartInterval is how often a container in its start period is checked (Docker's
	// start_interval default), so a service turns healthy soon after it is ready.
	healthStartInterval = 5 * time.Second
	healthTick          = time.Second
	healthMaxParallel   = 8
	leaseCollectEvery   = 5 * time.Minute
)

// healthConfig is nerdctl's Healthcheck label (durations in nanoseconds, as time.Duration marshals).
type healthConfig struct {
	Test        []string      `json:"Test,omitempty"`
	Interval    time.Duration `json:"Interval,omitempty"`
	Timeout     time.Duration `json:"Timeout,omitempty"`
	Retries     int           `json:"Retries,omitempty"`
	StartPeriod time.Duration `json:"StartPeriod,omitempty"`
}

func (h healthConfig) enabled() bool { return len(h.Test) > 0 && h.Test[0] != "NONE" }

// withDefaults is nerdctl's ApplyDefaults (30s interval and timeout, 3 retries, no start period).
func (h healthConfig) withDefaults() healthConfig {
	if h.Interval <= 0 {
		h.Interval = 30 * time.Second
	}
	if h.Timeout <= 0 {
		h.Timeout = 30 * time.Second
	}
	if h.Retries <= 0 {
		h.Retries = 3
	}
	return h
}

// healthTarget is a running container with a health check.
type healthTarget struct {
	ID  string
	Pid uint32
	HC  healthConfig
}

type healthEntry struct {
	pid     uint32
	started time.Time // when this task was first seen
	next    time.Time
	busy    bool
}

// healthScheduler decides which checks are due. It is pure (the clock is passed in) for tests.
type healthScheduler struct {
	mu      sync.Mutex
	entries map[string]*healthEntry
}

func newHealthScheduler() *healthScheduler {
	return &healthScheduler{entries: map[string]*healthEntry{}}
}

// interval is the time to the next check: the start interval while in the start period, else the
// configured one.
func (h healthConfig) intervalAt(sinceStart time.Duration) time.Duration {
	if sinceStart < h.StartPeriod && healthStartInterval < h.Interval {
		return healthStartInterval
	}
	return h.Interval
}

// due returns the targets whose check should start now and marks them busy. A container seen for the
// first time, or restarted (new pid), starts its schedule again; containers that are gone are dropped.
func (s *healthScheduler) due(now time.Time, targets []healthTarget) []healthTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []healthTarget
	for _, t := range targets {
		seen[t.ID] = true
		hc := t.HC.withDefaults()
		e := s.entries[t.ID]
		if e == nil || e.pid != t.Pid {
			e = &healthEntry{pid: t.Pid, started: now, next: now.Add(hc.intervalAt(0))}
			s.entries[t.ID] = e
		}
		if e.busy || now.Before(e.next) {
			continue
		}
		e.busy = true
		out = append(out, t)
	}
	for id := range s.entries {
		if !seen[id] {
			delete(s.entries, id)
		}
	}
	return out
}

// done records that a check finished and schedules the next one.
func (s *healthScheduler) done(id string, hc healthConfig, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[id]; e != nil {
		e.busy = false
		e.next = now.Add(hc.withDefaults().intervalAt(now.Sub(e.started)))
	}
}

// healthTargets lists the running containers that have a health check.
func healthTargets(ctx context.Context, c *ctrdClient) ([]healthTarget, error) {
	list, err := c.Containers(ctx, `labels."`+healthLabel+`"`)
	if err != nil {
		return nil, err
	}
	var out []healthTarget
	for _, ct := range list {
		var hc healthConfig
		if json.Unmarshal([]byte(ct.Labels[healthLabel]), &hc) != nil || !hc.enabled() {
			continue
		}
		t, err := c.Task(ctx, ct.ID)
		if err != nil || t.Status != ctrdTaskRunning {
			continue
		}
		out = append(out, healthTarget{ID: ct.ID, Pid: t.Pid, HC: hc})
	}
	return out, nil
}

// runHealthcheck runs one check the way nerdctl's systemd timer does.
func runHealthcheck(ctx context.Context, id string, hc healthConfig) error {
	ctx, cancel := context.WithTimeout(ctx, hc.withDefaults().Timeout+15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nerdctl", "container", "healthcheck", id).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(sanitizeLabel(string(out), 200)))
	}
	return nil
}

// collectLeases removes the address leases of containers that no longer exist (docker_network.go).
func collectLeases(ctx context.Context, c *ctrdClient) {
	list, err := c.Containers(ctx)
	if err != nil {
		return
	}
	exists, running := map[string]bool{}, map[string]bool{}
	for _, ct := range list {
		exists[ct.ID] = true
		if t, err := c.Task(ctx, ct.ID); err == nil && t.Status == ctrdTaskRunning {
			running[ct.ID] = true
		}
	}
	for _, l := range releaseStaleCNILeases(cniCacheDir, c.namespace, running, exists) {
		log.Printf("released the address lease %s of a removed container", l)
	}
}

func serveContainerHealth(ctx context.Context) error {
	c := newCtrdClient(containerdSocket, containerdNamespace())
	sched := newHealthScheduler()
	slots := make(chan struct{}, healthMaxParallel)
	tick := time.NewTicker(healthTick)
	defer tick.Stop()
	lastCollect := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-tick.C:
			if containerdSick() { // each tick would add connections to a daemon that is not accepting them
				continue
			}
			if now.Sub(lastCollect) >= leaseCollectEvery {
				collectLeases(ctx, c)
				lastCollect = now
			}
			targets, err := healthTargets(ctx, c)
			if err != nil {
				continue // containerd is restarting; try again on the next tick
			}
			for _, t := range sched.due(now, targets) {
				slots <- struct{}{}
				go func(t healthTarget) {
					defer func() { <-slots }()
					if err := runHealthcheck(ctx, t.ID, t.HC); err != nil {
						log.Printf("health check of %s: %v", t.ID[:min(12, len(t.ID))], err)
					}
					sched.done(t.ID, t.HC, time.Now())
				}(t)
			}
		}
	}
}

var containerHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Run container health checks without systemd",
	Long: `Runs each running container's health check on its schedule, as nerdctl's systemd timers would, so
inspect, ps and the Docker API report healthy or unhealthy. It runs as the container-health service.`,
	Example: "  ziroctl container health serve",
}

var containerHealthServeCmd = &cobra.Command{
	Use:     "serve",
	Short:   "Run the health check scheduler in the foreground",
	Example: "  ziroctl container health serve",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serveContainerHealth(cmd.Context())
	},
}

func init() {
	containerHealthCmd.AddCommand(containerHealthServeCmd)
	containerCmd.AddCommand(containerHealthCmd)
}

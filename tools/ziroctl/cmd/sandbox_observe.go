package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// Seeing what sandboxes do: list filters, resource usage (read from the container's cgroup, as
// `ziroctl top` does) and the main command's output.

var sandboxStates = []string{"pending", "running", "paused", "failed"}

// filterSandboxes keeps the sandboxes that match ?state= and every ?label=key[=value]. The
// daemon and a cluster master (on the merged list) both filter with it.
func filterSandboxes(list []sdkapi.Sandbox, q url.Values) ([]sdkapi.Sandbox, error) {
	state := q.Get("state")
	if state != "" && !slices.Contains(sandboxStates, state) {
		return nil, fmt.Errorf("state: one of %s", strings.Join(sandboxStates, ", "))
	}
	labels := q["label"]
	if len(labels) > 16 {
		return nil, fmt.Errorf("at most 16 labels")
	}
	out := []sdkapi.Sandbox{}
	for _, sb := range list {
		if state != "" && sb.State != state {
			continue
		}
		ok := true
		for _, l := range labels {
			k, v, hasV := strings.Cut(l, "=")
			got, has := sb.Spec.Metadata[k]
			if !has || (hasV && got != v) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, sb)
		}
	}
	return out, nil
}

// sandboxStatsSample is how long CPU use is measured over.
var sandboxStatsSample = 500 * time.Millisecond

// stats reads a sandbox's resource use from its container's cgroup.
func (m *sandboxManager) stats(ctx context.Context, id string, c sandboxCaller) (sdkapi.SandboxStats, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sdkapi.SandboxStats{}, err
	}
	if sb.State != "running" && sb.State != "paused" {
		return sdkapi.SandboxStats{}, fmt.Errorf("sandbox %s is %s", id, sb.State)
	}
	out, err := sandboxNerdctl(ctx, "inspect", "--format", "{{.ID}}", sandboxContainer(id))
	if err != nil {
		return sdkapi.SandboxStats{}, fmt.Errorf("inspect: %s", cmdError(out, err))
	}
	dir, ok := containerCgroups()[strings.TrimSpace(string(out))]
	if !ok {
		return sdkapi.SandboxStats{}, fmt.Errorf("sandbox %s: no cgroup found", id)
	}
	cpu0, t0 := kv(filepath.Join(dir, "cpu.stat"), "usage_usec"), time.Now()
	select {
	case <-ctx.Done():
		return sdkapi.SandboxStats{}, ctx.Err()
	case <-time.After(sandboxStatsSample):
	}
	cpu1, dt := kv(filepath.Join(dir, "cpu.stat"), "usage_usec"), time.Since(t0)
	s := sdkapi.SandboxStats{State: sb.State, MemoryBytes: readUint(filepath.Join(dir, "memory.current")),
		MemoryLimit: readUint(filepath.Join(dir, "memory.max")), PIDs: readUint(filepath.Join(dir, "pids.current")),
		CPUPercent: float64(cpu1-min(cpu0, cpu1)) / (float64(dt.Microseconds()) / 100)}
	s.BlockRead, s.BlockWrite = ioBytes(filepath.Join(dir, "io.stat"))
	if procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")); err == nil {
		if pid, _, _ := strings.Cut(string(procs), "\n"); pid != "" {
			s.NetRx, s.NetTx = netBytes(pid)
		}
	}
	return s, nil
}

const sandboxLogsMaxLines = 10000

// logs returns the last lines of the sandbox's main command's output (stdout and stderr).
func (m *sandboxManager) logs(ctx context.Context, id string, c sandboxCaller, tail string) (sdkapi.SandboxLogs, error) {
	if _, err := m.st.get(id, c); err != nil {
		return sdkapi.SandboxLogs{}, err
	}
	n := 200
	if tail != "" {
		var err error
		if n, err = strconv.Atoi(tail); err != nil || n < 1 || n > sandboxLogsMaxLines {
			return sdkapi.SandboxLogs{}, fmt.Errorf("tail: 1 to %d lines", sandboxLogsMaxLines)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := sandboxNerdctl(ctx, "logs", "--tail", strconv.Itoa(n), sandboxContainer(id))
	if err != nil {
		return sdkapi.SandboxLogs{}, fmt.Errorf("logs: %s", cmdError(out, err))
	}
	return sdkapi.SandboxLogs{Logs: clipTail(string(out))}, nil
}

// clipTail keeps the last 4 MiB of an oversized log (lines can be long).
func clipTail(s string) string {
	const max = 4 << 20
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}

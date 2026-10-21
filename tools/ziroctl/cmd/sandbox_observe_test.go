package cmd

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

func TestFilterSandboxes(t *testing.T) {
	list := []sdkapi.Sandbox{
		{ID: "a", State: "running", Spec: schema.SandboxSpec{Metadata: map[string]string{"task": "1", "agent": "x"}}},
		{ID: "b", State: "paused", Spec: schema.SandboxSpec{Metadata: map[string]string{"task": "2"}}},
		{ID: "c", State: "running"},
	}
	ids := func(q string) string {
		v, _ := url.ParseQuery(q)
		out, err := filterSandboxes(list, v)
		if err != nil {
			return "error"
		}
		var s []string
		for _, sb := range out {
			s = append(s, sb.ID)
		}
		return strings.Join(s, ",")
	}
	for q, want := range map[string]string{
		"":                         "a,b,c",
		"state=running":            "a,c",
		"label=task":               "a,b",
		"label=task=2":             "b",
		"label=task=1&label=agent": "a",
		"state=paused&label=agent": "",
		"state=gone":               "error",
	} {
		if got := ids(q); got != want {
			t.Errorf("%q: %q, want %q", q, got, want)
		}
	}
}

// Stats come from the sandbox container's cgroup; logs from nerdctl logs, bounded.
func TestSandboxStatsAndLogs(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	sb, err := m.create(context.Background(), schema.SandboxSpec{Image: "a", Command: []string{"server"}}, alice)
	if err != nil {
		t.Fatal(err)
	}
	cid := strings.Repeat("ab", 32)
	oldCg, oldSample := cgroupRoot, sandboxStatsSample
	cgroupRoot, sandboxStatsSample = t.TempDir(), 10*time.Millisecond
	defer func() { cgroupRoot, sandboxStatsSample = oldCg, oldSample }()
	dir := filepath.Join(cgroupRoot, "default", cid)
	os.MkdirAll(dir, 0755)
	for name, v := range map[string]string{"memory.current": "1048576", "memory.max": "1073741824", "pids.current": "3",
		"cpu.stat": "usage_usec 5000\n", "io.stat": "8:0 rbytes=100 wbytes=200 rios=1 wios=1\n"} {
		os.WriteFile(filepath.Join(dir, name), []byte(v), 0644)
	}
	real := sandboxNerdctl
	sandboxNerdctl = func(ctx context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "inspect":
			return []byte(cid + "\n"), nil
		case "logs":
			return []byte("listening on :8080\n"), nil
		}
		return real(ctx, args...)
	}
	s, err := m.stats(context.Background(), sb.ID, alice)
	if err != nil || s.MemoryBytes != 1<<20 || s.MemoryLimit != 1<<30 || s.PIDs != 3 || s.BlockRead != 100 || s.BlockWrite != 200 || s.State != "running" {
		t.Fatalf("stats %+v %v", s, err)
	}
	if _, err := m.stats(context.Background(), sb.ID, bob); err == nil {
		t.Error("bob read alice's stats")
	}
	l, err := m.logs(context.Background(), sb.ID, alice, "50")
	if err != nil || l.Logs != "listening on :8080\n" {
		t.Fatalf("logs %+v %v", l, err)
	}
	for _, bad := range []string{"0", "x", "10001"} {
		if _, err := m.logs(context.Background(), sb.ID, alice, bad); err == nil {
			t.Errorf("tail %q accepted", bad)
		}
	}
	if len(clipTail(strings.Repeat("x", 5<<20))) != 4<<20 {
		t.Error("clipTail")
	}
}

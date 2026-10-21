package cmd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

func stubTemplates(t *testing.T) {
	old := sandboxTemplateDir
	sandboxTemplateDir = filepath.Join(t.TempDir(), "templates")
	t.Cleanup(func() { sandboxTemplateDir = old })
}

func TestSandboxTemplates(t *testing.T) {
	stubTemplates(t)
	tpl := schema.SandboxSpec{Image: "python:3.13-slim", Env: map[string]string{"A": "1", "B": "2"},
		Network: &schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org"}}, Metadata: map[string]string{"kind": "py"}}
	if err := saveTemplate("python", tpl); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]schema.SandboxSpec{
		"no image": {},
		"nested":   {Image: "a", Template: "python"},
		"secrets":  {Image: "a", Network: &schema.SandboxNetwork{Mode: "open"}, Secrets: []schema.SandboxSecret{{Name: "T", Hosts: []string{"a.com"}}}},
		"bad spec": {Image: "--x"},
	} {
		if saveTemplate("x", bad) == nil {
			t.Errorf("%s: saved", name)
		}
	}
	if saveTemplate("../etc", tpl) == nil {
		t.Error("a path as a template name")
	}
	s, err := applyTemplate(schema.SandboxSpec{Template: "python", Env: map[string]string{"B": "x"}, Metadata: map[string]string{"task": "7"}, Timeout: "10m"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Image != "python:3.13-slim" || s.Env["A"] != "1" || s.Env["B"] != "x" || s.Metadata["kind"] != "py" || s.Metadata["task"] != "7" ||
		s.Timeout != "10m" || s.Network.Allow[0] != "pypi.org" {
		t.Errorf("merged %+v", s)
	}
	if _, err := applyTemplate(schema.SandboxSpec{Template: "nope"}); err == nil {
		t.Error("missing template")
	}
	if ts := listTemplates(); len(ts) != 1 || ts["python"].Image != "python:3.13-slim" {
		t.Errorf("list %v", ts)
	}
}

func TestSandboxWarmPool(t *testing.T) {
	m, f, _ := stubSandboxes(t)
	stubTemplates(t)
	saveTemplate("py", schema.SandboxSpec{Image: "python:3"})
	os.WriteFile(sandboxConfigFile, []byte(`{"pools":{"py":2}}`), 0600)
	cfg, err := loadSandboxConfig()
	if err != nil {
		t.Fatal(err)
	}
	m.fillPools(cfg)
	for deadline := time.Now().Add(5 * time.Second); poolFilling.Load() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	pooled := 0
	for _, sb := range m.st.list(ops) {
		if sb.Owner == "pool:py" && sb.State == "paused" {
			pooled++
		}
	}
	if pooled != 2 {
		t.Fatalf("%d pooled sandboxes", pooled)
	}
	m.reconcile(context.Background()) // paused pool sandboxes are alive, not failed
	for _, sb := range m.st.list(ops) {
		if sb.State != "paused" {
			t.Fatalf("pool sandbox %s after the reaper: %s", sb.ID, sb.State)
		}
	}
	runs := func() int {
		return len(slices.DeleteFunc(slices.Clone(f.calls), func(c []string) bool { return c[0] != "run" }))
	}
	before := runs()
	// A plain template create is served by the pool: resumed, handed over, no container start.
	sb, err := m.create(context.Background(), schema.SandboxSpec{Template: "py", Timeout: "20m", Metadata: map[string]string{"task": "1"}}, alice)
	if err != nil || sb.Owner != "alice" || sb.State != "running" || sb.Spec.Metadata["task"] != "1" || runs() != before {
		t.Fatalf("claim: %+v %v (runs %d -> %d)", sb, err, before, runs())
	}
	if !slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "unpause" }) {
		t.Error("not resumed")
	}
	if got, _ := m.st.get(sb.ID, alice); got.Expires.Sub(got.Created) != 20*time.Minute {
		t.Errorf("lifetime %v", got.Expires.Sub(got.Created))
	}
	// Anything fixed at create (env) can't come from the pool.
	sb2, err := m.create(context.Background(), schema.SandboxSpec{Template: "py", Env: map[string]string{"X": "1"}}, alice)
	if err != nil || runs() != before+1 || sb2.Spec.Env["X"] != "1" {
		t.Errorf("non-claimable create: %v runs %d", err, runs())
	}
	if poolClaimable(schema.SandboxSpec{Image: "python:3"}) || !poolClaimable(schema.SandboxSpec{Template: "py", IdleTimeout: "5m"}) {
		t.Error("poolClaimable")
	}
	os.WriteFile(sandboxConfigFile, []byte(`{"pools":{"py":100}}`), 0600)
	if _, err := loadSandboxConfig(); err == nil {
		t.Error("a pool bigger than max_per_owner")
	}
}

func TestSandboxSnapshots(t *testing.T) {
	m, f, _ := stubSandboxes(t)
	sb, _ := m.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	ws := filepath.Join(sandboxDir(sb.ID), "workspace")
	os.MkdirAll(filepath.Join(ws, ".venv/bin"), 0755)
	os.WriteFile(filepath.Join(ws, "main.py"), []byte("print(1)"), 0640)
	os.WriteFile(filepath.Join(ws, ".venv/bin/run"), []byte("#!/bin/sh"), 0755)
	os.Symlink("/usr/bin/python3", filepath.Join(ws, ".venv/bin/python")) // venvs link out: kept verbatim
	snap, err := m.snapshot(context.Background(), sb.ID, alice, "deps")
	if err != nil || !strings.HasPrefix(snap.Image, "ziro.local/sandbox/alice/deps:") || snap.WorkspaceSize == 0 {
		t.Fatalf("%+v %v", snap, err)
	}
	// A running sandbox is flushed and frozen around the commit, and thawed after.
	var verbs []string
	for _, c := range f.calls[len(f.calls)-4:] {
		verbs = append(verbs, strings.Join(c[:min(len(c), 2)], " "))
	}
	if want := []string{"exec " + sandboxContainer(sb.ID), "pause " + sandboxContainer(sb.ID), "commit --pause=false", "unpause " + sandboxContainer(sb.ID)}; !slices.Equal(verbs, want) {
		t.Errorf("snapshot calls %v, want %v", verbs, want)
	}
	if got, _ := m.st.get(sb.ID, alice); got.State != "running" || f.ps[sandboxContainer(sb.ID)] == "Paused" {
		t.Errorf("after the snapshot: %s / %s", got.State, f.ps[sandboxContainer(sb.ID)])
	}
	// A paused sandbox stays paused: no pause of its own, and commit mustn't pause it.
	m.setPaused(context.Background(), sb.ID, alice, true)
	n := len(f.calls)
	if _, err := m.snapshot(context.Background(), sb.ID, alice, "paused"); err != nil {
		t.Fatal(err)
	}
	if c := f.calls[n:]; len(c) != 1 || c[0][0] != "commit" || c[0][1] != "--pause=false" {
		t.Errorf("snapshot of a paused sandbox: %v", c)
	}
	m.setPaused(context.Background(), sb.ID, alice, false)
	if _, err := m.snapshot(context.Background(), sb.ID, alice, "Bad Name"); err == nil {
		t.Error("bad name")
	}
	if _, err := m.snapshot(context.Background(), sb.ID, bob, "x"); err == nil {
		t.Error("bob snapshotted alice's sandbox")
	}
	// A sandbox started from it has the workspace back: content, modes, links.
	fork, err := m.create(context.Background(), schema.SandboxSpec{Image: snap.Image}, alice)
	if err != nil {
		t.Fatal(err)
	}
	fws := filepath.Join(sandboxDir(fork.ID), "workspace")
	if b, _ := os.ReadFile(filepath.Join(fws, "main.py")); string(b) != "print(1)" {
		t.Errorf("main.py = %q", b)
	}
	if fi, err := os.Stat(filepath.Join(fws, "main.py")); err != nil || fi.Mode().Perm() != 0640 {
		t.Errorf("main.py mode %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(fws, ".venv/bin/run")); err != nil || fi.Mode().Perm() != 0755 {
		t.Errorf("run mode %v %v", fi, err)
	}
	if l, err := os.Readlink(filepath.Join(fws, ".venv/bin/python")); l != "/usr/bin/python3" {
		t.Errorf("symlink %q %v", l, err)
	}
	// Starting from a snapshot: one's own (no image policy), never another owner's.
	os.WriteFile(sandboxConfigFile, []byte(`{"image_policy":{"allow_registries":["ghcr.io/acme"]}}`), 0600)
	if _, err := m.create(context.Background(), schema.SandboxSpec{Image: snap.Image}, alice); err != nil {
		t.Errorf("own snapshot: %v", err)
	}
	if _, err := m.create(context.Background(), schema.SandboxSpec{Image: snap.Image}, bob); err == nil {
		t.Error("bob started from alice's snapshot")
	}
	if _, err := m.create(context.Background(), schema.SandboxSpec{Image: "docker.io/library/alpine"}, alice); err == nil {
		t.Error("the image policy no longer applies")
	}
	f.images = "ziro.local/sandbox/alice/deps:1760000000\t120MB\nziro.local/sandbox/bob/x:1\t5MB\npython:3\t50MB\n"
	if l, _ := m.snapshots(context.Background(), alice); len(l) != 1 || l[0].Image != "ziro.local/sandbox/alice/deps:1760000000" || l[0].Created.Unix() != 1760000000 {
		t.Errorf("alice's list %+v", l)
	}
	if l, _ := m.snapshots(context.Background(), ops); len(l) != 2 {
		t.Errorf("operator's list %+v", l)
	}
	if m.removeSnapshot(context.Background(), bob, "ziro.local/sandbox/alice/deps:1760000000") == nil || m.removeSnapshot(context.Background(), alice, "python:3") == nil {
		t.Error("removed someone else's image")
	}
	if err := m.removeSnapshot(context.Background(), alice, "ziro.local/sandbox/alice/deps:1760000000"); err != nil {
		t.Error(err)
	}
	// Removing a snapshot removes its workspace archive too.
	f.images = snap.Image + "\t1MB\n"
	if err := m.removeSnapshot(context.Background(), alice, snap.Image); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshotArchive(snap.Image)); !os.IsNotExist(err) {
		t.Errorf("archive left: %v", err)
	}
}

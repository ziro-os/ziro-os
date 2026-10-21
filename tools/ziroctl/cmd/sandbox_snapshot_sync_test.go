package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// A snapshot exported by one node imports on another with its image and /workspace; an archive
// whose image isn't a snapshot is refused before anything is loaded.
func TestSnapshotExportImport(t *testing.T) {
	m, f, _ := stubSandboxes(t)
	sb, _ := m.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	os.WriteFile(filepath.Join(sandboxDir(sb.ID), "workspace", "data"), []byte("kept"), 0644)
	snap, err := m.snapshot(context.Background(), sb.ID, alice, "deps")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	m.exportSnapshot(w, httptest.NewRequest("GET", "/v1/snapshots/export?image="+snap.Image, nil))
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body)
	}
	export := w.Body.Bytes()

	// "Another node": the image and the archive are gone here, then imported back.
	f.images = ""
	arc := snapshotArchive(snap.Image)
	os.Remove(arc)
	ref, err := m.importSnapshotTar(context.Background(), bytes.NewReader(export))
	if err != nil || ref != snap.Image {
		t.Fatalf("import: %q %v", ref, err)
	}
	if !strings.Contains(f.images, snap.Image) {
		t.Error("the image wasn't loaded")
	}
	fork, err := m.create(context.Background(), schema.SandboxSpec{Image: snap.Image}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(sandboxDir(fork.ID), "workspace", "data")); string(b) != "kept" {
		t.Errorf("workspace after import: %q", b)
	}

	// Not a snapshot image: refused, nothing loaded.
	bad := filepath.Join(t.TempDir(), "bad.tar")
	writeImageTar(bad, "docker.io/library/evil:latest")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tarFile(tw, "image.tar", bad)
	tw.Close()
	loads := len(f.calls)
	if _, err := m.importSnapshotTar(context.Background(), &buf); err == nil || !strings.Contains(err.Error(), "not a snapshot image") {
		t.Errorf("foreign image: %v", err)
	}
	for _, c := range f.calls[loads:] {
		if c[0] == "load" {
			t.Error("a foreign image was loaded")
		}
	}
	if _, err := m.importSnapshotTar(context.Background(), strings.NewReader("not a tar")); err == nil {
		t.Error("garbage imported")
	}
	// Export of an image that isn't a snapshot here: not found.
	w = httptest.NewRecorder()
	m.exportSnapshot(w, httptest.NewRequest("GET", "/v1/snapshots/export?image=python:3", nil))
	if w.Code != 404 {
		t.Errorf("export of a non-snapshot: %d", w.Code)
	}
}

// A master lists a snapshot held by several nodes once, with how many hold it.
func TestMergeSnapshots(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	got := mergeSnapshots([]json.RawMessage{raw(`{"image":"ziro.local/sandbox/a/x:1"}`), raw(`{"image":"ziro.local/sandbox/a/x:1"}`),
		raw(`{"image":"ziro.local/sandbox/a/y:2"}`), raw(`bogus`)})
	if len(got) != 2 || got[0].Nodes != 2 || got[1].Nodes != 1 {
		t.Errorf("%+v", got)
	}
}

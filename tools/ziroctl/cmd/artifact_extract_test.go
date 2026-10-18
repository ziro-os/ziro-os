package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTarMember(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "./bin/", Typeflag: tar.TypeDir, Mode: 0755})
	tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
	tw.WriteHeader(&tar.Header{Name: "./tool", Typeflag: tar.TypeReg, Mode: 0755, Size: 5})
	tw.Write([]byte("hello"))
	tw.Close()
	gz.Close()
	archive := filepath.Join(dir, "a.tar.gz")
	os.WriteFile(archive, buf.Bytes(), 0600)

	dst := filepath.Join(dir, "tool")
	if err := extractTarMember(archive, "tool", dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "hello" {
		t.Fatalf("got %q", b)
	}
	if err := extractTarMember(archive, "link", dst); err == nil {
		t.Error("a symlink member was extracted")
	}
	if err := extractTarMember(archive, "missing", dst); err == nil {
		t.Error("a missing member passed")
	}
	os.WriteFile(archive, []byte("not an archive"), 0600)
	if err := extractTarMember(archive, "tool", dst); err == nil {
		t.Error("a non-archive passed")
	}
	// The real gVisor release (bzip2), when a copy is at hand: ZIRO_TEST_BZ2=path/to/gvisor-x86_64.tar.bz2
	if p := os.Getenv("ZIRO_TEST_BZ2"); p != "" {
		if err := extractTarMember(p, "runsc", filepath.Join(dir, "runsc")); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(filepath.Join(dir, "runsc")); err != nil || fi.Size() < 10<<20 {
			t.Fatalf("runsc: %v", err)
		}
	}
}

// Two files from one archive: one download, both extracted, and nothing downloaded again once
// they are in place.
func TestArtifactsShareOneArchive(t *testing.T) {
	root, _, _ := stubModules(t)
	moduleDirRoot = root
	defer func() { moduleDirRoot = "" }()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []string{"runsc", "gvisor-bin/gvisor_sentry"} {
		tw.WriteHeader(&tar.Header{Name: f, Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(f))})
		tw.Write([]byte(f))
	}
	tw.Close()
	gz.Close()
	downloads := 0
	artifactDownload = func(u, dst string, max int64) (string, error) {
		downloads++
		return sha256Hex(buf.Bytes()), os.WriteFile(dst, buf.Bytes(), 0600)
	}
	defer func() { artifactDownload = catalogDownload }()
	sum := sha256Hex(buf.Bytes())
	m := ModuleManifest{Name: "sbx", Artifacts: []ModuleArtifact{
		{URL: "https://example.com/g.tar.gz", SHA256: sum, Extract: "runsc", Path: "/var/lib/ziro/plugins/sbx/runsc", Mode: "0755"},
		{URL: "https://example.com/g.tar.gz", SHA256: sum, Extract: "gvisor-bin/gvisor_sentry", Path: "/var/lib/ziro/plugins/sbx/gvisor-bin/gvisor_sentry", Mode: "0755"},
	}}
	st := &ModuleState{}
	for i := 0; i < 2; i++ {
		if err := fetchArtifacts(m, st); err != nil {
			t.Fatal(err)
		}
	}
	if downloads != 1 {
		t.Errorf("%d downloads", downloads)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "var/lib/ziro/plugins/sbx/gvisor-bin/gvisor_sentry")); string(b) != "gvisor-bin/gvisor_sentry" {
		t.Errorf("sidecar %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(root, "var/lib/ziro/plugins/sbx/*.dl")); len(left) > 0 {
		t.Errorf("archive left behind: %v", left)
	}
}

package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func names(t *testing.T, b []byte) []string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			slices.Sort(out)
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, h.Name)
	}
}

func write(t *testing.T, dir string, files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPackDir(t *testing.T) {
	dir := t.TempDir() // not a git work tree: the default skips apply
	write(t, dir, "package.json", "src/a.js", ".env", ".env.local", "node_modules/x/i.js", ".git/config", ".next/b")
	os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	var b bytes.Buffer
	n, err := Pack(dir, &b, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(t, b.Bytes()); !slices.Equal(got, []string{"package.json", "src/a.js"}) || n != 2 {
		t.Fatalf("packed %v (%d)", got, n)
	}
}

func TestPackFileAndLimits(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "index.html", "b.txt")
	var b bytes.Buffer
	if _, err := Pack(filepath.Join(dir, "index.html"), &b, 100); err != nil {
		t.Fatal(err)
	}
	if got := names(t, b.Bytes()); !slices.Equal(got, []string{"index.html"}) {
		t.Fatalf("single file packed %v", got)
	}
	if _, err := Pack(dir, io.Discard, 1); err == nil {
		t.Error("the file limit isn't enforced")
	}
	if _, err := Pack(filepath.Join(dir, "missing"), io.Discard, 10); err == nil {
		t.Error("a missing path packed")
	}
}

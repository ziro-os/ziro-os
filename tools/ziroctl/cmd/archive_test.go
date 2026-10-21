package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEnt struct {
	name string
	typ  byte
	body string
	link string
}

func mkTarGz(t *testing.T, ents ...tarEnt) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		if e.typ == 0 {
			e.typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0644, Linkname: e.link}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return bytes.NewReader(buf.Bytes())
}

func TestExtractTarGz(t *testing.T) {
	dst := t.TempDir()
	err := extractTarGz(dst, mkTarGz(t,
		tarEnt{name: "./", typ: tar.TypeDir},
		tarEnt{name: "./index.html", body: "hi"},
		tarEnt{name: "src/app/page.js", body: "x"}), 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "src/app/page.js")); string(b) != "x" {
		t.Fatalf("page.js = %q", b)
	}

	bad := map[string]struct {
		ents []tarEnt
		want string
	}{
		"traversal": {[]tarEnt{{name: "../evil"}}, "bad name"},
		"absolute":  {[]tarEnt{{name: "/etc/passwd"}}, "bad name"},
		"nested ..": {[]tarEnt{{name: "a/../../evil"}}, "bad name"},
		"symlink":   {[]tarEnt{{name: "l", typ: tar.TypeSymlink, link: "/etc"}}, "isn't allowed"},
		"hardlink":  {[]tarEnt{{name: "l", typ: tar.TypeLink, link: "x"}}, "isn't allowed"},
		"device":    {[]tarEnt{{name: "d", typ: tar.TypeChar}}, "isn't allowed"},
		"too big":   {[]tarEnt{{name: "a", body: strings.Repeat("x", 200)}}, "expands beyond"},
		"too many":  {[]tarEnt{{name: "a"}, {name: "b"}, {name: "c"}}, "more than"},
		"duplicate": {[]tarEnt{{name: "a"}, {name: "a"}}, "member"},
		"backslash": {[]tarEnt{{name: `a\b`}}, "bad name"},
	}
	for name, c := range bad {
		d := t.TempDir()
		err := extractTarGz(d, mkTarGz(t, c.ents...), 100, 2)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if err := extractTarGz(t.TempDir(), strings.NewReader("plain text"), 1<<20, 10); err == nil {
		t.Error("a non-gzip body was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil")); err == nil {
		t.Error("a member escaped the destination")
	}
}

// A workspace archive round-trips files, modes and symlinks; a link can't carry a later member
// out of the destination.
func TestWorkspaceArchive(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "d/e"), 0700)
	os.WriteFile(filepath.Join(src, "d/e/f"), []byte("data"), 0600)
	os.Symlink("../../etc", filepath.Join(src, "d/out"))
	root, _ := os.OpenRoot(src)
	defer root.Close()
	var buf bytes.Buffer
	if err := tarGzDir(root, &buf, 1<<20, 10); err != nil {
		t.Fatal(err)
	}
	if err := tarGzDir(root, io.Discard, 1<<20, 2); err == nil {
		t.Error("entry cap")
	}
	if err := tarGzDir(root, io.Discard, 2, 10); err == nil {
		t.Error("byte cap")
	}
	dst := t.TempDir()
	o := untarOpts{maxBytes: 1 << 20, maxFiles: 10, links: true, owners: true}
	if err := untarGz(dst, bytes.NewReader(buf.Bytes()), o); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "d/e")); err != nil || fi.Mode().Perm() != 0700 {
		t.Errorf("dir %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "d/e/f")); string(b) != "data" {
		t.Errorf("file %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "d/out")); l != "../../etc" {
		t.Errorf("link %q", l)
	}
	err := untarGz(t.TempDir(), mkTarGz(t, tarEnt{name: "l", typ: tar.TypeSymlink, link: "/etc"}, tarEnt{name: "l/passwd", body: "x"}), o)
	if err == nil {
		t.Error("a member was written through a symlink out of the destination")
	}
	if err := untarGz(t.TempDir(), mkTarGz(t, tarEnt{name: "../l", typ: tar.TypeSymlink, link: "x"}), o); err == nil {
		t.Error("a link named out of the destination")
	}
}

package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cpioEntry struct {
	name  string
	mode  uint32
	data  string
	ino   uint32
	nlink uint32
}

const (
	cReg = 0100644
	cExe = 0100755
	cDir = 040755
	cLnk = 0120777
)

// writeCpio writes a gzip'd newc archive, the format of the release initramfs.
func writeCpio(t *testing.T, path string, entries []cpioEntry) {
	t.Helper()
	var raw bytes.Buffer
	emit := func(e cpioEntry) {
		nlink := e.nlink
		if nlink == 0 {
			nlink = 1
		}
		name := e.name + "\x00"
		fmt.Fprintf(&raw, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			e.ino, e.mode, 0, 0, nlink, 0, len(e.data), 0, 0, 0, 0, len(name), 0)
		raw.WriteString(name)
		raw.Write(make([]byte, pad4(110+len(name))))
		raw.WriteString(e.data)
		raw.Write(make([]byte, pad4(len(e.data))))
	}
	for i, e := range entries {
		if e.ino == 0 {
			e.ino = uint32(i + 1000)
		}
		emit(e)
	}
	emit(cpioEntry{name: "TRAILER!!!"})
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(raw.Bytes())
	w.Close()
	if err := os.WriteFile(path, gz.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// snapshot maps every regular file / symlink under root to its content,
// ignoring upgrade bookkeeping and GRUB configs (the previous entry stays).
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		if rel == upgradeRelDir || strings.HasPrefix(rel, "boot/grub") {
			return fs.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 {
			l, _ := os.Readlink(p)
			out[rel] = "-> " + l
		} else if d.Type().IsRegular() {
			out[rel] = readFile(t, p)
		}
		return nil
	})
	return out
}

func TestExtractRejectsUnsafeMembers(t *testing.T) {
	cases := map[string][]cpioEntry{
		"traversal": {{name: "../escape", mode: cReg, data: "x"}},
		"through symlink": {
			{name: "etc", mode: cLnk, data: "/etc"},
			{name: "etc/passwd", mode: cReg, data: "x"},
		},
		"dir over symlink": {
			{name: "lib", mode: cLnk, data: "/tmp"},
			{name: "lib", mode: cDir},
		},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			img := filepath.Join(dir, "img.cpio.gz")
			writeCpio(t, img, entries)
			if err := extractInitramfs(img, filepath.Join(dir, "out")); err == nil {
				t.Fatal("expected extraction to be refused")
			}
		})
	}
}

func TestExtractFilesLinksAndHardlinks(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "img.cpio.gz")
	writeCpio(t, img, []cpioEntry{
		{name: ".", mode: cDir},
		{name: "./bin", mode: cDir},
		{name: "./bin/busybox", mode: cExe, data: "BB"},
		{name: "./bin/sh", mode: cLnk, data: "busybox"},
		{name: "./usr/bin/a", mode: cReg, ino: 7, nlink: 2},                 // data comes later
		{name: "./usr/bin/b", mode: cReg, data: "shared", ino: 7, nlink: 2}, // data carrier
		{name: "./usr/bin/c", mode: cReg, data: "first", ino: 8, nlink: 2},  // data first
		{name: "./usr/bin/d", mode: cReg, ino: 8, nlink: 2},
	})
	out := filepath.Join(dir, "out")
	if err := extractInitramfs(img, out); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(out, "bin/busybox")); got != "BB" {
		t.Errorf("busybox = %q", got)
	}
	if fi, _ := os.Stat(filepath.Join(out, "bin/busybox")); fi.Mode().Perm() != 0755 {
		t.Errorf("busybox mode = %v", fi.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(out, "bin/sh")); l != "busybox" {
		t.Errorf("sh -> %q", l)
	}
	for _, pair := range [][2]string{{"a", "b"}, {"c", "d"}} {
		a, _ := os.Stat(filepath.Join(out, "usr/bin", pair[0]))
		b, _ := os.Stat(filepath.Join(out, "usr/bin", pair[1]))
		if a == nil || b == nil || !os.SameFile(a, b) {
			t.Errorf("%s and %s should be hardlinked", pair[0], pair[1])
		}
	}
	if got := readFile(t, filepath.Join(out, "usr/bin/a")); got != "shared" {
		t.Errorf("hardlink a = %q", got)
	}
}

func newRelease(ver, arch string) string {
	return fmt.Sprintf("NAME=\"Ziro-OS\"\nVERSION=\"%s\"\nARCH=\"%s\"\nKERNEL_FLAVOR=\"alpine\"\n", ver, arch)
}

func oldRoot(t *testing.T) string {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/ziro-release":          newRelease("1.0.9", "x86_64"),
		"etc/ziro-installed":        "2026-01-01",
		"etc/x":                     "local-config",
		"etc/ssh/sshd_config":       "PasswordAuthentication no",
		"bin/busybox":               "old-busybox",
		"bin/old-only":              "legacy",
		"lib/modules/6.1/m.ko":      "old-module",
		"var/lib/containerd/data":   "container-state",
		"root/.ssh/authorized_keys": "ssh-ed25519 AAAA",
		"boot/vmlinuz":              "kernel-1",
		"boot/initramfs.cpio.gz":    "initramfs-1",
		"boot/grub/grub.cfg":        "menuentry \"Ziro-OS Container Host\" {}\n",
	})
	return root
}

func newImage(t *testing.T, arch string) string {
	img := filepath.Join(t.TempDir(), "ziro-initramfs.cpio.gz")
	writeCpio(t, img, []cpioEntry{
		{name: "etc/ziro-release", mode: cReg, data: newRelease("1.1.0", arch)},
		{name: "etc/x", mode: cReg, data: "image-default"},
		{name: "etc/y", mode: cReg, data: "new-file"},
		{name: "etc/ssh/sshd_config", mode: cReg, data: "PasswordAuthentication yes"},
		{name: "sbin/init", mode: cExe, data: "init-2"},
		{name: "bin/busybox", mode: cExe, data: "new-busybox"},
		{name: "usr/bin/ziroctl", mode: cExe, data: "ziroctl-2"},
		{name: "lib/modules/6.6/m.ko", mode: cReg, data: "new-module"},
		{name: "boot/vmlinuz", mode: cReg, data: "kernel-2"},
		{name: "var/empty", mode: 040700},
		{name: "var/lib/containerd/data", mode: cReg, data: "image-must-not-win"},
		{name: "root/.ssh/authorized_keys", mode: cReg, data: "image-must-not-win"},
	})
	return img
}

func TestApplyUpgradeAndRollback(t *testing.T) {
	root := oldRoot(t)
	before := snapshot(t, root)
	img := newImage(t, "x86_64")

	state, err := applyUpgrade(root, img)
	if err != nil {
		t.Fatal(err)
	}
	if state.From != "1.0.9" || state.To != "1.1.0" || state.Status != "applied" {
		t.Fatalf("state = %+v", state)
	}
	want := map[string]string{
		"bin/busybox":                 "new-busybox",
		"usr/bin/ziroctl":             "ziroctl-2",
		"bin/old-only":                "legacy",     // not in image: left alone
		"lib/modules/6.1/m.ko":        "old-module", // previous kernel stays bootable
		"lib/modules/6.6/m.ko":        "new-module",
		"etc/x":                       "local-config", // local config wins
		"etc/ssh/sshd_config":         "PasswordAuthentication no",
		"etc/y":                       "new-file", // new defaults are added
		"var/lib/containerd/data":     "container-state",
		"root/.ssh/authorized_keys":   "ssh-ed25519 AAAA",
		"boot/vmlinuz":                "kernel-2",
		"boot/vmlinuz.prev":           "kernel-1",
		"boot/initramfs.cpio.gz.prev": "initramfs-1",
		filepath.Join(upgradeRelDir, "rollback/bin/busybox"): "old-busybox",
	}
	for rel, w := range want {
		if got := readFile(t, filepath.Join(root, rel)); got != w {
			t.Errorf("%s = %q, want %q", rel, got, w)
		}
	}
	if readRelease(filepath.Join(root, "etc/ziro-release"))["VERSION"] != "1.1.0" {
		t.Error("ziro-release not updated")
	}
	if readFile(t, filepath.Join(root, "boot/initramfs.cpio.gz")) != readFile(t, img) {
		t.Error("boot initramfs is not the verified image")
	}
	if fi, err := os.Stat(filepath.Join(root, "var/empty")); err != nil || !fi.IsDir() {
		t.Error("missing /var directory was not created")
	}
	if _, err := os.Stat(filepath.Join(root, upgradeRelDir, "staging")); !os.IsNotExist(err) {
		t.Error("staging directory left behind")
	}
	if err := addPrevGrubEntry(root); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, filepath.Join(root, "boot/grub/grub.cfg")), prevGrubMarker); n != 1 {
		t.Errorf("previous-version GRUB entry appears %d times, want 1", n)
	}

	state, err = rollbackUpgrade(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "rolled-back" {
		t.Errorf("state after rollback = %+v", state)
	}
	after := snapshot(t, root)
	for rel, w := range before {
		if after[rel] != w {
			t.Errorf("after rollback %s = %q, want %q", rel, after[rel], w)
		}
	}
	for rel := range after {
		if _, ok := before[rel]; !ok {
			t.Errorf("after rollback unexpected file %s", rel)
		}
	}
	if _, err := rollbackUpgrade(root); err == nil {
		t.Error("second rollback should report nothing to roll back")
	}
}

func TestApplyUpgradeRefusesWrongArchAndIncompleteImage(t *testing.T) {
	root := oldRoot(t)
	before := snapshot(t, root)
	if _, err := applyUpgrade(root, newImage(t, "arm64")); err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("expected architecture mismatch, got %v", err)
	}
	partial := filepath.Join(t.TempDir(), "partial.cpio.gz")
	writeCpio(t, partial, []cpioEntry{{name: "etc/ziro-release", mode: cReg, data: newRelease("1.1.0", "x86_64")}})
	if _, err := applyUpgrade(root, partial); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete image error, got %v", err)
	}
	after := snapshot(t, root)
	for rel, w := range before {
		if after[rel] != w {
			t.Errorf("refused upgrade modified %s", rel)
		}
	}
}

func TestParseSums(t *testing.T) {
	h := strings.Repeat("a", 64)
	sums := parseSums([]byte(h + "  ziro-initramfs-x86_64.cpio.gz\n" + h + " *ziroctl-arm64\ngarbage line\nABC  bad-hash\n"))
	if sums["ziro-initramfs-x86_64.cpio.gz"] != h || sums["ziroctl-arm64"] != h {
		t.Errorf("sums = %v", sums)
	}
	if _, ok := sums["bad-hash"]; ok {
		t.Error("accepted a malformed hash")
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.10", "1.0.9", 1},
		{"v1.1.0", "1.0.99", 1},
		{"1.0.9", "1.0.9", 0},
		{"1.0.8", "v1.0.9", -1},
		{"2.0.0-rc1", "1.9.9", 1},
		{"garbage", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssetNameFollowsKernelFlavor(t *testing.T) {
	if got := imageAssetName("x86_64", "alpine"); got != "ziro-initramfs-x86_64.cpio.gz" {
		t.Error(got)
	}
	if got := imageAssetName("arm64", "custom"); got != "ziro-initramfs-arm64-custom.cpio.gz" {
		t.Error(got)
	}
}

func TestTrustedURLs(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://github.com/ziro-os/ziro-os/releases/download/v1/x": true,
		"https://objects.githubusercontent.com/x":                   true,
		"https://release-assets.githubusercontent.com/x":            true,
		"http://github.com/x":                                       false,
		"https://evil.example.com/x":                                false,
		"https://githubusercontent.com.evil.example/x":              false,
	} {
		u, _ := url.Parse(raw)
		if got := isTrustedURL(u); got != want {
			t.Errorf("isTrustedURL(%s) = %v, want %v", raw, got, want)
		}
	}
}

// withTestServer points the release client at a local TLS server.
func withTestServer(t *testing.T, h http.Handler) *httptest.Server {
	srv := httptest.NewTLSServer(h)
	u, _ := url.Parse(srv.URL)
	oldAPI, oldHosts, oldClient := githubAPI, trustedHosts, upgradeHTTP
	githubAPI = srv.URL
	trustedHosts = append([]string{u.Hostname()}, trustedHosts...)
	upgradeHTTP = &http.Client{Transport: srv.Client().Transport, CheckRedirect: checkUpgradeRedirect}
	t.Cleanup(func() {
		srv.Close()
		githubAPI, trustedHosts, upgradeHTTP = oldAPI, oldHosts, oldClient
	})
	return srv
}

func TestFetchReleaseAndDownload(t *testing.T) {
	payload := []byte("os-image-bytes")
	sum := sha256.Sum256(payload)
	var srv *httptest.Server
	srv = withTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + upgradeRepo + "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.2.0","assets":[{"name":"img","browser_download_url":"%s/img","size":%d}]}`, srv.URL, len(payload))
		case "/repos/" + upgradeRepo + "/releases/tags/v1.1.0":
			fmt.Fprint(w, `{"tag_name":"v1.1.0","assets":[]}`)
		case "/img":
			w.Write(payload)
		case "/evil-redirect":
			http.Redirect(w, r, "https://evil.example.com/img", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))

	rel, err := fetchRelease(context.Background(), "")
	if err != nil || rel.TagName != "v1.2.0" || rel.asset("img") == nil {
		t.Fatalf("latest release = %+v, %v", rel, err)
	}
	if rel, err := fetchRelease(context.Background(), "1.1.0"); err != nil || rel.TagName != "v1.1.0" {
		t.Fatalf("tagged release = %+v, %v", rel, err)
	}
	if _, err := fetchRelease(context.Background(), "../../etc"); err == nil {
		t.Error("accepted an invalid version tag")
	}

	dir := t.TempDir()
	got, err := download(srv.URL+"/img", filepath.Join(dir, "img"), 1<<20)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("download hash = %s, %v", got, err)
	}
	if _, err := download(srv.URL+"/img", filepath.Join(dir, "small"), 4); err == nil {
		t.Error("download ignored the size limit")
	}
	if _, err := os.Stat(filepath.Join(dir, "small.part")); !os.IsNotExist(err) {
		t.Error("partial download left behind")
	}
	if _, err := download(srv.URL+"/evil-redirect", filepath.Join(dir, "evil"), 1<<20); err == nil {
		t.Error("followed a redirect to an untrusted host")
	}
	if _, err := download("https://evil.example.com/img", filepath.Join(dir, "evil"), 1<<20); err == nil {
		t.Error("downloaded from an untrusted host")
	}
}

func TestValidateHostConfig(t *testing.T) {
	root := oldRoot(t)
	if p := validateHostConfig(root); len(p) != 1 || !strings.Contains(p[0], "fstab") {
		t.Fatalf("problems = %v, want only the fstab one", p)
	}
	writeTree(t, root, map[string]string{"etc/fstab": "LABEL=ZIRO_ROOT / ext4 defaults 0 1\n"})
	if p := validateHostConfig(root); len(p) != 0 {
		t.Fatalf("problems = %v, want none", p)
	}
}

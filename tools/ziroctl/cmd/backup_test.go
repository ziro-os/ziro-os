package cmd

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// backupFixture points the backup at a small tree and a private key, and restores the globals.
func backupFixture(t *testing.T) (root string) {
	t.Helper()
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("needs tar")
	}
	t.Setenv("COPYFILE_DISABLE", "1")
	root = t.TempDir()
	oldPaths, oldKey, oldNo, oldAuto, oldDir, oldVols, oldArg := backupPaths, backupKeyPath, backupNoSecrets, backupAuto, defaultBackupDir, backupIncludeVols, backupKeyArg
	oldBulk, oldState := backupBulkExcludes, backupStateExcludes
	rel := strings.TrimPrefix(filepath.Join(root, "state"), "/") // the real excludes name /var/lib/ziro: point them at the fixture
	backupBulkExcludes, backupStateExcludes = []string{rel + "/volumes"}, []string{rel + "/upgrade"}
	backupPaths = []string{filepath.Join(root, "state")}
	backupKeyPath = filepath.Join(root, "state", "backup.key") // inside the backed-up tree on purpose
	backupNoSecrets, backupAuto, backupIncludeVols, backupKeyArg = false, true, false, ""
	defaultBackupDir = filepath.Join(root, "var", "backups")
	t.Cleanup(func() {
		backupPaths, backupKeyPath, backupNoSecrets, backupAuto, defaultBackupDir, backupIncludeVols, backupKeyArg = oldPaths, oldKey, oldNo, oldAuto, oldDir, oldVols, oldArg
		backupBulkExcludes, backupStateExcludes = oldBulk, oldState
	})
	for f, body := range map[string]string{"gateway/certs/a.pem": "CERT", "firewall.json": "{}", "volumes/big": "BULK", "upgrade/img": "IMAGE"} {
		p := filepath.Join(root, "state", f)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, []byte(body), 0600)
	}
	return root
}

// The original report: a fresh install has no backup directory and the caller names the file.
func TestCreateBackupMakesAMissingBackupDirectory(t *testing.T) {
	root := backupFixture(t)
	for _, no := range []bool{false, true} {
		backupNoSecrets = no
		out, err := createBackup(filepath.Join(defaultBackupDir, "ziro-backup-preupgrade-1.0.30-x.tar.gz"))
		if err != nil {
			t.Fatalf("noSecrets=%v: %v", no, err)
		}
		if !fileExists(out) || !fileExists(out+".sha256") {
			t.Fatalf("missing archive or checksum: %s", out)
		}
		if fi, _ := os.Stat(defaultBackupDir); fi.Mode().Perm() != 0700 {
			t.Fatalf("backup dir mode %v", fi.Mode().Perm())
		}
		os.RemoveAll(defaultBackupDir)
	}
	// and --output into a directory that does not exist yet
	out, err := createBackup(filepath.Join(root, "new", "dir", "x.tar.gz"))
	if err != nil || !fileExists(out) {
		t.Fatalf("output in a new directory: %v", err)
	}
}

func archiveNames(t *testing.T, p string) []string {
	t.Helper()
	ms, err := scanBackup(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func TestBackupContentsAndKeyHandling(t *testing.T) {
	root := backupFixture(t)
	out, err := createBackup("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, ".tar.gz.enc") {
		t.Fatalf("default archive is %s, want an encrypted one", out)
	}
	if !fileExists(backupKeyPath) {
		t.Fatal("the first backup must make the key")
	}
	names := strings.Join(archiveNames(t, out), " ")
	state := filepath.Join(root, "state")
	for _, want := range []string{state + "/gateway/certs/a.pem", state + "/firewall.json"} {
		if !strings.Contains(names, strings.TrimPrefix(want, "/")) && !strings.Contains(names, want) {
			t.Errorf("archive lacks %s:\n%s", want, names)
		}
	}
	for _, dont := range []string{"backup.key", "volumes/big", "upgrade/img"} {
		if strings.Contains(names, dont) {
			t.Errorf("archive contains %s", dont)
		}
	}
	// the sealed file reveals nothing of the contents
	raw, _ := os.ReadFile(out)
	if bytes.Contains(raw, []byte("CERT")) || bytes.Contains(raw, []byte("firewall")) {
		t.Fatal("the archive is not encrypted")
	}
	// a wrong key and a damaged file are both refused by verification
	wrong := filepath.Join(root, "wrong.key")
	if _, _, err := loadBackupKey(wrong, true); err != nil {
		t.Fatal(err)
	}
	backupKeyArg = wrong
	if _, err := scanBackup(out); err == nil {
		t.Fatal("the wrong key opened the archive")
	}
	backupKeyArg = ""
	raw[len(raw)/2] ^= 0xff
	os.WriteFile(out, raw, 0600)
	if _, err := scanBackup(out); err == nil {
		t.Fatal("a damaged archive passed verification")
	}
	// volumes come back with --include-volumes
	backupIncludeVols = true
	out2, err := createBackup(filepath.Join(root, "vols.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(archiveNames(t, out2), " "), "volumes/big") {
		t.Fatal("--include-volumes did not include volumes")
	}
}

func TestNoSecretsArchiveIsPlainAndKeyless(t *testing.T) {
	root := backupFixture(t)
	backupNoSecrets = true
	out, err := createBackup("")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(out, ".enc") || fileExists(backupKeyPath) {
		t.Fatalf("a no-secrets archive must be plain and need no key: %s", out)
	}
	if strings.Contains(strings.Join(archiveNames(t, out), " "), "backup.key") {
		t.Fatal("the key is in the archive")
	}
	_ = root
}

func TestBackupAllowlistCoversHostState(t *testing.T) {
	for _, ok := range []string{"/var/lib/ziro/gateway/certs/x.pem", "/var/log/ziro/audit.log", "/etc/ziro-installed", "/etc/sysctl.d/99-ziro.conf", "/etc/cni/net.d/10-ziro.conflist", "/var/lib/zirocd-moon/state"} {
		hdr := []*tar.Header{{Name: strings.TrimPrefix(ok, "/"), Typeflag: tar.TypeReg}}
		if err := validateBackupArchive(writeTarGz(t, hdr)); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"/root/.ssh/authorized_keys", "/usr/bin/ziroctl", "/var/lib/containerd/x", "/var/backups/ziro/x"} {
		hdr := []*tar.Header{{Name: strings.TrimPrefix(bad, "/"), Typeflag: tar.TypeReg}}
		if err := validateBackupArchive(writeTarGz(t, hdr)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// A bad checksum used to print "Aborting" and exit 0.
func TestChecksumMismatchAndMissingAreErrors(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.tar.gz")
	os.WriteFile(a, []byte("data"), 0600)
	if err := checkBackupChecksum(a, false); err == nil {
		t.Fatal("a missing checksum file was accepted")
	}
	os.WriteFile(a+".sha256", []byte(strings.Repeat("0", 64)+"  a.tar.gz\n"), 0600)
	if err := checkBackupChecksum(a, false); err == nil {
		t.Fatal("a wrong checksum was accepted")
	}
	if err := checkBackupChecksum(a, true); err != nil {
		t.Fatalf("--force must continue: %v", err)
	}
	h, _ := computeFileSHA256(a)
	os.WriteFile(a+".sha256", []byte(h+"  a.tar.gz\n"), 0600)
	if err := checkBackupChecksum(a, false); err != nil {
		t.Fatal(err)
	}
}

func TestPruneKeepsNewestAndSafetyArchivesSeparately(t *testing.T) {
	backupFixture(t)
	os.MkdirAll(defaultBackupDir, 0700)
	base := time.Now().Add(-48 * time.Hour)
	names := []string{"ziro-backup-1.tar.gz.enc", "ziro-backup-2.tar.gz.enc", "ziro-backup-3.tar.gz.enc",
		"ziro-backup-preupgrade-1.0.30-a.tar.gz.enc", "ziro-backup-preupgrade-1.0.31-b.tar.gz.enc", "ziro-backup-prerestore-c.tar.gz"}
	for i, n := range names {
		p := filepath.Join(defaultBackupDir, n)
		os.WriteFile(p, []byte("x"), 0600)
		os.WriteFile(p+".sha256", []byte("x"), 0600)
		mt := base.Add(time.Duration(i) * time.Hour)
		os.Chtimes(p, mt, mt)
	}
	removed, err := pruneBackups(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "ziro-backup-1.tar.gz.enc,ziro-backup-preupgrade-1.0.30-a.tar.gz.enc" {
		t.Fatalf("removed %v", removed)
	}
	if fileExists(filepath.Join(defaultBackupDir, "ziro-backup-1.tar.gz.enc.sha256")) {
		t.Fatal("the checksum file was left behind")
	}
	if _, err := pruneBackups(0, 1); err == nil {
		t.Fatal("--keep 0 would delete everything")
	}
	for _, bad := range []string{"../etc/passwd", "a/b.tar.gz", "notabackup", "-rf.tar.gz"} {
		if err := removeBackup(bad); err == nil {
			t.Errorf("removeBackup(%q) accepted", bad)
		}
	}
}

package cmd

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func sealForTest(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := newEncryptWriter(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	// write in odd pieces so chunking does not depend on the caller's write sizes
	for rest := plain; len(rest) > 0; {
		n := min(len(rest), 10007)
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openForTest(sealed, key []byte) ([]byte, error) {
	r, err := newDecryptReader(bytes.NewReader(sealed), key)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestBackupEncryptionRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	for _, n := range []int{0, 1, backupChunkSize - 1, backupChunkSize, backupChunkSize + 1, 3*backupChunkSize + 5} {
		plain := make([]byte, n)
		rand.Read(plain)
		got, err := openForTest(sealForTest(t, key, plain), key)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%d bytes: err=%v equal=%v", n, err, bytes.Equal(got, plain))
		}
	}
}

func TestBackupEncryptionRejectsWrongKeyDamageAndTruncation(t *testing.T) {
	key, other := make([]byte, 32), make([]byte, 32)
	rand.Read(key)
	rand.Read(other)
	plain := make([]byte, 3*backupChunkSize)
	rand.Read(plain)
	sealed := sealForTest(t, key, plain)

	if _, err := openForTest(sealed, other); err == nil {
		t.Fatal("wrong key accepted")
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)/2] ^= 1
	if _, err := openForTest(flipped, key); err == nil {
		t.Fatal("a flipped bit was accepted")
	}
	// cut exactly after the first chunk: every remaining chunk is intact, but the stream has no final one
	first := len(backupMagic) + 8 + 4 + backupMaxChunk
	if _, err := openForTest(sealed[:first], key); err == nil {
		t.Fatal("a stream cut at a chunk boundary was accepted")
	}
	if _, err := openForTest(sealed[:len(sealed)-3], key); err == nil {
		t.Fatal("a stream cut mid-chunk was accepted")
	}
	if _, err := openForTest([]byte("not a backup at all"), key); err == nil {
		t.Fatal("a plain file was accepted")
	}
	if _, err := openForTest(sealed[:len(backupMagic)+8], key); err == nil {
		t.Fatal("an empty stream was accepted")
	}
}

func TestBackupKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "ziro", "backup.key")
	if _, _, err := loadBackupKey(path, false); err == nil {
		t.Fatal("a missing key was invented when not asked to create")
	}
	key, created, err := loadBackupKey(path, true)
	if err != nil || !created || len(key) != 32 {
		t.Fatalf("create: %v %v %d", err, created, len(key))
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	again, created, err := loadBackupKey(path, true)
	if err != nil || created || !bytes.Equal(again, key) {
		t.Fatalf("second load: %v %v", err, created)
	}
	os.WriteFile(path, []byte("short\n"), 0600)
	if _, _, err := loadBackupKey(path, true); err == nil {
		t.Fatal("a damaged key file was replaced instead of reported")
	}
}

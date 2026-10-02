package cmd

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "svc.log")
	big := strings.Repeat("x", int(maxLogSize))
	for gen := 1; gen <= 4; gen++ {
		os.WriteFile(p, []byte(big[:len(big)-1]+string(rune('0'+gen))), 0600)
		rotateLog(p)
	}
	if fi, _ := os.Stat(p); fi.Size() != 0 {
		t.Error("not truncated")
	}
	for gen, want := range map[int]byte{1: '4', 2: '3', 3: '2'} {
		f, err := os.Open(p + "." + string(rune('0'+gen)) + ".gz")
		if err != nil {
			t.Fatalf("generation %d: %v", gen, err)
		}
		zr, _ := gzip.NewReader(f)
		b, _ := io.ReadAll(zr)
		f.Close()
		if len(b) != len(big) || b[len(b)-1] != want {
			t.Errorf("generation %d holds rotation %c", gen, b[len(b)-1])
		}
	}
	if _, err := os.Stat(p + ".4.gz"); err == nil {
		t.Error("kept more than 3 generations")
	}
}

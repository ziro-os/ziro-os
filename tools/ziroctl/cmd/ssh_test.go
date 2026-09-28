package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHStatus(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"ssh", "status"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ssh status failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Ziro-OS SSH Remote Management") {
		t.Errorf("expected SSH management header, got: %s", out)
	}
}

func TestSSHKeyValidation(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"ssh", "key", "add", "invalid-key-data"})

	err := rootCmd.Execute()
	if err == nil {
		t.Errorf("expected error when adding invalid SSH key, got nil")
	}
}

func TestSSHKeyLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	original := sshAuthorizedKeysPath
	sshAuthorizedKeysPath = filepath.Join(tmpDir, ".ssh", "authorized_keys")
	t.Cleanup(func() { sshAuthorizedKeysPath = original })

	testKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGo4wS84K2x... test@ziro-os"

	// Add key
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"ssh", "key", "add", testKey})

	// Run command
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sshAuthorizedKeysPath)
	if err != nil || strings.TrimSpace(string(data)) != testKey {
		t.Fatalf("key not saved: %q, %v", data, err)
	}

	// List keys
	buf.Reset()
	rootCmd.SetArgs([]string{"ssh", "key", "list"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "test@ziro-os") {
		t.Fatal("key not listed")
	}

	// Clear keys
	buf.Reset()
	rootCmd.SetArgs([]string{"ssh", "key", "clear"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sshAuthorizedKeysPath); !os.IsNotExist(err) {
		t.Fatal("key not cleared")
	}
}

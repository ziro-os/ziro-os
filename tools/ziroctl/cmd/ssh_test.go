package cmd

import (
	"bytes"
	"os"
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
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	testKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGo4wS84K2x... test@ziro-os"

	// Add key
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"ssh", "key", "add", testKey})

	// Run command
	_ = rootCmd.Execute()

	// List keys
	buf.Reset()
	rootCmd.SetArgs([]string{"ssh", "key", "list"})
	_ = rootCmd.Execute()

	// Clear keys
	buf.Reset()
	rootCmd.SetArgs([]string{"ssh", "key", "clear"})
	_ = rootCmd.Execute()
}

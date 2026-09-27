package cmd

import (
	"bytes"
	"testing"
)

func TestInstallHelpCommand(t *testing.T) {
	cmd := rootCmd
	b := bytes.NewBufferString("")
	cmd.SetOut(b)
	cmd.SetArgs([]string{"install", "--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Expected no error running 'ziroctl install --help', got %v", err)
	}

	out := b.String()
	if !bytes.Contains([]byte(out), []byte("ziroctl install")) {
		t.Errorf("Expected 'ziroctl install' in help output, got: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("--disk")) {
		t.Errorf("Expected '--disk' flag in help output, got: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("--ssh-key")) {
		t.Errorf("Expected '--ssh-key' flag in help output, got: %s", out)
	}
}

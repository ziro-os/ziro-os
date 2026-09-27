package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ziropkg version") {
		t.Errorf("expected output to contain 'ziropkg version', got: %s", out)
	}
}

func TestInstallHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"install", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("install help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Install one or more packages") {
		t.Errorf("expected help output, got: %s", out)
	}
}

func TestSearchHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"search", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("search help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Search for available packages") {
		t.Errorf("expected help output, got: %s", out)
	}
}

func TestListHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"list", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("list help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "List installed packages") {
		t.Errorf("expected help output, got: %s", out)
	}
}

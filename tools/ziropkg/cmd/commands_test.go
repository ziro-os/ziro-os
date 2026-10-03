package cmd

import (
	"bytes"
	"os"
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
	if !strings.Contains(out, "reinstalled at boot after an OS upgrade") {
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
	if !strings.Contains(out, "Search available packages") {
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

func TestRecordPackages(t *testing.T) {
	old := packagesFile
	packagesFile = t.TempDir() + "/etc/ziro/packages"
	defer func() { packagesFile = old }()
	if err := recordPackages([]string{"jq", "curl", "jq"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := recordPackages([]string{"htop"}, []string{"curl"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(packagesFile); string(b) != "htop\njq\n" {
		t.Errorf("packages file = %q", b)
	}
	if validNames([]string{"curl", "-rf"}) == nil || validNames([]string{"../x"}) == nil {
		t.Error("invalid package names accepted")
	}
}

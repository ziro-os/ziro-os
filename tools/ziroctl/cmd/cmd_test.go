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
	if !strings.Contains(out, "ziroctl version") {
		t.Errorf("expected version output to contain 'ziroctl version', got: %s", out)
	}
}

func TestSystemInspect(t *testing.T) {
	st := inspectSystem()
	if st.OSName == "" {
		t.Errorf("expected non-empty OSName")
	}
	if st.KernelVersion == "" {
		t.Errorf("expected non-empty KernelVersion")
	}
}

func TestSecurityAuditCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"security", "audit"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("security audit command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Ziro-OS Security") {
		t.Errorf("expected output to contain 'Ziro-OS Security', got: %s", out)
	}
}

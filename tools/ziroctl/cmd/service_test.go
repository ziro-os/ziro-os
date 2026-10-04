package cmd

import (
	"slices"
	"testing"
)

func TestGoMemEnvKeepsOperatorOverrides(t *testing.T) {
	got := goMemEnv([]string{"PATH=/bin"})
	if !slices.Contains(got, "GOGC=25") || !slices.Contains(got, "GOMEMLIMIT=128MiB") {
		t.Fatalf("defaults missing: %v", got)
	}
	got = goMemEnv([]string{"GOGC=100", "GOMEMLIMIT=1GiB"})
	if len(got) != 2 {
		t.Fatalf("operator values must win, got %v", got)
	}
}

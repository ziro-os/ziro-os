package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeImageRef(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"nginx", "docker.io/library/nginx:latest"},
		{"nginx:alpine", "docker.io/library/nginx:alpine"},
		{"alpine", "docker.io/library/alpine:latest"},
		{"alpine:3.20", "docker.io/library/alpine:3.20"},
		{"redis/redis-stack", "docker.io/redis/redis-stack:latest"},
		{"redis/redis-stack:7.2", "docker.io/redis/redis-stack:7.2"},
		{"quay.io/coreos/etcd", "quay.io/coreos/etcd:latest"},
		{"quay.io/coreos/etcd:v3.5.0", "quay.io/coreos/etcd:v3.5.0"},
		{"ghcr.io/ziro-os/base:latest", "ghcr.io/ziro-os/base:latest"},
		{"localhost:5000/test/image", "localhost:5000/test/image:latest"},
		{"docker.io/library/ubuntu:22.04", "docker.io/library/ubuntu:22.04"},
		{"ubuntu@sha256:1234567890abcdef", "docker.io/library/ubuntu@sha256:1234567890abcdef"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			actual := normalizeImageRef(tc.input)
			if actual != tc.expected {
				t.Errorf("normalizeImageRef(%q) = %q; expected %q", tc.input, actual, tc.expected)
			}
		})
	}
}

func TestContainerHelpCommands(t *testing.T) {
	subcommands := []string{"run", "pull", "list", "images", "stop", "start", "restart", "rm", "logs", "exec", "inspect"}

	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs([]string{"container", sub, "--help"})

			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("help for container %s failed: %v", sub, err)
			}

			out := buf.String()
			if !strings.Contains(out, "Usage:") {
				t.Errorf("expected usage info for %s, got: %s", sub, out)
			}
		})
	}
}

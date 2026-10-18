package schema

import (
	"strings"
	"testing"
)

func TestSandboxSpecValidate(t *testing.T) {
	ok := []SandboxSpec{
		{Image: "python:3.13-slim"},
		{Image: "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64), Runtime: "gvisor", User: "1000:1000", Workdir: "/work",
			Timeout: "30m", IdleTimeout: "5m", Env: map[string]string{"A": "1"}, Metadata: map[string]string{"agent": "x"},
			Resources: &Resources{Memory: "2Gi", CPUs: 2, PIDs: 256}, Command: []string{"python3", "-m", "http.server"},
			Network: &SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org", "*.github.com", "1.2.3.4", "10.0.0.0/8"}}},
		{Image: "x", Network: &SandboxNetwork{Mode: "open"}},
	}
	for _, s := range ok {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bad := map[string]SandboxSpec{
		"flag image":   {Image: "--privileged"},
		"upper image":  {Image: "Python"},
		"runtime":      {Image: "x", Runtime: "kata-fc"},
		"user name":    {Image: "x", User: "root"},
		"relative wd":  {Image: "x", Workdir: "work"},
		"unclean wd":   {Image: "x", Workdir: "/a/../b"},
		"ziro env":     {Image: "x", Env: map[string]string{"ZIRO_TOKEN": "x"}},
		"bad env":      {Image: "x", Env: map[string]string{"A-B": "x"}},
		"nul env":      {Image: "x", Env: map[string]string{"A": "a\x00b"}},
		"short ttl":    {Image: "x", Timeout: "10s"},
		"bad ttl":      {Image: "x", IdleTimeout: "soon"},
		"meta key":     {Image: "x", Metadata: map[string]string{"Bad Key": "x"}},
		"memory":       {Image: "x", Resources: &Resources{Memory: "1Mi"}},
		"nul argument": {Image: "x", Command: []string{"a\x00"}},
		"net mode":     {Image: "x", Network: &SandboxNetwork{Mode: "host"}},
		"allow open":   {Image: "x", Network: &SandboxNetwork{Mode: "open", Allow: []string{"a.com"}}},
		"allow ipv6":   {Image: "x", Network: &SandboxNetwork{Mode: "allowlist", Allow: []string{"::1"}}},
		"allow upper":  {Image: "x", Network: &SandboxNetwork{Mode: "allowlist", Allow: []string{"PyPI.org"}}},
		"allow port":   {Image: "x", Network: &SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org:443"}}},
		"allow star":   {Image: "x", Network: &SandboxNetwork{Mode: "allowlist", Allow: []string{"*"}}},
	}
	for name, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dockerModule(t *testing.T) ModuleManifest {
	t.Helper()
	b, err := moduleFS.ReadFile("modules/docker.json")
	if err != nil {
		t.Fatal(err)
	}
	var m ModuleManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

// The docker module installs the real Docker Engine: pinned binaries for both architectures, a service that
// cannot clash with the translator's "dockerd" service file, and a hardened daemon.json.
func TestDockerModuleManifest(t *testing.T) {
	m := dockerModule(t)
	if m.Name != "docker" || len(m.Services) != 1 || m.Services[0].Name == dockerService {
		t.Fatalf("service must not reuse %q (disabling the module would delete the translator's service file): %+v", dockerService, m.Services)
	}
	want := map[string]bool{}
	for _, bin := range []string{"docker", "dockerd", "docker-proxy", "docker-init"} {
		for _, arch := range []string{"x86_64", "aarch64"} {
			want[bin+"/"+arch] = false
		}
	}
	archives := map[string]string{} // arch -> sha256 of the release archive
	for _, a := range m.Artifacts {
		bin := filepath.Base(a.Path)
		if !strings.HasPrefix(a.URL, "https://download.docker.com/linux/static/stable/"+a.Arch+"/docker-") {
			t.Errorf("%s: unexpected source %s", bin, a.URL)
		}
		if a.Extract != "docker/"+bin {
			t.Errorf("%s: extracts %q", bin, a.Extract)
		}
		if prev, ok := archives[a.Arch]; ok && prev != a.SHA256 {
			t.Errorf("%s: the %s binaries come from different archives", bin, a.Arch)
		}
		archives[a.Arch] = a.SHA256
		want[bin+"/"+a.Arch] = true
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("no pinned artifact for %s", k)
		}
	}
	if archives["x86_64"] == archives["aarch64"] {
		t.Error("both architectures pin the same archive")
	}
	// Every artifact is one release: its version is in the module description.
	var ver string
	for _, a := range m.Artifacts {
		v := strings.TrimSuffix(strings.TrimPrefix(a.URL[strings.LastIndex(a.URL, "/")+1:], "docker-"), ".tgz")
		if ver != "" && v != ver {
			t.Errorf("mixed releases %s and %s", ver, v)
		}
		ver = v
	}
	if !strings.Contains(m.Description, ver) {
		t.Errorf("description %q does not name release %s", m.Description, ver)
	}
}

func TestDockerModuleDaemonJSON(t *testing.T) {
	m := dockerModule(t)
	var content string
	for _, f := range m.Files {
		if f.Path == "/etc/docker/daemon.json" {
			content = f.Content
		}
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(content), &d); err != nil {
		t.Fatalf("daemon.json: %v", err)
	}
	if d["containerd"] != "/run/containerd/containerd.sock" {
		t.Errorf("must share the host's containerd, got %v", d["containerd"])
	}
	if _, ok := d["hosts"]; ok {
		t.Error("no extra listeners: the API is the group-restricted unix socket only")
	}
	if d["group"] != "docker" || d["live-restore"] != true || d["userland-proxy"] != false {
		t.Errorf("hardening/reliability defaults missing: %v", d)
	}
	if opts, _ := d["exec-opts"].([]any); len(opts) != 1 || opts[0] != "native.cgroupdriver=cgroupfs" {
		t.Errorf("no systemd on Ziro OS, the cgroupfs driver is required: %v", d["exec-opts"])
	}
	if !strings.Contains(m.Services[0].Args, "--host unix:///run/docker.sock") || strings.Contains(m.Services[0].Args, "tcp://") {
		t.Errorf("dockerd args: %q", m.Services[0].Args)
	}
}

// Two programs cannot both own /run/docker.sock: the lightweight translator refuses to start next to the engine.
func TestDockerAPIEnableRefusedWhileEngineInstalled(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "dockerd")
	old := dockerEngineBin
	dockerEngineBin = bin
	defer func() { dockerEngineBin = old }()
	if dockerEngineInstalled() {
		t.Fatal("engine reported without the binary")
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !dockerEngineInstalled() {
		t.Fatal("engine not detected")
	}
	if err := dockerAPIEnable(); err == nil || !strings.Contains(err.Error(), "docker module") {
		t.Fatalf("docker-api enable next to the engine: %v", err)
	}
}

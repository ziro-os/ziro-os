package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposePreflight(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) []ComposeService {
		p := filepath.Join(dir, "compose.yaml")
		os.WriteFile(p, []byte(body), 0644)
		svcs, err := parseComposeFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return svcs
	}
	ok := write(`
services:
  web:
    image: nginx:1.27
    ports: ["8080:80"]
    volumes: ["./html:/usr/share/nginx/html:ro", "/var/lib/ziro/volumes/web:/data", "cache:/cache"]
  db:
    image: postgres:17
    volumes:
      - type: volume
        source: pg
        target: /var/lib/postgresql/data
`)
	if p := composePreflight(ok, false); len(p) != 0 {
		t.Fatalf("plain project refused: %v", p)
	}
	bad := write(`
services:
  a: {image: x, privileged: true}
  b: {image: x, network_mode: host}
  c: {image: x, pid: host}
  d: {image: x, cap_add: [SYS_ADMIN]}
  e: {image: x, devices: ["/dev/kvm"]}
  f: {image: x, security_opt: ["seccomp=unconfined"]}
  g: {image: x, volumes: ["/:/host"]}
  h: {image: x, volumes: ["/run/containerd/containerd.sock:/c.sock"]}
  i: {image: x, volumes: [{type: bind, source: /etc, target: /etc}]}
  j: {build: .}
`)
	p := composePreflight(bad, false)
	got := strings.Join(p, "\n")
	for _, want := range []string{"a: privileged", "b: network_mode: host", "c: pid: host", "d: cap_add: SYS_ADMIN", "e: devices",
		"f: security_opt", "g: bind mount of /", "h: bind mount of /run/containerd", "i: bind mount of /etc", "j: build"} {
		if !strings.Contains(got, want) {
			t.Errorf("preflight missed %q:\n%s", want, got)
		}
	}
	if p := composePreflight(bad, true); len(p) != 1 || !strings.HasPrefix(p[0], "j: build") {
		t.Errorf("--allow-privileged should only leave build: %v", p)
	}
	files, sub := composeArgs([]string{"-f", "a.yml", "--file=b.yml", "-p", "shop", "up", "-d"})
	if strings.Join(files, ",") != "a.yml,b.yml" || sub != "up" {
		t.Errorf("composeArgs = %v %q", files, sub)
	}
}

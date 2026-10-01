package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDevScaffoldsLintClean(t *testing.T) {
	m, _ := json.Marshal(scaffoldPlugin("hello"))
	a, _ := json.Marshal(appScaffold("web"))
	for name, b := range map[string][]byte{"plugin": m, "app": a} {
		if f := lintDefinition(name, b); len(f) != 0 {
			t.Errorf("%s scaffold: %+v", name, f)
		}
	}
}

func TestDevLints(t *testing.T) {
	m := scaffoldPlugin("hello")
	m.Services[0].User = ""
	m.Health = nil
	b, _ := json.Marshal(m)
	got := lintDefinition("m", b)
	if len(got) != 2 || !strings.Contains(got[0].Message, "root") || !strings.Contains(got[1].Message, "health") {
		t.Errorf("module lints: %+v", got)
	}

	d := appScaffold("web")
	d.Components[0].Args = []string{"sh", "-c", "exec nginx"}
	b, _ = json.Marshal(d)
	if got := lintDefinition("a", b); len(got) != 1 || !strings.Contains(got[0].Message, "privileges") {
		t.Errorf("app lints: %+v", got)
	}

	if got := lintDefinition("x", []byte("{")); len(got) != 1 || got[0].Level != "error" {
		t.Errorf("bad json: %+v", got)
	}
}

func TestDevQemuArgs(t *testing.T) {
	bin, args, err := devQemuArgs("arm64", "k", "i", 1024, []string{"8080:80"})
	joined := strings.Join(args, " ")
	if err != nil || bin != "qemu-system-aarch64" || !strings.Contains(joined, "hostfwd=tcp:127.0.0.1:8080-:80") ||
		!strings.Contains(joined, "console=ttyAMA0 rdinit=/init") {
		t.Fatalf("%s %s %v", bin, joined, err)
	}
	for _, bad := range []string{"8080", "0.0.0.0:8080:80", "a:b", "8080:80,hostfwd=tcp::22-:22"} {
		if _, _, err := devQemuArgs("x86_64", "k", "i", 1024, []string{bad}); err == nil {
			t.Errorf("forward %q accepted", bad)
		}
	}
	if got := shQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("shQuote: %s", got)
	}
}

package cmd

import (
	"bytes"
	"testing"
)

func TestExitFilter(t *testing.T) {
	var out bytes.Buffer
	f := newExitFilter(&out)
	for _, chunk := range []string{"err: no", " such file\n", "prompt> ", "time=\"2026-10-18T13:13:09Z\" level=fa", "tal msg=\"exec failed with exit code 7\"\n"} {
		f.Write([]byte(chunk))
	}
	if code := f.finish(1); code != 7 || out.String() != "err: no such file\nprompt> " {
		t.Fatalf("%d %q", code, out.String())
	}
	out.Reset()
	f = newExitFilter(&out)
	f.Write([]byte("time=\"x\" level=fatal msg=\"container is not running\"\n"))
	if code := f.finish(1); code != 1 || !bytes.Contains(out.Bytes(), []byte("not running")) {
		t.Fatalf("other nerdctl errors pass: %d %q", code, out.String())
	}
	out.Reset()
	f = newExitFilter(&out)
	f.Write([]byte("tim"))
	if code := f.finish(0); code != 0 || out.String() != "tim" {
		t.Fatalf("held-back bytes flushed: %q", out.String())
	}
}

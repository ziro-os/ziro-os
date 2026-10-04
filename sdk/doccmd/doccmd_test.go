package doccmd

import (
	"strings"
	"testing"
)

func TestLines(t *testing.T) {
	md := "text ziroctl not-code\n```sh\n# a comment\nziroctl router moon add sg-1 --public h:1 # trailing\nZIROCD_KEY=k sudo zirocd up --name \"a b\"\nziroctl a \\\n  --b c && ziroctl d | grep x\ndocker run img\n```\n"
	got := Lines([]byte(md), "ziroctl")
	want := []string{"router moon add sg-1 --public h:1", "a --b c", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i, w := range want {
		if strings.Join(got[i], " ") != w {
			t.Errorf("line %d: %q, want %q", i, got[i], w)
		}
	}
	if z := Lines([]byte(md), "zirocd"); len(z) != 1 || strings.Join(z[0], "|") != "up|--name|a b" {
		t.Errorf("zirocd: %q", z)
	}
}

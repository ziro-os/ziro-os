package router

import (
	"strings"
	"testing"
)

func TestInvite(t *testing.T) {
	in := Invite{Endpoints: []string{"r.example.com:7443"}, Pin: "sha256:" + strings.Repeat("a", 64), Network: "0123456789abcdef", Key: "id.secret"}
	got, err := ParseInvite(" " + in.String() + "\n")
	if err != nil || got.Key != in.Key || got.Endpoints[0] != in.Endpoints[0] || got.Pin != in.Pin {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "zr1_", "zr1_!!", "zr2_" + in.String()[4:], Invite{Pin: in.Pin, Network: "n"}.String(),
		Invite{Endpoints: in.Endpoints, Pin: "md5:x", Network: "n"}.String(), "zr1_" + strings.Repeat("A", 5000)} {
		if _, err := ParseInvite(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

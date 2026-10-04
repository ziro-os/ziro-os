package daemon

import (
	"context"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

func TestStateAndKeys(t *testing.T) {
	dir := t.TempDir() + "/z"
	inv := zr.Invite{Endpoints: []string{"127.0.0.1:1"}, Pin: "sha256:" + strings.Repeat("a", 64), Network: "n", Key: "k.s"}
	st, err := newState(inv, Prefs{AcceptDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.WGKey == st.DiscoKey {
		t.Fatal("WireGuard and disco keys must differ")
	}
	pub, err := publicOf(st.WGKey)
	if err != nil || len(pub) != 44 {
		t.Fatalf("public key: %q %v", pub, err)
	}
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(statePath(dir))
		di, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0600 || di.Mode().Perm() != 0700 {
			t.Fatalf("state %v dir %v: private keys must be owner-only", fi.Mode(), di.Mode())
		}
	}
	got, err := LoadState(dir)
	if err != nil || got.WGKey != st.WGKey || got.JoinKey != "k.s" {
		t.Fatalf("round trip: %v", err)
	}
	if none, err := LoadState(t.TempDir()); none != nil || err != nil {
		t.Fatal("missing state must be nil, nil")
	}

	// A stored CA that does not match the pin is never trusted.
	d := New(dir, "test")
	st.CA = "-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----\n"
	if _, err := d.caCert(context.Background(), st); err == nil {
		t.Fatal("CA not matching the pin accepted")
	}
}

func TestPlanetCandidates(t *testing.T) {
	st := &State{Endpoints: []string{"a:7443", "b:7443"}, Planets: []string{"b:7443", "c:7443"}}
	got := planetCandidates(st)
	if want := []string{"b:7443", "c:7443", "a:7443"}; !slices.Equal(got, want) {
		t.Fatalf("candidates %v, want %v (announced planets first, no repeats)", got, want)
	}
	if !sameSet([]string{"c:7443", "a:7443", "b:7443"}, got) || sameSet([]string{"a:7443"}, got) {
		t.Fatal("sameSet")
	}
}

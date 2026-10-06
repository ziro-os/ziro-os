package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/url"
	"testing"
)

func TestVerifyAndParse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sums := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  zirocd-linux-amd64\nbad line\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)))
	if err := Verify(sums, sig, key); err != nil {
		t.Fatal(err)
	}
	if Verify(append(sums, 'x'), sig, key) == nil || Verify(sums, sig, PublicKey) == nil || Verify(sums, []byte("!"), key) == nil {
		t.Fatal("bad signature accepted")
	}
	if m := ParseSums(sums); len(m) != 1 || m["zirocd-linux-amd64"] == "" {
		t.Fatalf("sums: %v", m)
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.0.10", "1.0.9", 1}, {"v1.2.0", "1.2.0", 0}, {"1.0.0", "dev", 1}, {"x", "1.0.0", -1}} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d", c.a, c.b, got)
		}
	}
	for raw, ok := range map[string]bool{"https://github.com/x": true, "https://objects.githubusercontent.com/x": true,
		"http://github.com/x": false, "https://github.com.evil.io/x": false, "https://evilgithubusercontent.com/x": false} {
		u, _ := url.Parse(raw)
		if trustedGitHub(u) != ok {
			t.Errorf("trusted(%s) != %v", raw, ok)
		}
	}
}

func TestCompareToolsVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.21.10", "1.0.21.9", 1},    // numeric, not lexical
		{"1.0.21.1", "1.0.21", 1},       // a builder release follows its OS build
		{"1.0.22", "1.0.21.9", 1},       // the next OS version beats any build of the previous one
		{"1.0.21", "1.0.21.0", 0},       // a missing N is 0
		{"v1.0.21.3", "1.0.21.3", 0},    // optional v
		{"1.0.21.3-rc1", "1.0.21.3", 0}, // suffix ignored
		{"1.0.21.3", "dev", 1},          // invalid is oldest
		{"dev", "1.0.21.3", -1},
		{"dev", "also-bad", 0},
		{"1.0.21.3.1", "1.0.21", -1}, // five parts are invalid
		{"1.0", "1.0.0", -1},
		{"1.0.+1", "1.0.0", -1},
		{"1.0.21.", "1.0.21", -1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestValidToolsAndOS(t *testing.T) {
	for s, ok := range map[string]bool{
		"1.0.21": true, "1.0.21.1": true, "0.0.0": true, "10.20.30.40": true,
		"1.0.21.0": false, "1.0.21.01": false, "01.0.21": false, "v1.0.21": false, "1.0.21-rc1": false,
		"1.0": false, "1.0.21.1.2": false, "": false, "1.0.x": false, "latest": false,
	} {
		if got := ValidTools(s); got != ok {
			t.Errorf("ValidTools(%q) = %v", s, got)
		}
	}
	for in, want := range map[string]string{"1.0.21.3": "1.0.21", "v1.0.21": "1.0.21", "1.0.21-rc1": "1.0.21", "1.0.21": "1.0.21", "dev": "", "1.0": ""} {
		if got := OS(in); got != want {
			t.Errorf("OS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToolsTagRe(t *testing.T) {
	for tag, want := range map[string]string{
		"tools/v1.0.21": "1.0.21", "tools/v1.0.21.3": "1.0.21.3", "tools/v1.0.210": "1.0.210",
		"tools/v1.0.21.0": "", "tools/v1.0.21.3.1": "", "tools/v1.0.21-rc1": "", "tools/v01.0.21": "", "v1.0.21.3": "", "tools/v1.0": "",
	} {
		got := ""
		if m := ToolsTagRe.FindStringSubmatch(tag); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("ToolsTagRe(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestCheckMeta(t *testing.T) {
	meta := []byte(`{"version":"1.0.21.3","min_os":"1.0.16"}`)
	h := sha256.Sum256(meta)
	sums := []byte(hex.EncodeToString(h[:]) + "  tools.json\n")
	m, err := CheckMeta(sums, meta, "1.0.21.3")
	if err != nil || m.MinOS != "1.0.16" || m.Version != "1.0.21.3" {
		t.Fatalf("good meta: %+v %v", m, err)
	}
	if _, err := CheckMeta(sums, meta, "1.0.21.4"); err == nil {
		t.Fatal("a release re-labelled under another tag was accepted")
	}
	if _, err := CheckMeta(sums, append([]byte{' '}, meta...), "1.0.21.3"); err == nil {
		t.Fatal("tools.json differing from the signed hash was accepted")
	}
	if _, err := CheckMeta([]byte{}, meta, "1.0.21.3"); err == nil {
		t.Fatal("tools.json missing from SHA256SUMS was accepted")
	}
	bad := []byte(`{"version":"1.0.21.3","min_os":"1.0.16.1"}`)
	hb := sha256.Sum256(bad)
	if _, err := CheckMeta([]byte(hex.EncodeToString(hb[:])+"  tools.json\n"), bad, "1.0.21.3"); err == nil {
		t.Fatal("a 4-part min_os was accepted")
	}
}

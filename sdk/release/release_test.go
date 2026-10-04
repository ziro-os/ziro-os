package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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

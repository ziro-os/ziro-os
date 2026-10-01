package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func testKey(t *testing.T) (string, []byte) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pb, _ := x509.MarshalPKIXPublicKey(pub)
	sb, _ := x509.MarshalPKCS8PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb})), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sb})
}

func TestRepoValidation(t *testing.T) {
	pub, _ := testKey(t)
	for _, r := range []Repo{
		{Name: "x", URL: "http://example.com", Kind: "module", Key: pub},
		{Name: "x", URL: "https://u:p@example.com", Kind: "module", Key: pub},
		{Name: "x", URL: "https://example.com", Kind: "module", Key: "junk"},
		{Name: "../x", URL: "https://example.com", Kind: "module", Key: pub},
		{Name: "x", URL: "https://example.com", Kind: "binary", Key: pub},
	} {
		if r.Validate() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	for _, p := range []string{"../x", "/etc/x", "a/../../x", ""} {
		if SafeEntryPath(p) == nil {
			t.Errorf("accepted entry path %q", p)
		}
	}
}

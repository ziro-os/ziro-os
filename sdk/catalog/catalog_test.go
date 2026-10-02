package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestBuildPublishesStacks(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(src, p)), 0755)
		os.WriteFile(filepath.Join(src, p), []byte(s), 0644)
	}
	w("apps/web/app.yaml", "name: web\n")
	w("stacks/shop/stack.yaml", "stack: shop\nversion: 1\ndescription: d\napps:\n  web: {app: web}\n")
	check := func(b []byte) (Entry, error) { return Entry{Name: "web", Version: "1"}, nil }
	idx, err := Build(src, out, "r", "app", time.Hour, time.Now(), check)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Entries) != 2 || idx.Entries[1].Type != "stack" || idx.Entries[1].Path != "stacks/shop.json" {
		t.Fatalf("entries %+v", idx.Entries)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "stacks", "shop.json")); !strings.HasPrefix(string(b), "{") {
		t.Errorf("stack not served as JSON: %s", b)
	}
	w("stacks/shop/stack.yaml", "stack: shop\nversion: 1\napps:\n  web: {app: ./apps/web/app.yaml}\n")
	if _, err := Build(src, t.TempDir(), "r", "app", time.Hour, time.Now(), check); err == nil {
		t.Error("a published stack with a local app was accepted")
	}
}

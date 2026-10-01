package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pubLine(t *testing.T, key any) string {
	pk, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func TestParseKeySource(t *testing.T) {
	for _, ok := range []string{"gh:octocat", "gh:a-b", "gl:some.user_1", "lp:ubuntu+dev"} {
		if _, _, _, err := parseKeySource(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	// No path or host injection: the username only fills a validated path segment.
	for _, bad := range []string{"gh:", "gh:../../x", "gh:a/b", "gh:evil.com#", "gh:-lead", "xx:user", "octocat",
		"gh:a?b", "gh:" + strings.Repeat("a", 40), "lp:Upper"} {
		if _, _, _, err := parseKeySource(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	_, _, url, _ := parseKeySource("gh:octocat")
	if url != "https://github.com/octocat.keys" {
		t.Fatal(url)
	}
}

func TestAcceptKeysAndMerge(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	goodRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	// A fixed 1024-bit public key: only its rejection is under test, so no weak key is generated.
	const weak = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCwjVNzwHNG5kvpKL9iUAhYd2lZGpMfXvBB7VyArPMxaNd9ezyiRW/S5iz6sbx8pV2CcAgksjejnsKf9QCz9XQ0GHGVF4axh+liX4Qw2pZ8wz9o6oVmODZv5F5DY+o0fAXfMilJbEu7mbtRihxYSfFJJvHwS7yb0mePJsSuBvESfw=="
	ed, good := pubLine(t, edPub), pubLine(t, &goodRSA.PublicKey)
	data := ed + " provider-comment\n" + weak + "\n" + good + "\n" + ed + "\n" +
		`command="/bin/evil" ` + good + "\n" + "garbage\n"
	keys, rejected := acceptKeys([]byte(data), "ziro-import:gh:alice")
	if len(keys) != 2 || len(rejected) != 3 {
		t.Fatalf("keys=%d rejected=%v", len(keys), rejected)
	}
	if strings.Contains(keys[0].line, "provider-comment") || !strings.HasSuffix(keys[0].line, " ziro-import:gh:alice") {
		t.Fatalf("line %q", keys[0].line)
	}

	manual := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeButParsableKeyMaterial0000000000000000000 admin@laptop"
	existing := manual + "\n" + keys[0].line + "\n"
	out, added, removed := mergeAuthorizedKeys([]byte(existing), keys, "ziro-import:gh:alice", false)
	if added != 1 || removed != 0 || !strings.HasPrefix(string(out), manual+"\n") {
		t.Fatalf("merge: +%d -%d\n%s", added, removed, out)
	}
	// alice removed her ed25519 key upstream: --sync drops only that imported key.
	out2, added, removed := mergeAuthorizedKeys(out, keys[1:], "ziro-import:gh:alice", true)
	if added != 0 || removed != 1 || !strings.Contains(string(out2), manual) || strings.Contains(string(out2), strings.Fields(ed)[1]) {
		t.Fatalf("sync: +%d -%d\n%s", added, removed, out2)
	}
}

func TestImportKeysFromProvider(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := pubLine(t, edPub) + "\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alice.keys":
			w.Write([]byte(body))
		case "/empty.keys":
		case "/bounce.keys":
			http.Redirect(w, r, "https://evil.example/alice.keys", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	orig := keySources["gh"]
	keySources["gh"] = keySource{"gh", srv.URL + "/%s.keys", regexp.MustCompile(`^[a-z]+$`)}
	origClient := keyFetchClient.Transport
	keyFetchClient.Transport = srv.Client().Transport
	defer func() { keySources["gh"], keyFetchClient.Transport = orig, origClient }()
	sshAuthorizedKeysPath = filepath.Join(t.TempDir(), ".ssh", "authorized_keys")

	if added, _, _, err := importKeys("gh:alice", false); err != nil || added != 1 {
		t.Fatalf("import: %d %v", added, err)
	}
	if added, _, _, err := importKeys("gh:alice", false); err != nil || added != 0 {
		t.Fatalf("re-import must be a no-op: %d %v", added, err)
	}
	fi, _ := os.Stat(sshAuthorizedKeysPath)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if _, _, _, err := importKeys("gh:nobody", false); err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Fatalf("unknown user: %v", err)
	}
	// A provider returning nothing must never sync away every key (lockout).
	if _, _, _, err := importKeys("gh:empty", true); err == nil {
		t.Fatal("empty key list accepted")
	}
	if _, _, _, err := importKeys("gh:bounce", false); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("cross-host redirect followed: %v", err)
	}
	if n, err := removeImportedKeys("gh:alice"); err != nil || n != 1 {
		t.Fatalf("remove: %d %v", n, err)
	}
}

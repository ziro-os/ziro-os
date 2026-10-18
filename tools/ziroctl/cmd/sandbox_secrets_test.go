package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

func TestSecretRewrite(t *testing.T) {
	s := &sandboxSecrets{recs: []secretRecord{
		{Name: "GH", Value: "ghp_real", Hosts: []string{"api.github.com"}, Placeholder: "zsec_gh"},
		{Name: "OAI", Value: "sk-real", Hosts: []string{"*.openai.com"}, Placeholder: "zsec_oai"},
	}}
	req := httptest.NewRequest("GET", "https://api.github.com/repos/zsec_gh/x?token=zsec_gh&q=1", nil)
	req.Header.Set("Authorization", "Bearer zsec_gh")
	req.Header.Set("X-Basic", "unchanged")
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("me:zsec_gh")))
	used, err := s.rewriteRequest(req, "api.github.com")
	if err != nil || len(used) != 1 || used[0] != "GH" {
		t.Fatalf("%v %v", used, err)
	}
	pa, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Proxy-Authorization"), "Basic "))
	if req.Header.Get("Authorization") != "Bearer ghp_real" || string(pa) != "me:ghp_real" || req.URL.Query().Get("token") != "ghp_real" ||
		req.URL.Path != "/repos/ghp_real/x" || req.Header.Get("X-Basic") != "unchanged" {
		t.Fatalf("rewritten: %v %s %s", req.Header, pa, req.URL)
	}
	// Wildcard host.
	r2 := httptest.NewRequest("GET", "https://api.openai.com/v1", nil)
	r2.Header.Set("Authorization", "Bearer zsec_oai")
	if _, err := s.rewriteRequest(r2, "api.openai.com"); err != nil || r2.Header.Get("Authorization") != "Bearer sk-real" {
		t.Fatalf("wildcard: %v %v", r2.Header, err)
	}
	// A placeholder sent to a host it isn't bound to: refused, nothing rewritten.
	for _, host := range []string{"evil.example.com", "openai.com", "api.github.com.evil.com", ""} {
		r := httptest.NewRequest("GET", "https://x/", nil)
		r.Header.Set("Authorization", "Bearer zsec_oai")
		if _, err := s.rewriteRequest(r, host); !errors.Is(err, errCredentialMismatch) {
			t.Errorf("%q: %v", host, err)
		}
	}
	r3 := httptest.NewRequest("GET", "https://api.github.com/?k=zsec_oai", nil)
	if _, err := s.rewriteRequest(r3, "api.github.com"); !errors.Is(err, errCredentialMismatch) {
		t.Errorf("query mismatch: %v", err)
	}
}

func TestSandboxSecretsAtCreate(t *testing.T) {
	m, f, _ := stubSandboxes(t)
	m.egress = newEgressProxy(m)
	dir := t.TempDir()
	old := hostCABundle
	hostCABundle = filepath.Join(dir, "roots.pem")
	os.WriteFile(hostCABundle, []byte("-----HOST ROOTS-----\n"), 0644)
	defer func() { hostCABundle = old }()
	spec := schema.SandboxSpec{Image: "a", Network: &schema.SandboxNetwork{Mode: "open"},
		Secrets: []schema.SandboxSecret{{Name: "GITHUB_TOKEN", Value: "ghp_supersecret", Hosts: []string{"api.github.com"}}}}
	sb, err := m.create(context.Background(), spec, alice)
	if err != nil {
		t.Fatal(err)
	}
	// The value is nowhere but secrets.json (0600): not in the record, the API answer or argv.
	view, _ := json.Marshal(sb)
	rec, _ := os.ReadFile(filepath.Join(sandboxDir(sb.ID), "sandbox.json"))
	var argv string
	for _, c := range f.calls {
		if c[0] == "run" {
			argv = strings.Join(c, " ")
		}
	}
	for what, s := range map[string]string{"answer": string(view), "record": string(rec), "argv": argv} {
		if strings.Contains(s, "ghp_supersecret") {
			t.Errorf("the secret value is in the %s", what)
		}
	}
	if fi, err := os.Stat(secretsFile(sb.ID)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("secrets file: %v", err)
	}
	if !strings.Contains(argv, "-e GITHUB_TOKEN=zsec_") || !strings.Contains(argv, ":/etc/ziro/ca-bundle.crt:ro") ||
		!strings.Contains(argv, "-e SSL_CERT_FILE=/etc/ziro/ca-bundle.crt") || !strings.Contains(argv, "-e NODE_EXTRA_CA_CERTS=/etc/ziro/sandbox-ca.crt") {
		t.Errorf("run args %s", argv)
	}
	_, _, bundle := caFiles(sb.ID)
	if b, _ := os.ReadFile(bundle); !strings.Contains(string(b), "HOST ROOTS") || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Errorf("bundle %s", b)
	}
	if _, key, _ := caFiles(sb.ID); func() bool { fi, err := os.Stat(key); return err != nil || fi.Mode().Perm() != 0600 }() {
		t.Error("CA key not 0600")
	}
	// The redirect to the proxy is in the table for this sandbox only.
	m.net.proxyPort = 22996
	m.applyNet()
	last := f.calls[len(f.calls)-1]
	if last[0] != "nft" || !strings.Contains(last[1], "ip saddr "+sb.IP+" tcp dport 443 redirect to :22996") {
		t.Errorf("nft %v", last)
	}
	// Without the proxy, secrets are refused.
	m.egress = nil
	if _, err := m.create(context.Background(), spec, alice); err == nil {
		t.Error("secrets accepted without the egress proxy")
	}
}

func TestEgressAllowed(t *testing.T) {
	n := newSandboxNet(sandboxDefSubnet)
	open := ipPolicy{"aaaaaaaaaaaa", &schema.SandboxNetwork{Mode: "open"}}
	allow := ipPolicy{"bbbbbbbbbbbb", &schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org", "10.9.0.0/16"}}}
	n.learned["bbbbbbbbbbbb"] = map[string]time.Time{"151.101.0.1": time.Now().Add(time.Minute), "151.101.0.2": time.Now().Add(-time.Minute)}
	for _, c := range []struct {
		p    ipPolicy
		dst  string
		want bool
	}{
		{open, "8.8.8.8", true}, {open, "169.254.169.254", false}, {open, "192.168.1.1", false},
		{allow, "151.101.0.1", true}, {allow, "151.101.0.2", false}, {allow, "8.8.8.8", false}, {allow, "10.9.1.1", true},
		{ipPolicy{}, "8.8.8.8", false},
	} {
		if got := n.egressAllowed(c.p, netip.MustParseAddr(c.dst)); got != c.want {
			t.Errorf("%v %s: %v", c.p.net, c.dst, got)
		}
	}
}

// The proxy end to end with real TLS on both sides: a bound host is intercepted and gets the
// real secret; another host is spliced through untouched (the placeholder is all it sees).
func TestEgressProxy(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	id := "aaaaaaaaaaaa"
	certPEM, keyPEM, err := newCA("test sandbox CA", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := tls.X509KeyPair(certPEM, keyPEM)
	ca.Leaf, _ = x509.ParseCertificate(ca.Certificate[0])
	sec := &sandboxSecrets{ca: &ca, leafs: map[string]*tls.Certificate{}, recs: []secretRecord{
		{Name: "TOKEN", Value: "real-secret", Hosts: []string{"example.com"}, Placeholder: "zsec_tok"}}}

	seen := make(chan string, 4)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host + " " + r.Header.Get("Authorization")
		io.WriteString(w, "upstream ok")
	}))
	defer up.Close()
	upAddr := netip.MustParseAddrPort(strings.TrimPrefix(up.URL, "https://"))

	p := newEgressProxy(m)
	p.secrets[id] = sec
	p.origDst = func(net.Conn) (netip.AddrPort, error) { return upAddr, nil }
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	p.roots = &tls.Config{RootCAs: pool}
	m.net.byIP = map[string]ipPolicy{"127.0.0.1": {id, &schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"127.0.0.1"}}}}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.serve(ctx, ln)

	client := func(sni string, insecure bool) *http.Client {
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(certPEM)
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) },
			TLSClientConfig: &tls.Config{ServerName: sni, RootCAs: roots, InsecureSkipVerify: insecure}}}
	}
	get := func(c *http.Client, u, auth string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", auth)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	// Bound host: the sandbox's CA signs it, the upstream gets the real value.
	resp, body := get(client("example.com", false), "https://example.com/", "Bearer zsec_tok")
	if resp.StatusCode != 200 || body != "upstream ok" {
		t.Fatalf("intercepted: %d %s", resp.StatusCode, body)
	}
	if got := <-seen; got != "example.com Bearer real-secret" {
		t.Fatalf("upstream saw %q", got)
	}
	// Another Host on the intercepted connection: the placeholder is refused, nothing is sent.
	req0, _ := http.NewRequest("GET", "https://example.com/", nil)
	req0.Host = "evil.test"
	req0.Header.Set("Authorization", "Bearer zsec_tok")
	r0, err := client("example.com", false).Do(req0)
	if err != nil {
		t.Fatal(err)
	}
	b0, _ := io.ReadAll(r0.Body)
	r0.Body.Close()
	if r0.StatusCode != 403 || !strings.Contains(string(b0), "credential_endpoint_mismatch") || len(seen) != 0 {
		t.Fatalf("mismatch: %d %s", r0.StatusCode, b0)
	}
	// Not bound: spliced, the real server's certificate, and the placeholder stays a placeholder.
	resp, _ = get(client("www.other.test", true), "https://www.other.test/", "Bearer zsec_tok")
	if got := <-seen; resp.StatusCode != 200 || got != "www.other.test Bearer zsec_tok" {
		t.Fatalf("spliced: %d %q", resp.StatusCode, got)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || !resp.TLS.PeerCertificates[0].Equal(up.Certificate()) {
		t.Error("a spliced connection was intercepted")
	}
	// A destination the policy doesn't allow: the connection is dropped.
	m.net.byIP["127.0.0.1"] = ipPolicy{id, &schema.SandboxNetwork{Mode: "open"}} // 127.0.0.1 is blocked for open
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if _, err := client("example.com", false).Do(req); err == nil {
		t.Error("a blocked destination was reached through the proxy")
	}
}

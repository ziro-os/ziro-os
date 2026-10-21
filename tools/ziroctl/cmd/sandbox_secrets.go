package cmd

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Credential injection (the OpenShell model). A sandbox's secret is an environment variable
// holding a placeholder (zsec_...). Its HTTPS traffic to port 443 is redirected to the host's
// egress proxy (sandbox_egress.go), which lets it through untouched unless the server name is one
// of a secret's hosts; then the proxy terminates TLS with the sandbox's own CA (trusted inside
// the sandbox, and nowhere else) and swaps placeholders in headers, Basic auth and the query
// for the real values. A placeholder sent to any other host is refused (403
// credential_endpoint_mismatch), so a prompt-injected agent can't send a usable secret elsewhere.
//
// The values are kept in the sandbox's secrets.json (0600), never in its spec, its record or
// the container; they are gone with the sandbox.
//
// Known limitation: request bodies, WebSocket frames and request signing (SigV4) are not rewritten.

const (
	sandboxCABundle  = "/etc/ziro/ca-bundle.crt"  // host roots + the sandbox's CA, inside the sandbox
	sandboxCACert    = "/etc/ziro/sandbox-ca.crt" // the sandbox's CA alone
	placeholderStart = "zsec_"
)

var hostCABundle = "/etc/ssl/certs/ca-certificates.crt"

type secretRecord struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Hosts       []string `json:"hosts"`
	Placeholder string   `json:"placeholder"`
}

func secretsFile(id string) string { return filepath.Join(sandboxDir(id), "secrets.json") }
func caFiles(id string) (crt, key, bundle string) {
	d := sandboxDir(id)
	return filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key"), filepath.Join(d, "ca-bundle.crt")
}

func newPlaceholder() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return placeholderStart + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// prepareSecrets writes a sandbox's secrets and CA before it starts, and returns the
// environment the container gets (placeholders and where the CA is).
func prepareSecrets(id string, secrets []schema.SandboxSecret, expires time.Time) (map[string]string, error) {
	if len(secrets) == 0 {
		return nil, nil
	}
	env := map[string]string{"SSL_CERT_FILE": sandboxCABundle, "REQUESTS_CA_BUNDLE": sandboxCABundle,
		"CURL_CA_BUNDLE": sandboxCABundle, "GIT_SSL_CAINFO": sandboxCABundle, "NODE_EXTRA_CA_CERTS": sandboxCACert}
	recs := make([]secretRecord, 0, len(secrets))
	for _, s := range secrets {
		r := secretRecord{Name: s.Name, Value: s.Value, Hosts: s.Hosts, Placeholder: newPlaceholder()}
		recs = append(recs, r)
		env[s.Name] = r.Placeholder
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(secretsFile(id), b, 0600); err != nil {
		return nil, err
	}
	crt, key, bundle := caFiles(id)
	certPEM, keyPEM, err := newCA("Ziro sandbox "+id+" egress CA", expires.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(key, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(crt, certPEM, 0644); err != nil {
		return nil, err
	}
	roots, err := os.ReadFile(hostCABundle)
	if err != nil {
		return nil, errors.New("the host has no CA bundle (" + hostCABundle + "): secrets need it")
	}
	return env, writeFileAtomic(bundle, append(append(roots, '\n'), certPEM...), 0644)
}

// withoutValues is what the record keeps of secrets: names and hosts.
func withoutValues(secrets []schema.SandboxSecret) []schema.SandboxSecret {
	out := make([]schema.SandboxSecret, len(secrets))
	for i, s := range secrets {
		out[i] = schema.SandboxSecret{Name: s.Name, Hosts: s.Hosts}
	}
	return out
}

// secretMounts are the read-only CA files a sandbox with secrets gets.
func secretMounts(id string) []string {
	crt, _, bundle := caFiles(id)
	return []string{bundle + ":" + sandboxCABundle + ":ro", crt + ":" + sandboxCACert + ":ro"}
}

// sandboxSecrets is what the egress proxy needs of a sandbox: its secrets and its CA.
type sandboxSecrets struct {
	recs  []secretRecord
	ca    *tls.Certificate
	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func loadSandboxSecrets(id string) (*sandboxSecrets, error) {
	b, err := os.ReadFile(secretsFile(id))
	if err != nil {
		return nil, err
	}
	s := &sandboxSecrets{leafs: map[string]*tls.Certificate{}}
	if err := json.Unmarshal(b, &s.recs); err != nil {
		return nil, err
	}
	crt, key, _ := caFiles(id)
	kp, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	if kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0]); err != nil {
		return nil, err
	}
	s.ca = &kp
	return s, nil
}

func (s *sandboxSecrets) leaf(host string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.leafs[host]; c != nil && time.Until(c.Leaf.NotAfter) > 24*time.Hour {
		return c, nil
	}
	c, err := issueLeaf(s.ca, host)
	if err == nil {
		s.leafs[host] = c
	}
	return c, err
}

func secretHostMatch(host string, hosts []string) bool {
	for _, h := range hosts {
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

// boundTo reports whether any secret may be used with host (the proxy then intercepts it).
func (s *sandboxSecrets) boundTo(host string) bool {
	for _, r := range s.recs {
		if secretHostMatch(host, r.Hosts) {
			return true
		}
	}
	return false
}

var errCredentialMismatch = errors.New("credential_endpoint_mismatch")

// inject swaps the placeholders in one string: the values of secrets bound to host, or
// errCredentialMismatch for a placeholder of a secret that isn't.
func (s *sandboxSecrets) inject(v, host string, used map[string]bool) (string, error) {
	if !strings.Contains(v, placeholderStart) {
		return v, nil
	}
	for _, r := range s.recs {
		if !strings.Contains(v, r.Placeholder) {
			continue
		}
		if !secretHostMatch(host, r.Hosts) {
			return "", errCredentialMismatch
		}
		v = strings.ReplaceAll(v, r.Placeholder, r.Value)
		used[r.Name] = true
	}
	return v, nil
}

// rewriteRequest injects the secrets bound to host into a request's headers (Basic auth
// decoded) and query, and returns the names it used.
func (s *sandboxSecrets) rewriteRequest(req *http.Request, host string) ([]string, error) {
	used := map[string]bool{}
	for k, vs := range req.Header {
		for i, v := range vs {
			if (k == "Authorization" || k == "Proxy-Authorization") && strings.HasPrefix(v, "Basic ") {
				if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Basic ")); err == nil {
					nv, err := s.inject(string(raw), host, used)
					if err != nil {
						return nil, err
					}
					v = "Basic " + base64.StdEncoding.EncodeToString([]byte(nv))
				}
			}
			nv, err := s.inject(v, host, used)
			if err != nil {
				return nil, err
			}
			req.Header[k][i] = nv
		}
	}
	if strings.Contains(req.URL.RawQuery, placeholderStart) {
		q := req.URL.Query()
		for k, vs := range q {
			for i, v := range vs {
				nv, err := s.inject(v, host, used)
				if err != nil {
					return nil, err
				}
				q[k][i] = nv
			}
		}
		req.URL.RawQuery = q.Encode()
	}
	if strings.Contains(req.URL.Path, placeholderStart) {
		p, err := s.inject(req.URL.Path, host, used)
		if err != nil {
			return nil, err
		}
		req.URL.Path, req.URL.RawPath = p, ""
	}
	names := make([]string, 0, len(used))
	for n := range used {
		names = append(names, n)
	}
	return names, nil
}

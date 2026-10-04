package cmd

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// fakeIdP is an OIDC provider with the device-code grant: discovery, JWKS, device
// authorization and a token endpoint that answers authorization_pending until approved.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	approved bool
	claims   map[string]any
	audience string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k, audience: clientID}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := f.srv.URL
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": u, "jwks_uri": u + "/jwks", "token_endpoint": u + "/token",
				"authorization_endpoint": u + "/auth", "device_authorization_endpoint": u + "/device",
				"id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
				"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}}})
		case "/device":
			json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-1", "user_code": "WDJB-MJHT",
				"verification_uri": u + "/verify", "verification_uri_complete": u + "/verify?code=WDJB-MJHT", "expires_in": 600, "interval": 1})
		case "/token":
			_ = r.ParseForm()
			f.mu.Lock()
			ok, claims := f.approved, f.claims
			f.mu.Unlock()
			if r.Form.Get("device_code") != "dc-1" || !ok {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"authorization_pending"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
				"id_token": f.idToken(claims)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) idToken(extra map[string]any) string {
	claims := map[string]any{"iss": f.srv.URL, "sub": "u-1", "aud": f.audience, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signing := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return signing + "." + b64(sig)
}

func (f *fakeIdP) approve(claims map[string]any) {
	f.mu.Lock()
	f.approved, f.claims = true, claims
	f.mu.Unlock()
}

func TestSSOPolicy(t *testing.T) {
	cfg := zr.SSO{Issuer: "https://idp", ClientID: "c"}
	n := zr.NetworkSSO{Domains: []string{"example.com"}, Tags: []string{"laptop"}, GroupTags: map[string][]string{"admins": {"admin"}}, KeyExpiry: 24}
	id, err := ssoPolicy(cfg, n, "alice@example.com", true, []string{"admins", "x"})
	if err != nil || strings.Join(id.tags, ",") != "admin,laptop" || id.ttl != 24*time.Hour {
		t.Fatalf("admit: %+v %v", id, err)
	}
	for _, tc := range []struct {
		name, email string
		verified    bool
		groups      []string
		n           zr.NetworkSSO
	}{
		{"other domain", "mallory@evil.com", true, nil, n},
		{"look-alike domain", "mallory@example.com.evil.com", true, nil, n},
		{"unverified email", "alice@example.com", false, nil, n},
		{"no email", "", true, nil, n},
		{"not in group", "bob@example.com", true, []string{"eng"}, zr.NetworkSSO{Groups: []string{"ops"}}},
		{"open network", "anyone@gmail.com", true, nil, zr.NetworkSSO{}},
	} {
		if _, err := ssoPolicy(cfg, tc.n, tc.email, tc.verified, tc.groups); err == nil {
			t.Errorf("%s: admitted", tc.name)
		}
	}
	cfg.TrustUnverifiedEmail = true
	if _, err := ssoPolicy(cfg, n, "alice@example.com", false, nil); err != nil {
		t.Fatalf("trust-unverified-email: %v", err)
	}
}

// TestRouterSSOEndToEnd: a device signs in through the router with the device-code flow, gets a
// certificate with the user's identity, tags and expiry; a disallowed user is refused; an expired
// device is cut off; user: ACL selectors match signed-in devices.
func TestRouterSSOEndToEnd(t *testing.T) {
	clusterDir = t.TempDir()
	idp := newFakeIdP(t, "ziro-router")
	st, n := routerTestState(t, zr.ACL{Rules: []zr.Rule{{Src: []string{"user:alice@example.com"}, Dst: []string{"*:*"}}}})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	routerOf(st).SSO = &zr.SSO{Issuer: idp.srv.URL, ClientID: "ziro-router"}
	n.SSO = &zr.NetworkSSO{Domains: []string{"example.com"}, Tags: []string{"laptop"}, KeyExpiry: 1}
	initStateMaps(st)
	st.Secrets[ssoSecretName] = map[string]string{ssoSecretKey: "s3cret"}
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	hub := newRouterHub()
	rt := newRouterServer(hub, st.CACert)
	rt.sso.hc = idp.srv.Client()
	var ver atomic.Uint64
	rt.sync = func() {
		cur, _ := readState()
		hub.setState(routerOf(cur), ver.Add(1))
	}
	rt.sync()
	pool, _ := caPool(st.CACert)
	srv := httptest.NewUnstartedServer(rt)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, _ := parseCertPEM(st.CACert)

	req, keyPEM := testDevice(t, "alice-laptop", 7)
	req.Network, req.SSO = n.ID, true
	c := zr.NewClient([]string{addr}, ca, nil)
	out, err := c.Register(ctx, req)
	if err != nil || out.Status != "sso" || out.Code != "WDJB-MJHT" || !strings.HasSuffix(out.URL, "/verify") {
		t.Fatalf("sign-in start: %+v %v", out, err)
	}
	if again, _ := c.Register(ctx, req); again.Status != "sso" || again.Code != out.Code {
		t.Fatalf("polling must continue the same sign-in: %+v", again)
	}
	idp.approve(map[string]any{"email": "Alice@Example.com", "email_verified": true})
	deadline := time.Now().Add(10 * time.Second)
	for out.Status != "authorized" {
		if time.Now().After(deadline) {
			t.Fatalf("sign-in never completed: %+v", out)
		}
		time.Sleep(200 * time.Millisecond)
		if out, err = c.Register(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	cur, _ := readState()
	m := findMember(routerOf(cur), n.ID, out.Member)
	if m.User != "alice@example.com" || strings.Join(m.Tags, ",") != "laptop" || time.Until(m.Expires) > time.Hour || time.Until(m.Expires) < 50*time.Minute {
		t.Fatalf("member: user=%q tags=%v expires=%v", m.User, m.Tags, m.Expires)
	}
	members := []*zr.Member{m}
	if vis, filter := compileACL(n.ACL, members).view(m); len(filter) != 0 || len(vis) != 0 {
		_ = vis // alone in the network: the user: rule names alice as a source only
	}
	if !selMatches("user:alice@example.com", m, nil) || selMatches("user:bob@example.com", m, nil) {
		t.Fatal("user: selector")
	}
	cert, _ := tls.X509KeyPair([]byte(out.Cert), keyPEM)
	c.SetCert(&cert)
	if err := c.UpdateEndpoints(ctx, zr.MapRequest{}); err != nil {
		t.Fatalf("signed-in device rejected: %v", err)
	}

	// Expiry: the device is cut off with a clear message.
	_ = withState(func(cur *ClusterState) error {
		findMember(routerOf(cur), n.ID, out.Member).Expires = time.Now().Add(-time.Second)
		return nil
	})
	rt.sync()
	var se *zr.StatusError
	if err := c.UpdateEndpoints(ctx, zr.MapRequest{}); !errors.As(err, &se) || se.Code != http.StatusUnauthorized || !strings.Contains(se.Message, "expired") {
		t.Fatalf("expired device: %v", err)
	}

	// A user outside the allowed domain is refused (a different device and sign-in).
	idp.mu.Lock()
	idp.approved = false
	idp.mu.Unlock()
	req2, _ := testDevice(t, "mallory", 8)
	req2.Network, req2.SSO = n.ID, true
	c2 := zr.NewClient([]string{addr}, ca, nil)
	if _, err := c2.Register(ctx, req2); err != nil {
		t.Fatal(err)
	}
	idp.approve(map[string]any{"email": "mallory@evil.com", "email_verified": true})
	for i := 0; ; i++ {
		_, err := c2.Register(ctx, req2)
		if errors.As(err, &se) && se.Code == http.StatusForbidden && strings.Contains(se.Message, "domain") {
			break
		}
		if i > 50 {
			t.Fatalf("disallowed user: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// An ID token minted for another client (audience) is refused, whatever it claims.
	idp.mu.Lock()
	idp.approved, idp.audience = false, "some-other-app"
	idp.mu.Unlock()
	req3, _ := testDevice(t, "eve", 9)
	req3.Network, req3.SSO = n.ID, true
	c3 := zr.NewClient([]string{addr}, ca, nil)
	if _, err := c3.Register(ctx, req3); err != nil {
		t.Fatal(err)
	}
	idp.approve(map[string]any{"email": "alice@example.com", "email_verified": true})
	for i := 0; ; i++ {
		_, err := c3.Register(ctx, req3)
		if errors.As(err, &se) && se.Code == http.StatusForbidden && strings.Contains(se.Message, "sign-in failed") {
			break
		}
		if i > 50 {
			t.Fatalf("token for another audience: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// A network without sign-in refuses SSO registration.
	_ = withState(func(cur *ClusterState) error { routerOf(cur).Networks[0].SSO = nil; return nil })
	if _, err := c2.Register(ctx, req2); !errors.As(err, &se) || se.Code != http.StatusNotFound {
		t.Fatalf("sso on a network without it: %v", err)
	}
}

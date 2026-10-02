package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAPIMiddleware(t *testing.T) {
	h := newAPIHarness(t, func(a *apiRouter) {
		a.get("/api/v1/x", "viewer", func(w http.ResponseWriter, r *http.Request) { apiReply(w, nil, map[string]string{"role": apiRole(r)}) })
		a.post("/api/v1/x/{name}", "operator", func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("name") == "bad" {
				apiReply(w, errNotFound("no such x"), nil)
				return
			}
			apiReply(w, nil, APIMessage{Status: "ok"})
		})
		a.get("/api/v1/open", "public", func(w http.ResponseWriter, r *http.Request) { apiReply(w, nil, "ok") })
	})
	envelope := func(role, method, path string) (int, APIMessage, http.Header) {
		rec := h.req(role, method, path, "")
		var m APIMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m, rec.Header()
	}
	if c, m, _ := envelope("", "GET", "/api/v1/x"); c != 401 || m.Code != "unauthorized" {
		t.Errorf("no token: %d %+v", c, m)
	}
	if c, _, _ := envelope("", "GET", "/api/v1/open"); c != 200 {
		t.Errorf("public: %d", c)
	}
	if c, m, _ := envelope("viewer", "POST", "/api/v1/x/a"); c != 403 || m.Code != "forbidden" {
		t.Errorf("viewer POST: %d %+v", c, m)
	}
	if c, _, _ := envelope("operator", "POST", "/api/v1/x/a"); c != 200 {
		t.Errorf("operator POST: %d", c)
	}
	if c, m, _ := envelope("operator", "POST", "/api/v1/x/bad"); c != 404 || m.Code != "not_found" || m.Message != "no such x" {
		t.Errorf("not found: %d %+v", c, m)
	}
	if c, m, hd := envelope("admin", "DELETE", "/api/v1/x"); c != 405 || m.Code != "method_not_allowed" || hd.Get("Allow") != "GET" {
		t.Errorf("405: %d %+v %v", c, m, hd)
	}
	if c, m, _ := envelope("admin", "GET", "/api/v1/nope"); c != 404 || m.Code != "not_found" {
		t.Errorf("404: %d %+v", c, m)
	}
	if rec := h.req("viewer", "GET", "/api/v1/x", ""); rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("security headers %v", rec.Header())
	}

	// Every change is audited with the caller and the result; reads are not.
	b, _ := os.ReadFile(auditPath)
	log := string(b)
	if !strings.Contains(log, `"actor":"api-token:t-operator(operator)"`) || !strings.Contains(log, `"action":"api POST /api/v1/x/{name}"`) ||
		!strings.Contains(log, "HTTP 404: no such x") || strings.Contains(log, "GET /api/v1/x\"") {
		t.Errorf("audit log:\n%s", log)
	}
	if _, _, err := verifyAudit(auditFiles()); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

func TestAPIRateLimitPerToken(t *testing.T) {
	h := newAPIHarness(t, func(a *apiRouter) {
		a.get("/api/v1/x", "viewer", func(w http.ResponseWriter, r *http.Request) { apiReply(w, nil, "ok") })
	})
	srv := newAPIHandler(&apiRouter{routes: []apiRoute{{"GET", "/api/v1/x", "viewer", func(w http.ResponseWriter, r *http.Request) { apiReply(w, nil, "ok") }}}},
		apiServerConfig{perToken: newRateLimiter(2, time.Minute)})
	h.h = srv
	for i, want := range []int{200, 200, 429} {
		if c := h.code("viewer", "GET", "/api/v1/x", ""); c != want {
			t.Errorf("request %d: %d, want %d", i, c, want)
		}
	}
	if c := h.code("admin", "GET", "/api/v1/x", ""); c != 200 {
		t.Errorf("another token is limited separately: %d", c)
	}
}

func TestPathMatches(t *testing.T) {
	for _, c := range []struct {
		pat, path string
		ok        bool
	}{
		{"/api/v1/x/{name}", "/api/v1/x/a", true}, {"/api/v1/x/{name}", "/api/v1/x/", false}, {"/api/v1/x/{name}", "/api/v1/x/a/b", false},
		{"/api/v1/x", "/api/v1/x", true}, {"/api/v1/x", "/api/v1/y", false}, {"/api/v1/f/{p...}", "/api/v1/f/a/b", true},
	} {
		if pathMatches(c.pat, c.path) != c.ok {
			t.Errorf("%s ~ %s: want %v", c.pat, c.path, c.ok)
		}
	}
}

func TestTLSCertRenewal(t *testing.T) {
	dir := t.TempDir()
	cert := dir + "/c.pem"
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5")}
	if tlsCertCurrent(cert, ips, time.Now()) {
		t.Fatal("missing cert reported current")
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(notAfter time.Time, ips []net.IP) {
		tmpl := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IPAddresses: ips}
		der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
		os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	}
	mk(time.Now().Add(300*24*time.Hour), ips)
	if !tlsCertCurrent(cert, ips, time.Now()) {
		t.Error("fresh cert not current")
	}
	if tlsCertCurrent(cert, append(ips, net.ParseIP("192.0.2.9")), time.Now()) {
		t.Error("cert missing a new host address reported current")
	}
	mk(time.Now().Add(20*24*time.Hour), ips)
	if tlsCertCurrent(cert, ips, time.Now()) {
		t.Error("cert expiring within 30 days reported current")
	}
}

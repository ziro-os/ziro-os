package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// ---- a minimal ACME CA (RFC 8555) ----
//
// Enough of the protocol for golang.org/x/crypto/acme: directory, nonces, accounts, orders,
// authorizations with a dns-01 challenge (validated against the fake DNS provider, as a CA would
// query the zone's name servers), finalize and the certificate. Request signatures are not checked.

type fakeCA struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caDER  []byte

	life     time.Duration // validity of what it issues
	validate func(name, value string) bool
	accounts map[string]string // kid -> thumbprint
	orders   []*fakeOrder
	authzs   []*fakeAuthz
	log      []string
	newAccts int
}

type fakeAuthz struct {
	id       int
	ident    string // identifier value without the wildcard
	wildcard bool
	token    string
	status   string
	acct     string
}

type fakeOrder struct {
	id       int
	idents   []string
	authz    []int
	finalDER []byte
	cert     string
}

func newFakeCA(t *testing.T, validate func(name, value string) bool) *fakeCA {
	t.Helper()
	f := &fakeCA{t: t, validate: validate, life: 90 * 24 * time.Hour, accounts: map[string]string{}}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.caCert = &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	f.caDER, _ = x509.CreateCertificate(rand.Reader, f.caCert, f.caCert, &f.caKey.PublicKey, f.caKey)
	f.caCert, _ = x509.ParseCertificate(f.caDER) // the parsed form is what a pool and the issuer need
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	old := acmeAllowHTTP
	acmeAllowHTTP = true
	t.Cleanup(func() { acmeAllowHTTP = old })
	return f
}

func (f *fakeCA) url(p string) string { return f.srv.URL + p }

func (f *fakeCA) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeCA) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// jws is the part of a request the fake reads.
func (f *fakeCA) jws(r *http.Request) (hdr map[string]any, payload []byte) {
	body, _ := io.ReadAll(r.Body)
	var env struct{ Protected, Payload string }
	_ = json.Unmarshal(body, &env)
	p, _ := base64.RawURLEncoding.DecodeString(env.Protected)
	_ = json.Unmarshal(p, &hdr)
	payload, _ = base64.RawURLEncoding.DecodeString(env.Payload)
	return hdr, payload
}

func (f *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("n%d", time.Now().UnixNano()))
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/directory":
		reply(200, map[string]string{"newNonce": f.url("/nonce"), "newAccount": f.url("/acct"), "newOrder": f.url("/neworder")})
	case r.URL.Path == "/nonce":
		w.WriteHeader(200)
	case r.URL.Path == "/acct":
		hdr, _ := f.jws(r)
		jwk, _ := hdr["jwk"].(map[string]any)
		x, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["x"]))
		y, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["y"]))
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
			return
		}
		th, err := acme.JWKThumbprint(pub)
		if err != nil {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
			return
		}
		kid := f.url("/acct/" + th[:8])
		f.mu.Lock()
		_, existed := f.accounts[kid]
		f.accounts[kid] = th
		if !existed {
			f.newAccts++
		}
		f.mu.Unlock()
		f.record("account")
		w.Header().Set("Location", kid)
		code := 201
		if existed {
			code = 200
		}
		reply(code, map[string]any{"status": "valid"})
	case r.URL.Path == "/neworder":
		hdr, payload := f.jws(r)
		var req struct {
			Identifiers []struct{ Type, Value string }
		}
		_ = json.Unmarshal(payload, &req)
		f.mu.Lock()
		o := &fakeOrder{id: len(f.orders)}
		var authURLs []string
		var ids []map[string]string
		for _, id := range req.Identifiers {
			base, wild := strings.CutPrefix(id.Value, "*.")
			a := &fakeAuthz{id: len(f.authzs), ident: base, wildcard: wild, token: fmt.Sprintf("tok%d", len(f.authzs)), status: "pending", acct: fmt.Sprint(hdr["kid"])}
			f.authzs = append(f.authzs, a)
			o.authz = append(o.authz, a.id)
			o.idents = append(o.idents, id.Value)
			authURLs = append(authURLs, f.url(fmt.Sprintf("/authz/%d", a.id)))
			ids = append(ids, map[string]string{"type": "dns", "value": id.Value})
		}
		f.orders = append(f.orders, o)
		f.mu.Unlock()
		f.record("order " + strings.Join(o.idents, ","))
		w.Header().Set("Location", f.url(fmt.Sprintf("/order/%d", o.id)))
		reply(201, map[string]any{"status": "pending", "identifiers": ids, "authorizations": authURLs, "finalize": f.url(fmt.Sprintf("/finalize/%d", o.id))})
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		f.jws(r)
		var id int
		fmt.Sscanf(r.URL.Path, "/authz/%d", &id)
		f.mu.Lock()
		a := f.authzs[id]
		resp := map[string]any{"status": a.status, "identifier": map[string]string{"type": "dns", "value": a.ident}, "wildcard": a.wildcard,
			"challenges": []map[string]string{{"type": "dns-01", "url": f.url(fmt.Sprintf("/chal/%d", a.id)), "token": a.token, "status": a.status}}}
		f.mu.Unlock()
		f.record("authz")
		reply(200, resp)
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		hdr, _ := f.jws(r)
		var id int
		fmt.Sscanf(r.URL.Path, "/chal/%d", &id)
		f.mu.Lock()
		a := f.authzs[id]
		th := f.accounts[fmt.Sprint(hdr["kid"])]
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(a.token + "." + th))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		ok := f.validate("_acme-challenge."+a.ident, want)
		f.mu.Lock()
		a.status = "invalid"
		if ok {
			a.status = "valid"
		}
		f.mu.Unlock()
		f.record(fmt.Sprintf("validate %s %v", a.ident, ok))
		reply(200, map[string]string{"type": "dns-01", "url": f.url(r.URL.Path), "token": a.token, "status": "processing"})
	case strings.HasPrefix(r.URL.Path, "/order/"):
		f.jws(r)
		var id int
		fmt.Sscanf(r.URL.Path, "/order/%d", &id)
		reply(200, f.orderJSON(id, w))
	case strings.HasPrefix(r.URL.Path, "/finalize/"):
		_, payload := f.jws(r)
		var id int
		fmt.Sscanf(r.URL.Path, "/finalize/%d", &id)
		var req struct{ CSR string }
		_ = json.Unmarshal(payload, &req)
		der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:badCSR"})
			return
		}
		f.mu.Lock()
		o := f.orders[id]
		leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(f.life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		cert, _ := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
		o.cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caDER}))
		o.finalDER = der
		f.mu.Unlock()
		f.record("finalize")
		reply(200, f.orderJSON(id, w))
	case strings.HasPrefix(r.URL.Path, "/cert/"):
		f.jws(r)
		var id int
		fmt.Sscanf(r.URL.Path, "/cert/%d", &id)
		f.mu.Lock()
		c := f.orders[id].cert
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = io.WriteString(w, c)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeCA) orderJSON(id int, w http.ResponseWriter) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[id]
	status := "ready"
	for _, ai := range o.authz {
		switch f.authzs[ai].status {
		case "invalid":
			status = "invalid"
		case "pending":
			if status != "invalid" {
				status = "pending"
			}
		}
	}
	resp := map[string]any{"status": status, "finalize": f.url(fmt.Sprintf("/finalize/%d", id))}
	if o.cert != "" {
		resp["status"], resp["certificate"] = "valid", f.url(fmt.Sprintf("/cert/%d", id))
	}
	w.Header().Set("Location", f.url(fmt.Sprintf("/order/%d", id)))
	return resp
}

// fastACME makes the waits in an issuance instant.
func fastACME(t *testing.T) {
	t.Helper()
	oldMax, oldPoll, oldSettle := dnsPropagationMax, dnsPropagationPoll, dnsPropagationSettle
	dnsPropagationMax, dnsPropagationPoll, dnsPropagationSettle = 300*time.Millisecond, 10*time.Millisecond, 0
	t.Cleanup(func() { dnsPropagationMax, dnsPropagationPoll, dnsPropagationSettle = oldMax, oldPoll, oldSettle })
}

// txtAt is what a CA querying the zone would see: the TXT values published at name.
func (f *fakeDNS) txtAt(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, recs := range f.recs {
		for _, r := range recs {
			if r.Type == "TXT" && r.Name == name {
				out = append(out, r.Content)
			}
		}
	}
	return out
}

func (f *fakeDNS) challengeRecords() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, recs := range f.recs {
		for _, r := range recs {
			if strings.HasPrefix(r.Name, "_acme-challenge.") {
				n++
			}
		}
	}
	return n
}

// acmeEnv is dnsEnv plus a fake CA configured as the ACME directory and a fake DNS provider the CA
// validates against.
func acmeEnv(t *testing.T) (localRouteStore, *fakeDNS, *fakeCA) {
	t.Helper()
	fastACME(t)
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	ca := newFakeCA(t, func(name, value string) bool { return slices.Contains(f.txtAt(name), value) })
	addProvider(t, s, "cf")
	if err := s.update(func(d *gatewayData) error {
		d.ACME = GatewayACME{Email: "ops@example.com", Directory: ca.url("/directory")}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, f, ca
}

func readStoredCert(t *testing.T, s routeStore, name string) (*x509.Certificate, GatewayCert) {
	t.Helper()
	g, err := s.getCert(name)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(g.Cert))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, g
}

// ---- issuance ----

func TestIssueWildcardCertificateThroughDNS01(t *testing.T) {
	s, f, ca := acmeEnv(t)
	// A foreign TXT at the same name, and one of the sync's own records, must survive.
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.apps.example.com", Type: "TXT", Content: "someone-elses", Comment: "mine"})
	f.seed("z-example.com", DNSRec{Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300, Comment: dnsMarker()})
	c, err := dnsCertAdd(s, []string{"*.apps.example.com", "apps.example.com"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "dns01-wild-apps-example-com" {
		t.Fatalf("name: %s", c.Name)
	}

	// While the CA validates, both challenge values sit at one name and carry the ACME marker.
	var seen []string
	var owners []string
	ca.validate = func(name, value string) bool {
		f.mu.Lock()
		for _, r := range f.recs["z-example.com"] {
			if r.Name == name && r.Type == "TXT" && strings.HasPrefix(r.Comment, "ziro-acme:") {
				owners = append(owners, r.Comment)
			}
		}
		f.mu.Unlock()
		seen = append(seen, name)
		return slices.Contains(f.txtAt(name), value)
	}
	if err := issueAndStore(s, c); err != nil {
		t.Fatal(err)
	}

	if ca.count("order *.apps.example.com,apps.example.com") != 1 || ca.count("validate apps.example.com true") != 2 {
		t.Fatalf("a wildcard and its base name are two authorizations for the same record name: %v", ca.log)
	}
	if len(seen) != 2 || seen[0] != "_acme-challenge.apps.example.com" || len(owners) < 2 || owners[0] != "ziro-acme:"+dnsOwner() {
		t.Fatalf("challenge records: %v %v", seen, owners)
	}
	leaf, g := readStoredCert(t, s, c.Name)
	if !slices.Equal(leaf.DNSNames, []string{"*.apps.example.com", "apps.example.com"}) {
		t.Fatalf("names on the certificate: %v", leaf.DNSNames)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "web.apps.example.com", Roots: pool}); err != nil {
		t.Fatalf("the wildcard must verify for an app host: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "a.b.apps.example.com", Roots: pool}); err == nil {
		t.Fatal("a wildcard covers one label only")
	}
	if !strings.Contains(g.Key, "PRIVATE KEY") {
		t.Fatal("the key is stored with the certificate")
	}

	// Cleanup: ours are gone, the foreign TXT and the sync's record are untouched.
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"_acme-challenge.apps.example.com TXT someone-elses", "www.example.com A 192.0.2.1"}) {
		t.Fatalf("records after issuance: %v", got)
	}
	if fi, err := os.Stat(acmeAccountFile(ca.url("/directory"))); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("account key file: %v %v", fi, err)
	}
	log, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(log), "dns cert issue") || !strings.Contains(string(log), c.Name) {
		t.Fatalf("issuance is audited:\n%s", log)
	}

	// A second issuance reuses the ACME account instead of registering another.
	if err := issueAndStore(s, c); err != nil {
		t.Fatal(err)
	}
	if ca.newAccts != 1 {
		t.Fatalf("one ACME account for one key, got %d", ca.newAccts)
	}
}

func TestIssueCleansUpAndKeepsTheOldCertificateWhenTheCARefuses(t *testing.T) {
	s, f, ca := acmeEnv(t)
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	if err := issueAndStore(s, c); err != nil {
		t.Fatal(err)
	}
	before, _ := readStoredCert(t, s, c.Name)

	ca.validate = func(string, string) bool { return false } // the CA cannot see the record
	err := issueAndStore(s, c)
	if err == nil || !strings.Contains(err.Error(), "could not validate") {
		t.Fatalf("a refused challenge is an error: %v", err)
	}
	if n := f.challengeRecords(); n != 0 {
		t.Fatalf("the TXT records must be removed after a failure: %d left", n)
	}
	after, _ := readStoredCert(t, s, c.Name)
	if after.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Fatal("a failed renewal must leave the working certificate in place")
	}
	log, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(log), "dns cert issue") {
		t.Fatal("the failure is audited too")
	}
}

func TestIssueGivesUpWhenTheProviderNeverListsTheRecord(t *testing.T) {
	s, f, ca := acmeEnv(t)
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	// A provider that accepts the record but does not list it (its API is lagging or broken): the
	// listing is what the wait polls, and it is what cleanup uses too.
	hide := &hidingDNS{fakeDNS: f, hidden: true}
	dnsProviderFactory = func(DNSProviderConf, string) (DNSProvider, error) { return hide, nil }

	err := issueAndStore(s, c)
	if err == nil || !strings.Contains(err.Error(), "did not list the challenge record") {
		t.Fatalf("%v", err)
	}
	if ca.count("validate") != 0 {
		t.Fatal("the CA must not be asked to validate a record that is not there yet")
	}
	if _, err := s.getCert(c.Name); err == nil {
		t.Fatal("no certificate was stored")
	}
	// What cleanup could not see is swept by the next issuance, once the provider lists again.
	if f.challengeRecords() != 1 {
		t.Fatalf("the unlisted record is still at the provider: %v", f.names("z-example.com"))
	}
	hide.hidden = false
	if err := issueAndStore(s, c); err != nil {
		t.Fatal(err)
	}
	if f.challengeRecords() != 0 {
		t.Fatalf("the stale record is swept by the next issuance: %v", f.names("z-example.com"))
	}
}

// hidingDNS does not list challenge records while hidden is set.
type hidingDNS struct {
	*fakeDNS
	hidden bool
}

func (h *hidingDNS) List(zone string) ([]DNSRec, error) {
	recs, _ := h.fakeDNS.List(zone)
	if !h.hidden {
		return recs, nil
	}
	var out []DNSRec
	for _, r := range recs {
		if !strings.HasPrefix(r.Name, "_acme-challenge.") {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestIssueSweepsStaleChallengeRecordsOfItsOwn(t *testing.T) {
	s, f, _ := acmeEnv(t)
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.old.example.com", Type: "TXT", Content: "stale", Comment: dnsChallengeOwner()})
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.other.example.com", Type: "TXT", Content: "theirs", Comment: "ziro-acme:another-cluster"})
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.sync.example.com", Type: "TXT", Content: "x", Comment: dnsMarker()}) // the sync's marker is not ours
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	if err := issueAndStore(s, c); err != nil {
		t.Fatal(err)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"_acme-challenge.other.example.com TXT theirs", "_acme-challenge.sync.example.com TXT x"}) {
		t.Fatalf("only this cluster's challenge records are removed: %v", got)
	}
}

func TestSyncNeverDeletesAChallengeRecordMidIssuance(t *testing.T) {
	s, f, _ := acmeEnv(t)
	// Both markers on `_acme-challenge` names: the reconciler must leave even its own marker alone there.
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.x.example.com", Type: "TXT", Content: "v", Comment: dnsMarker()})
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.y.example.com", Type: "TXT", Content: "v", Comment: dnsChallengeOwner()})
	setRoutes(t, s, "")
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	if f.challengeRecords() != 2 {
		t.Fatalf("the sync deleted a challenge record: %v", f.names("z-example.com"))
	}
}

func TestIssueNeedsHTTPSDirectoryAndAProviderForTheZone(t *testing.T) {
	s, f, _ := acmeEnv(t)
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	acmeAllowHTTP = false
	if err := issueAndStore(s, c); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("a plain-HTTP directory is refused: %v", err)
	}
	acmeAllowHTTP = true

	other := DNSCert{Name: "dns01-wild-example-org", Domains: []string{"*.example.org"}}
	err := issueAndStore(s, other)
	if err == nil || !strings.Contains(err.Error(), "no DNS zone for example.org") {
		t.Fatalf("a name outside every managed zone: %v", err)
	}
	if f.challengeRecords() != 0 {
		t.Fatal("nothing published")
	}
}

func TestPackCertRejectsWhatDoesNotBelong(t *testing.T) {
	ca := newFakeCA(t, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(names []string, life time.Duration, pub *ecdsa.PublicKey) []byte {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(5), DNSNames: names, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(life)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, ca.caCert, pub, ca.caKey)
		return der
	}
	if _, err := packCert([][]byte{mk([]string{"a.example.com"}, time.Hour, &key.PublicKey)}, key, []string{"a.example.com"}); err != nil {
		t.Fatalf("a good certificate: %v", err)
	}
	if _, err := packCert(nil, key, nil); err == nil {
		t.Fatal("an empty chain")
	}
	if _, err := packCert([][]byte{mk([]string{"a.example.com"}, time.Hour, &other.PublicKey)}, key, []string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a certificate for another key: %v", err)
	}
	if _, err := packCert([][]byte{mk([]string{"a.example.com"}, time.Hour, &key.PublicKey)}, key, []string{"a.example.com", "*.example.com"}); err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Fatalf("a certificate missing a requested name: %v", err)
	}
	if _, err := packCert([][]byte{mk([]string{"a.example.com"}, -time.Hour, &key.PublicKey)}, key, []string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired certificate: %v", err)
	}
}

// ---- configuration ----

func TestDNSCertNamesAndCoverage(t *testing.T) {
	got, err := cleanDNSCertDomains([]string{"*.Example.com.", "example.com", "EXAMPLE.com", ""})
	if err != nil || !slices.Equal(got, []string{"*.example.com", "example.com"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{nil, {"a.b.local"}, {"nas.home.lan"}, {"localhost"}, {"bad name.com"}, {"*.*.example.com"}, {"foo.*.example.com"}, {strings.Repeat("a", 64) + ".example.com"}} {
		if _, err := cleanDNSCertDomains(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.example.com", i)
	}
	if _, err := cleanDNSCertDomains(many); err == nil {
		t.Error("more names than a certificate may carry")
	}

	c := DNSCert{Name: "x", Domains: []string{"*.apps.example.com", "example.com"}}
	for host, want := range map[string]bool{
		"web.apps.example.com": true, "a.b.apps.example.com": false, "apps.example.com": false,
		"example.com": true, "www.example.com": false, "*.apps.example.com": true, "WEB.apps.example.com.": true,
	} {
		if c.covers(host) != want {
			t.Errorf("covers(%q) = %v, want %v", host, !want, want)
		}
	}
	if c.coversAll(nil) || !c.coversAll([]string{"a.apps.example.com", "example.com"}) || c.coversAll([]string{"a.apps.example.com", "x.org"}) {
		t.Error("coversAll")
	}
	if dnsCertName([]string{strings.Repeat("a", 70) + ".example.com"}) != "dns01-"+strings.Repeat("a", 57) {
		t.Errorf("long names are cut to a valid store name: %s", dnsCertName([]string{strings.Repeat("a", 70) + ".example.com"}))
	}
}

func TestDNSCertConfigAndRouteRules(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	if _, err := dnsCertAdd(s, []string{"*.example.com"}, "", ""); err == nil {
		t.Fatal("no DNS provider yet")
	}
	addProvider(t, s, "cf")
	if _, err := dnsCertAdd(s, []string{"*.example.com"}, "bad-name", ""); err == nil {
		t.Fatal("a name must start with dns01-")
	}
	if _, err := dnsCertAdd(s, []string{"*.example.com"}, "", "nope"); err == nil {
		t.Fatal("unknown provider")
	}
	c, err := dnsCertAdd(s, []string{"*.example.com"}, "", "cf")
	if err != nil || c.Name != "dns01-wild-example-com" {
		t.Fatal(err, c)
	}

	r := GatewayRoute{Name: "web", Hosts: []string{"web.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}, TLS: "dns01"}
	if _, err := putRoute(s, GatewayRoute{Name: "x", Hosts: []string{"x.other.org"}, To: r.To, TLS: "dns01"}); err == nil || !strings.Contains(err.Error(), "no DNS-01 certificate covers x.other.org") {
		t.Fatalf("a dns01 route needs a covering certificate: %v", err)
	}
	if _, err := putRoute(s, r); err != nil {
		t.Fatal(err)
	}
	wild := GatewayRoute{Name: "shop", Hosts: []string{"*.example.com"}, To: r.To, TLS: "dns01"}
	if _, err := putRoute(s, wild); err != nil {
		t.Fatalf("a wildcard route host is valid with dns01 (ACME HTTP-01 refuses it): %v", err)
	}
	if err := dnsCertRm(s, c.Name); err == nil || !strings.Contains(err.Error(), "route") {
		t.Fatalf("a certificate a route needs cannot be removed: %v", err)
	}
	// A second certificate that also covers them frees the first.
	if _, err := dnsCertAdd(s, []string{"*.example.com", "example.com"}, "dns01-both", ""); err != nil {
		t.Fatal(err)
	}
	if err := dnsCertRm(s, c.Name); err != nil {
		t.Fatalf("another certificate covers the routes: %v", err)
	}
	if err := dnsCertRm(s, "dns01-nope"); err == nil {
		t.Fatal("removing an unknown certificate must say so")
	}
}

func TestDNSRoutesWaitForTheirCertificateThenServeIt(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	to := []GatewayUpstream{{Address: "127.0.0.1:80"}}
	_, _ = putRoute(s, GatewayRoute{Name: "web", Hosts: []string{"web.example.com"}, To: to, TLS: "dns01"})
	_, _ = putRoute(s, GatewayRoute{Name: "plain", Hosts: []string{"plain.example.com"}, To: to, TLS: "off"})

	cfg, err := s.config()
	if err != nil || len(cfg.Routes) != 1 || cfg.Routes[0].Name != "plain" {
		t.Fatalf("until the certificate exists the route is not served (and an older gateway never sees an unknown TLS mode): %+v %v", cfg.Routes, err)
	}
	ca := newFakeCA(t, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), DNSNames: c.Domains, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, ca.caCert, &key.PublicKey, ca.caKey)
	g, err := packCert([][]byte{der}, key, c.Domains)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.putCert(c.Name, g); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.config()
	if len(cfg.Routes) != 2 {
		t.Fatalf("once issued the route is served: %+v", cfg.Routes)
	}
	var web GatewayRouteState
	for _, r := range cfg.Routes {
		if r.Name == "web" {
			web = r
		}
	}
	if web.TLS != "cert:"+c.Name || cfg.Certs[c.Name].Cert == "" {
		t.Fatalf("the route serves the issued certificate through the existing cert: path: %q %v", web.TLS, cfg.Certs)
	}
	// What the gateway re-validates on load.
	if err := validateRoute(&web.GatewayRoute); err != nil {
		t.Fatalf("the resolved route is valid for any gateway: %v", err)
	}

	// The cluster resolves the same way.
	st := &ClusterState{Routes: []GatewayRoute{{Name: "web", Hosts: []string{"web.example.com"}, To: to, TLS: "dns01"}}, DNSCloud: DNSCloud{Certs: []DNSCert{c}}, Secrets: map[string]map[string]string{}}
	if got := gatewayConfigFor(st); len(got.Routes) != 0 {
		t.Fatalf("cluster: not served before issuance: %+v", got.Routes)
	}
	st.Secrets[gatewayCertSecret(c.Name)] = map[string]string{"cert": g.Cert, "key": g.Key}
	if got := gatewayConfigFor(st); len(got.Routes) != 1 || got.Routes[0].TLS != "cert:"+c.Name || got.Certs[c.Name].Key == "" {
		t.Fatalf("cluster: served with the cluster secret: %+v", got)
	}
}

func TestWildcardCertForTheBaseDomain(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	if _, err := setGatewayDomainOpts("apps.example.com", true); err == nil || !strings.Contains(err.Error(), "no DNS provider") {
		t.Fatalf("needs a provider: %v", err)
	}
	addProvider(t, s, "cf")
	if _, err := setGatewayDomainOpts("apps.internal", true); err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("a private domain cannot have a public wildcard: %v", err)
	}
	info, err := setGatewayDomainOpts("apps.example.com", true)
	if err != nil || info.TLS != "dns01" {
		t.Fatalf("%+v %v", info, err)
	}
	d, _ := s.read()
	if len(d.DNSCloud.Certs) != 1 || d.DNSCloud.Certs[0].Name != "dns01-wild-apps-example-com" || d.DNSCloud.Certs[0].Source != dnsCertSourceDom ||
		!slices.Equal(d.DNSCloud.Certs[0].Domains, []string{"*.apps.example.com"}) || !d.Domain.WildcardCert {
		t.Fatalf("the domain owns a wildcard certificate: %+v %+v", d.DNSCloud.Certs, d.Domain)
	}
	if host, mode := exposeFor(&Deployment{Name: "web"}); host != "web.apps.example.com" || mode != "dns01" {
		t.Fatalf("deployed apps use the wildcard: %s %s", host, mode)
	}
	if _, err := putRoute(s, GatewayRoute{Name: "web", Hosts: []string{"web.apps.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}, TLS: "dns01"}); err != nil {
		t.Fatalf("the app's route is accepted at once: %v", err)
	}

	if err := dnsCertRm(s, "dns01-wild-apps-example-com"); err == nil || !strings.Contains(err.Error(), "belongs to the base domain") {
		t.Fatalf("the domain's own certificate is not removed on its own: %v", err)
	}

	// An explicit certificate is not the domain's: it survives a domain change.
	_, _ = dnsCertAdd(s, []string{"mine.example.com"}, "", "")
	_ = s.putCert("dns01-wild-apps-example-com", GatewayCert{Cert: "x", Key: "y"})
	if _, err := setGatewayDomainOpts("apps.example.com", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.getCert("dns01-wild-apps-example-com"); err != nil {
		t.Fatal("re-setting the same domain keeps its certificate")
	}
	if _, err := setGatewayDomainOpts("other.example.com", true); err != nil {
		t.Fatal(err)
	}
	d, _ = s.read()
	var names []string
	for _, c := range d.DNSCloud.Certs {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"dns01-mine-example-com", "dns01-wild-other-example-com"}) {
		t.Fatalf("the old domain's certificate is replaced, the explicit one stays: %v", names)
	}
	if _, err := s.getCert("dns01-wild-apps-example-com"); err == nil {
		t.Fatal("the old domain's stored certificate is deleted")
	}
	if _, err := setGatewayDomainOpts("other.example.com", false); err != nil {
		t.Fatal(err)
	}
	d, _ = s.read()
	if len(d.DNSCloud.Certs) != 1 || d.Domain.WildcardCert || d.Domain.TLS() != "auto" {
		t.Fatalf("without --wildcard-cert the domain is back on HTTP-01: %+v", d)
	}
}

// ---- renewal ----

func storeCertWithLife(t *testing.T, s routeStore, ca *fakeCA, c DNSCert, life time.Duration) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: c.Domains, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, ca.caCert, &key.PublicKey, ca.caKey)
	g, err := packCert([][]byte{der}, key, c.Domains)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.putCert(c.Name, g); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateDueRules(t *testing.T) {
	s, _, ca := acmeEnv(t)
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	now := time.Now()
	if due, why := dnsCertDue(s, c, now); !due || why != "not issued yet" {
		t.Fatalf("%v %s", due, why)
	}
	storeCertWithLife(t, s, ca, c, 60*24*time.Hour)
	if due, _ := dnsCertDue(s, c, now); due {
		t.Fatal("60 days left is not due")
	}
	if due, _ := dnsCertDue(s, c, now.Add(31*24*time.Hour)); !due {
		t.Fatal("29 days left is due (renew 30 days before expiry)")
	}
	storeCertWithLife(t, s, ca, c, 10*24*time.Hour)
	if due, why := dnsCertDue(s, c, now); !due || !strings.Contains(why, "expires in 9 days") && !strings.Contains(why, "expires in 10 days") {
		t.Fatalf("%v %s", due, why)
	}
	storeCertWithLife(t, s, ca, c, 60*24*time.Hour)
	c2 := c
	c2.Domains = []string{"*.example.com", "example.com"}
	if due, why := dnsCertDue(s, c2, now); !due || why != "its names changed" {
		t.Fatalf("adding a name reissues: %v %s", due, why)
	}
	_ = s.putCert(c.Name, GatewayCert{Cert: "garbage", Key: "k"})
	if due, _ := dnsCertDue(s, c, now); !due {
		t.Fatal("an unreadable stored certificate is replaced")
	}
}

func TestCertLoopRenewsWithBackoffAndLeaderGating(t *testing.T) {
	s, _, ca := acmeEnv(t)
	c1, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	c2, _ := dnsCertAdd(s, []string{"www.example.com"}, "", "")
	now := time.Now()
	storeCertWithLife(t, s, ca, c2, 80*24*time.Hour) // fine: not touched

	leader := false
	var tried []string
	failing := true
	var announced []string
	l := &certLoop{
		store:  func() (routeStore, error) { return s, nil },
		leader: func() bool { return leader },
		issue: func(rs routeStore, c DNSCert) error {
			tried = append(tried, c.Name)
			if failing {
				return errors.New("the CA is down")
			}
			storeCertWithLife(t, rs, ca, c, 90*24*time.Hour)
			return nil
		},
		now: func() time.Time { return now },
		announce: func(c DNSCert, why string, err error) {
			announced = append(announced, fmt.Sprintf("%s|%s|%v", c.Name, why, err))
		},
	}
	if got := l.tick(); got != nil || len(tried) != 0 {
		t.Fatal("a follower never issues")
	}
	leader = true
	if got := l.tick(); !slices.Equal(got, []string{c1.Name}) || !slices.Equal(tried, []string{c1.Name}) {
		t.Fatalf("only the certificate that is due: %v", got)
	}
	st := readDNSCertStatus()[c1.Name]
	if st.Failures != 1 || !strings.Contains(st.LastError, "CA is down") || st.NextAttempt == "" {
		t.Fatalf("status: %+v", st)
	}
	if len(announced) != 1 || !strings.Contains(announced[0], "not issued yet") || !strings.Contains(announced[0], "CA is down") {
		t.Fatalf("a failure is announced (this is the alert): %v", announced)
	}
	if got := l.tick(); got != nil {
		t.Fatalf("no retry before the backoff has passed: %v", got)
	}

	for i, want := range []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 6 * time.Hour} {
		if got := dnsCertBackoff(i + 1); got != want {
			t.Errorf("backoff after %d failures = %v, want %v", i+1, got, want)
		}
	}
	now = now.Add(6 * time.Minute)
	if got := l.tick(); !slices.Equal(got, []string{c1.Name}) {
		t.Fatalf("retried after 5 minutes: %v", got)
	}
	if st := readDNSCertStatus()[c1.Name]; st.Failures != 2 {
		t.Fatalf("%+v", st)
	}
	now = now.Add(16 * time.Minute)
	failing = false
	if got := l.tick(); !slices.Equal(got, []string{c1.Name}) {
		t.Fatalf("%v", got)
	}
	if st := readDNSCertStatus()[c1.Name]; st.Failures != 0 || st.LastError != "" || st.LastIssued == "" || st.NextAttempt != "" {
		t.Fatalf("success clears the failure state: %+v", st)
	}
	if last := announced[len(announced)-1]; !strings.HasSuffix(last, "|<nil>") {
		t.Fatalf("success is announced: %v", announced)
	}
	if got := l.tick(); got != nil {
		t.Fatalf("nothing is due once issued: %v", got)
	}

	// It is picked up again when it nears expiry.
	now = now.Add(70 * 24 * time.Hour) // 20 days left
	if got := l.tick(); !slices.Contains(got, c1.Name) {
		t.Fatalf("renewal 30 days before expiry: %v", got)
	}
}

func TestRenewCommandRunsOnTheLeaderAndRecordsFailures(t *testing.T) {
	s, _, ca := acmeEnv(t)
	if _, err := renewDNSCerts(s, nil, false, time.Now()); err == nil || !strings.Contains(err.Error(), "no DNS-01 certificate") {
		t.Fatalf("%v", err)
	}
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	if _, err := renewDNSCerts(s, []string{"dns01-nope"}, false, time.Now()); err == nil || !strings.Contains(err.Error(), "no DNS-01 certificate \"dns01-nope\"") {
		t.Fatalf("%v", err)
	}
	issued, err := renewDNSCerts(s, nil, false, time.Now())
	if err != nil || !slices.Equal(issued, []string{c.Name}) {
		t.Fatalf("%v %v", issued, err)
	}
	if issued, err := renewDNSCerts(s, nil, false, time.Now()); err != nil || len(issued) != 0 {
		t.Fatalf("nothing is due: %v %v", issued, err)
	}
	if issued, err := renewDNSCerts(s, []string{c.Name}, true, time.Now()); err != nil || len(issued) != 1 {
		t.Fatalf("--force issues anyway: %v %v", issued, err)
	}
	ca.validate = func(string, string) bool { return false }
	if _, err := renewDNSCerts(s, []string{c.Name}, true, time.Now()); err == nil {
		t.Fatal("a failure is returned")
	}
	if st := readDNSCertStatus()[c.Name]; st.Failures != 1 || st.LastError == "" {
		t.Fatalf("and recorded for doctor and `dns cert ls`: %+v", st)
	}

	// Two issuances on one host never overlap.
	err = withDNSCertLock(func() error {
		return withDNSCertLock(func() error { return nil })
	})
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("the host lock: %v", err)
	}
}

// ---- views, doctor, API ----

func TestCertViewsAndDoctorRow(t *testing.T) {
	s, _, ca := acmeEnv(t)
	now := time.Now()
	if _, ok := dnsCertDoctorCheck(now); ok {
		t.Fatal("no certificates: no row")
	}
	c, _ := dnsCertAdd(s, []string{"*.example.com"}, "", "")
	if c, _ := dnsCertDoctorCheck(now); c.Passed || !strings.Contains(c.Details, "not issued yet") || c.fix == nil {
		t.Fatalf("before issuance: %+v", c)
	}
	v, _ := dnsCertViews(s, now)
	if len(v) != 1 || v[0].Issued {
		t.Fatalf("%+v", v)
	}
	storeCertWithLife(t, s, ca, c, 60*24*time.Hour)
	if row, _ := dnsCertDoctorCheck(time.Now()); !row.Passed || !strings.Contains(row.Details, "left") {
		t.Fatalf("issued and fresh: %+v", row)
	}
	v, _ = dnsCertViews(s, now)
	if !v[0].Issued || v[0].DaysLeft < 58 || v[0].NotAfter == "" {
		t.Fatalf("%+v", v[0])
	}
	storeCertWithLife(t, s, ca, c, 5*24*time.Hour)
	if row, _ := dnsCertDoctorCheck(time.Now()); row.Passed || !strings.Contains(row.Details, "expires in") {
		t.Fatalf("a certificate about to expire: %+v", row)
	}
	storeCertWithLife(t, s, ca, c, 60*24*time.Hour)
	writeDNSCertStatus(map[string]dnsCertState{c.Name: {LastError: "the CA is down", NextAttempt: "later"}})
	if row, _ := dnsCertDoctorCheck(time.Now()); row.Passed || !strings.Contains(row.Details, "the CA is down") {
		t.Fatalf("a failing renewal shows even while the old certificate works: %+v", row)
	}
	row, _ := dnsCertDoctorCheck(time.Now())
	if err := row.fix(); err != nil {
		t.Fatalf("the fix issues what is due (nothing here): %v", err)
	}

	if certAlertSeverity(s, c, now) != "high" {
		t.Fatal("a failing renewal with weeks left is high")
	}
	storeCertWithLife(t, s, ca, c, 3*24*time.Hour)
	if certAlertSeverity(s, c, now) != "critical" {
		t.Fatal("a certificate about to expire is critical")
	}
	_ = s.rmCert(c.Name)
	if certAlertSeverity(s, c, now) != "critical" {
		t.Fatal("no certificate at all is critical")
	}
}

func TestDNSCertAPI(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	h := newAPIHarness(t)
	for _, c := range []struct {
		role, method, path string
		want               int
	}{
		{"", "GET", "/api/v1/dns/cloud/certs", 401},
		{"viewer", "GET", "/api/v1/dns/cloud/certs", 200},
		{"operator", "POST", "/api/v1/dns/cloud/certs", 403},
		{"operator", "DELETE", "/api/v1/dns/cloud/certs?name=x", 403},
		{"operator", "POST", "/api/v1/dns/cloud/certs/renew", 403},
	} {
		if got := h.code(c.role, c.method, c.path, `{}`); got != c.want {
			t.Errorf("%s %s as %q: %d, want %d", c.method, c.path, c.role, got, c.want)
		}
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/certs", `{"domains":["*.example.com"]}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), "dns01-wild-example-com") {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/certs", `{"domains":["host.internal"]}`); rec.Code != 400 {
		t.Fatalf("a private name: %d", rec.Code)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/certs", `{"domains":["a.example.com"],"extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown fields: %d", rec.Code)
	}
	if rec := h.req("viewer", "GET", "/api/v1/dns/cloud/certs", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"issued":false`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "DELETE", "/api/v1/dns/cloud/certs", ""); rec.Code != 400 {
		t.Fatalf("a delete without a name: %d", rec.Code)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/certs/renew", `{"name":"dns01-nope"}`); rec.Code == 200 {
		t.Fatal("renewing an unknown certificate must fail")
	}
	if rec := h.req("admin", "DELETE", "/api/v1/dns/cloud/certs?name=dns01-wild-example-com", ""); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
}

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{clusterSNI, legacySNI}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestClusterPKI(t *testing.T) {
	old := clusterDir
	clusterDir = t.TempDir()
	defer func() { clusterDir = old }()

	st := &ClusterState{}
	if err := ensureCA(st); err != nil {
		t.Fatal(err)
	}
	ca := st.CACert
	if err := ensureCA(st); err != nil || st.CACert != ca {
		t.Fatal("ensureCA must keep an existing CA")
	}
	if err := ensureMasterCert(st, "master-1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	master, err := loadMasterTLS()
	if err != nil || len(master.Certificate) != 2 {
		t.Fatalf("master chain must carry the CA: %v", err)
	}
	leaf, _ := x509.ParseCertificate(master.Certificate[0])
	if leaf.Subject.CommonName != "master-1" || verifyMaster(leaf, ca) != nil {
		t.Fatalf("master cert: %+v", leaf.Subject)
	}

	// The CSR only proves key possession: identity comes from the caller.
	csr, _ := masterKeyAndCSR()
	crt, err := signMasterCSR(st, csr, "master-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := parseCertPEM(crt)
	if c2.Subject.CommonName != "master-2" || verifyMaster(c2, ca) != nil {
		t.Fatal("signed cert identity")
	}
	if _, err := signMasterCSR(st, strings.Replace(csr, "A", "B", 5), "x", nil); err == nil {
		t.Fatal("a tampered CSR was signed")
	}
	other := &ClusterState{}
	_ = ensureCA(other)
	if verifyMaster(c2, other.CACert) == nil {
		t.Fatal("a cert from another cluster CA passed as a master")
	}
	worker := selfSigned(t, "worker")
	wl, _ := x509.ParseCertificate(worker.Certificate[0])
	if verifyMaster(wl, ca) == nil {
		t.Fatal("a non-CA cert passed as a master")
	}

	// A master like `cluster serve`: CA-signed chain for SNI clients, the old cert otherwise.
	legacy := selfSigned(t, "legacy")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	// Certificates is set so httptest keeps it; without SNI Go serves it, with SNI it asks GetCertificate.
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{legacy}, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == clusterSNI {
			return master, nil
		}
		return &legacy, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	caHash, _ := pemHash(ca)
	legacyHash := certDERHash(legacy.Certificate[0])
	for name, pin := range map[string]string{"CA pin": caHash, "pre-CA leaf pin (no-SNI fallback)": legacyHash} {
		if err := clusterPost(addr, pin, "/x", "", struct{}{}, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	err = clusterPost(addr, "sha256:"+strings.Repeat("0", 64), "/x", "", struct{}{}, nil)
	var pe pinError
	if err == nil || !errors.As(err, &pe) {
		t.Fatalf("wrong pin must fail with a pin error: %v", err)
	}

	// An attacker who shows the real CA cert next to a leaf the CA never signed is rejected.
	forged := selfSigned(t, "forged")
	caBlock, _ := pem.Decode([]byte(ca))
	forged.Certificate = append(forged.Certificate, caBlock.Bytes)
	evil := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	evil.TLS = &tls.Config{Certificates: []tls.Certificate{forged}}
	evil.StartTLS()
	defer evil.Close()
	if err := clusterPost(strings.TrimPrefix(evil.URL, "https://"), caHash, "/x", "", struct{}{}, nil); err == nil {
		t.Fatal("forged leaf accepted")
	}
}

func TestLeaderRedirect(t *testing.T) {
	var target string
	leader := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":"leader"}`))
	}))
	defer leader.Close()
	follower := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMisdirectedRequest)
		w.Write([]byte(`{"status":"redirect","leader":"` + target + `"}`))
	}))
	defer follower.Close()
	target = strings.TrimPrefix(leader.URL, "https://")
	pin := certDERHash(leader.TLS.Certificates[0].Certificate[0])
	// Both test servers share httptest's certificate, so one pin covers the redirect hop.
	var out struct{ OK string }
	if err := clusterPost(strings.TrimPrefix(follower.URL, "https://"), pin, "/x", "", struct{}{}, &out); err != nil || out.OK != "leader" {
		t.Fatalf("redirect not followed: %v %+v", err, out)
	}
	target = "not-an-address"
	if err := clusterPost(strings.TrimPrefix(follower.URL, "https://"), pin, "/x", "", struct{}{}, nil); err == nil {
		t.Fatal("invalid leader address accepted")
	}
}

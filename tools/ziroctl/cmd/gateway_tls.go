package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// ---- TLS: ACME, uploaded certificates, internal CA ----

func (g *gatewayServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(hello.ServerName)
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto && g.acmeMgr != nil {
			return g.acmeMgr.GetCertificate(hello) // TLS-ALPN-01 challenge
		}
	}
	r := g.hostRoute(host)
	if r == nil {
		return nil, fmt.Errorf("no route for %q", host)
	}
	switch {
	case r.TLS == "auto" && g.acmeMgr != nil:
		return g.acmeMgr.GetCertificate(hello)
	case r.TLS == "internal":
		return g.internalLeaf(host)
	case strings.HasPrefix(r.TLS, "cert:"):
		g.certMu.Lock()
		c := g.certs[strings.TrimPrefix(r.TLS, "cert:")]
		g.certMu.Unlock()
		if c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("certificate %s not uploaded", r.TLS)
	}
	return nil, fmt.Errorf("no TLS for %q", host)
}

// loadInternalCA uses the cluster's internal CA (distributed to gateway nodes) or a local one,
// created on first use (ECDSA P-256, root-only files).
func (g *gatewayServer) loadInternalCA() error {
	g.certMu.Lock()
	defer g.certMu.Unlock()
	var certPEM, keyPEM []byte
	if t := g.tbl.Load(); t != nil && t.cfg != nil && t.cfg.InternalCA != nil {
		certPEM, keyPEM = []byte(t.cfg.InternalCA.Cert), []byte(t.cfg.InternalCA.Key)
	} else {
		var err error
		if certPEM, keyPEM, err = localInternalCA(); err != nil {
			return err
		}
	}
	if g.ca != nil && bytes.Equal(certPEM, g.caPEM) {
		return nil
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	kp.Leaf, err = x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return err
	}
	g.ca, g.caPEM, g.leafs = &kp, certPEM, map[string]*tls.Certificate{}
	return nil
}

var internalCAPaths = func() (string, string) {
	return filepath.Join(gatewayCertDir, "internal-ca.crt"), filepath.Join(gatewayCertDir, "internal-ca.key")
}

func localInternalCA() ([]byte, []byte, error) {
	crtPath, keyPath := internalCAPaths()
	if c, err := os.ReadFile(crtPath); err == nil {
		k, err := os.ReadFile(keyPath)
		return c, k, err
	}
	c, k, err := newInternalCA()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(crtPath), 0700); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(keyPath, k, 0600); err != nil {
		return nil, nil, err
	}
	return c, k, writeFileAtomic(crtPath, c, 0644)
}

// newInternalCA creates the gateway's private CA (10 years; signs only server certificates).
func newInternalCA() (certPEM, keyPEM []byte, err error) {
	return newCA("Ziro gateway internal CA", time.Now().AddDate(10, 0, 0))
}

// newCA creates a private CA (ECDSA P-256) that signs only server certificates.
func newCA(name string, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name, Organization: []string{"Ziro OS"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

const (
	leafCacheMax    = 1024 // cached internal-CA leaf certificates
	leafIssuePerSec = 50   // new leaves per second: a wildcard route must not let SNI floods burn CPU
	leafRenewBefore = 10 * 24 * time.Hour
)

// internalLeaf issues (and caches) a 30-day server certificate for host from the internal CA.
// The cache is bounded and issuing is rate limited, because a wildcard route answers for any
// name a client sends as SNI.
func (g *gatewayServer) internalLeaf(host string) (*tls.Certificate, error) {
	if err := g.loadInternalCA(); err != nil {
		return nil, err
	}
	g.certMu.Lock()
	if c := g.leafs[host]; c != nil && time.Until(c.Leaf.NotAfter) > leafRenewBefore {
		g.certMu.Unlock()
		return c, nil
	}
	ca := g.ca
	g.certMu.Unlock()
	if !g.leafLimit.allow("leaf", time.Now()) {
		return nil, fmt.Errorf("too many certificates requested; retry shortly")
	}
	c, err := issueLeaf(ca, host)
	if err != nil {
		return nil, err
	}
	g.certMu.Lock()
	defer g.certMu.Unlock()
	if g.ca != ca { // the CA changed while signing
		return c, nil
	}
	if len(g.leafs) >= leafCacheMax {
		for k := range g.leafs {
			delete(g.leafs, k)
			break
		}
	}
	g.leafs[host] = c
	return c, nil
}

// issueLeaf signs a 30-day server certificate for host with ca (whose Leaf is parsed).
func issueLeaf(ca *tls.Certificate, host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der, ca.Certificate[0]}, PrivateKey: key, Leaf: leaf}, nil
}

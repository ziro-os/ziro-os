package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cluster PKI. A cluster CA (created at init, or when an older cluster first starts this
// version) signs every master's certificate. Workers trust the CA, pinned by hash, instead of one
// master's certificate, so they can talk to any master and survive failover and renewal.
// Masters authenticate each other (Raft, forwarded CLI calls) with mutual TLS on those certs.
// Workers never hold CA-signed certs: they authenticate with their node tokens.
//
// Compatibility: agents from before the CA pinned the first master's own certificate. The
// master keeps serving that certificate to clients that send no SNI, and CA-aware clients send
// SNI clusterSNI. The CA reaches old agents in their next heartbeat, over the channel they
// already trust, and they switch to it.

const (
	clusterSNI    = "ziro-cluster"
	masterOU      = "ziro-master"
	masterCertTTL = 365 * 24 * time.Hour
	renewBefore   = 30 * 24 * time.Hour
)

func clusterCAPath() string  { return filepath.Join(clusterDir, "ca.crt") }
func masterKeyPath() string  { return filepath.Join(clusterDir, "master.key") }
func masterCertPath() string { return filepath.Join(clusterDir, "master.crt") }
func certDERHash(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func pemHash(p string) (string, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return "", errors.New("no PEM certificate")
	}
	return certDERHash(b.Bytes), nil
}

func parseCertPEM(p string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func pemEncode(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}

// ensureCA creates the cluster CA once (ECDSA P-256, 10 years).
func ensureCA(st *ClusterState) error {
	if st.CACert != "" {
		// Never mint a second CA over an existing one: every node trusts the first.
		if st.CAKey == "" {
			return errors.New("the cluster CA key is not available on this master")
		}
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Ziro cluster CA", OrganizationalUnit: []string{"ziro-ca"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	st.CACert, st.CAKey = pemEncode("CERTIFICATE", der), pemEncode("EC PRIVATE KEY", kder)
	return nil
}

func caSigner(st *ClusterState) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	ca, err := parseCertPEM(st.CACert)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster CA: %w", err)
	}
	b, _ := pem.Decode([]byte(st.CAKey))
	if b == nil {
		return nil, nil, errors.New("cluster CA key missing")
	}
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, key, nil
}

// signMasterCSR issues a master certificate. Identity (CN, OU, SANs) comes from the caller,
// never from the CSR: the CSR only proves possession of the key.
func signMasterCSR(st *ClusterState, csrPEM, nodeID string, ips []net.IP) (string, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature: %w", err)
	}
	ca, key, err := caSigner(st)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: nodeID, OrganizationalUnit: []string{masterOU}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(masterCertTTL),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{clusterSNI}, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, key)
	if err != nil {
		return "", err
	}
	return pemEncode("CERTIFICATE", der), nil
}

// masterKeyAndCSR loads (or creates, 0600) this master's key and returns a CSR for it.
func masterKeyAndCSR() (string, error) {
	var key *ecdsa.PrivateKey
	if data, err := os.ReadFile(masterKeyPath()); err == nil {
		if b, _ := pem.Decode(data); b != nil {
			key, _ = x509.ParseECPrivateKey(b.Bytes)
		}
	}
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(clusterDir, 0700); err != nil {
			return "", err
		}
		if err := writeFileAtomic(masterKeyPath(), []byte(pemEncode("EC PRIVATE KEY", der)), 0600); err != nil {
			return "", err
		}
		key = k
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ziro-master"}}, key)
	if err != nil {
		return "", err
	}
	return pemEncode("CERTIFICATE REQUEST", der), nil
}

// ensureMasterCert (re)issues this master's certificate from the replicated CA when it is
// missing, about to expire, or no longer chains to the CA.
func ensureMasterCert(st *ClusterState, nodeID string, ips []net.IP) error {
	if cur, err := os.ReadFile(masterCertPath()); err == nil {
		// NotBefore is backdated an hour (clock skew), so +1h is when the cert was issued; cert
		// times have one-second resolution, so compare at that resolution (else it re-issues in a loop).
		if c, err := parseCertPEM(string(cur)); err == nil && time.Until(c.NotAfter) > renewBefore && verifyMaster(c, st.CACert) == nil &&
			!c.NotBefore.Add(time.Hour).Before(st.RotateCertsBefore.Truncate(time.Second)) {
			return nil
		}
	}
	csr, err := masterKeyAndCSR()
	if err != nil {
		return err
	}
	crt, err := signMasterCSR(st, csr, nodeID, ips)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(clusterCAPath(), []byte(st.CACert), 0644); err != nil {
		return err
	}
	return writeFileAtomic(masterCertPath(), []byte(crt), 0644)
}

// loadMasterTLS returns this master's certificate with the CA appended to the chain, so
// clients that pin the CA by hash can find it in the handshake.
func loadMasterTLS() (*tls.Certificate, error) {
	crt, err := os.ReadFile(masterCertPath())
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(clusterCAPath())
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(append(crt, ca...), mustRead(masterKeyPath()))
	return &c, err
}

func mustRead(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

func caPool(caPEM string) (*x509.CertPool, error) {
	ca, err := parseCertPEM(caPEM)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p, nil
}

// verifyMaster: c chains to the cluster CA and carries the master OU.
func verifyMaster(c *x509.Certificate, caPEM string) error {
	pool, err := caPool(caPEM)
	if err != nil {
		return err
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return err
	}
	for _, ou := range c.Subject.OrganizationalUnit {
		if ou == masterOU {
			return nil
		}
	}
	return errors.New("not a cluster master certificate")
}

// ---- client side ----

// pinError: the master's certificate did not match the pin (as opposed to a network error).
type pinError string

func (e pinError) Error() string { return string(e) }

// caVerifiedTLS returns standard verification against the local cluster CA when its hash is the
// pin, or nil when this node does not hold that CA yet.
func caVerifiedTLS(pin string) *tls.Config {
	b, err := os.ReadFile(clusterCAPath())
	if err != nil {
		return nil
	}
	if h, err := pemHash(string(b)); err != nil || h != pin {
		return nil
	}
	pool, err := caPool(string(b))
	if err != nil {
		return nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: clusterSNI}
}

// legacySNI is a name on pre-CA master certificates (ensureTLSCertificates); CA-aware masters
// serve that certificate to clients that do not ask for clusterSNI.
const legacySNI = "ziro-host"

var pinnedConfigs sync.Map // addr|pin -> *tls.Config

// pinnedTLS turns a pin into a standard verifying config; no verification is ever skipped. The
// chain a master presents is read from a probe handshake that fails verification (Go reports it
// in CertificateVerificationError), and the certificate whose hash is the pin becomes the only
// root: the cluster CA, which the leaf must chain to under clusterSNI, or, for agents from before
// the cluster CA, the master's own self-signed certificate under legacySNI.
func pinnedTLS(addr, pin string) (*tls.Config, error) {
	if c, ok := pinnedConfigs.Load(addr + "|" + pin); ok {
		return c.(*tls.Config), nil
	}
	for _, sni := range []string{clusterSNI, legacySNI} {
		probe := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, RootCAs: x509.NewCertPool()}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, probe)
		if err == nil {
			conn.Close() // cannot verify against an empty pool; never trust it
			continue
		}
		var ve *tls.CertificateVerificationError
		if !errors.As(err, &ve) {
			return nil, err // network or handshake failure, not a certificate question
		}
		for i, c := range ve.UnverifiedCertificates {
			if subtle.ConstantTimeCompare([]byte(certDERHash(c.Raw)), []byte(pin)) != 1 {
				continue
			}
			// A pinned CA must be a CA; a pinned leaf is only a pre-CA master (legacySNI).
			if (i > 0 && !c.IsCA) || (i == 0 && sni != legacySNI) {
				continue
			}
			name := sni
			if i == 0 {
				name = leafName(c) // the pin names this exact certificate: verify it under its own name
			}
			pool := x509.NewCertPool()
			pool.AddCert(c)
			tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: name}
			pinnedConfigs.Store(addr+"|"+pin, tc)
			return tc, nil
		}
	}
	return nil, pinError("master certificate does not match the pinned " + pin)
}

// leafName picks a name a pinned pre-CA certificate carries (legacySNI on real ones), never
// clusterSNI, which would make a CA-aware master present its CA-signed certificate instead.
func leafName(c *x509.Certificate) string {
	for _, n := range c.DNSNames {
		if n == legacySNI {
			return n
		}
	}
	for _, n := range c.DNSNames {
		if n != clusterSNI {
			return n
		}
	}
	if len(c.IPAddresses) > 0 {
		return c.IPAddresses[0].String()
	}
	return legacySNI
}

// masterClientTLS is used between masters: present our cert, require a master cert back.
func masterClientTLS(caPEM string) (*tls.Config, error) {
	pool, err := caPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: clusterSNI,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return loadMasterTLS() },
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			return verifyMaster(cs.PeerCertificates[0], caPEM)
		},
	}, nil
}

// requestFromMaster reports whether an inbound TLS request carries a verified master cert.
func requestFromMaster(cs *tls.ConnectionState, caPEM string) bool {
	return cs != nil && len(cs.PeerCertificates) > 0 && len(cs.VerifiedChains) > 0 &&
		verifyMaster(cs.PeerCertificates[0], caPEM) == nil
}

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// TLS for a Postgres cluster. Each cluster has its own CA, so a certificate of one cluster is worth
// nothing to another: replicas check the primary's certificate against it (sslmode=verify-ca, the
// member names change with every replica added), and clients can check the read-write and read-only
// names (sslmode=verify-full). The CA key stays in its own cluster secret, which no container gets;
// the members get the CA certificate and the server certificate and key, written by the entry script
// into the data volume, readable by postgres only.
//
// Known limitation: a cluster created before TLS keeps running without it (switching it on would
// restart every member and require TLS of a primary that has none yet); certificates last 825 days
// and are renewed with the member's next restart.

const (
	pgTLSDir     = pgDataPath + "/ziro-tls" // inside the member container (pg_entry.sh writes it)
	pgCAValidity = 10 * 365 * 24 * time.Hour
	pgTLSValid   = 825 * 24 * time.Hour
)

func (c *PGCluster) caSecretName() string { return pgSecretPrefix + c.Name + "-ca" }

// pgTLSEnabled: the cluster's members have TLS material.
func pgTLSEnabled(st *ClusterState, c *PGCluster) bool {
	return st.Secrets[c.secretName()]["PG_TLS_CERT"] != ""
}

func pemB64(typ string, der []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// pgServerNames are the names a client may check: the read-write and read-only names of every group
// and the default-group aliases, plus any name under the cluster domain (replicas connect to member
// names, which come and go).
func pgServerNames(c *PGCluster) []string {
	names := []string{c.Name + "-rw." + meshDomain, c.Name + "-ro." + meshDomain}
	for _, g := range c.Groups {
		names = append(names, c.dnsRW(g.Name)+"."+meshDomain, c.dnsRO(g.Name)+"."+meshDomain)
	}
	return append(uniq(names), "*."+meshDomain, "localhost")
}

// pgIssueTLS makes a cluster CA and a server certificate signed by it. It returns the members' secret
// values (base64 PEM) and the CA secret.
func pgIssueTLS(c *PGCluster, now time.Time) (member, ca map[string]string, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ziro postgres " + c.Name + " CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(pgCAValidity),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if serial, err = newSerial(); err != nil {
		return nil, nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: c.Name + "-rw." + meshDomain},
		DNSNames: pgServerNames(c), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(pgTLSValid),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return nil, nil, err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}
	member = map[string]string{"PG_TLS_CA": pemB64("CERTIFICATE", caDER), "PG_TLS_CERT": pemB64("CERTIFICATE", srvDER), "PG_TLS_KEY": pemB64("PRIVATE KEY", srvKeyDER)}
	ca = map[string]string{"CA_CERT": pemB64("CERTIFICATE", caDER), "CA_KEY": pemB64("PRIVATE KEY", caKeyDER)}
	return member, ca, nil
}

// pgCACert is the cluster CA certificate (PEM), for clients that check the server (pg credentials --ca).
func pgCACert(st *ClusterState, c *PGCluster) (string, error) {
	b64 := st.Secrets[c.secretName()]["PG_TLS_CA"]
	if b64 == "" {
		return "", fmt.Errorf("cluster %s was created without TLS", c.Name)
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	return string(b), err
}

package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// The DNS-01 issuer. One issuance is an ACME order (RFC 8555) for the certificate's names: for each
// the CA hands out a token, we publish SHA-256(token + account key thumbprint) as a TXT record at
// _acme-challenge.<name> through the DNS provider, wait until the provider lists it, tell the CA to
// validate, wait for the order, finalise it with a fresh key, and store the chain. The TXT records
// are removed afterwards whatever happened. A wildcard needs no more than its base name's record.
//
// Challenge records carry the comment "ziro-acme:<owner>", never the sync's "ziro:<owner>", so the
// reconciler (dnsprovider_sync.go) can never delete one in the middle of an issuance and an issuance
// never touches a record of the sync or of anyone else.

const (
	dnsCertRenewBefore = 30 * 24 * time.Hour // renew this long before expiry
	dnsCertTimeout     = 10 * time.Minute    // one issuance, all in
	dnsChallengeTTL    = 120
	dnsChallengePrefix = "_acme-challenge."
)

var (
	// how long to look for the TXT records at the provider, how often, and a last pause for the
	// provider's authoritative servers to answer (the CA queries them, not the provider's API).
	dnsPropagationMax    = 2 * time.Minute
	dnsPropagationPoll   = 2 * time.Second
	dnsPropagationSettle = 10 * time.Second
	// acmeAllowHTTP lets tests use a plain-HTTP ACME directory; the configuration only takes https.
	acmeAllowHTTP = false
)

func dnsChallengeOwner() string { return "ziro-acme:" + dnsOwner() }

// acmeDirectoryURL is the configured directory (`gateway acme --directory`, e.g. a staging CA) or
// Let's Encrypt.
func acmeDirectoryURL(a GatewayACME) string {
	if a.Directory != "" {
		return a.Directory
	}
	return autocert.DefaultACMEDirectory
}

// ---- the ACME account key ----

func acmeAccountID(directory string) string {
	h := sha256.Sum256([]byte(directory))
	return hex.EncodeToString(h[:4])
}

func acmeAccountSecret(directory string) string {
	return "gateway-acme-account-" + acmeAccountID(directory)
}

func acmeAccountFile(directory string) string {
	return filepath.Join(gatewayLocalDir, "acme-account-"+acmeAccountID(directory)+".key")
}

// acmeAccountKey returns the account key for a directory, creating it on first use. It is kept in the
// cluster state (a secret, so a new leader keeps the account) or in a root-only file, one per
// directory (a staging account is not a production one).
func acmeAccountKey(s routeStore, directory string) (*ecdsa.PrivateKey, error) {
	load := func(pemKey string) (*ecdsa.PrivateKey, error) {
		blk, _ := pem.Decode([]byte(pemKey))
		if blk == nil {
			return nil, errors.New("the stored ACME account key is not PEM")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		return k, err
	}
	newKey := func() (*ecdsa.PrivateKey, string, error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, "", err
		}
		return k, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
	}
	if s.name() == "cluster" {
		var key *ecdsa.PrivateKey
		err := withState(func(st *ClusterState) error {
			if cur := st.Secrets[acmeAccountSecret(directory)]["key"]; cur != "" {
				var err error
				key, err = load(cur)
				return err
			}
			k, p, err := newKey()
			if err != nil {
				return err
			}
			if st.Secrets == nil {
				st.Secrets = map[string]map[string]string{}
			}
			st.Secrets[acmeAccountSecret(directory)] = map[string]string{"key": p}
			key = k
			return nil
		})
		return key, err
	}
	path := acmeAccountFile(directory)
	if b, err := os.ReadFile(path); err == nil {
		return load(string(b))
	}
	k, p, err := newKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return k, writeFileAtomic(path, []byte(p), 0600)
}

// ---- one issuance ----

type dns01Challenge struct {
	prov  *dnsProv
	zone  DNSZone
	name  string // _acme-challenge.<identifier>
	value string
	chal  *acme.Challenge
	authz string // authorization URL
}

// issueDNSCert gets a certificate for c through DNS-01 and returns the PEM chain and key.
func issueDNSCert(ctx context.Context, s routeStore, d *gatewayData, c DNSCert) (GatewayCert, error) {
	dir := acmeDirectoryURL(d.ACME)
	if !strings.HasPrefix(dir, "https://") && !acmeAllowHTTP {
		return GatewayCert{}, errors.New("the ACME directory must be an https:// URL")
	}
	ss := openDNSSession(s, d)
	var provs []*dnsProv
	for _, p := range ss.provs {
		if c.Provider == "" || p.conf.Name == c.Provider {
			provs = append(provs, p)
		}
	}
	if len(provs) == 0 {
		return GatewayCert{}, fmt.Errorf("no usable DNS provider for %s (%s)", c.Name, strings.Join(ss.warns, "; "))
	}
	key, err := acmeAccountKey(s, dir)
	if err != nil {
		return GatewayCert{}, err
	}
	client := &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "ziroctl", HTTPClient: &http.Client{Timeout: 30 * time.Second}}
	acct := &acme.Account{}
	if d.ACME.Email != "" {
		acct.Contact = []string{"mailto:" + d.ACME.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return GatewayCert{}, fmt.Errorf("ACME account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(c.Domains...))
	if err != nil {
		return GatewayCert{}, fmt.Errorf("new order: %w", err)
	}

	// Whatever happens from here, the challenge records are removed (and stale ones from a crashed run
	// first), with a context of their own: ours may be what ran out.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		purgeChallengeRecords(cctx, provs)
	}()
	purgeChallengeRecords(ctx, provs)

	var pending []*dns01Challenge
	for _, url := range order.AuthzURLs {
		a, err := client.GetAuthorization(ctx, url)
		if err != nil {
			return GatewayCert{}, fmt.Errorf("authorization: %w", err)
		}
		if a.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range a.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
			}
		}
		if chal == nil {
			return GatewayCert{}, fmt.Errorf("the CA offers no dns-01 challenge for %s", a.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return GatewayCert{}, err
		}
		name := dnsChallengePrefix + normDNSName(a.Identifier.Value)
		var dp *dnsProv
		var zone *DNSZone
		for _, p := range provs {
			if zone = zoneOf(p.zones, name); zone != nil {
				dp = p
				break
			}
		}
		if dp == nil {
			return GatewayCert{}, fmt.Errorf("no DNS zone for %s at any provider (the token must see its zone)", a.Identifier.Value)
		}
		pending = append(pending, &dns01Challenge{prov: dp, zone: *zone, name: name, value: value, chal: chal, authz: url})
	}

	for _, p := range pending {
		rec := DNSRec{Name: p.name, Type: "TXT", Content: p.value, TTL: dnsChallengeTTL, Comment: dnsChallengeOwner()}
		if err := p.prov.p.Upsert(p.zone.ID, rec); err != nil {
			return GatewayCert{}, fmt.Errorf("publish %s: %w", p.name, err)
		}
	}
	if err := waitChallengeRecords(ctx, pending); err != nil {
		return GatewayCert{}, err
	}
	select {
	case <-time.After(dnsPropagationSettle):
	case <-ctx.Done():
		return GatewayCert{}, ctx.Err()
	}
	for _, p := range pending {
		if _, err := client.Accept(ctx, p.chal); err != nil {
			return GatewayCert{}, fmt.Errorf("accept %s: %w", p.name, err)
		}
	}
	for _, p := range pending {
		if _, err := client.WaitAuthorization(ctx, p.authz); err != nil {
			return GatewayCert{}, fmt.Errorf("the CA could not validate %s: %w", p.name, err)
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return GatewayCert{}, fmt.Errorf("order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return GatewayCert{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: c.Domains}, certKey)
	if err != nil {
		return GatewayCert{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return GatewayCert{}, fmt.Errorf("finalize: %w", err)
	}
	return packCert(chain, certKey, c.Domains)
}

// packCert PEM-encodes the chain and key and checks they belong together and name every domain, so a
// bad answer from the CA never replaces a certificate that works.
func packCert(chain [][]byte, key crypto.Signer, domains []string) (GatewayCert, error) {
	if len(chain) == 0 {
		return GatewayCert{}, errors.New("the CA returned no certificate")
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return GatewayCert{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return GatewayCert{}, fmt.Errorf("the certificate does not match its key: %w", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return GatewayCert{}, err
	}
	for _, d := range domains {
		if !slices.Contains(leaf.DNSNames, d) {
			return GatewayCert{}, fmt.Errorf("the certificate does not name %s", d)
		}
	}
	if !leaf.NotAfter.After(time.Now()) {
		return GatewayCert{}, errors.New("the certificate has already expired")
	}
	return GatewayCert{Cert: string(certPEM), Key: string(keyPEM)}, nil
}

// waitChallengeRecords polls the provider until it lists every TXT record we published. The
// provider's API is the source of truth here, not public resolvers (which cache); the pause that
// follows is for its name servers.
func waitChallengeRecords(ctx context.Context, pending []*dns01Challenge) error {
	deadline := time.Now().Add(dnsPropagationMax)
	for {
		missing := ""
		for _, p := range pending {
			recs, err := p.prov.p.List(p.zone.ID)
			if err != nil {
				missing = fmt.Sprintf("%s (%v)", p.name, err)
				break
			}
			found := slices.ContainsFunc(recs, func(r DNSRec) bool {
				return r.Type == "TXT" && r.Name == p.name && r.Content == p.value
			})
			if !found {
				missing = p.name
				break
			}
		}
		if missing == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the provider did not list the challenge record for %s within %s", missing, dnsPropagationMax)
		}
		select {
		case <-time.After(dnsPropagationPoll):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// purgeChallengeRecords deletes the challenge records this owner left in the providers' zones. Only
// TXT records at _acme-challenge.* with exactly our comment are touched; one issuance runs at a time
// (see withDNSCertLock), so nothing of a concurrent issuance is lost.
func purgeChallengeRecords(ctx context.Context, provs []*dnsProv) {
	owner := dnsChallengeOwner()
	for _, dp := range provs {
		for _, z := range dp.zones {
			if ctx.Err() != nil {
				return
			}
			recs, err := dp.p.List(z.ID)
			if err != nil {
				fmt.Printf("[dns] cleanup of challenge records in %s: %v\n", z.Name, err)
				continue
			}
			for _, r := range recs {
				if r.Type != "TXT" || r.Comment != owner || !strings.HasPrefix(r.Name, dnsChallengePrefix) {
					continue
				}
				if err := dp.p.Delete(z.ID, r.ID); err != nil {
					fmt.Printf("[dns] cleanup of %s: %v\n", r.Name, err)
				}
			}
		}
	}
}

// ---- one issuance at a time ----

// withDNSCertLock runs fn holding an exclusive lock, so the daemon and `ziroctl dns cert renew` on one
// host never run two issuances (and two cleanups) at once.
func withDNSCertLock(fn func() error) error {
	if err := os.MkdirAll(dnsStatusDir, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dnsStatusDir, "issue.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("a certificate is being issued on this host already")
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// ---- renewal ----

// certSANs are the DNS names of the first certificate in a PEM chain.
func certSANs(chainPEM string) []string {
	blk, _ := pem.Decode([]byte(chainPEM))
	if blk == nil {
		return nil
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil
	}
	return c.DNSNames
}

// dnsCertDue reports whether c should be issued now: nothing stored, the names changed, or expiry
// is within dnsCertRenewBefore.
func dnsCertDue(s routeStore, c DNSCert, now time.Time) (due bool, why string) {
	g, err := s.getCert(c.Name)
	if err != nil {
		return true, "not issued yet"
	}
	na, err := certExpiry(g.Cert)
	if err != nil {
		return true, "the stored certificate is unreadable"
	}
	sans := append([]string(nil), certSANs(g.Cert)...)
	sort.Strings(sans)
	if !slices.Equal(sans, c.Domains) {
		return true, "its names changed"
	}
	if left := na.Sub(now); left < dnsCertRenewBefore {
		return true, fmt.Sprintf("expires in %d days", int(left.Hours()/24))
	}
	return false, ""
}

// dnsCertState is what a certificate's issuance has been like, persisted so a restart keeps the
// backoff and doctor can show it.
type dnsCertState struct {
	LastError   string `json:"last_error,omitempty"`
	LastAttempt string `json:"last_attempt,omitempty"`
	NextAttempt string `json:"next_attempt,omitempty"`
	LastIssued  string `json:"last_issued,omitempty"`
	Failures    int    `json:"failures,omitempty"`
}

func dnsCertStatusPath() string { return filepath.Join(dnsStatusDir, "certs.json") }

func readDNSCertStatus() map[string]dnsCertState {
	out := map[string]dnsCertState{}
	if b, err := os.ReadFile(dnsCertStatusPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func writeDNSCertStatus(m map[string]dnsCertState) {
	b, _ := json.Marshal(m)
	if err := os.MkdirAll(dnsStatusDir, 0755); err == nil {
		_ = writeFileAtomic(dnsCertStatusPath(), b, 0644)
	}
}

func dnsCertForget(name string) {
	m := readDNSCertStatus()
	if _, ok := m[name]; ok {
		delete(m, name)
		writeDNSCertStatus(m)
	}
}

// dnsCertBackoff is the wait after the nth consecutive failure: 5 minutes, then 15, 1 hour, 3, 6.
func dnsCertBackoff(failures int) time.Duration {
	steps := []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour}
	return steps[min(max(failures, 1), len(steps))-1]
}

// issueAndStore issues c and stores it, holding the host lock.
func issueAndStore(s routeStore, c DNSCert) error {
	return withDNSCertLock(func() error {
		d, err := s.read()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dnsCertTimeout)
		defer cancel()
		g, err := issueDNSCert(ctx, s, d, c)
		if err == nil {
			err = s.putCert(c.Name, g)
		}
		if aerr := auditLog("dns-sync", "dnsprovider", "dns cert issue", fmt.Sprintf("%s (%s)", c.Name, strings.Join(c.Domains, ", ")), err); aerr != nil {
			fmt.Printf("[dns] audit log: %v\n", aerr)
		}
		return err
	})
}

// certLoop issues and renews the DNS-01 certificates. Like dnsLoop it works only while leader() is
// true and every func is a seam for tests.
type certLoop struct {
	store    func() (routeStore, error)
	leader   func() bool
	issue    func(s routeStore, c DNSCert) error
	now      func() time.Time
	announce func(c DNSCert, why string, err error)
}

// tick looks at every certificate once and issues those due whose backoff has passed. It returns the
// names it tried.
func (l *certLoop) tick() []string {
	if !l.leader() {
		return nil
	}
	s, err := l.store()
	if err != nil {
		return nil
	}
	d, err := s.read()
	if err != nil || len(d.DNSCloud.Certs) == 0 {
		return nil
	}
	now := l.now()
	state := readDNSCertStatus()
	var tried []string
	changed := false
	for _, c := range d.DNSCloud.Certs {
		due, why := dnsCertDue(s, c, now)
		st := state[c.Name]
		if !due {
			if st.LastError != "" || st.NextAttempt != "" {
				st.LastError, st.NextAttempt, st.Failures = "", "", 0
				state[c.Name], changed = st, true
			}
			continue
		}
		if next, err := time.Parse(time.RFC3339, st.NextAttempt); err == nil && now.Before(next) {
			continue
		}
		tried = append(tried, c.Name)
		err := l.issue(s, c)
		st.LastAttempt = now.UTC().Format(time.RFC3339)
		if err != nil {
			st.Failures++
			st.LastError = sanitizeLabel(err.Error(), 400)
			st.NextAttempt = now.Add(dnsCertBackoff(st.Failures)).UTC().Format(time.RFC3339)
		} else {
			st = dnsCertState{LastAttempt: st.LastAttempt, LastIssued: st.LastAttempt}
		}
		state[c.Name], changed = st, true
		if l.announce != nil {
			l.announce(c, why, err)
		}
	}
	if changed {
		writeDNSCertStatus(state)
	}
	return tried
}

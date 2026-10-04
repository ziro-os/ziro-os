package router

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ServerName is the name router (master) certificates are verified under, whatever address
// the client dialled: trust comes from the pinned cluster CA, not from public DNS.
const ServerName = "ziro-cluster"

// KeepaliveTimeout: the router sends a keepalive every 30s; a stream silent for longer is dead.
const KeepaliveTimeout = 75 * time.Second

// PinCA dials addr and returns the CA certificate in the chain the router presents whose hash
// is pin. Nothing is trusted on the way: the probe handshake cannot verify (empty root pool),
// and only a CA certificate matching the pin is returned.
func PinCA(ctx context.Context, addr, pin string) (*x509.Certificate, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName, RootCAs: x509.NewCertPool()}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return nil, errors.New("router certificate verified against an empty pool")
	}
	var ve *tls.CertificateVerificationError
	if !errors.As(err, &ve) {
		return nil, err
	}
	for _, c := range ve.UnverifiedCertificates {
		if c.IsCA && subtle.ConstantTimeCompare([]byte(CertHash(c.Raw)), []byte(pin)) == 1 {
			return c, nil
		}
	}
	return nil, fmt.Errorf("router at %s does not present the pinned CA %s", addr, pin)
}

// CertHash is "sha256:<hex>" of a DER certificate (the pin format of `cluster join --ca-hash`).
func CertHash(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PublicKeyHash identifies a TLS key: sha256 of its SubjectPublicKeyInfo.
func PublicKeyHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// NewTLSKey returns a P-256 key for the device certificate (PEM) and a CSR for it.
func NewTLSKey() (keyPEM, csrPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	csrPEM, err = CSR(keyPEM)
	return keyPEM, csrPEM, err
}

// CSR returns a certificate request for an existing key (renewal keeps the key).
func CSR(keyPEM []byte) ([]byte, error) {
	b, _ := pem.Decode(keyPEM)
	if b == nil {
		return nil, errors.New("invalid device key")
	}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ziro-device"}}, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Client talks to the router over TLS 1.3, verifying it against the cluster CA and, once
// registered, authenticating with the device certificate. Any planet (master) works: each
// serves netmaps itself and relays writes to the Raft leader.
type Client struct {
	endpoints []string
	pool      *x509.CertPool

	mu        sync.Mutex
	hc        *http.Client
	cert      *tls.Certificate
	preferred string
}

func NewClient(endpoints []string, ca *x509.Certificate, cert *tls.Certificate) *Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	c := &Client{endpoints: endpoints, pool: pool}
	c.SetCert(cert)
	return c
}

// SetCert switches to a renewed certificate. Requests use a new transport (HTTP/2 shares one
// connection, which keeps the certificate it was opened with); open streams finish on the old.
func (c *Client) SetCert(cert *tls.Certificate) {
	tr := &http.Transport{
		ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.pool, ServerName: ServerName,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if cert == nil {
					return &tls.Certificate{}, nil // registration: no certificate yet
				}
				return cert, nil
			}},
	}
	c.mu.Lock()
	old := c.hc
	c.hc, c.cert = &http.Client{Transport: tr}, cert
	c.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
}

// Reset drops the client's connections (new requests dial afresh): after a network change, the
// old ones lead through a NAT that no longer exists.
func (c *Client) Reset() {
	c.mu.Lock()
	cert := c.cert
	c.mu.Unlock()
	c.SetCert(cert)
}

// Current is the endpoint the client last reached ("" before the first request).
func (c *Client) Current() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.preferred
}

// PlanetRTT is a router endpoint and its TLS handshake time (0: unreachable).
type PlanetRTT struct {
	Addr string
	RTT  time.Duration
}

// Nearest measures a verified TLS handshake to every endpoint at once and returns them fastest
// first, unreachable ones last. It also makes the fastest one the client's first choice, so the
// netmap stream comes from the closest planet and fails over in this order.
func (c *Client) Nearest(ctx context.Context) []PlanetRTT {
	c.mu.Lock()
	eps := append([]string(nil), c.endpoints...)
	c.mu.Unlock()
	out := make([]PlanetRTT, len(eps))
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].Addr = ep
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: c.pool, ServerName: ServerName,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }}}
			start := time.Now()
			if conn, err := d.DialContext(ctx, "tcp", ep); err == nil {
				out[i].RTT = max(time.Since(start), time.Microsecond)
				conn.Close()
			}
		}()
	}
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].RTT, out[j].RTT
		return a != 0 && (b == 0 || a < b)
	})
	if len(out) > 0 && out[0].RTT > 0 {
		c.mu.Lock()
		c.preferred = out[0].Addr
		c.mu.Unlock()
	}
	return out
}

func (c *Client) order() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.endpoints)+1)
	if c.preferred != "" {
		out = append(out, c.preferred)
	}
	for _, e := range c.endpoints {
		if e != c.preferred {
			out = append(out, e)
		}
	}
	return out
}

// post sends to the first endpoint that answers (503 = no leader there yet: try the next).
func (c *Client) post(ctx context.Context, path string, in any) (*http.Response, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	last := errors.New("no router endpoints")
	for _, ep := range c.order() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+ep+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		c.mu.Lock()
		hc := c.hc
		c.mu.Unlock()
		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = err
			continue
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			last = statusError(resp)
			continue
		}
		c.mu.Lock()
		c.preferred = ep
		c.mu.Unlock()
		if resp.StatusCode != http.StatusOK {
			return nil, statusError(resp)
		}
		return resp, nil
	}
	return nil, last
}

// StatusError is a non-200 reply; Code 401/403 means the device was revoked or never admitted.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("router: HTTP %d: %s", e.Code, e.Message) }

func statusError(resp *http.Response) error {
	defer resp.Body.Close()
	var m struct{ Message string }
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&m)
	return &StatusError{Code: resp.StatusCode, Message: m.Message}
}

func (c *Client) call(ctx context.Context, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.post(ctx, path, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// Register joins a network with a join key, or asks for approval (Status "pending": call again
// with the same CSR until it is "authorized").
func (c *Client) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	var out RegisterResponse
	return out, c.call(ctx, "/router/v1/register", req, &out)
}

// Renew returns a fresh certificate (PEM) for the key in csr.
func (c *Client) Renew(ctx context.Context, csr []byte) (string, error) {
	var out RegisterResponse
	err := c.call(ctx, "/router/v1/renew", RenewRequest{CSR: string(csr)}, &out)
	return out.Cert, err
}

// UpdateEndpoints reports this device's current endpoint candidates.
func (c *Client) UpdateEndpoints(ctx context.Context, req MapRequest) error {
	return c.call(ctx, "/router/v1/endpoints", req, nil)
}

// Map opens the netmap stream and calls fn for every message until ctx ends, fn fails, or the
// stream breaks (a "full" message always comes first, so callers simply reconnect).
func (c *Client) Map(ctx context.Context, req MapRequest, fn func(MapMessage) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(KeepaliveTimeout, cancel)
	defer idle.Stop()
	resp, err := c.post(ctx, "/router/v1/map", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var m MapMessage
		if err := dec.Decode(&m); err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("netmap stream idle: %w", ctx.Err())
			}
			return err
		}
		idle.Reset(KeepaliveTimeout)
		if m.Type == "keepalive" {
			continue
		}
		if err := fn(m); err != nil {
			return err
		}
	}
}

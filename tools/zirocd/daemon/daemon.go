package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"
	"sync"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Daemon owns the device's identity, its connection to the router and the data plane. The CLI
// talks to it over a root-only local socket (an Administrators-only named pipe on Windows).

const renewBefore = 10 * 24 * time.Hour

type Status struct {
	State         string       `json:"state"` // stopped, pending, connecting, connected, revoked, needs-login
	Error         string       `json:"error,omitempty"`
	Network       string       `json:"network,omitempty"`
	Domain        string       `json:"domain,omitempty"`
	Name          string       `json:"name,omitempty"`
	IPv4          string       `json:"ipv4,omitempty"`
	IPv6          string       `json:"ipv6,omitempty"`
	Interface     string       `json:"interface,omitempty"`
	Version       string       `json:"version"`
	ClientVersion string       `json:"client_version,omitempty"` // pinned by the network admin
	Update        string       `json:"update,omitempty"`         // newer version available (notify mode)
	CertExpires   time.Time    `json:"cert_expires,omitempty"`
	Dropped       uint64       `json:"dropped_packets"`
	Peers         []PeerStatus `json:"peers"`
}

type UpRequest struct {
	Key        string   `json:"key,omitempty"` // zr1_ invite (with or without a join key)
	Name       string   `json:"name,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	AcceptDNS  *bool    `json:"accept_dns,omitempty"`
	AutoUpdate string   `json:"auto_update,omitempty"`
}

type Daemon struct {
	Dir       string
	Version   string
	OnHealthy func() // first netmap after start (the updater clears its rollback marker)

	mu       sync.Mutex
	st       *State
	status   Status
	eng      *Engine
	cancel   context.CancelFunc
	done     chan struct{}
	pinnedCV string
	update   string
}

func New(dir, version string) *Daemon {
	return &Daemon{Dir: dir, Version: version, status: Status{State: "needs-login"}}
}

// Start resumes a registered device (called once at daemon start).
func (d *Daemon) Start() error {
	st, err := LoadState(d.Dir)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st = st
	if st != nil && (st.Status == "authorized" || st.Status == "pending") {
		d.startLocked()
	}
	return nil
}

func (d *Daemon) setStatus(fn func(s *Status)) {
	d.mu.Lock()
	fn(&d.status)
	d.mu.Unlock()
}

// Up joins a network with an invite, or reconnects the current one.
func (d *Daemon) Up(ctx context.Context, req UpRequest) (Status, error) {
	d.mu.Lock()
	cur := d.st
	d.mu.Unlock()
	if req.AutoUpdate != "" && !slices.Contains([]string{"on", "notify", "off"}, req.AutoUpdate) {
		return d.Status(), errors.New("auto-update must be on, notify or off")
	}
	if req.Key == "" {
		if cur == nil {
			return d.Status(), errors.New("not registered: zirocd up --key <zr1_...>")
		}
		d.mu.Lock()
		applyPrefs(&cur.Prefs, req)
		err := SaveState(d.Dir, cur)
		d.stopLocked()
		d.startLocked()
		d.mu.Unlock()
		return d.Status(), err
	}
	inv, err := zr.ParseInvite(req.Key)
	if err != nil {
		return d.Status(), err
	}
	prefs := Prefs{AcceptDNS: true, AutoUpdate: "on"}
	if cur != nil && cur.Network == inv.Network {
		prefs = cur.Prefs
	}
	applyPrefs(&prefs, req)
	st := cur
	if st == nil || st.Network != inv.Network || st.Pin != inv.Pin {
		if st, err = newState(inv, prefs); err != nil {
			return d.Status(), err
		}
	} else {
		st.Endpoints, st.JoinKey, st.Prefs = inv.Endpoints, inv.Key, prefs
	}
	if err := d.register(ctx, st); err != nil {
		return d.Status(), err
	}
	d.mu.Lock()
	d.stopLocked()
	d.st = st
	d.startLocked()
	d.mu.Unlock()
	return d.Status(), nil
}

func applyPrefs(p *Prefs, req UpRequest) {
	if req.Name != "" {
		p.Name = req.Name
	}
	if req.Routes != nil {
		p.Routes = req.Routes
	}
	if req.AcceptDNS != nil {
		p.AcceptDNS = *req.AcceptDNS
	}
	if req.AutoUpdate != "" {
		p.AutoUpdate = req.AutoUpdate
	}
}

// caCert returns the router CA: the stored one, or the one the pin selects on first contact.
func (d *Daemon) caCert(ctx context.Context, st *State) (*x509.Certificate, error) {
	if st.CA != "" {
		b, _ := pem.Decode([]byte(st.CA))
		if b != nil {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil && zr.CertHash(c.Raw) == st.Pin {
				return c, nil
			}
		}
		return nil, errors.New("stored router CA does not match the pin")
	}
	var last error
	for _, ep := range st.Endpoints {
		c, err := zr.PinCA(ctx, ep, st.Pin)
		if err == nil {
			st.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
			return c, nil
		}
		last = err
	}
	return nil, fmt.Errorf("reach the router: %w", last)
}

func (d *Daemon) client(ctx context.Context, st *State) (*zr.Client, error) {
	ca, err := d.caCert(ctx, st)
	if err != nil {
		return nil, err
	}
	var cert *tls.Certificate
	if st.Cert != "" {
		c, err := tls.X509KeyPair([]byte(st.Cert), []byte(st.TLSKey))
		if err != nil {
			return nil, err
		}
		cert = &c
	}
	return zr.NewClient(st.Endpoints, ca, cert), nil
}

// register sends the device's keys to the router; a key admits it, otherwise it waits for approval.
func (d *Daemon) register(ctx context.Context, st *State) error {
	c, err := d.client(ctx, st)
	if err != nil {
		return err
	}
	csr, err := zr.CSR([]byte(st.TLSKey))
	if err != nil {
		return err
	}
	wgPub, err := publicOf(st.WGKey)
	if err != nil {
		return err
	}
	discoPub, err := publicOf(st.DiscoKey)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	req := zr.RegisterRequest{Key: st.JoinKey, Name: st.Prefs.Name, Hostname: host, OS: runtime.GOOS + "/" + runtime.GOARCH,
		NodeKey: wgPub, DiscoKey: discoPub, CSR: string(csr), Routes: st.Prefs.Routes}
	if st.JoinKey == "" {
		req.Network = st.Network
	}
	out, err := c.Register(ctx, req)
	if err != nil {
		return err
	}
	if out.CA != "" && out.CA != st.CA {
		b, _ := pem.Decode([]byte(out.CA))
		if b == nil || zr.CertHash(b.Bytes) != st.Pin {
			return errors.New("router returned a CA that does not match the pin")
		}
	}
	st.Member, st.Status = out.Member, out.Status
	if out.Status == "authorized" {
		st.Cert, st.IPv4, st.IPv6, st.JoinKey = out.Cert, out.IPv4, out.IPv6, "" // the key is spent: never kept
	}
	return SaveState(d.Dir, st)
}

func (d *Daemon) startLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel, d.done = cancel, make(chan struct{})
	st := *d.st
	d.status = Status{State: "connecting", Network: st.Network, Name: st.Prefs.Name, IPv4: st.IPv4, IPv6: st.IPv6}
	go func(done chan struct{}) {
		defer close(done)
		d.run(ctx, &st)
	}(d.done)
}

func (d *Daemon) stopLocked() {
	if d.cancel == nil {
		return
	}
	d.cancel()
	done := d.done
	d.mu.Unlock()
	<-done
	d.mu.Lock()
	d.cancel = nil
	if d.eng != nil {
		d.eng.Close()
		d.eng = nil
	}
	d.status.State, d.status.Peers = "stopped", nil
}

// Down disconnects but keeps the identity (zirocd up reconnects).
func (d *Daemon) Down() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	if d.st != nil && d.st.Status == "authorized" {
		d.st.Status = "down"
		_ = SaveState(d.Dir, d.st)
	}
}

// Logout disconnects and forgets the identity.
func (d *Daemon) Logout() error {
	d.Down()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st = nil
	d.status = Status{State: "needs-login"}
	err := os.Remove(statePath(d.Dir))
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return err
}

func sleepCtx(ctx context.Context, dur time.Duration) bool {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// run keeps the device connected: approval polling, certificate renewal, the netmap stream with
// jittered backoff, and endpoint reporting.
func (d *Daemon) run(ctx context.Context, st *State) {
	fail := func(state string, err error) {
		d.setStatus(func(s *Status) { s.State, s.Error = state, err.Error() })
	}
	for st.Status == "pending" {
		d.setStatus(func(s *Status) { s.State, s.Error = "pending", "waiting for an admin: ziroctl router member approve" })
		if !sleepCtx(ctx, 10*time.Second) {
			return
		}
		if err := d.register(ctx, st); err != nil {
			var se *zr.StatusError
			if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusNotFound) {
				fail("revoked", err)
				return
			}
			fail("pending", err)
		}
	}
	d.mu.Lock()
	if d.st != nil && d.st.Network == st.Network {
		*d.st = *st
	}
	d.mu.Unlock()

	port := st.Prefs.Port
	if port == 0 {
		port = DefaultPort
	}
	epChanged := make(chan struct{}, 1)
	eng, err := NewEngine(st.WGKey, st.DiscoKey, port, st.Prefs.AcceptDNS, d.relayAuth, func() {
		select {
		case epChanged <- struct{}{}:
		default:
		}
	})
	if err != nil {
		fail("error", err)
		return
	}
	d.mu.Lock()
	d.eng = eng
	d.status.Interface = eng.Name()
	d.mu.Unlock()

	backoff := time.Second
	healthy := false
	for ctx.Err() == nil {
		c, err := d.client(ctx, st)
		if err == nil {
			err = d.maybeRenew(ctx, c, st)
		}
		if err == nil {
			epCtx, stopEP := context.WithCancel(ctx)
			go d.reportEndpoints(epCtx, c, eng, port, epChanged)
			err = c.Map(ctx, d.mapRequest(eng, port), func(m zr.MapMessage) error {
				if err := eng.Apply(m); err != nil {
					log.Printf("zirocd: apply netmap: %v", err)
					d.setStatus(func(s *Status) { s.Error = err.Error() })
				} else {
					d.setStatus(func(s *Status) { s.Error = "" })
				}
				d.setStatus(func(s *Status) {
					s.State = "connected"
					if m.Domain != "" {
						s.Domain = m.Domain
					}
					if m.Self != nil {
						s.Name = m.Self.Name
					}
				})
				if m.Type == "full" || m.ClientVersion != "" {
					d.mu.Lock()
					d.pinnedCV = m.ClientVersion
					d.mu.Unlock()
				}
				if !healthy && d.OnHealthy != nil {
					healthy = true
					d.OnHealthy()
				}
				backoff = time.Second
				return nil
			})
			stopEP()
		}
		if ctx.Err() != nil {
			return
		}
		var se *zr.StatusError
		if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
			fail("revoked", errors.New("this device was removed from the network (zirocd up --key to join again)"))
			d.mu.Lock()
			if d.st != nil {
				d.st.Status = "revoked"
				_ = SaveState(d.Dir, d.st)
			}
			d.mu.Unlock()
			return
		}
		fail("connecting", err)
		if !sleepCtx(ctx, backoff+rand.N(backoff)) {
			return
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// maybeRenew replaces the certificate when it is within renewBefore of expiry (same key).
func (d *Daemon) maybeRenew(ctx context.Context, c *zr.Client, st *State) error {
	b, _ := pem.Decode([]byte(st.Cert))
	if b == nil {
		return errors.New("no device certificate")
	}
	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	d.setStatus(func(s *Status) { s.CertExpires = crt.NotAfter })
	if time.Until(crt.NotAfter) > renewBefore {
		return nil
	}
	csr, err := zr.CSR([]byte(st.TLSKey))
	if err != nil {
		return err
	}
	newPEM, err := c.Renew(ctx, csr)
	if err != nil {
		return fmt.Errorf("renew certificate: %w", err)
	}
	st.Cert = newPEM
	d.mu.Lock()
	if d.st != nil {
		d.st.Cert = newPEM
		_ = SaveState(d.Dir, d.st)
	}
	d.mu.Unlock()
	cert, err := tls.X509KeyPair([]byte(newPEM), []byte(st.TLSKey))
	if err == nil {
		c.SetCert(&cert)
	}
	return err
}

// localEndpoints lists this host's addresses with the WireGuard port. ponytail: interface
// addresses only; R3 adds STUN-discovered public endpoints.
func localEndpoints(port int, tunName string) []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == tunName {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil || !pfx.Addr().IsGlobalUnicast() || pfx.Addr().Is4In6() {
				continue
			}
			out = append(out, netip.AddrPortFrom(pfx.Addr().Unmap(), uint16(port)).String())
		}
	}
	sort.Strings(out)
	if len(out) > zr.MaxEndpoints {
		out = out[:zr.MaxEndpoints]
	}
	return out
}

// mapRequest is this device's soft state: local and STUN-discovered endpoints, home relay.
func (d *Daemon) mapRequest(eng *Engine, port int) zr.MapRequest {
	eps := localEndpoints(port, eng.Name())
	for _, p := range eng.Bind().PublicEndpoints() {
		if !slices.Contains(eps, p) && len(eps) < zr.MaxEndpoints {
			eps = append(eps, p)
		}
	}
	return zr.MapRequest{Endpoints: eps, Version: d.Version, HomeRelay: eng.Bind().Home()}
}

// reportEndpoints tells the router when this device's endpoints or home relay change (network
// switch, new NAT mapping): peers then punch towards the new address at once.
func (d *Daemon) reportEndpoints(ctx context.Context, c *zr.Client, eng *Engine, port int, changed <-chan struct{}) {
	last := d.mapRequest(eng, port)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-changed:
		}
		cur := d.mapRequest(eng, port)
		if slices.Equal(cur.Endpoints, last.Endpoints) && cur.HomeRelay == last.HomeRelay {
			continue
		}
		if err := c.UpdateEndpoints(ctx, cur); err == nil {
			last = cur
		}
	}
}

// relayAuth gives relay connections the router CA and the current device certificate.
func (d *Daemon) relayAuth() (*x509.Certificate, *tls.Certificate) {
	d.mu.Lock()
	st := d.st
	d.mu.Unlock()
	if st == nil || st.CA == "" || st.Cert == "" {
		return nil, nil
	}
	b, _ := pem.Decode([]byte(st.CA))
	if b == nil {
		return nil, nil
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil
	}
	cert, err := tls.X509KeyPair([]byte(st.Cert), []byte(st.TLSKey))
	if err != nil {
		return nil, nil
	}
	return ca, &cert
}

// Netcheck probes UDP reachability, NAT mapping and relay latency.
func (d *Daemon) Netcheck(ctx context.Context) (Netcheck, error) {
	d.mu.Lock()
	eng := d.eng
	d.mu.Unlock()
	if eng == nil {
		return Netcheck{}, errors.New("not connected (zirocd up)")
	}
	return eng.Bind().Netcheck(ctx), nil
}

// PinnedVersion is the zirocd version the network admin pinned ("" = latest).
func (d *Daemon) PinnedVersion() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pinnedCV
}

// AutoUpdate is the device's update policy.
func (d *Daemon) AutoUpdate() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st == nil || d.st.Prefs.AutoUpdate == "" {
		return "on"
	}
	return d.st.Prefs.AutoUpdate
}

func (d *Daemon) SetUpdateAvailable(v string) {
	d.mu.Lock()
	d.update = v
	d.mu.Unlock()
}

func (d *Daemon) Status() Status {
	d.mu.Lock()
	s := d.status
	s.Version, s.ClientVersion, s.Update = d.Version, d.pinnedCV, d.update
	eng := d.eng
	d.mu.Unlock()
	s.Peers = []PeerStatus{}
	if eng != nil {
		s.Peers = eng.Peers()
		s.Dropped = eng.Dropped()
	}
	return s
}

// ---- local control API ----

// Handler serves the CLI. Access control is the listener's: root-only socket / admin-only pipe.
func (d *Daemon) Handler(update func(ctx context.Context) (string, error)) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, d.Status(), nil) })
	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		var req UpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			reply(w, nil, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		s, err := d.Up(ctx, req)
		reply(w, s, err)
	})
	mux.HandleFunc("GET /netcheck", func(w http.ResponseWriter, r *http.Request) {
		nc, err := d.Netcheck(r.Context())
		reply(w, nc, err)
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) { d.Down(); reply(w, d.Status(), nil) })
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) { reply(w, d.Status(), d.Logout()) })
	mux.HandleFunc("POST /update", func(w http.ResponseWriter, r *http.Request) {
		v, err := update(r.Context())
		reply(w, map[string]string{"version": v}, err)
	})
	return mux
}

// Close stops the data plane (daemon shutdown).
func (d *Daemon) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
}

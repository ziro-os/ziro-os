package cmd

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Router control plane, served on the cluster API port of every master (/router/v1/*). The
// leader owns the live netmap hub; followers verify the device certificate and relay the request
// to the leader over mutual TLS, so clients can dial any public router endpoint.
//
// Desired state (networks, members, keys, ACLs) is committed through Raft with the cluster state;
// liveness and endpoints are soft state in the leader's hub and never touch the log.

const (
	deviceOU        = "ziro-device"
	deviceCertTTL   = 30 * 24 * time.Hour
	routerBodyLimit = 64 << 10
	streamKeepalive = 30 * time.Second
	streamWriteWait = 10 * time.Second
	subBuffer       = 64
	ephemeralTTL    = 10 * time.Minute
	pendingTTL      = 7 * 24 * time.Hour
)

var errRouterLoading = httpError{http.StatusServiceUnavailable, "router state is loading"}

var versionRe = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)

func routerOf(st *ClusterState) *zr.State {
	if st.Router == nil {
		st.Router = &zr.State{}
	}
	return st.Router
}

func findNetwork(r *zr.State, ref string) *zr.Network {
	for i := range r.Networks {
		if r.Networks[i].ID == ref || r.Networks[i].Name == ref {
			return &r.Networks[i]
		}
	}
	return nil
}

func findMember(r *zr.State, netID, ref string) *zr.Member {
	for i := range r.Members {
		m := &r.Members[i]
		if m.Network == netID && (m.ID == ref || m.Name == ref) {
			return m
		}
	}
	return nil
}

// ---- certificates ----

// parseCSR checks the CSR's self-signature (possession of the key) and returns the key's hash.
func parseCSR(p string) (*x509.CertificateRequest, string, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, "", httpError{http.StatusBadRequest, "invalid CSR"}
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, "", httpError{http.StatusBadRequest, "invalid CSR signature"}
	}
	return csr, zr.PublicKeyHash(csr.RawSubjectPublicKeyInfo), nil
}

// issueDeviceCert signs a client certificate for a member. Identity comes from the router, never
// from the CSR; the OU keeps it from ever passing as a master (verifyMaster).
func issueDeviceCert(st *ClusterState, csr *x509.CertificateRequest, memberID string) (string, error) {
	ca, key, err := caSigner(st)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: memberID, OrganizationalUnit: []string{deviceOU}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(deviceCertTTL),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, key)
	if err != nil {
		return "", err
	}
	return pemEncode("CERTIFICATE", der), nil
}

// deviceFromTLS returns the member ID and key hash of a verified device certificate.
func deviceFromTLS(cs *tls.ConnectionState) (id, keyHash string, ok bool) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return "", "", false
	}
	c := cs.PeerCertificates[0]
	if len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != deviceOU {
		return "", "", false
	}
	return c.Subject.CommonName, zr.PublicKeyHash(c.RawSubjectPublicKeyInfo), true
}

// ---- registration (pure state transitions; tested without a server) ----

var errBadJoinKey = httpError{http.StatusUnauthorized, "invalid, expired or used join key"}

func checkRegister(req *zr.RegisterRequest) error {
	if req.Name == "" {
		req.Name = strings.ToLower(sanitizeLabel(strings.Split(req.Hostname, ".")[0], 63))
	}
	if validLabel(req.Name) != nil {
		req.Name = "device"
	}
	req.Hostname, req.OS = sanitizeLabel(req.Hostname, 253), sanitizeLabel(req.OS, 32)
	if !validWGKey(req.NodeKey) || !validWGKey(req.DiscoKey) || req.NodeKey == req.DiscoKey {
		return httpError{http.StatusBadRequest, "invalid node or disco key"}
	}
	routes, err := validRoutes(req.Routes)
	if err != nil {
		return httpError{http.StatusBadRequest, err.Error()}
	}
	req.Routes = routes
	return nil
}

// routerRegister admits a device with a join key, re-registers a known device (same TLS key),
// or files an approval request. A reply lost in transit is safe to retry: the device's TLS key
// identifies its member, so a consumed single-use key still works for that same device.
func routerRegister(st *ClusterState, req zr.RegisterRequest, csr *x509.CertificateRequest, keyHash string, now time.Time) (zr.RegisterResponse, error) {
	R := routerOf(st)
	var key *zr.JoinKey
	var n *zr.Network
	if req.Key != "" {
		id, secret, _ := strings.Cut(req.Key, ".")
		for i := range R.Keys {
			if R.Keys[i].ID == id {
				key = &R.Keys[i]
			}
		}
		if key == nil || subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(key.Hash)) != 1 {
			return zr.RegisterResponse{}, errBadJoinKey
		}
		n = findNetwork(R, key.Network)
	} else if req.Network != "" {
		for i := range R.Networks {
			if R.Networks[i].ID == req.Network { // by ID only: names are guessable
				n = &R.Networks[i]
			}
		}
	}
	if n == nil {
		return zr.RegisterResponse{}, httpError{http.StatusNotFound, "unknown network"}
	}
	idx := -1
	for i := range R.Members {
		m := &R.Members[i]
		if m.Network == n.ID && subtle.ConstantTimeCompare([]byte(m.KeyHash), []byte(keyHash)) == 1 {
			idx = i
		} else if m.NodeKey == req.NodeKey {
			return zr.RegisterResponse{}, httpError{http.StatusConflict, "node key belongs to another device"}
		}
	}
	known := idx >= 0 && R.Members[idx].Authorized
	if key != nil && !known && (now.After(key.Expires) || (!key.Reusable && key.Uses > 0)) {
		return zr.RegisterResponse{}, errBadJoinKey
	}
	if idx < 0 {
		if key == nil {
			pending := 0
			for _, m := range R.Members {
				if m.Network == n.ID && !m.Authorized {
					pending++
				}
			}
			if pending >= maxPending {
				return zr.RegisterResponse{}, httpError{http.StatusTooManyRequests, "too many pending requests for this network"}
			}
		}
		v4, v6, err := allocMemberIP(R, n)
		if err != nil {
			return zr.RegisterResponse{}, err
		}
		id := randomHex(6)
		name := req.Name
		if findMember(R, n.ID, name) != nil {
			name = name + "-" + id[:4]
		}
		R.Members = append(R.Members, zr.Member{ID: id, Network: n.ID, Name: name, IPv4: v4, IPv6: v6, KeyHash: keyHash, CreatedAt: now})
		idx = len(R.Members) - 1
	}
	m := &R.Members[idx]
	m.Hostname, m.OS, m.NodeKey, m.DiscoKey, m.Routes = req.Hostname, req.OS, req.NodeKey, req.DiscoKey, req.Routes
	var approved []string
	for _, a := range m.Approved { // a withdrawn route loses its approval
		if hasString(m.Routes, a) {
			approved = append(approved, a)
		}
	}
	m.Approved = approved
	if key != nil && !m.Authorized {
		key.Uses++
		m.Authorized, m.Tags, m.Ephemeral = true, append([]string(nil), key.Tags...), key.Ephemeral
	}
	out := zr.RegisterResponse{Status: "pending", Member: m.ID}
	if m.Authorized {
		crt, err := issueDeviceCert(st, csr, m.ID)
		if err != nil {
			return zr.RegisterResponse{}, err
		}
		out = zr.RegisterResponse{Status: "authorized", Member: m.ID, Cert: crt, CA: st.CACert, IPv4: m.IPv4, IPv6: m.IPv6}
	}
	return out, nil
}

// routerRenew issues a new certificate to an authenticated member; a new key replaces the old
// one at once (the old certificate stops working).
func routerRenew(st *ClusterState, memberID string, csr *x509.CertificateRequest, keyHash string) (string, error) {
	R := routerOf(st)
	for i := range R.Members {
		if m := &R.Members[i]; m.ID == memberID && m.Authorized {
			m.KeyHash = keyHash
			return issueDeviceCert(st, csr, m.ID)
		}
	}
	return "", errUnauthorized
}

// routerHousekeeping drops ephemeral members that went offline and stale approval requests.
func routerHousekeeping(st *ClusterState, lastSeen func(id string) time.Time, now time.Time) []string {
	R := routerOf(st)
	var gone []string
	kept := R.Members[:0]
	for _, m := range R.Members {
		if (m.Ephemeral && now.Sub(lastSeen(m.ID)) > ephemeralTTL) || (!m.Authorized && now.Sub(m.CreatedAt) > pendingTTL) {
			gone = append(gone, m.ID)
			continue
		}
		kept = append(kept, m)
	}
	R.Members = kept
	return gone
}

// ---- the netmap hub (leader only) ----

type routerSoft struct {
	Endpoints []string  `json:"endpoints,omitempty"`
	Version   string    `json:"version,omitempty"`
	HomeRelay string    `json:"home_relay,omitempty"`
	Seen      time.Time `json:"seen"`
	Online    bool      `json:"online"`
}

type hubPeer struct {
	p   zr.Peer
	ver uint64
}

type routerSub struct {
	id      string
	ch      chan []byte
	done    chan struct{}
	seen    map[string]uint64 // peer ID -> version last sent
	selfVer uint64
	filter  string
	cv      string
	relays  string // hash of the relay list last sent
}

// ponytail: each stream keeps the versions of the peers it was sent: O(visible) memory per
// device, fine to a few thousand devices per full-mesh network; members with identical views
// could share one map past that.
type routerHub struct {
	mu      sync.Mutex
	loaded  bool
	version uint64
	members map[string]*zr.Member
	nets    map[string]*zr.Network
	acl     map[string]*compiledACL
	peers   map[string]*hubPeer
	seq     uint64
	soft    map[string]*routerSoft
	subs    map[string]*routerSub
	since   time.Time // liveness is not replicated: everyone gets a grace period from here
	relays  []zr.Relay
	relayH  string
}

func newRouterHub() *routerHub {
	h := &routerHub{}
	h.reset()
	return h
}

// reset drops every stream and all soft state (lost leadership).
func (h *routerHub) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.subs {
		close(s.done)
	}
	h.loaded, h.version = false, 0
	h.members, h.nets, h.acl = map[string]*zr.Member{}, map[string]*zr.Network{}, map[string]*compiledACL{}
	h.peers, h.soft, h.subs = map[string]*hubPeer{}, map[string]*routerSoft{}, map[string]*routerSub{}
	h.since = time.Now()
}

func (h *routerHub) projectLocked(m *zr.Member) zr.Peer {
	p := zr.Peer{ID: m.ID, Name: m.Name, NodeKey: m.NodeKey, DiscoKey: m.DiscoKey, Tags: m.Tags,
		Addresses: memberAddrs(m)}
	p.AllowedIPs = append(append([]string(nil), p.Addresses...), m.Approved...)
	if s := h.soft[m.ID]; s != nil {
		p.Endpoints, p.HomeRelay = s.Endpoints, s.HomeRelay
	}
	_, p.Online = h.subs[m.ID]
	return p
}

// refreshPeerLocked re-projects a member and reports whether peers must hear about it.
func (h *routerHub) refreshPeerLocked(m *zr.Member) bool {
	p := h.projectLocked(m)
	if cur := h.peers[m.ID]; cur != nil && reflect.DeepEqual(cur.p, p) {
		return false
	}
	h.seq++
	h.peers[m.ID] = &hubPeer{p: p, ver: h.seq}
	return true
}

// setState loads a new committed router state and sends every stream what changed for it.
func (h *routerHub) setState(st *zr.State, version uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loaded, h.version = true, version
	h.relays = st.Relays
	rb, _ := json.Marshal(st.Relays)
	h.relayH = hashToken(string(rb))
	h.members, h.nets, h.acl = map[string]*zr.Member{}, map[string]*zr.Network{}, map[string]*compiledACL{}
	byNet := map[string][]*zr.Member{}
	for i := range st.Networks {
		h.nets[st.Networks[i].ID] = &st.Networks[i]
	}
	for i := range st.Members {
		m := &st.Members[i]
		h.members[m.ID] = m
		if m.Authorized && h.nets[m.Network] != nil {
			byNet[m.Network] = append(byNet[m.Network], m)
			h.refreshPeerLocked(m)
		}
	}
	for id, n := range h.nets {
		h.acl[id] = compileACL(n.ACL, byNet[id])
	}
	for id := range h.peers {
		if m := h.members[id]; m == nil || !m.Authorized {
			delete(h.peers, id)
		}
	}
	for id, s := range h.subs {
		if m := h.members[id]; m == nil || !m.Authorized || h.nets[m.Network] == nil {
			h.closeLocked(s) // revoked: the stream ends now
			continue
		}
		h.pushLocked(s, false)
	}
}

func (h *routerHub) closeLocked(s *routerSub) {
	if h.subs[s.id] == s {
		delete(h.subs, s.id)
		close(s.done)
	}
}

func (h *routerHub) sendLocked(s *routerSub, b []byte) {
	select {
	case s.ch <- b:
	default: // too slow: drop it; the client reconnects and gets a full map
		h.closeLocked(s)
	}
}

// pushLocked sends s its full map, or the delta since what it was sent.
func (h *routerHub) pushLocked(s *routerSub, full bool) {
	m := h.members[s.id]
	n := h.nets[m.Network]
	c := h.acl[m.Network]
	if c == nil {
		c = &compiledACL{}
	}
	visible, filter := c.view(m)
	msg := zr.MapMessage{Type: "delta"}
	if full {
		s.seen, s.filter, s.selfVer, s.cv, s.relays = map[string]uint64{}, "", 0, "", ""
		msg = zr.MapMessage{Type: "full", Domain: n.Name + routerDomainS, Networks: []string{n.IPv4, n.IPv6}, FilterChanged: true, Filter: filter}
	}
	if self := h.peers[m.ID]; self != nil && self.ver != s.selfVer {
		s.selfVer, msg.Self = self.ver, &self.p
	}
	if n.ClientVersion != s.cv {
		s.cv, msg.ClientVersion = n.ClientVersion, n.ClientVersion
	}
	if h.relayH != s.relays {
		s.relays, msg.Relays, msg.RelaysChanged = h.relayH, h.relays, true
	}
	ids := make([]string, 0, len(visible))
	for id := range visible {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if hp := h.peers[id]; hp != nil && s.seen[id] != hp.ver {
			s.seen[id] = hp.ver
			msg.Peers = append(msg.Peers, hp.p)
		}
	}
	for id := range s.seen {
		if !visible[id] || h.peers[id] == nil {
			delete(s.seen, id)
			msg.Removed = append(msg.Removed, id)
		}
	}
	sort.Strings(msg.Removed)
	fb, _ := json.Marshal(filter)
	if fh := hashToken(string(fb)); fh != s.filter {
		s.filter, msg.Filter, msg.FilterChanged = fh, filter, true
	}
	if !full && msg.Self == nil && msg.ClientVersion == "" && msg.Peers == nil && msg.Removed == nil && !msg.FilterChanged && !msg.RelaysChanged {
		return
	}
	b, _ := json.Marshal(msg)
	h.sendLocked(s, b)
}

// peerChangedLocked tells the streams that see member id (and its own) about its new soft state.
func (h *routerHub) peerChangedLocked(id string, skip *routerSub) {
	m := h.members[id]
	if m == nil || !m.Authorized || !h.refreshPeerLocked(m) {
		return
	}
	hp := h.peers[id]
	b, _ := json.Marshal(zr.MapMessage{Type: "delta", Peers: []zr.Peer{hp.p}}) // same bytes for every viewer
	for _, s := range h.subs {
		if s == skip {
			continue
		}
		if s.id == id {
			h.pushLocked(s, false)
		} else if v, ok := s.seen[id]; ok && v != hp.ver {
			s.seen[id] = hp.ver
			h.sendLocked(s, b)
		}
	}
}

// authorize returns the member when id/keyHash name an authorized device.
func (h *routerHub) authorize(id, keyHash string) (*zr.Member, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		return nil, errRouterLoading
	}
	m := h.members[id]
	if m == nil || !m.Authorized || h.nets[m.Network] == nil || subtle.ConstantTimeCompare([]byte(m.KeyHash), []byte(keyHash)) != 1 {
		return nil, errUnauthorized
	}
	return m, nil
}

func (h *routerHub) updateSoft(id string, req zr.MapRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.soft[id]
	if s == nil {
		s = &routerSoft{}
		h.soft[id] = s
	}
	s.Endpoints, s.Version, s.HomeRelay, s.Seen = req.Endpoints, req.Version, req.HomeRelay, time.Now()
	h.peerChangedLocked(id, nil)
}

// subscribe opens member id's stream (replacing an older one) with its full map queued.
func (h *routerHub) subscribe(id string) (*routerSub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.members[id]; m == nil || !m.Authorized {
		return nil, errUnauthorized
	}
	if old := h.subs[id]; old != nil {
		h.closeLocked(old)
	}
	s := &routerSub{id: id, ch: make(chan []byte, subBuffer), done: make(chan struct{})}
	h.subs[id] = s
	h.peerChangedLocked(id, s) // now online
	h.pushLocked(s, true)
	return s, nil
}

func (h *routerHub) unsubscribe(s *routerSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[s.id] != s {
		return
	}
	h.closeLocked(s)
	if soft := h.soft[s.id]; soft != nil {
		soft.Seen = time.Now()
	}
	h.peerChangedLocked(s.id, nil)
}

func (h *routerHub) lastSeen(id string) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[id]; ok {
		return time.Now()
	}
	if s := h.soft[id]; s != nil && s.Seen.After(h.since) {
		return s.Seen
	}
	return h.since
}

// online is the soft state the CLI shows (member ls).
func (h *routerHub) online() map[string]routerSoft {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]routerSoft{}
	for id, s := range h.soft {
		v := *s
		_, v.Online = h.subs[id]
		out[id] = v
	}
	return out
}

// ---- HTTP ----

type routerServer struct {
	hub       *routerHub
	caPEM     string
	isLeader  func() bool
	leaderURL func() (string, error) // leader's cluster API address
	sync      func()                 // load committed state into the hub right after a change
	limiter   *rateLimiter           // per client IP
	devLimit  *rateLimiter           // per device
	denied    *clusterServer         // rate-limited audit of rejected credentials
	proxyOnce sync.Once
	proxyTr   http.RoundTripper
}

func newRouterServer(hub *routerHub, caPEM string) *routerServer {
	return &routerServer{hub: hub, caPEM: caPEM, isLeader: func() bool { return true },
		limiter: newRateLimiter(600, time.Minute), devLimit: newRateLimiter(60, time.Minute),
		denied: newClusterServer(), sync: func() {}}
}

type routerIdent struct {
	ip, member, keyHash string
	forwarded           bool
}

var routerHeaders = []string{"X-Ziro-Forwarded", "X-Ziro-Client-Ip", "X-Ziro-Device", "X-Ziro-Device-Key"}

// ident reads who is calling: a device certificate on this connection, or, only on a connection
// from a master, the identity the relaying follower verified.
func (rt *routerServer) ident(r *http.Request) routerIdent {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if r.Header.Get("X-Ziro-Forwarded") == "1" && requestFromMaster(r.TLS, rt.caPEM) {
		fip := r.Header.Get("X-Ziro-Client-Ip")
		if _, err := netip.ParseAddr(fip); err != nil {
			fip = ip
		}
		return routerIdent{ip: fip, member: r.Header.Get("X-Ziro-Device"), keyHash: r.Header.Get("X-Ziro-Device-Key"), forwarded: true}
	}
	id, kh, _ := deviceFromTLS(r.TLS)
	return routerIdent{ip: ip, member: id, keyHash: kh}
}

func (rt *routerServer) fail(w http.ResponseWriter, who routerIdent, path string, err error) {
	code := http.StatusInternalServerError
	var he httpError
	if errors.As(err, &he) {
		code = he.code
	} else {
		err = errors.New("internal error") // details stay in the leader's log
	}
	if code == http.StatusUnauthorized {
		rt.denied.auditDenied(who.ip, path)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: err.Error()})
}

func (rt *routerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who := rt.ident(r)
	switch {
	case r.Method != http.MethodPost:
		rt.fail(w, who, r.URL.Path, httpError{http.StatusMethodNotAllowed, "method not allowed"})
		return
	case !who.forwarded && !rt.limiter.allow(who.ip):
		rt.fail(w, who, r.URL.Path, httpError{http.StatusTooManyRequests, "rate limit exceeded"})
		return
	case !rt.isLeader():
		if who.forwarded { // one hop only
			rt.fail(w, who, r.URL.Path, httpError{http.StatusServiceUnavailable, "no router leader here"})
			return
		}
		rt.forward(w, r, who)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, routerBodyLimit)
	if r.URL.Path == "/router/v1/register" {
		out, err := rt.register(r, who)
		if err != nil {
			rt.fail(w, who, r.URL.Path, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	// Everything else needs an admitted device.
	m, err := rt.hub.authorize(who.member, who.keyHash)
	if err == nil && !rt.devLimit.allow(m.ID) {
		err = httpError{http.StatusTooManyRequests, "rate limit exceeded"}
	}
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	switch r.URL.Path {
	case "/router/v1/map":
		rt.serveMap(w, r, m.ID, who)
	case "/router/v1/endpoints":
		req, err := decodeMapRequest(r)
		if err != nil {
			rt.fail(w, who, r.URL.Path, err)
			return
		}
		rt.hub.updateSoft(m.ID, req)
		_ = json.NewEncoder(w).Encode(APIMessage{Status: "ok"})
	case "/router/v1/renew":
		var req zr.RenewRequest
		var crt string
		err := json.NewDecoder(r.Body).Decode(&req)
		if err == nil {
			var csr *x509.CertificateRequest
			var kh string
			if csr, kh, err = parseCSR(req.CSR); err == nil {
				err = withState(func(st *ClusterState) error {
					var e error
					crt, e = routerRenew(st, m.ID, csr, kh)
					return e
				})
			}
		}
		clusterAudit("device:"+m.ID, "router renew", m.Network, err)
		if err != nil {
			rt.fail(w, who, r.URL.Path, err)
			return
		}
		rt.sync()
		_ = json.NewEncoder(w).Encode(zr.RegisterResponse{Status: "authorized", Member: m.ID, Cert: crt})
	default:
		rt.fail(w, who, r.URL.Path, httpError{http.StatusNotFound, "not found"})
	}
}

func decodeMapRequest(r *http.Request) (zr.MapRequest, error) {
	var req zr.MapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, httpError{http.StatusBadRequest, "invalid request"}
	}
	if len(req.Endpoints) > zr.MaxEndpoints {
		return req, httpError{http.StatusBadRequest, "too many endpoints"}
	}
	for i, e := range req.Endpoints {
		ap, err := netip.ParseAddrPort(e)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
			return req, httpError{http.StatusBadRequest, "invalid endpoint"}
		}
		req.Endpoints[i] = ap.String()
	}
	if req.Version != "" && !versionRe.MatchString(req.Version) {
		return req, httpError{http.StatusBadRequest, "invalid version"}
	}
	if req.HomeRelay != "" && validLabel(req.HomeRelay) != nil {
		return req, httpError{http.StatusBadRequest, "invalid home relay"}
	}
	return req, nil
}

func (rt *routerServer) register(r *http.Request, who routerIdent) (zr.RegisterResponse, error) {
	var req zr.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return zr.RegisterResponse{}, httpError{http.StatusBadRequest, "invalid request"}
	}
	csr, kh, err := parseCSR(req.CSR)
	if err == nil {
		err = checkRegister(&req)
	}
	var out zr.RegisterResponse
	if err == nil {
		err = withState(func(st *ClusterState) error {
			var e error
			out, e = routerRegister(st, req, csr, kh, time.Now())
			return e
		})
	}
	if err == nil { // failures are not logged one by one (unauthenticated: a flood); 401s go through auditDenied
		clusterAudit("ip:"+who.ip, "router register "+out.Status, out.Member, nil)
		rt.sync()
	}
	return out, err
}

// serveMap streams the netmap: full map first, then deltas and keepalives, until the client goes
// away, the device is revoked, or this master stops leading.
func (rt *routerServer) serveMap(w http.ResponseWriter, r *http.Request, id string, who routerIdent) {
	req, err := decodeMapRequest(r)
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	rt.hub.updateSoft(id, req)
	sub, err := rt.hub.subscribe(id)
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	defer rt.hub.unsubscribe(sub)
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	keep := time.NewTicker(streamKeepalive)
	defer keep.Stop()
	write := func(b []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(streamWriteWait))
		if _, err := w.Write(append(b, '\n')); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			for { // drain what was queued before the close (e.g. the revocation's last delta)
				select {
				case b := <-sub.ch:
					write(b)
				default:
					return
				}
			}
		case b := <-sub.ch:
			if !write(b) {
				return
			}
		case <-keep.C:
			if !write([]byte(`{"type":"keepalive"}`)) {
				return
			}
		}
	}
}

// forward relays a device's request to the leader over mutual TLS, carrying the identity this
// follower verified. Streams pass through unbuffered.
func (rt *routerServer) forward(w http.ResponseWriter, r *http.Request, who routerIdent) {
	leader, err := rt.leaderURL()
	if err != nil {
		rt.fail(w, who, r.URL.Path, httpError{http.StatusServiceUnavailable, "no router leader elected"})
		return
	}
	rt.proxyOnce.Do(func() {
		tc, err := masterClientTLS(rt.caPEM)
		if err != nil {
			tc = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()} // fails closed
		}
		rt.proxyTr = &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second}
	})
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	p := &httputil.ReverseProxy{
		Transport:     rt.proxyTr,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: leader})
			for _, h := range routerHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set("X-Ziro-Forwarded", "1")
			pr.Out.Header.Set("X-Ziro-Client-Ip", who.ip)
			if who.member != "" {
				pr.Out.Header.Set("X-Ziro-Device", who.member)
				pr.Out.Header.Set("X-Ziro-Device-Key", who.keyHash)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rt.fail(w, who, r.URL.Path, httpError{http.StatusServiceUnavailable, "router leader unreachable"})
		},
	}
	p.ServeHTTP(w, r)
}

// ---- wiring into cluster serve ----

// routerSnapshot copies the committed router state on the leader (nil elsewhere).
func (rs *raftStore) routerSnapshot() (*zr.State, uint64) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !rs.leading || rs.cur == nil {
		return nil, 0
	}
	st := &zr.State{}
	if rs.cur.Router != nil {
		b, _ := json.Marshal(rs.cur.Router)
		_ = json.Unmarshal(b, st)
	}
	return st, rs.version
}

var localRouterHub *routerHub // set inside `cluster serve` (the local socket shows its soft state)

// startRouter attaches the router to the master's API mux and runs the leader's hub loop.
func startRouter(mux *http.ServeMux, rs *raftStore, cfg *ClusterConfig, caPEM string) {
	hub := newRouterHub()
	localRouterHub = hub
	rt := newRouterServer(hub, caPEM)
	rt.isLeader = rs.isLeader
	rt.leaderURL = func() (string, error) { return rs.leaderAPI(clusterPortOf(cfg)) }
	load := func() {
		st, ver := rs.routerSnapshot()
		hub.mu.Lock()
		stale := st != nil && (!hub.loaded || ver != hub.version)
		hub.mu.Unlock()
		if stale {
			hub.setState(st, ver)
		}
	}
	rt.sync = load
	mux.Handle("/router/v1/", rt)
	go func() {
		tick, house := time.NewTicker(250*time.Millisecond), time.NewTicker(time.Minute)
		for {
			select {
			case <-tick.C:
				if !rs.isLeader() {
					hub.mu.Lock()
					loaded := hub.loaded
					hub.mu.Unlock()
					if loaded {
						hub.reset()
					}
					continue
				}
				load()
			case <-house.C:
				if !rs.isLeader() {
					continue
				}
				var gone []string
				err := withState(func(st *ClusterState) error {
					gone = routerHousekeeping(st, hub.lastSeen, time.Now())
					return nil
				})
				for _, id := range gone {
					clusterAudit("router", "router member expire", id, err)
				}
			}
		}
	}()
}

// routerKeySecret returns a new join key's "<id>.<secret>" and the hash stored for it.
func routerKeySecret() (id, full, hash string) {
	id = randomHex(4)
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	return id, id + "." + secret, hashToken(secret)
}

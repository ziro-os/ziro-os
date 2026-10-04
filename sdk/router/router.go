// Package router is the wire protocol between the Ziro router (ziroctl router, on the cluster
// masters) and its clients (zirocd, relays): networks, members, ACLs and the streamed netmap.
package router

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// State is the router's desired state, replicated with the cluster state (Raft). Liveness and
// endpoints are soft state on the leader and never stored here.
type State struct {
	Endpoints []string  `json:"endpoints,omitempty"` // public host:port clients dial (default: the masters)
	Networks  []Network `json:"networks,omitempty"`
	Members   []Member  `json:"members,omitempty"`
	Keys      []JoinKey `json:"keys,omitempty"`
}

// Network is one isolated virtual network (ZeroTier-style), addressed by its random ID.
type Network struct {
	ID            string    `json:"id"`   // 16 hex chars
	Name          string    `json:"name"` // DNS label: <member>.<name>.ziro
	IPv4          string    `json:"ipv4"` // CIDR (a /16 of 100.64.0.0/10)
	IPv6          string    `json:"ipv6"` // ULA /48
	ACL           ACL       `json:"acl"`
	ClientVersion string    `json:"client_version,omitempty"` // zirocd version pinned for the fleet ("" = latest)
	CreatedAt     time.Time `json:"created_at"`
}

// ACL is default deny: traffic is allowed only by a rule. Selectors: "*", "tag:<t>",
// "group:<g>", "member:<name>" or a CIDR. Dst entries add ":<ports>" ("*", "443", "8000-8100").
type ACL struct {
	Groups map[string][]string `json:"groups,omitempty" yaml:"groups,omitempty"` // group -> member names
	Rules  []Rule              `json:"rules,omitempty" yaml:"rules,omitempty"`
}

type Rule struct {
	Src   []string `json:"src" yaml:"src"`
	Dst   []string `json:"dst" yaml:"dst"`
	Proto string   `json:"proto,omitempty" yaml:"proto,omitempty"` // tcp, udp, icmp or "" (any)
}

// Member is a device admitted (or waiting to be admitted) to a network.
type Member struct {
	ID         string    `json:"id"` // also the CN of its client certificate
	Network    string    `json:"network"`
	Name       string    `json:"name"`
	Hostname   string    `json:"hostname,omitempty"`
	OS         string    `json:"os,omitempty"`
	NodeKey    string    `json:"node_key"`  // WireGuard public key
	DiscoKey   string    `json:"disco_key"` // NaCl box public key for path discovery
	IPv4       string    `json:"ipv4"`
	IPv6       string    `json:"ipv6"`
	Tags       []string  `json:"tags,omitempty"`
	Authorized bool      `json:"authorized"`
	Ephemeral  bool      `json:"ephemeral,omitempty"` // removed after going offline
	KeyHash    string    `json:"key_hash"`            // sha256 of the TLS public key its certificate must carry
	Routes     []string  `json:"routes,omitempty"`    // subnets it advertises
	Approved   []string  `json:"approved,omitempty"`  // advertised subnets an admin approved
	CreatedAt  time.Time `json:"created_at"`
}

// JoinKey admits devices without approval. Only a hash of its secret is stored.
type JoinKey struct {
	ID        string    `json:"id"`
	Network   string    `json:"network"`
	Hash      string    `json:"hash"`
	Reusable  bool      `json:"reusable,omitempty"`
	Ephemeral bool      `json:"ephemeral,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Expires   time.Time `json:"expires"`
	Uses      int       `json:"uses"`
	CreatedAt time.Time `json:"created_at"`
}

// ---- invites: everything a client needs to reach and trust the router, in one string ----

const invitePrefix = "zr1_"

// Invite carries the router endpoints, the cluster CA pin and the network; Key (a join key
// "<id>.<secret>") is empty for a request that waits for an admin's approval.
type Invite struct {
	Endpoints []string `json:"r"`
	Pin       string   `json:"p"` // "sha256:<hex>" of the cluster CA certificate
	Network   string   `json:"n"`
	Key       string   `json:"k,omitempty"`
}

func (i Invite) String() string {
	b, _ := json.Marshal(i)
	return invitePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func ParseInvite(s string) (Invite, error) {
	var i Invite
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), invitePrefix)
	if !ok || len(raw) > 4096 {
		return i, errors.New("not a Ziro router key (want zr1_...)")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &i) != nil {
		return i, errors.New("malformed Ziro router key")
	}
	if len(i.Endpoints) == 0 || !strings.HasPrefix(i.Pin, "sha256:") || i.Network == "" {
		return i, errors.New("incomplete Ziro router key")
	}
	return i, nil
}

// ---- wire messages ----

type RegisterRequest struct {
	Key      string   `json:"key,omitempty"`     // join key; empty = ask for approval
	Network  string   `json:"network,omitempty"` // with no key
	Name     string   `json:"name"`
	Hostname string   `json:"hostname,omitempty"`
	OS       string   `json:"os,omitempty"`
	NodeKey  string   `json:"node_key"`
	DiscoKey string   `json:"disco_key"`
	CSR      string   `json:"csr"` // PEM; proves possession of the TLS key
	Routes   []string `json:"routes,omitempty"`
}

type RegisterResponse struct {
	Status string `json:"status"` // "authorized" or "pending"
	Member string `json:"member"`
	Cert   string `json:"cert,omitempty"` // PEM client certificate (when authorized)
	CA     string `json:"ca,omitempty"`   // PEM cluster CA
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
}

type RenewRequest struct {
	CSR string `json:"csr"`
}

// MapRequest opens the netmap stream and, sent to /endpoints, updates this device's soft state.
type MapRequest struct {
	Endpoints []string `json:"endpoints,omitempty"` // ip:port candidates, at most MaxEndpoints
	Version   string   `json:"version,omitempty"`
}

const MaxEndpoints = 16

// Peer is a member as another member sees it.
type Peer struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	NodeKey    string   `json:"node_key"`
	DiscoKey   string   `json:"disco_key"`
	Addresses  []string `json:"addresses"`   // its own /32 and /128
	AllowedIPs []string `json:"allowed_ips"` // addresses + approved routes
	Endpoints  []string `json:"endpoints,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Online     bool     `json:"online"`
}

// FilterRule allows inbound packets from Src to Dst on Ports; anything else is dropped.
type FilterRule struct {
	Src   []string    `json:"src"` // prefixes
	Dst   []string    `json:"dst"` // prefixes (own addresses or approved routes)
	Proto string      `json:"proto,omitempty"`
	Ports []PortRange `json:"ports,omitempty"` // empty = all
}

type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// MapMessage is one JSON line of the netmap stream: "full" first, then "delta" (Peers are
// upserts, Removed are member IDs, Filter is set when FilterChanged) and "keepalive".
type MapMessage struct {
	Type          string       `json:"type"`
	Self          *Peer        `json:"self,omitempty"`
	Domain        string       `json:"domain,omitempty"`   // <network>.ziro
	Networks      []string     `json:"networks,omitempty"` // the network's IPv4 and IPv6 prefixes (full only)
	Peers         []Peer       `json:"peers,omitempty"`
	Removed       []string     `json:"removed,omitempty"`
	Filter        []FilterRule `json:"filter,omitempty"`
	FilterChanged bool         `json:"filter_changed,omitempty"`
	ClientVersion string       `json:"client_version,omitempty"`
}

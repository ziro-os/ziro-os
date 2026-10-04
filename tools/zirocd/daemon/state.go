package daemon

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.org/x/crypto/curve25519"
)

// State is everything the device keeps between runs, in one 0600 file in a directory only root
// (SYSTEM and Administrators on Windows) can read. Private keys never leave it.
type State struct {
	Endpoints []string `json:"endpoints"`
	Pin       string   `json:"pin"`
	Network   string   `json:"network"`
	CA        string   `json:"ca,omitempty"` // PEM, verified against Pin on first contact
	JoinKey   string   `json:"join_key,omitempty"`
	Member    string   `json:"member,omitempty"`
	Status    string   `json:"status,omitempty"` // "pending", "authorized", "revoked"
	TLSKey    string   `json:"tls_key"`          // PEM
	Cert      string   `json:"cert,omitempty"`   // PEM
	WGKey     string   `json:"wg_key"`           // base64 private
	DiscoKey  string   `json:"disco_key"`        // base64 private
	IPv4      string   `json:"ipv4,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"`
	SSO       bool     `json:"sso,omitempty"` // registering by signing in (zirocd up --sso)
	Prefs     Prefs    `json:"prefs"`
}

// Prefs are the operator's choices for this device.
type Prefs struct {
	Name       string   `json:"name,omitempty"`
	Routes     []string `json:"routes,omitempty"`      // subnets to advertise
	AcceptDNS  bool     `json:"accept_dns"`            // configure <network>.ziro split DNS
	AutoUpdate string   `json:"auto_update,omitempty"` // on (default), notify, off
	Port       int      `json:"port,omitempty"`        // WireGuard UDP port (default 41641)
}

const DefaultPort = 41641

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func SaveState(dir string, st *State) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dir))
}

// newCurveKey returns a clamped Curve25519 private key and its public key (base64, WireGuard's
// format); the same kind of key serves WireGuard and path discovery.
func newCurveKey() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

func publicOf(priv string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return "", errors.New("invalid private key")
	}
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(p), err
}

// newState creates a device identity for an invite: all keys generated here.
func newState(inv zr.Invite, prefs Prefs) (*State, error) {
	tlsKey, _, err := zr.NewTLSKey()
	if err != nil {
		return nil, err
	}
	wg, _, err := newCurveKey()
	if err != nil {
		return nil, err
	}
	disco, _, err := newCurveKey()
	if err != nil {
		return nil, err
	}
	return &State{Endpoints: inv.Endpoints, Pin: inv.Pin, Network: inv.Network, JoinKey: inv.Key,
		TLSKey: string(tlsKey), WGKey: wg, DiscoKey: disco, Prefs: prefs}, nil
}

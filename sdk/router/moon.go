package router

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Moons are relays that are not masters: any Linux host or container in a region, running
// `zirocd moon`. A moon registers once with a one-time token, gets a certificate (OU MoonOU,
// DNS name MoonServerName(name)) and follows the relay map from the planets: just enough to
// forward WireGuard ciphertext between the devices of one network.

const (
	MasterOU      = "ziro-master" // planets (cluster masters)
	MoonOU        = "ziro-relay"  // moons
	DeviceOU      = "ziro-device" // router devices
	NodeOU        = "ziro-node"   // cluster nodes (mesh "anywhere")
	moonPrefix    = "zm1_"
	moonSNISuffix = ".moon.ziro"
)

// MoonServerName is the name a moon's certificate carries and devices verify. It is never
// ServerName, so a moon certificate can't stand in for a planet.
func MoonServerName(name string) string { return name + moonSNISuffix }

// MoonToken registers a moon (shown once by `ziroctl router moon add`).
type MoonToken struct {
	Endpoints []string `json:"r"`
	Pin       string   `json:"p"` // "sha256:<hex>" of the cluster CA certificate
	Name      string   `json:"n"`
	Secret    string   `json:"k"`
}

func (t MoonToken) String() string {
	b, _ := json.Marshal(t)
	return moonPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func ParseMoonToken(s string) (MoonToken, error) {
	var t MoonToken
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), moonPrefix)
	if !ok || len(raw) > 4096 {
		return t, errors.New("not a Ziro moon token (want zm1_...)")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &t) != nil {
		return t, errors.New("malformed Ziro moon token")
	}
	if len(t.Endpoints) == 0 || !strings.HasPrefix(t.Pin, "sha256:") || t.Name == "" || t.Secret == "" {
		return t, errors.New("incomplete Ziro moon token")
	}
	return t, nil
}

type MoonRegisterRequest struct {
	Name   string `json:"name"`
	Secret string `json:"secret,omitempty"` // registration; empty when renewing with the moon certificate
	CSR    string `json:"csr"`
}

type MoonRegisterResponse struct {
	Cert string `json:"cert"` // PEM
	CA   string `json:"ca"`   // PEM
}

// RelayMember is what a relay needs to forward for a device: who it is (certificate key hash),
// its WireGuard key, and its network. Nothing else (no names, endpoints or ACLs).
type RelayMember struct {
	ID      string `json:"id"`
	KeyHash string `json:"key_hash"`
	NodeKey string `json:"node_key"` // base64
	Network string `json:"network"`
}

// RelayMapMessage is one line of the relay map stream: "full" (Members is everything), "delta"
// (Members upserted, Removed gone), or "keepalive".
type RelayMapMessage struct {
	Type    string        `json:"type"`
	Members []RelayMember `json:"members,omitempty"`
	Removed []string      `json:"removed,omitempty"`
}

// verifyOU returns a VerifyConnection hook that requires the peer's leaf certificate to carry
// exactly ou (the chain itself is verified by crypto/tls first).
func verifyOU(ou string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificate")
		}
		if o := cs.PeerCertificates[0].Subject.OrganizationalUnit; len(o) != 1 || o[0] != ou {
			return errors.New("peer certificate is not a " + ou + " certificate")
		}
		return nil
	}
}

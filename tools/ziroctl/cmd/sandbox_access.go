package cmd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"golang.org/x/crypto/ssh"
)

// SSH session tokens for sandboxes. A token is the SSH user name, so one line gets a person or
// an agent into a sandbox from anywhere: ssh -p 22998 zsbx_<token>@host. A token is bound to
// one sandbox, expires (1h by default, 24h at most, never past its sandbox), can be single-use
// and can be bound to a public key, so a leaked user name alone opens nothing. Only its SHA-256
// is stored (in the sandbox's directory, 0600); it is gone with the sandbox.

const maxSandboxAccess = 16

// A token is zsbx_<sandbox id><secret>: the id lets an SSH edge on another cluster node find the
// owner; the 26-character secret (128 bits) is what authenticates.
var sandboxTokenRe = regexp.MustCompile(`^zsbx_(?:[a-z2-7]{12})?[a-z2-7]{26}$`)

// tokenSandbox is the sandbox id a token names ("" for one without).
func tokenSandbox(tok string) string {
	if len(tok) == 5+12+26 && sandboxTokenRe.MatchString(tok) {
		return tok[5:17]
	}
	return ""
}

type accessRecord struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	PublicKey string    `json:"public_key,omitempty"` // authorized_keys format
	SingleUse bool      `json:"single_use,omitempty"`
	Used      bool      `json:"used,omitempty"`
}

func (a accessRecord) view() sdkapi.SandboxAccess {
	v := sdkapi.SandboxAccess{ID: a.ID, Created: a.Created, Expires: a.Expires, SingleUse: a.SingleUse, Used: a.Used}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(a.PublicKey)); err == nil {
		v.KeyFingerprint = ssh.FingerprintSHA256(k)
	}
	return v
}

// accessStore holds every sandbox's tokens in memory, written through to access.json.
type accessStore struct {
	mu  sync.Mutex
	all map[string][]accessRecord // sandbox id -> tokens
}

func accessFile(id string) string { return filepath.Join(sandboxDir(id), "access.json") }

func loadAccessStore(ids []string) *accessStore {
	s := &accessStore{all: map[string][]accessRecord{}}
	for _, id := range ids {
		var recs []accessRecord
		if b, err := os.ReadFile(accessFile(id)); err == nil && json.Unmarshal(b, &recs) == nil {
			s.all[id] = recs
		}
	}
	return s
}

// save writes one sandbox's tokens; the caller holds mu.
func (s *accessStore) save(id string) error {
	b, err := json.MarshalIndent(s.all[id], "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(accessFile(id), b, 0600)
}

// create issues a token for a sandbox that expires at sbExpires; the token is returned once.
func (s *accessStore) create(id string, req sdkapi.SandboxAccessRequest, now, sbExpires time.Time) (string, accessRecord, error) {
	ttl := time.Hour
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return "", accessRecord{}, errors.New("ttl must be between 1m and 24h")
		}
		ttl = d
	}
	if req.PublicKey != "" {
		k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil || len(strings.TrimSpace(string(rest))) > 0 {
			return "", accessRecord{}, errors.New("public_key must be one authorized_keys line")
		}
		if weak := weakKey(k); weak != "" {
			return "", accessRecord{}, fmt.Errorf("public_key: %s", weak)
		}
		req.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", accessRecord{}, err
	}
	tok := "zsbx_" + id + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	exp := now.Add(ttl)
	if exp.After(sbExpires) {
		exp = sbExpires
	}
	rec := accessRecord{ID: randomHex(4), Hash: hashToken(tok), Created: now, Expires: exp, PublicKey: req.PublicKey, SingleUse: req.SingleUse}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.all[id][:0:0]
	for _, r := range s.all[id] {
		if now.Before(r.Expires) && !(r.SingleUse && r.Used) {
			live = append(live, r)
		}
	}
	if len(live) >= maxSandboxAccess {
		return "", accessRecord{}, fmt.Errorf("sandbox %s has %d live access tokens; revoke one first", id, maxSandboxAccess)
	}
	s.all[id] = append(live, rec)
	if err := s.save(id); err != nil {
		return "", accessRecord{}, err
	}
	return tok, rec, nil
}

func (s *accessStore) list(id string) []sdkapi.SandboxAccess {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []sdkapi.SandboxAccess{}
	for _, r := range s.all[id] {
		out = append(out, r.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func (s *accessStore) revoke(id, aid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.all[id][:0:0]
	for _, r := range s.all[id] {
		if r.ID != aid {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(s.all[id]) {
		return errNotFound("no access token " + aid)
	}
	s.all[id] = kept
	return s.save(id)
}

func (s *accessStore) drop(id string) {
	s.mu.Lock()
	delete(s.all, id)
	s.mu.Unlock()
}

// use checks a token (and the key the client proved, nil for none) and, for a single-use
// token, spends it. It returns the sandbox and the token's id.
func (s *accessStore) use(tok string, key ssh.PublicKey, now time.Time) (sandbox, aid string, err error) {
	if !sandboxTokenRe.MatchString(tok) {
		return "", "", errors.New("not a sandbox token")
	}
	h := []byte(hashToken(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, recs := range s.all {
		for i, r := range recs {
			if subtle.ConstantTimeCompare(h, []byte(r.Hash)) != 1 {
				continue
			}
			switch {
			case !now.Before(r.Expires):
				return "", r.ID, errors.New("token expired")
			case r.SingleUse && r.Used:
				return "", r.ID, errors.New("token already used")
			case r.PublicKey != "" && key == nil:
				return "", r.ID, errNeedKey
			case r.PublicKey != "":
				bound, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
				if err != nil || subtle.ConstantTimeCompare(bound.Marshal(), key.Marshal()) != 1 {
					return "", r.ID, errors.New("wrong key for this token")
				}
			}
			if r.SingleUse {
				recs[i].Used = true
				if err := s.save(id); err != nil {
					return "", r.ID, err
				}
			}
			return id, r.ID, nil
		}
	}
	return "", "", errors.New("unknown token")
}

var errNeedKey = errors.New("this token needs its public key")

// createAccess issues an SSH session token for a sandbox the caller owns. host is the name the
// caller reached the API by (the gateway is on the same host), unless ssh_host is configured.
func (m *sandboxManager) createAccess(id string, c sandboxCaller, req sdkapi.SandboxAccessRequest, host string) (sdkapi.SandboxAccess, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sdkapi.SandboxAccess{}, err
	}
	cfg, err := loadSandboxConfig()
	if err != nil {
		return sdkapi.SandboxAccess{}, err
	}
	if cfg.SSHPort == 0 || m.ssh == nil {
		return sdkapi.SandboxAccess{}, errors.New("the SSH gateway is off (ssh_port in " + sandboxConfigFile + ")")
	}
	tok, rec, err := m.access.create(id, req, m.now().UTC(), sb.Expires)
	if err != nil {
		return sdkapi.SandboxAccess{}, err
	}
	if cfg.SSHHost != "" {
		host = cfg.SSHHost
	}
	if host == "" || (!validDomain(host) && !validIP(host)) {
		host, _ = os.Hostname()
	}
	v := rec.view()
	v.Username = tok
	v.SSH = sshCommand(tok, host, cfg.SSHPort)
	v.HostKey = knownHostsLine(host, cfg.SSHPort, m.ssh.signer().PublicKey())
	return v, nil
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

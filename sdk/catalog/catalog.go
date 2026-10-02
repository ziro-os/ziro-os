// Code moved from tools/ziroctl/cmd: the one implementation ziroctl and SDK users share.

// Package catalog builds, signs and verifies Ziro catalogs: ed25519-signed indexes of plugin
// manifests and app definitions (github.com/ziro-os/pkgs, github.com/ziro-os/apps, or your own).
package catalog

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	MaxIndex = 4 << 20
	MaxEntry = 1 << 20
)

type Repo struct {
	Name     string `json:"name"`
	URL      string `json:"url"` // https base; index.json and entries are fetched below it
	Key      string `json:"key"` // ed25519 public key, PEM (PKIX)
	Kind     string `json:"kind"`
	Official bool   `json:"official,omitempty"`
}

type Entry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path"` // relative to the repo URL
	SHA256      string `json:"sha256"`
}

type Index struct {
	Schema  int       `json:"schema"`
	Repo    string    `json:"repo"`
	Kind    string    `json:"kind"` // "module" or "app"
	Serial  int64     `json:"serial"`
	Expires time.Time `json:"expires"`
	Entries []Entry   `json:"entries"`
}

func (r Repo) Validate() error {
	if err := schema.ValidName(r.Name); err != nil {
		return err
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("repo %s: URL must be plain https://host/path", r.Name)
	}
	if r.Kind != "module" && r.Kind != "app" {
		return fmt.Errorf("repo %s: kind must be module or app", r.Name)
	}
	_, err = Ed25519Key(r.Key)
	return err
}

func Ed25519Key(pemKey string) (ed25519.PublicKey, error) {
	pub, err := parsePublicKey(pemKey)
	if err != nil {
		return nil, err
	}
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("catalog keys must be ed25519")
	}
	return k, nil
}

// SafeEntryPath keeps an index path inside the repo (and the cache dir).
func SafeEntryPath(p string) error {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") || p == ".." || strings.Contains(p, "\\") {
		return fmt.Errorf("unsafe entry path %q", p)
	}
	return nil
}

// VerifyIndex checks the signature, schema, expiry and entries of a raw index.
func VerifyIndex(r Repo, raw, sigB64 []byte, now time.Time) (*Index, error) {
	key, err := Ed25519Key(r.Key)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return nil, fmt.Errorf("repo %s: index signature is invalid", r.Name)
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("repo %s: %w", r.Name, err)
	}
	if idx.Schema != 1 || idx.Kind != r.Kind {
		return nil, fmt.Errorf("repo %s: unsupported index (schema %d, kind %q)", r.Name, idx.Schema, idx.Kind)
	}
	if !now.Before(idx.Expires) {
		return nil, fmt.Errorf("repo %s: index expired %s (run: ziroctl plugin update)", r.Name, idx.Expires.Format(time.RFC3339))
	}
	for _, e := range idx.Entries {
		if err := schema.ValidName(e.Name); err != nil {
			return nil, fmt.Errorf("repo %s: %w", r.Name, err)
		}
		if err := SafeEntryPath(e.Path); err != nil {
			return nil, fmt.Errorf("repo %s: %w", r.Name, err)
		}
		if len(e.SHA256) != 64 {
			return nil, fmt.Errorf("repo %s: entry %s has no sha256", r.Name, e.Name)
		}
	}
	return &idx, nil
}

// Build writes index.json for the definitions under src/<kind>s/<name>/<file> into out,
// validating each with check and writing it to out/<kind>s/<name>.json. A definition may be
// YAML or JSON (manifest.yaml, app.yml, ...); the catalog always serves canonical JSON, which is
// what the signed index pins.
func Build(src, out, repo, kind string, ttl time.Duration, now time.Time, check func([]byte) (Entry, error)) (*Index, error) {
	file := map[string]string{"module": "manifest", "app": "app"}[kind]
	if file == "" {
		return nil, fmt.Errorf("kind must be module or app")
	}
	var dirs []string
	for _, ext := range []string{".json", ".yaml", ".yml"} {
		m, err := filepath.Glob(filepath.Join(src, kind+"s", "*", file+ext))
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, m...)
	}
	sort.Strings(dirs)
	now = now.UTC()
	idx := &Index{Schema: 1, Repo: repo, Kind: kind, Serial: now.Unix(), Expires: now.Add(ttl)}
	seen := map[string]bool{}
	for _, p := range dirs {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if b, err = schema.ToJSON(b); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		e, err := check(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if dir := filepath.Base(filepath.Dir(p)); dir != e.Name {
			return nil, fmt.Errorf("%s: name %q must match its directory", p, e.Name)
		}
		if seen[e.Name] {
			return nil, fmt.Errorf("duplicate %s %s", kind, e.Name)
		}
		seen[e.Name] = true
		e.Path, e.SHA256 = kind+"s/"+e.Name+".json", sha256Hex(b)
		if err := os.MkdirAll(filepath.Join(out, kind+"s"), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(out, e.Path), b, 0644); err != nil {
			return nil, err
		}
		idx.Entries = append(idx.Entries, e)
	}
	sort.Slice(idx.Entries, func(i, j int) bool { return idx.Entries[i].Name < idx.Entries[j].Name })
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	return idx, os.WriteFile(filepath.Join(out, "index.json"), b, 0644)
}

// Sign signs out/index.json with an ed25519 private key (PKCS#8 PEM).
func Sign(out string, privPEM []byte) error {
	blk, _ := pem.Decode(privPEM)
	if blk == nil {
		return errors.New("no PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return errors.New("catalog keys must be ed25519")
	}
	raw, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	return os.WriteFile(filepath.Join(out, "index.json.sig"), []byte(sig+"\n"), 0644)
}

func parsePublicKey(pemKey string) (crypto.PublicKey, error) {
	b, _ := pem.Decode([]byte(pemKey))
	if b == nil {
		return nil, errors.New("no PEM public key")
	}
	return x509.ParsePKIXPublicKey(b.Bytes)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

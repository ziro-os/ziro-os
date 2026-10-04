// Package release verifies and fetches signed Ziro releases. Every release's SHA256SUMS is
// signed with the Ziro release key (ed25519; public half embedded below, private half only in CI),
// and nothing is accepted unless the signature and the file's hash verify.
package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PublicKey verifies SHA256SUMS.sig (scripts/release/sign-sums.sh checks CI's key against it).
//
//go:embed release.pub
var PublicKey string

// Verify checks an ed25519 signature (base64) over SHA256SUMS with pubPEM.
func Verify(sums, sig []byte, pubPEM string) error {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return errors.New("bad release public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok {
		return errors.New("release public key is not ed25519")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, sums, raw) {
		return errors.New("SHA256SUMS signature does not verify: refusing the release")
	}
	return nil
}

// ParseSums reads "<sha256>  <name>" lines.
func ParseSums(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && len(f[0]) == 64 {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out
}

func parseSemver(s string) ([3]int, bool) {
	var v [3]int
	p := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(p) != 3 {
		return v, false
	}
	for i := range p {
		n, err := strconv.Atoi(p[i])
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// Compare orders X.Y.Z versions (a valid version sorts above an invalid one).
func Compare(a, b string) int {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	switch {
	case !oka && !okb:
		return 0
	case !okb:
		return 1
	case !oka:
		return -1
	}
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			if va[i] < vb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ---- GitHub release source ----

var toolsTagRe = regexp.MustCompile(`^tools/v([0-9]+\.[0-9]+\.[0-9]+)$`)

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type Release struct {
	TagName    string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

func (r *Release) Asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// Source reads the tools release stream (tags tools/vX.Y.Z) of a GitHub repository. Downloads
// only follow https redirects to GitHub hosts.
type Source struct {
	API       string // https://api.github.com
	Repo      string // ziro-os/ziro-os
	UserAgent string
	PublicKey string
	HTTP      *http.Client
	Trusted   func(*url.URL) bool
}

func trustedGitHub(u *url.URL) bool {
	h := u.Hostname()
	return u.Scheme == "https" && (h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com"))
}

func NewSource(userAgent string) *Source {
	s := &Source{API: "https://api.github.com", Repo: "ziro-os/ziro-os", UserAgent: userAgent, PublicKey: PublicKey, Trusted: trustedGitHub}
	s.HTTP = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !s.Trusted(req.URL) {
			return fmt.Errorf("refusing redirect to %s", req.URL.Host)
		}
		return nil
	}}
	return s
}

func (s *Source) get(ctx context.Context, rawURL string, max int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !s.Trusted(u) {
		return nil, fmt.Errorf("refusing untrusted URL %q", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.UserAgent)
	req.Header.Set("Accept", "application/vnd.github+json, application/octet-stream")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u.Path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("GET %s: larger than %d bytes", u.Path, max)
	}
	return b, err
}

// Tools returns the release of tools tag ("" = newest tools/vX.Y.Z) and its version.
func (s *Source) Tools(ctx context.Context, version string) (*Release, string, error) {
	tag := ""
	if version != "" {
		if _, ok := parseSemver(version); !ok {
			return nil, "", fmt.Errorf("invalid version %q", version)
		}
		tag = "tools/v" + strings.TrimPrefix(version, "v")
	} else {
		b, err := s.get(ctx, s.API+"/repos/"+s.Repo+"/git/matching-refs/tags/tools/v", 4<<20)
		if err != nil {
			return nil, "", err
		}
		var refs []struct{ Ref string }
		if err := json.Unmarshal(b, &refs); err != nil {
			return nil, "", err
		}
		best := ""
		for _, r := range refs {
			t := strings.TrimPrefix(r.Ref, "refs/tags/")
			if m := toolsTagRe.FindStringSubmatch(t); m != nil && (best == "" || Compare(m[1], best) > 0) {
				tag, best = t, m[1]
			}
		}
		if tag == "" {
			return nil, "", errors.New("no tools release published")
		}
	}
	b, err := s.get(ctx, s.API+"/repos/"+s.Repo+"/releases/tags/"+tag, 4<<20)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", tag, err)
	}
	var rel Release
	if err := json.Unmarshal(b, &rel); err != nil {
		return nil, "", err
	}
	m := toolsTagRe.FindStringSubmatch(rel.TagName)
	if m == nil || rel.TagName != tag || rel.Prerelease {
		return nil, "", fmt.Errorf("%s is not a published tools release", tag)
	}
	return &rel, m[1], nil
}

// Fetch downloads asset name from rel and returns it only if it matches the signed SHA256SUMS.
func (s *Source) Fetch(ctx context.Context, rel *Release, name string, max int64) ([]byte, error) {
	need := func(n string) (*Asset, error) {
		if a := rel.Asset(n); a != nil {
			return a, nil
		}
		return nil, fmt.Errorf("release %s has no %s", rel.TagName, n)
	}
	sa, err := need("SHA256SUMS")
	if err != nil {
		return nil, err
	}
	ga, err := need("SHA256SUMS.sig")
	if err != nil {
		return nil, err
	}
	aa, err := need(name)
	if err != nil {
		return nil, err
	}
	sums, err := s.get(ctx, sa.URL, 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := s.get(ctx, ga.URL, 4<<10)
	if err != nil {
		return nil, err
	}
	if err := Verify(sums, sig, s.PublicKey); err != nil {
		return nil, err
	}
	want := ParseSums(sums)[name]
	if want == "" {
		return nil, fmt.Errorf("%s is not in the signed SHA256SUMS", name)
	}
	b, err := s.get(ctx, aa.URL, max)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); !bytes.Equal([]byte(got), []byte(want)) {
		return nil, fmt.Errorf("%s: SHA-256 mismatch (got %s, want %s)", name, got, want)
	}
	return b, nil
}

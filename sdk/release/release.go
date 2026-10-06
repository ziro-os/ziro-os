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

// Versions. Ziro OS is "x.y.z". The tools (ziroctl, ziropkg, zirocd) are "x.y.z" for the build
// that ships with that OS and "x.y.z.N" (N >= 1) for the Nth tools-only build of the same OS
// version, so a CLI fix never needs another OS version. N = 0 is spelled without the fourth
// part: each version has exactly one spelling.

// parseVersion reads 3 or 4 numeric parts, with an optional "v" and an ignored "-suffix".
// A missing fourth part is 0.
func parseVersion(s string) ([4]int, bool) {
	var v [4]int
	s, _, _ = strings.Cut(strings.TrimPrefix(s, "v"), "-")
	p := strings.Split(s, ".")
	if len(p) != 3 && len(p) != 4 {
		return v, false
	}
	for i := range p {
		if p[i] == "" || strings.Trim(p[i], "0123456789") != "" {
			return v, false
		}
		n, err := strconv.Atoi(p[i])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// Compare orders X.Y.Z and X.Y.Z.N versions (a missing N is 0; a valid version sorts above an
// invalid one, two invalid versions are equal).
func Compare(a, b string) int {
	va, oka := parseVersion(a)
	vb, okb := parseVersion(b)
	switch {
	case !oka && !okb:
		return 0
	case !okb:
		return 1
	case !oka:
		return -1
	}
	for i := range va {
		if va[i] != vb[i] {
			if va[i] < vb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

var toolsVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}(\.[1-9][0-9]*)?$`)

// ValidTools reports whether s is a canonical tools version, X.Y.Z or X.Y.Z.N with N >= 1 (no
// "v", no leading zeros, no ".0").
func ValidTools(s string) bool { return toolsVersionRe.MatchString(s) }

// OS returns the Ziro OS version (X.Y.Z) a tools or OS version belongs to, "" if s is invalid.
func OS(s string) string {
	v, ok := parseVersion(s)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

// Meta is a tools release's signed tools.json.
type Meta struct {
	Version string `json:"version"`
	MinOS   string `json:"min_os"`
}

// CheckMeta accepts toolsJSON only if it matches the signed sums and names tagVersion: a signed
// release re-published under another tag (an older build under a newer tag, or the reverse)
// must not install as the tag says.
func CheckMeta(sums, toolsJSON []byte, tagVersion string) (Meta, error) {
	var m Meta
	want := ParseSums(sums)["tools.json"]
	got := sha256.Sum256(toolsJSON)
	if want == "" || hex.EncodeToString(got[:]) != want {
		return m, errors.New("tools.json does not match the signed SHA256SUMS")
	}
	if err := json.Unmarshal(toolsJSON, &m); err != nil {
		return m, fmt.Errorf("tools.json: %w", err)
	}
	if m.Version != tagVersion {
		return m, fmt.Errorf("tools.json says version %q but the release is %s: refusing it", m.Version, tagVersion)
	}
	if m.MinOS != "" && OS(m.MinOS) != m.MinOS {
		return m, fmt.Errorf("tools.json: bad min_os %q", m.MinOS)
	}
	return m, nil
}

// ---- GitHub release source ----

// ToolsTagRe matches a tools release tag, tools/vX.Y.Z or tools/vX.Y.Z.N; group 1 is the version.
var ToolsTagRe = regexp.MustCompile(`^tools/v((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}(?:\.[1-9][0-9]*)?)$`)

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

// Source reads the tools release stream (tags tools/vX.Y.Z[.N]) of a GitHub repository. Downloads
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

// Tools returns the release of a tools version ("" = the newest tools tag) and its version.
func (s *Source) Tools(ctx context.Context, version string) (*Release, string, error) {
	tag := ""
	if version != "" {
		version = strings.TrimPrefix(version, "v")
		if !ValidTools(version) {
			return nil, "", fmt.Errorf("invalid version %q (want X.Y.Z or X.Y.Z.N)", version)
		}
		tag = "tools/v" + version
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
			if m := ToolsTagRe.FindStringSubmatch(t); m != nil && (best == "" || Compare(m[1], best) > 0) {
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
	m := ToolsTagRe.FindStringSubmatch(rel.TagName)
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
	m := ToolsTagRe.FindStringSubmatch(rel.TagName)
	if m == nil {
		return nil, fmt.Errorf("%s is not a tools release", rel.TagName)
	}
	ma, err := need("tools.json")
	if err != nil {
		return nil, err
	}
	meta, err := s.get(ctx, ma.URL, 64<<10)
	if err != nil {
		return nil, err
	}
	if _, err := CheckMeta(sums, meta, m[1]); err != nil {
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

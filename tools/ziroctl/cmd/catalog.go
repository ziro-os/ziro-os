package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Catalogs: signed indexes of plugins (ziro-os/pkgs) and apps (ziro-os/apps), plus any
// third-party repo an admin adds with its key. This is the only path remote definitions take
// into a host:
//   - index.json is signed (ed25519, index.json.sig) by a key ziroctl embeds or the admin added
//   - an expired index (freeze) or a lower serial than the cached one (rollback) is refused
//   - every definition must match the sha256 the signed index lists for it
//   - the cache is re-verified on every read, so editing it on disk doesn't help an attacker

const (
	catalogMaxIndex = 4 << 20
	catalogMaxEntry = 1 << 20
)

type CatalogRepo struct {
	Name     string `json:"name"`
	URL      string `json:"url"` // https base; index.json and entries are fetched below it
	Key      string `json:"key"` // ed25519 public key, PEM (PKIX)
	Kind     string `json:"kind"`
	Official bool   `json:"official,omitempty"`
}

type CatalogEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path"` // relative to the repo URL
	SHA256      string `json:"sha256"`
}

type CatalogIndex struct {
	Schema  int            `json:"schema"`
	Repo    string         `json:"repo"`
	Kind    string         `json:"kind"` // "module" or "app"
	Serial  int64          `json:"serial"`
	Expires time.Time      `json:"expires"`
	Entries []CatalogEntry `json:"entries"`
}

// CatalogItem is one verified definition from a repo.
type CatalogItem struct {
	CatalogEntry
	Repo string
	Data []byte
}

// Official repositories and the public halves of their signing keys (the private keys are CI
// secrets of each repo).
var officialRepos = []CatalogRepo{
	{Name: "ziro", URL: "https://ziro-os.github.io/pkgs", Kind: "module", Official: true, Key: pkgsCatalogKey},
	{Name: "ziro-apps", URL: "https://ziro-os.github.io/apps", Kind: "app", Official: true, Key: appsCatalogKey},
}

var (
	reposPath  = "/etc/ziro/repos.json"
	catalogDir = "/var/lib/ziro/catalog"
	catalogNow = time.Now
	// Catalog downloads: https only, redirects stay on https (artifacts on GitHub releases redirect
	// to their CDN; the content is pinned by sha256 either way).
	catalogHTTP = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" {
			return errors.New("refusing redirect")
		}
		return nil
	}}
	catalogDownload = func(rawURL, dst string, max int64) (string, error) {
		return downloadWith(catalogHTTP, func(u *url.URL) bool { return u.Scheme == "https" && u.Host != "" }, rawURL, dst, max)
	}
)

func (r CatalogRepo) validate() error {
	if err := validName(r.Name); err != nil {
		return err
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("repo %s: URL must be plain https://host/path", r.Name)
	}
	if r.Kind != "module" && r.Kind != "app" {
		return fmt.Errorf("repo %s: kind must be module or app", r.Name)
	}
	_, err = ed25519Key(r.Key)
	return err
}

func ed25519Key(pemKey string) (ed25519.PublicKey, error) {
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

// catalogRepos returns the official repos, then the admin's (sorted by name).
func catalogRepos(kind string) ([]CatalogRepo, error) {
	var out []CatalogRepo
	for _, r := range officialRepos {
		if kind == "" || r.Kind == kind {
			out = append(out, r)
		}
	}
	extra, err := loadExtraRepos()
	if err != nil {
		return nil, err
	}
	for _, r := range extra {
		if kind == "" || r.Kind == kind {
			out = append(out, r)
		}
	}
	return out, nil
}

func loadExtraRepos() ([]CatalogRepo, error) {
	b, err := os.ReadFile(reposPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rs []CatalogRepo
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", reposPath, err)
	}
	for i := range rs {
		rs[i].Official = false
		if err := rs[i].validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", reposPath, err)
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
	return rs, nil
}

func saveExtraRepos(rs []CatalogRepo) error {
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(reposPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(reposPath, b, 0600)
}

// safeEntryPath keeps an index path inside the repo (and the cache dir).
func safeEntryPath(p string) error {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") || p == ".." || strings.Contains(p, "\\") {
		return fmt.Errorf("unsafe entry path %q", p)
	}
	return nil
}

// verifyIndex checks the signature, schema, expiry and entries of a raw index.
func verifyIndex(r CatalogRepo, raw, sigB64 []byte) (*CatalogIndex, error) {
	key, err := ed25519Key(r.Key)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return nil, fmt.Errorf("repo %s: index signature is invalid", r.Name)
	}
	var idx CatalogIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("repo %s: %w", r.Name, err)
	}
	if idx.Schema != 1 || idx.Kind != r.Kind {
		return nil, fmt.Errorf("repo %s: unsupported index (schema %d, kind %q)", r.Name, idx.Schema, idx.Kind)
	}
	if !catalogNow().Before(idx.Expires) {
		return nil, fmt.Errorf("repo %s: index expired %s (run: ziroctl plugin update)", r.Name, idx.Expires.Format(time.RFC3339))
	}
	for _, e := range idx.Entries {
		if err := validName(e.Name); err != nil {
			return nil, fmt.Errorf("repo %s: %w", r.Name, err)
		}
		if err := safeEntryPath(e.Path); err != nil {
			return nil, fmt.Errorf("repo %s: %w", r.Name, err)
		}
		if len(e.SHA256) != 64 {
			return nil, fmt.Errorf("repo %s: entry %s has no sha256", r.Name, e.Name)
		}
	}
	return &idx, nil
}

func repoCache(r CatalogRepo) string { return filepath.Join(catalogDir, r.Name) }

// refreshRepo downloads and verifies a repo's index and entries into a fresh directory, then
// swaps it in: a failed or partial refresh never replaces a good cache.
func refreshRepo(r CatalogRepo) (*CatalogIndex, error) {
	if err := os.MkdirAll(catalogDir, 0755); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(catalogDir, "."+r.Name+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	base := strings.TrimSuffix(r.URL, "/")
	for _, f := range []string{"index.json", "index.json.sig"} {
		if _, err := catalogDownload(base+"/"+f, filepath.Join(tmp, f), catalogMaxIndex); err != nil {
			return nil, fmt.Errorf("repo %s: %w", r.Name, err)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(tmp, "index.json"))
	sig, _ := os.ReadFile(filepath.Join(tmp, "index.json.sig"))
	idx, err := verifyIndex(r, raw, sig)
	if err != nil {
		return nil, err
	}
	if cur, err := readCachedIndex(r); err == nil && idx.Serial < cur.Serial {
		return nil, fmt.Errorf("repo %s: index serial %d is older than the cached %d (rollback refused)", r.Name, idx.Serial, cur.Serial)
	}
	for _, e := range idx.Entries {
		dst := filepath.Join(tmp, "entries", e.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return nil, err
		}
		sum, err := catalogDownload(base+"/"+e.Path, dst, catalogMaxEntry)
		if err != nil {
			return nil, fmt.Errorf("repo %s: %s: %w", r.Name, e.Name, err)
		}
		if sum != e.SHA256 {
			return nil, fmt.Errorf("repo %s: %s: sha256 mismatch", r.Name, e.Name)
		}
	}
	dir := repoCache(r)
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(dir, old); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.Rename(old, dir)
		return nil, err
	}
	_ = os.RemoveAll(old)
	return idx, nil
}

func readCachedIndex(r CatalogRepo) (*CatalogIndex, error) {
	dir := repoCache(r)
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "index.json.sig"))
	if err != nil {
		return nil, err
	}
	return verifyIndex(r, raw, sig)
}

// catalogItems returns the verified cached definitions of every repo of a kind. A repo that was
// never fetched is skipped; one that fails verification is reported in errs and skipped, so a
// broken third-party repo can't take the official catalog down with it.
func catalogItems(kind string) (items []CatalogItem, errs []error) {
	repos, err := catalogRepos(kind)
	if err != nil {
		return nil, []error{err}
	}
	for _, r := range repos {
		idx, err := readCachedIndex(r)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range idx.Entries {
			b, err := os.ReadFile(filepath.Join(repoCache(r), "entries", e.Path))
			if err == nil && len(b) <= catalogMaxEntry && sha256Hex(b) != e.SHA256 {
				err = errors.New("sha256 mismatch (cache modified?)")
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("repo %s: %s: %w", r.Name, e.Name, err))
				continue
			}
			items = append(items, CatalogItem{CatalogEntry: e, Repo: r.Name, Data: b})
		}
	}
	return items, errs
}

// ---- placeholders, secrets and settings (shared by plugins and apps) ----

var placeholderRe = regexp.MustCompile(`\{\{\s*([a-z]+(?:\.[A-Za-z0-9_]+)?)\s*\}\}`)

// expand substitutes {{secret.X}}, {{setting.X}}, {{replica}}, {{peers}}, {{host}} from vars. It
// only replaces values (no logic, no functions); an unknown or malformed placeholder is an error,
// so a definition can't contain a literal "{{".
func expand(s string, vars map[string]string) (string, error) {
	var missing []string
	out := placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		k := placeholderRe.FindStringSubmatch(m)[1]
		v, ok := vars[k]
		if !ok {
			missing = append(missing, k)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unknown placeholder {{%s}}", missing[0])
	}
	// Values are substituted once and never re-scanned, so a value can't smuggle in a placeholder.
	if rest := placeholderRe.ReplaceAllString(s, ""); strings.Contains(rest, "{{") {
		return "", fmt.Errorf("malformed placeholder in %q", lastLines(s, 1))
	}
	return out, nil
}

// Setting is a value an operator may set (--set name=value). Every value, the default included,
// must fully match Pattern, so settings can't inject lines or arguments into configs.
type Setting struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default"`
	Pattern     string `json:"pattern"`
}

var settingNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func validateSettings(defs []Setting) error {
	for _, s := range defs {
		if !settingNameRe.MatchString(s.Name) {
			return fmt.Errorf("setting %q: bad name", s.Name)
		}
		if !strings.HasPrefix(s.Pattern, "^") || !strings.HasSuffix(s.Pattern, "$") {
			return fmt.Errorf("setting %s: pattern must be anchored (^...$)", s.Name)
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("setting %s: %w", s.Name, err)
		}
		if !re.MatchString(s.Default) {
			return fmt.Errorf("setting %s: default %q doesn't match %s", s.Name, s.Default, s.Pattern)
		}
	}
	return nil
}

// resolveSettings merges prev (earlier choices) and set (this run) over the defaults.
func resolveSettings(defs []Setting, prev, set map[string]string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]bool{}
	for _, d := range defs {
		known[d.Name] = true
		v := d.Default
		if p, ok := prev[d.Name]; ok {
			v = p
		}
		if s, ok := set[d.Name]; ok {
			v = s
		}
		if !regexp.MustCompile(d.Pattern).MatchString(v) || strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("setting %s=%q must match %s", d.Name, v, d.Pattern)
		}
		out[d.Name] = v
	}
	for k := range set {
		if !known[k] {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	return out, nil
}

// parseSetFlags turns --set k=v flags into a map.
func parseSetFlags(sets []string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --set %q (want name=value)", s)
		}
		out[k] = v
	}
	return out, nil
}

var secretSpecRe = regexp.MustCompile(`^(hex|base64|alnum):([0-9]{1,2})$`)

// validSecretSpec: "hex:N", "base64:N" (N random bytes) or "alnum:N" (N characters), 12 <= N <= 64.
func validSecretSpec(spec string) error {
	m := secretSpecRe.FindStringSubmatch(spec)
	if m == nil {
		return fmt.Errorf("secret spec %q (want hex:N, base64:N or alnum:N)", spec)
	}
	if n, _ := strconv.Atoi(m[2]); n < 12 || n > 64 {
		return fmt.Errorf("secret spec %q: N must be 12..64", spec)
	}
	return nil
}

func genSecret(spec string) (string, error) {
	if err := validSecretSpec(spec); err != nil {
		return "", err
	}
	m := secretSpecRe.FindStringSubmatch(spec)
	n, _ := strconv.Atoi(m[2])
	if m[1] == "alnum" {
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, n)
		for i := range b {
			j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}
			b[i] = chars[j.Int64()]
		}
		return string(b), nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	if m[1] == "hex" {
		return hex.EncodeToString(b), nil
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loadOrCreateSecrets keeps generated secrets stable across re-runs (0600 JSON at path).
func loadOrCreateSecrets(path string, specs map[string]string) (map[string]string, error) {
	cur := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &cur); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	changed := false
	for k, spec := range specs {
		if cur[k] != "" {
			continue
		}
		v, err := genSecret(spec)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", k, err)
		}
		cur[k], changed = v, true
	}
	if changed {
		b, _ := json.Marshal(cur)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(path, b, 0600); err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// ---- building and signing catalogs (used by the repos' CI) ----

// buildCatalog writes index.json for the definitions under src/<kind>s/<name>/<file> into out,
// validating each with check and copying it to out/<kind>s/<name>.json.
func buildCatalog(src, out, repo, kind string, ttl time.Duration, check func([]byte) (CatalogEntry, error)) (*CatalogIndex, error) {
	file := map[string]string{"module": "manifest.json", "app": "app.json"}[kind]
	if file == "" {
		return nil, fmt.Errorf("kind must be module or app")
	}
	dirs, err := filepath.Glob(filepath.Join(src, kind+"s", "*", file))
	if err != nil {
		return nil, err
	}
	now := catalogNow().UTC()
	idx := &CatalogIndex{Schema: 1, Repo: repo, Kind: kind, Serial: now.Unix(), Expires: now.Add(ttl)}
	seen := map[string]bool{}
	for _, p := range dirs {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
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

// signCatalog signs out/index.json with an ed25519 private key (PKCS#8 PEM).
func signCatalog(out string, privPEM []byte) error {
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

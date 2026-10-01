package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
		if err := rs[i].Validate(); err != nil {
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

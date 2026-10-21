package cmd

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Updatable WAF rules. The rules are a pack (gateway_waf_rules.go) published in ziro-os/pkgs as a
// signed catalog of kind "waf" and cached like any other catalog:
//
//   - Trust: the index is signed with the pkgs key compiled into ziroctl; every entry is pinned by
//     sha256; an expired index or a lower serial than the cached one is refused.
//   - Safety: a pack is installed only after it compiles and passes the samples every rule carries;
//     a pack that fails any check never replaces the rules in use, and a damaged cache falls back
//     to the built-in rules.
//   - Speed: `waf update` swaps the cache atomically; running gateways notice within a second,
//     rebuild only the routes that have a WAF, and swap the route table without dropping a
//     connection. On a cluster master the update also bumps WAFPackEpoch, so every node fetches
//     at once instead of waiting for its next daily check.

const (
	wafRepoName     = "ziro-waf"
	wafPackName     = "zirogate-crs" // the entry of the catalog this gateway uses
	wafAutoInterval = 24 * time.Hour
)

func wafRepo() CatalogRepo {
	for _, r := range officialRepos {
		if r.Name == wafRepoName {
			return r
		}
	}
	panic("no WAF repository")
}

func wafHoldPath() string { return filepath.Join(catalogDir, wafRepoName+".hold") }

// wafPrevDir holds the pack that was in use before the last update (for rollback).
func wafPrevDir() string { return repoCache(wafRepo()) + ".prev" }

// wafPackFrom reads the pack entry out of a verified cache directory and builds its engine.
func wafPackFrom(r CatalogRepo, idx *CatalogIndex, dir string) (*wafEngine, *wafPackFile, error) {
	var ent *CatalogEntry
	for i := range idx.Entries {
		if idx.Entries[i].Name == wafPackName {
			ent = &idx.Entries[i]
		}
	}
	if ent == nil {
		return nil, nil, fmt.Errorf("the catalog has no %s pack", wafPackName)
	}
	b, err := os.ReadFile(filepath.Join(dir, "entries", ent.Path))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > catalogMaxEntry || sha256Hex(b) != ent.SHA256 {
		return nil, nil, errors.New("WAF pack does not match the signed index (cache modified?)")
	}
	p, err := decodeWAFPack(b, false)
	if err != nil {
		return nil, nil, err
	}
	e, err := wafBuild(p, wafPackInfo{Serial: idx.Serial, Digest: ent.SHA256, Source: "catalog", Expires: idx.Expires.UTC().Format(time.RFC3339)})
	return e, p, err
}

// wafLoadPack makes the cached pack the engine in use. It returns whether the engine changed.
// With no cache the built-in rules are used; a cache that fails verification leaves the engine
// in place and is reported, because dropping to older rules would weaken the gateway.
func wafLoadPack() (bool, error) {
	r := wafRepo()
	cur := wafEng()
	idx, err := readCachedIndex(r)
	switch {
	case os.IsNotExist(err):
		if cur.pack.Source != "builtin" {
			wafCur.Store(wafBuiltinEngine())
			return true, nil
		}
		return false, nil
	case err != nil:
		return false, err
	}
	e, _, err := wafPackFrom(r, idx, repoCache(r))
	if err != nil {
		return false, err
	}
	if e.pack.Digest == cur.pack.Digest {
		return false, nil
	}
	wafCur.Store(e)
	return true, nil
}

// wafCacheStamp identifies the cached index, cheaply, for change detection.
func wafCacheStamp() string {
	fi, err := os.Stat(filepath.Join(repoCache(wafRepo()), "index.json"))
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339Nano) + "/" + strconv.FormatInt(fi.Size(), 10)
}

// ---- update ----

type wafUpdateResult struct {
	Pack      wafPackInfo `json:"pack"`
	Rules     int         `json:"rules"`
	Changed   bool        `json:"changed"`
	Added     []string    `json:"added,omitempty"`
	Updated   []string    `json:"updated,omitempty"`
	Removed   []string    `json:"removed,omitempty"`
	Available string      `json:"available,omitempty"` // --check: the version on offer
	Held      string      `json:"held,omitempty"`      // why a newer pack was not installed
}

// wafDiff lists the rules that differ between two engines.
func wafDiff(old, cur *wafEngine) (added, updated, removed []string) {
	for _, r := range cur.rules {
		i, ok := old.index[r.ID]
		switch {
		case !ok:
			added = append(added, r.ID)
		case !reflect.DeepEqual(old.rules[i].wafRuleDef, r.wafRuleDef):
			updated = append(updated, r.ID)
		}
	}
	for _, r := range old.rules {
		if _, ok := cur.index[r.ID]; !ok {
			removed = append(removed, r.ID)
		}
	}
	sort.Strings(added)
	sort.Strings(updated)
	sort.Strings(removed)
	return
}

func readWAFHold() int64 {
	b, err := os.ReadFile(wafHoldPath())
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// fetchWAFIndex downloads and verifies the repository's current index only.
func fetchWAFIndex(r CatalogRepo) (*CatalogIndex, error) {
	tmp, err := os.MkdirTemp("", "ziro-waf-")
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
	return readIndexAt(r, tmp)
}

// wafUpdate fetches the newest signed pack and installs it. check only reports what is on offer.
// force installs even when the serial is not newer.
func wafUpdate(check, force bool) (*wafUpdateResult, error) {
	r := wafRepo()
	if _, err := wafLoadPack(); err != nil { // the pack in use, so the result can say what changed
		fmt.Fprintf(os.Stderr, "warning: the cached WAF pack is unusable (%v); it will be replaced\n", err)
	}
	old := wafEng()
	idx, err := fetchWAFIndex(r)
	if err != nil {
		return nil, err
	}
	res := &wafUpdateResult{Pack: old.pack, Rules: len(old.rules)}
	cached, cerr := readCachedIndex(r)
	for _, e := range idx.Entries {
		if e.Name == wafPackName {
			res.Available = e.Version
		}
	}
	if hold := readWAFHold(); hold != 0 && idx.Serial <= hold && !force {
		res.Held = fmt.Sprintf("serial %d was rolled back; a newer pack is installed when one is published", hold)
		return res, nil
	}
	if cerr == nil && idx.Serial == cached.Serial && !force && old.pack.Source == "catalog" {
		return res, nil // up to date
	}
	if check {
		return res, nil
	}
	if cerr == nil { // keep the pack in use for a rollback, unless the content is the same
		if cur, _, err := wafPackFrom(r, cached, repoCache(r)); err == nil && !packSame(cur, idx) {
			_ = os.RemoveAll(wafPrevDir())
			if err := copyTree(repoCache(r), wafPrevDir()); err != nil {
				return nil, fmt.Errorf("keeping the previous pack: %w", err)
			}
		}
	}
	if _, err := refreshRepoChecked(r, func(idx *CatalogIndex, dir string) error {
		_, _, err := wafPackFrom(r, idx, dir)
		return err
	}); err != nil {
		return nil, err
	}
	_ = os.Remove(wafHoldPath())
	if _, err := wafLoadPack(); err != nil {
		return nil, err
	}
	cur := wafEng()
	res.Pack, res.Rules, res.Changed = cur.pack, len(cur.rules), cur.pack.Digest != old.pack.Digest
	res.Added, res.Updated, res.Removed = wafDiff(old, cur)
	return res, nil
}

// packSame reports whether the index's pack has the digest of the engine.
func packSame(e *wafEngine, idx *CatalogIndex) bool {
	for _, ent := range idx.Entries {
		if ent.Name == wafPackName {
			return ent.SHA256 == e.pack.Digest
		}
	}
	return false
}

// copyTree copies a directory of regular files.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		switch {
		case d.IsDir():
			return os.MkdirAll(filepath.Join(dst, rel), 0755)
		case d.Type().IsRegular():
			return copyFileSync(p, filepath.Join(dst, rel))
		}
		return nil
	})
}

// wafRollback reinstates the pack that was in use before the last update and stops the next
// update from installing the same pack again.
func wafRollback() (*wafUpdateResult, error) {
	r := wafRepo()
	prev := wafPrevDir()
	pidx, err := readIndexAt(r, prev)
	if err != nil {
		return nil, fmt.Errorf("no previous WAF pack to return to: %w", err)
	}
	if _, _, err := wafPackFrom(r, pidx, prev); err != nil {
		return nil, fmt.Errorf("the previous WAF pack is unusable: %w", err)
	}
	if _, err := wafLoadPack(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	old := wafEng()
	dir := repoCache(r)
	if bad, err := readCachedIndex(r); err == nil {
		if err := writeFileAtomic(wafHoldPath(), []byte(strconv.FormatInt(bad.Serial, 10)+"\n"), 0600); err != nil {
			return nil, err
		}
	}
	gone := dir + ".rolledback"
	_ = os.RemoveAll(gone)
	if err := os.Rename(dir, gone); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Rename(prev, dir); err != nil {
		_ = os.Rename(gone, dir)
		return nil, err
	}
	_ = os.RemoveAll(gone)
	// The directory's own modification time is what running gateways watch: touch the index.
	now := time.Now()
	_ = os.Chtimes(filepath.Join(dir, "index.json"), now, now)
	if _, err := wafLoadPack(); err != nil {
		return nil, err
	}
	cur := wafEng()
	res := &wafUpdateResult{Pack: cur.pack, Rules: len(cur.rules), Changed: true}
	res.Added, res.Updated, res.Removed = wafDiff(old, cur)
	return res, nil
}

// ---- running gateway: hot reload, auto-update, cluster epoch ----

// wafPackLoop keeps a gateway's rules current until ctx ends. Every second it checks whether the
// cached pack changed (an administrator ran `waf update`, or this loop did) and, if so, installs
// it and calls changed so the gateway rebuilds the routes that use the WAF. Once a day, with
// jitter, and at once when the cluster epoch moves, it fetches a newer pack.
func (g *gatewayServer) wafPackLoop(ctx context.Context, changed func()) {
	stamp := wafCacheStamp()
	var epoch int64 // starts at zero: a node that was down when the epoch moved catches up when it starts
	next := time.Now().Add(wafAutoDelay(stamp == ""))
	var busy atomic.Bool
	fetch := func(reason string) {
		if !busy.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer busy.Store(false)
			_, err := wafUpdate(false, false)
			switch {
			case err != nil:
				g.metrics.wafUpdates[1].Add(1)
				fmt.Printf("[gateway] WAF rule update (%s): %v\n", reason, err)
			default:
				g.metrics.wafUpdates[0].Add(1)
			}
		}()
	}
	built := wafEng().pack.Digest // the rules the routes were last built with
	apply := func() {
		_, err := wafLoadPack()
		if err != nil {
			g.metrics.wafUpdates[2].Add(1)
			fmt.Printf("[gateway] WAF rules not loaded, keeping %s %s: %v\n", wafEng().pack.Name, wafEng().pack.Version, err)
			alertf("medium", "gateway", "WAF rule pack could not be loaded", map[string]any{"error": err.Error()})
			return
		}
		// The engine may already be new: this loop's own fetch installs it. What matters is
		// whether the routes were built with it.
		if e := wafEng(); e.pack.Digest != built {
			built = e.pack.Digest
			fmt.Printf("[gateway] WAF rules: %s %s (%d rules, source %s)\n", e.pack.Name, e.pack.Version, len(e.rules), e.pack.Source)
			changed()
		}
	}
	apply() // the cache written before this process started
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if s := wafCacheStamp(); s != stamp {
				stamp = s
				apply()
			}
			set := g.settings.Load()
			if set == nil || g.draining.Load() {
				continue
			}
			if set.wafEpoch != 0 && set.wafEpoch != epoch {
				epoch = set.wafEpoch
				fetch("cluster update")
				next = now.Add(wafAutoDelay(false))
			} else if set.wafAuto && now.After(next) {
				fetch("daily check")
				next = now.Add(wafAutoDelay(false))
			}
		}
	}
}

// wafAutoDelay is the wait before the next check: a day plus or minus an hour, so a fleet does
// not ask in the same minute. A host with no cached pack asks soon after it starts.
func wafAutoDelay(soon bool) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(2*time.Hour)))
	if err != nil {
		return wafAutoInterval
	}
	if soon {
		return time.Minute + time.Duration(n.Int64())/60
	}
	return wafAutoInterval - time.Hour + time.Duration(n.Int64())
}

// bumpWAFEpoch tells every gateway node of a cluster to fetch the new pack now. On a host that is
// not a cluster master it does nothing: the local gateway watches the cache itself.
func bumpWAFEpoch() error {
	s, err := gatewayStore()
	if err != nil {
		return nil // a worker: the master's gateway settings are not ours to change
	}
	if _, ok := s.(clusterRouteStore); !ok {
		return nil
	}
	return s.update(func(d *gatewayData) error { d.Settings.WAFPackEpoch = time.Now().UnixMilli(); return nil })
}

// ---- status ----

type wafStatus struct {
	InUse    wafPackInfo  `json:"in_use"`
	Rules    int          `json:"rules"`
	Staged   []string     `json:"staged,omitempty"` // rules at the detect stage
	Disabled []string     `json:"disabled,omitempty"`
	Retired  int          `json:"retired"`
	Cached   *wafPackInfo `json:"cached,omitempty"`
	Previous bool         `json:"previous_pack"` // a rollback is possible
	Held     int64        `json:"held_serial,omitempty"`
	Error    string       `json:"error,omitempty"`
}

func wafStatusNow() wafStatus {
	st := wafStatus{}
	if _, err := wafLoadPack(); err != nil {
		st.Error = err.Error()
	}
	e := wafEng()
	st.InUse, st.Rules, st.Retired = e.pack, len(e.rules), len(e.retired)
	for _, r := range e.rules {
		switch r.Stage {
		case wafStageDetect:
			st.Staged = append(st.Staged, r.ID)
		case wafStageOff:
			st.Disabled = append(st.Disabled, r.ID)
		}
	}
	if _, err := readIndexAt(wafRepo(), wafPrevDir()); err == nil {
		st.Previous = true
	}
	st.Held = readWAFHold()
	if idx, err := readCachedIndex(wafRepo()); err == nil {
		st.Cached = &wafPackInfo{Name: wafPackName, Serial: idx.Serial, Source: "catalog", Expires: idx.Expires.UTC().Format(time.RFC3339)}
	}
	return st
}

// wafTestFile checks a pack file the way CI and a host do, and reports what it holds.
func wafTestFile(path string, out io.Writer) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	p, err := decodeWAFPack(b, true)
	if err != nil {
		return err
	}
	e, err := wafBuild(p, wafPackInfo{Source: "file"})
	if err != nil {
		return err
	}
	samples := 0
	for _, r := range e.rules {
		if r.Tests != nil {
			samples += len(r.Tests.Match) + len(r.Tests.NoMatch)
		}
	}
	fmt.Fprintf(out, "✓ %s %s: %d rules, %d samples pass\n", p.Name, p.Version, len(e.rules), samples)
	return nil
}

// wafPackCheck is the catalog checker for kind "waf" (CI of ziro-os/pkgs).
func wafPackCheck(b []byte) (CatalogEntry, error) {
	p, err := decodeWAFPack(b, true)
	if err != nil {
		return CatalogEntry{}, err
	}
	if _, err := wafBuild(p, wafPackInfo{Source: "file"}); err != nil {
		return CatalogEntry{}, err
	}
	return CatalogEntry{Name: p.Name, Version: p.Version, Description: fmt.Sprintf("%d WAF rules", len(p.Rules))}, nil
}

func init() {
	catalogCheckers["waf"] = wafPackCheck
}

func jsonString(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

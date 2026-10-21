package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/catalog"
)

// wafHarness serves a signed WAF catalog from a temporary directory and points the official WAF
// repository at it. Each publish gets a later serial, as CI's would.
type wafHarness struct {
	t     *testing.T
	dir   string
	priv  []byte
	clock time.Time
}

func newWAFHarness(t *testing.T) *wafHarness {
	stubModules(t)
	pub, priv := testCatalogKey(t)
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(srv.Close)
	oldHTTP, oldRepos, oldNow := catalogHTTP, officialRepos, catalogNow
	h := &wafHarness{t: t, dir: dir, priv: priv, clock: time.Now().Add(-time.Hour)}
	catalogHTTP = srv.Client()
	officialRepos = []CatalogRepo{{Name: wafRepoName, URL: srv.URL, Kind: "waf", Key: pub, Official: true}}
	catalogNow = func() time.Time { return h.clock }
	wafCur.Store(nil)
	t.Cleanup(func() {
		catalogHTTP, officialRepos, catalogNow = oldHTTP, oldRepos, oldNow
		wafCur.Store(nil)
	})
	return h
}

// basePack is the built-in rules as a pack named like the catalog's, at a version.
func basePack(version string, mod func(*wafPackFile)) *wafPackFile {
	var p wafPackFile
	_ = json.Unmarshal(wafBuiltinJSON, &p)
	p.Name, p.Version = wafPackName, version
	if mod != nil {
		mod(&p)
	}
	return &p
}

func (h *wafHarness) publishWith(p *wafPackFile, check func([]byte) (CatalogEntry, error)) {
	h.t.Helper()
	h.clock = h.clock.Add(time.Minute)
	src := h.t.TempDir()
	path := filepath.Join(src, "waf", p.Name, "rules.json")
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	b, _ := json.Marshal(p)
	_ = os.WriteFile(path, b, 0644)
	_ = os.RemoveAll(filepath.Join(h.dir, "rules"))
	if _, err := catalog.Build(src, h.dir, wafRepoName, "waf", 24*time.Hour, h.clock, check); err != nil {
		h.t.Fatal(err)
	}
	if err := catalog.Sign(h.dir, h.priv); err != nil {
		h.t.Fatal(err)
	}
}

// publish builds a pack the way CI does: through the checker, which refuses a bad one.
func (h *wafHarness) publish(p *wafPackFile) {
	h.t.Helper()
	h.publishWith(p, catalogCheckers["waf"])
}

// publishUnchecked signs a pack without the CI check, to test what a host does with one.
func (h *wafHarness) publishUnchecked(p *wafPackFile) {
	h.t.Helper()
	h.publishWith(p, func([]byte) (CatalogEntry, error) {
		return CatalogEntry{Name: p.Name, Version: p.Version}, nil
	})
}

var evilRule = wafRuleDef{ID: "ZW-999001", Group: "rce", Level: 1, Score: 5, Msg: "Test: evilmagic", Targets: []string{"args"},
	Needles: []string{"evilmagic"}, Re: `evilmagic\d+`, Tests: &wafRuleTests{Match: []string{"x evilmagic42"}, NoMatch: []string{"evilmagic"}}}

func withRule(r wafRuleDef) func(*wafPackFile) {
	return func(p *wafPackFile) { p.Rules = append(p.Rules, r) }
}

func wafBlocks(t *testing.T, target string) bool {
	t.Helper()
	p, err := newWAFPolicy(&GatewayWAF{Mode: "block"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://x.test"+target, nil)
	v := p.inspect(r, "198.51.100.1", nil, false)
	return p.action(&v) == wafBlocked
}

func TestWAFPackUpdateRollbackAndHold(t *testing.T) {
	h := newWAFHarness(t)
	if wafEng().pack.Source != "builtin" {
		t.Fatal("a host with no pack uses the built-in rules")
	}
	if wafBlocks(t, "/?q=evilmagic42") {
		t.Fatal("the rule is not there yet")
	}

	h.publish(basePack("1", withRule(evilRule)))
	res, err := wafUpdate(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || strings.Join(res.Added, ",") != "ZW-999001" || res.Pack.Source != "catalog" || res.Pack.Version != "1" {
		t.Fatalf("update: %+v", res)
	}
	if !wafBlocks(t, "/?q=evilmagic42") {
		t.Fatal("the new rule must block")
	}
	if res, err := wafUpdate(false, false); err != nil || res.Changed {
		t.Fatalf("a second update with nothing new: %+v %v", res, err)
	}

	// A new version changes the rule and drops it from block to detect (a staged rule).
	staged := evilRule
	staged.Stage = wafStageDetect
	h.publish(basePack("2", withRule(staged)))
	if res, err = wafUpdate(true, false); err != nil || res.Changed || res.Available != "2" {
		t.Fatalf("--check must report and change nothing: %+v %v", res, err)
	}
	if res, err = wafUpdate(false, false); err != nil || strings.Join(res.Updated, ",") != "ZW-999001" {
		t.Fatalf("update 2: %+v %v", res, err)
	}
	if wafBlocks(t, "/?q=evilmagic42") {
		t.Fatal("a staged rule must not block")
	}
	st := wafStatusNow()
	if !st.Previous || len(st.Staged) != 1 || st.Staged[0] != "ZW-999001" {
		t.Fatalf("status: %+v", st)
	}

	// Rollback returns to version 1, and the daily update does not undo it.
	if res, err = wafRollback(); err != nil || res.Pack.Version != "1" {
		t.Fatalf("rollback: %+v %v", res, err)
	}
	if !wafBlocks(t, "/?q=evilmagic42") {
		t.Fatal("version 1 blocks")
	}
	if res, err = wafUpdate(false, false); err != nil || res.Held == "" || res.Pack.Version != "1" {
		t.Fatalf("a rolled-back pack must be held: %+v %v", res, err)
	}
	if _, err = wafRollback(); err == nil {
		t.Fatal("there is nothing older to return to")
	}
	// A newer pack is installed, and the hold ends.
	h.publish(basePack("3", withRule(evilRule)))
	if res, err = wafUpdate(false, false); err != nil || res.Pack.Version != "3" || res.Held != "" {
		t.Fatalf("a newer pack: %+v %v", res, err)
	}
	if readWAFHold() != 0 {
		t.Error("the hold must end when a newer pack is installed")
	}
}

func TestWAFPackRefusesBadPacks(t *testing.T) {
	h := newWAFHarness(t)
	h.publish(basePack("good", withRule(evilRule)))
	if _, err := wafUpdate(false, false); err != nil {
		t.Fatal(err)
	}
	good := wafEng()

	bad := map[string]func(*wafPackFile){
		"expression that does not compile": func(p *wafPackFile) { p.Rules[0].Re = `(` },
		"expression that matches nothing":  func(p *wafPackFile) { p.Rules[0].Re = `x*` },
		"sample the rule fails":            func(p *wafPackFile) { p.Rules[0].Tests = &wafRuleTests{Match: []string{"harmless"}} },
		"sample the rule must not match":   func(p *wafPackFile) { p.Rules[0].Tests = &wafRuleTests{NoMatch: []string{"1 union select 2"}} },
		"missing protocol rule": func(p *wafPackFile) {
			for i, r := range p.Rules {
				if r.ID == "ZW-920100" {
					p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
					return
				}
			}
		},
		"protocol rule with an expression": func(p *wafPackFile) {
			for i, r := range p.Rules {
				if r.ID == "ZW-920100" {
					p.Rules[i].Re, p.Rules[i].Needles, p.Rules[i].Targets = ".", []string{"a"}, []string{"path"}
				}
			}
		},
		"duplicate ID":       func(p *wafPackFile) { p.Rules = append(p.Rules, p.Rules[0]) },
		"unknown group":      func(p *wafPackFile) { p.Rules[0].Group = "nonsense" },
		"upper-case needle":  func(p *wafPackFile) { p.Rules[0].Needles = []string{"UNION"} },
		"score out of range": func(p *wafPackFile) { p.Rules[0].Score = 9 },
		"too many rules": func(p *wafPackFile) {
			for i := 0; len(p.Rules) <= wafMaxRules; i++ {
				r := evilRule
				r.ID = fmt.Sprintf("ZW-99%04d", i)
				p.Rules = append(p.Rules, r)
			}
		},
		"retired and present": func(p *wafPackFile) { p.Retired = []string{p.Rules[0].ID} },
	}
	for name, mod := range bad {
		h.publishUnchecked(basePack("bad", mod))
		if _, err := wafUpdate(false, false); err == nil {
			t.Errorf("%s: installed", name)
		}
		if wafEng() != good {
			t.Errorf("%s: the engine in use changed", name)
		}
		if _, err := wafLoadPack(); err != nil || wafEng() != good {
			t.Errorf("%s: the cache no longer holds the good pack: %v", name, err)
		}
	}

	// An older index than the one installed is a rollback attack.
	h.publish(basePack("replay", nil))
	h.clock = h.clock.Add(-48 * time.Hour)
	h.publish(basePack("old", nil))
	if _, err := wafUpdate(false, false); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Errorf("an older serial: %v", err)
	}
}

func TestWAFPackTamperedCacheKeepsEngine(t *testing.T) {
	h := newWAFHarness(t)
	h.publish(basePack("1", withRule(evilRule)))
	if _, err := wafUpdate(false, false); err != nil {
		t.Fatal(err)
	}
	cur := wafEng()
	entry := filepath.Join(repoCache(wafRepo()), "entries", "rules", wafPackName+".json")
	b, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, bytes.Replace(b, []byte("evilmagic"), []byte("goodmagic"), -1), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := wafLoadPack(); err == nil || !strings.Contains(err.Error(), "signed index") {
		t.Fatalf("a modified cache must be refused: %v", err)
	}
	if wafEng() != cur {
		t.Fatal("the engine in use must not change")
	}
	// Removing the cache returns the host to the built-in rules.
	if err := os.RemoveAll(repoCache(wafRepo())); err != nil {
		t.Fatal(err)
	}
	if changed, err := wafLoadPack(); err != nil || !changed || wafEng().pack.Source != "builtin" {
		t.Fatalf("no cache: %v %v %s", changed, err, wafEng().pack.Source)
	}
}

func TestWAFStagesAndProtocolMetadata(t *testing.T) {
	h := newWAFHarness(t)
	off := evilRule
	off.ID, off.Stage, off.Needles, off.Re = "ZW-999002", wafStageOff, []string{"offmagic"}, `offmagic`
	off.Tests = nil
	det := evilRule
	det.ID, det.Stage, det.Needles, det.Re = "ZW-999003", wafStageDetect, []string{"detmagic"}, `detmagic`
	det.Tests = nil
	h.publish(basePack("1", func(p *wafPackFile) {
		p.Rules = append(p.Rules, off, det)
		for i, r := range p.Rules { // metadata of a protocol rule may change; its logic may not
			if r.ID == "ZW-920110" {
				p.Rules[i].Score = scoreNotice
			}
		}
	}))
	if _, err := wafUpdate(false, false); err != nil {
		t.Fatal(err)
	}
	p, _ := newWAFPolicy(&GatewayWAF{Mode: "block"})
	scan := func(target string) wafVerdict {
		return p.inspect(httptest.NewRequest("GET", "http://x.test"+target, nil), "198.51.100.1", nil, false)
	}
	if v := scan("/?q=offmagic"); v.n != 0 {
		t.Errorf("a rule that is off ran: %v", v.ids[:v.n])
	}
	if v := scan("/?q=detmagic"); !hasID(v, "ZW-999003") || v.score != 0 || p.action(&v) != wafLogged {
		t.Errorf("a staged rule is logged and scores nothing: %v score %d", v.ids[:v.n], v.score)
	}
	if v := p.inspect(httptest.NewRequest("TRACE", "http://x.test/", nil), "198.51.100.1", nil, false); !hasID(v, "ZW-920110") || v.score != scoreNotice {
		t.Errorf("protocol rule metadata: %v score %d", v.ids[:v.n], v.score)
	}
}

func TestWAFMatcherIsUsedOnlyWithItsOwnExpression(t *testing.T) {
	e := wafEng()
	if e.rules[e.index["ZW-932100"]].fn == nil {
		t.Fatal("the built-in expression must use the hand-written matcher")
	}
	p := basePack("1", func(p *wafPackFile) {
		for i, r := range p.Rules {
			if r.ID == "ZW-932100" {
				p.Rules[i].Re = r.Re + `|zzz`
				p.Rules[i].Tests = nil
			}
		}
	})
	e2, err := wafBuild(p, wafPackInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if e2.rules[e2.index["ZW-932100"]].fn != nil {
		t.Fatal("a changed expression must not be replaced by the old matcher")
	}
}

func TestWAFPackValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		json string
		ok   bool
	}{
		"builtin":       {string(wafBuiltinJSON), true},
		"trailing":      {string(wafBuiltinJSON) + " {}", false},
		"empty":         {`{"schema":1,"name":"x","version":"1","rules":[]}`, false},
		"schema":        {`{"schema":2,"name":"x","version":"1","rules":[]}`, false},
		"not json":      {`<html>`, false},
		"unknown field": {strings.Replace(string(wafBuiltinJSON), `"rules"`, `"extra": 1, "rules"`, 1), false}, // strict (CI) mode
	} {
		_, err := decodeWAFPack([]byte(tc.json), true)
		if err == nil {
			var p *wafPackFile
			p, _ = decodeWAFPack([]byte(tc.json), true)
			err = validateWAFPack(p)
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A host accepts fields a newer pack adds.
	if _, err := decodeWAFPack([]byte(strings.Replace(string(wafBuiltinJSON), `"rules"`, `"extra": 1, "rules"`, 1)), false); err != nil {
		t.Errorf("a host must ignore unknown fields: %v", err)
	}
}

// Rules are swapped while requests are inspected; run with -race.
func TestWAFEngineSwapUnderLoad(t *testing.T) {
	a, err := wafBuild(basePack("a", nil), wafPackInfo{Digest: "a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := wafBuild(basePack("b", withRule(evilRule)), wafPackInfo{Digest: "b"})
	if err != nil {
		t.Fatal(err)
	}
	wafCur.Store(a)
	t.Cleanup(func() { wafCur.Store(nil) })
	var stop atomic.Bool
	var wg sync.WaitGroup
	var blocked atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				p, _ := newWAFPolicy(&GatewayWAF{Mode: "block"})
				r := httptest.NewRequest("GET", "http://x.test/?q=1+union+select+2", nil)
				if v := p.inspect(r, "198.51.100.1", nil, false); p.action(&v) == wafBlocked {
					blocked.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		wafCur.Store([]*wafEngine{a, b}[i%2])
		time.Sleep(time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if blocked.Load() == 0 {
		t.Error("nothing was blocked")
	}
}

// A gateway picks up a new pack without a restart, rebuilds the routes that use the WAF, and
// keeps the ones that do not.
func TestGatewayReloadsRoutesOnNewPack(t *testing.T) {
	h := newWAFHarness(t)
	up := echoUpstream(t, "A", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	g := fwServer(t, GatewaySettings{},
		rs(GatewayRoute{Name: "w", Hosts: []string{"w.test"}, WAF: &GatewayWAF{Mode: "block"}}, up),
		rs(GatewayRoute{Name: "plain", Hosts: []string{"p.test"}}, up))
	cfg := g.tbl.Load().cfg
	handler := g.handler(false)
	if w := fwDo(handler, fwReq{target: "/?q=evilmagic42"}); w.Code != 200 {
		t.Fatalf("before the pack: %d", w.Code)
	}
	before := map[string]*gwRoute{}
	for _, r := range g.tbl.Load().all {
		before[r.Name] = r
	}

	h.publish(basePack("1", withRule(evilRule)))
	if _, err := wafUpdate(false, false); err != nil {
		t.Fatal(err)
	}
	if err := g.load(cfg); err != nil {
		t.Fatal(err)
	}
	if w := fwDo(handler, fwReq{target: "/?q=evilmagic42"}); w.Code != 403 {
		t.Fatalf("after the pack: %d", w.Code)
	}
	for _, r := range g.tbl.Load().all {
		switch {
		case r.Name == "w" && r == before["w"]:
			t.Error("the WAF route must be rebuilt for the new rules")
		case r.Name == "plain" && r != before["plain"]:
			t.Error("a route without a WAF must be carried over")
		}
	}
	if m := g.metricsText(); !strings.Contains(m, `zirogate_waf_pack_info{pack="zirogate-crs",version="1",source="catalog"} 1`) {
		t.Errorf("metrics lack the pack:\n%s", m)
	}
}

// The gateway's own loop installs a pack an administrator fetched, and fetches on a cluster update.
func TestGatewayWAFPackLoop(t *testing.T) {
	h := newWAFHarness(t)
	h.publish(basePack("1", nil))
	g := newGatewayServer()
	g.log = func(any) {}
	if err := g.load(&GatewayConfig{}); err != nil {
		t.Fatal(err)
	}
	var changed atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.wafPackLoop(ctx, func() { changed.Add(1) }); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// Nothing is cached yet: the loop asks soon after it starts (a cluster epoch change asks at once).
	cfg := GatewayConfig{Settings: GatewaySettings{WAFPackEpoch: 1}}
	if err := g.load(&cfg); err != nil {
		t.Fatal(err)
	}
	gwWaitFor(t, func() bool { return changed.Load() >= 1 && wafEng().pack.Version == "1" })

	// An administrator updates (here: this test); the loop notices the new cache.
	h.publish(basePack("2", withRule(evilRule)))
	if _, err := wafUpdate(false, false); err != nil {
		t.Fatal(err)
	}
	gwWaitFor(t, func() bool { return changed.Load() >= 2 && wafEng().pack.Version == "2" })

	// A cluster master bumps the epoch: the node fetches by itself.
	h.publish(basePack("3", withRule(evilRule)))
	cfg.Settings.WAFPackEpoch = 2
	if err := g.load(&cfg); err != nil {
		t.Fatal(err)
	}
	gwWaitFor(t, func() bool { return wafEng().pack.Version == "3" })
	if g.metrics.wafUpdates[0].Load() == 0 {
		t.Error("the fetch was not counted")
	}
}

func TestWAFCommands(t *testing.T) {
	h := newWAFHarness(t)
	h.publish(basePack("1", withRule(evilRule)))
	var out bytes.Buffer
	file := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(file, wafBuiltinJSON, 0644); err != nil {
		t.Fatal(err)
	}
	if err := wafTestFile(file, "", &out); err != nil || !strings.Contains(out.String(), "rules") {
		t.Fatalf("waf test: %v %q", err, out.String())
	}
	if err := os.WriteFile(file, bytes.Replace(wafBuiltinJSON, []byte(`"nomatch": ["union station timetable"]`), []byte(`"nomatch": ["1 union select 2"]`), 1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := wafTestFile(file, "", &out); err == nil || !strings.Contains(err.Error(), "ZW-942100") {
		t.Fatalf("a failing sample must fail the test: %v", err)
	}
	if err := gatewayWAFUpdateCmd.RunE(gatewayWAFUpdateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if st := wafStatusNow(); st.InUse.Version != "1" || st.Cached == nil {
		t.Fatalf("status: %+v", st)
	}
}

func TestWAFBenignCorpusCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("# legitimate\n/search?q=union+station\n/\tMozilla/5.0 (X11; Linux x86_64) Firefox/126.0\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("/search?q=1+union+select+2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := wafTestBenign(wafEng(), good, &out); err != nil || !strings.Contains(out.String(), "2 legitimate") {
		t.Fatalf("good corpus: %v %q", err, out.String())
	}
	if err := wafTestBenign(wafEng(), bad, &out); err == nil || !strings.Contains(err.Error(), "ZW-942100") {
		t.Fatalf("a corpus the rules block must fail: %v", err)
	}
}

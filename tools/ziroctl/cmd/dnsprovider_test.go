package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- an in-memory provider ----

type fakeDNS struct {
	mu      sync.Mutex
	zones   []DNSZone
	recs    map[string][]DNSRec
	next    int
	calls   []string
	failOn  string // "create example.com A" style: the call fails
	zonesFn func() ([]DNSZone, error)
}

func newFakeDNS(zones ...string) *fakeDNS {
	f := &fakeDNS{recs: map[string][]DNSRec{}}
	for _, z := range zones {
		f.zones = append(f.zones, DNSZone{ID: "z-" + z, Name: z})
	}
	return f
}

func (f *fakeDNS) Zones() ([]DNSZone, error) {
	if f.zonesFn != nil {
		return f.zonesFn()
	}
	return f.zones, nil
}

func (f *fakeDNS) List(zone string) ([]DNSRec, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "list "+zone)
	return append([]DNSRec(nil), f.recs[zone]...), nil
}

func (f *fakeDNS) Upsert(zone string, r DNSRec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	verb := "create"
	if r.ID != "" {
		verb = "update"
	}
	key := fmt.Sprintf("%s %s %s", verb, r.Name, r.Type)
	f.calls = append(f.calls, key)
	if f.failOn == key {
		return errors.New("provider said no")
	}
	if r.ID == "" {
		f.next++
		r.ID = fmt.Sprintf("id%d", f.next)
		f.recs[zone] = append(f.recs[zone], r)
		return nil
	}
	for i := range f.recs[zone] {
		if f.recs[zone][i].ID == r.ID {
			f.recs[zone][i] = r
			return nil
		}
	}
	return errors.New("no such record")
}

func (f *fakeDNS) Delete(zone, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "delete "+id)
	kept := f.recs[zone][:0]
	for _, r := range f.recs[zone] {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	f.recs[zone] = kept
	return nil
}

func (f *fakeDNS) seed(zone string, r DNSRec) string {
	f.next++
	r.ID = fmt.Sprintf("seed%d", f.next)
	f.recs[zone] = append(f.recs[zone], r)
	return r.ID
}

func (f *fakeDNS) names(zone string) []string {
	var out []string
	for _, r := range f.recs[zone] {
		out = append(out, r.Name+" "+r.Type+" "+r.Content)
	}
	slices.Sort(out)
	return out
}

func (f *fakeDNS) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "list ") {
			out = append(out, c)
		}
	}
	return out
}

// dnsEnv isolates the stores and returns a standalone route store whose gateway answers on addr.
func dnsEnv(t *testing.T, fake DNSProvider, addr string) localRouteStore {
	t.Helper()
	root := t.TempDir()
	oldFactory, oldHost := dnsProviderFactory, hostAddrs
	oldLocal, oldDir, oldStatus, oldAudit, oldCluster := gatewayLocalDir, dnsProviderDir, dnsStatusDir, auditPath, clusterDir
	oldAlertCfg, oldSpool, oldDNSConf := alertConfigPath, alertSpoolDir, dnsConfigPath
	dnsConfigPath = filepath.Join(root, "dns.json") // setting a base domain also writes the built-in DNS records
	gatewayLocalDir, dnsProviderDir, dnsStatusDir = filepath.Join(root, "gw"), filepath.Join(root, "tokens"), filepath.Join(root, "status")
	auditPath, clusterDir = filepath.Join(root, "audit.log"), filepath.Join(root, "cluster")
	alertConfigPath, alertSpoolDir = filepath.Join(root, "alerting.json"), filepath.Join(root, "spool")
	dnsProviderFactory = func(DNSProviderConf, string) (DNSProvider, error) { return fake, nil }
	hostAddrs = func() []HostAddress { return []HostAddress{{IP: addr}} }
	t.Cleanup(func() {
		dnsProviderFactory, hostAddrs = oldFactory, oldHost
		gatewayLocalDir, dnsProviderDir, dnsStatusDir, auditPath, clusterDir = oldLocal, oldDir, oldStatus, oldAudit, oldCluster
		alertConfigPath, alertSpoolDir, dnsConfigPath = oldAlertCfg, oldSpool, oldDNSConf
	})
	return localRouteStore{dir: gatewayLocalDir}
}

func addProvider(t *testing.T, s routeStore, name string, zones ...string) {
	t.Helper()
	if _, _, err := dnsProviderAdd(s, name, dnsKindCloudflare, "tok-"+name, zones); err != nil {
		t.Fatal(err)
	}
}

func setRoutes(t *testing.T, s routeStore, domain string, hosts ...string) {
	t.Helper()
	if err := s.update(func(d *gatewayData) error {
		d.Domain = GatewayDomain{Name: domain}
		d.Routes = nil
		for i, h := range hosts {
			d.Routes = append(d.Routes, GatewayRoute{Name: fmt.Sprintf("r%d", i), Hosts: []string{h}, To: []GatewayUpstream{{Address: "127.0.0.1:8080"}}, TLS: "off"})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ---- derived records ----

func TestDesiredRecordsFromGateway(t *testing.T) {
	s := dnsEnv(t, newFakeDNS("example.com"), "203.0.113.10")
	addProvider(t, s, "cf")
	_ = s.update(func(d *gatewayData) error {
		d.Domain = GatewayDomain{Name: "apps.example.com"}
		d.Routes = []GatewayRoute{
			{Name: "web", Hosts: []string{"web.apps.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}},  // covered by the wildcard
			{Name: "deep", Hosts: []string{"a.b.apps.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}}, // two labels: not covered
			{Name: "www", Hosts: []string{"www.example.com", "*.shop.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}},
			{Name: "db", Kind: "tcp", Listen: 5432, To: []GatewayUpstream{{Address: "127.0.0.1:5432"}}},                       // no host
			{Name: "lan", Hosts: []string{"nas.home.lan"}, To: []GatewayUpstream{{Address: "127.0.0.1:80"}}, TLS: "internal"}, // private: built-in DNS
		}
		d.DNSCloud.Records = []DNSCloudRecord{{Name: "TXT.Example.com.", Type: "txt", Content: "hello"}}
		return nil
	})
	d, _ := s.read()
	recs, warns := dnsDesired(s, d)
	var got []string
	for _, r := range recs {
		got = append(got, r.Name+" "+r.Type+" "+r.Content)
	}
	want := []string{
		"*.apps.example.com A 203.0.113.10",
		"*.shop.example.com A 203.0.113.10",
		"a.b.apps.example.com A 203.0.113.10",
		"www.example.com A 203.0.113.10",
	}
	// explicit records pass through validation in dnsRecordAdd; here the raw entry is normalised too
	want = append(want, "txt.example.com TXT hello")
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("desired records\n got %v\nwant %v", got, want)
	}
	if len(warns) != 0 {
		t.Fatalf("a public address needs no warning: %v", warns)
	}
	for _, r := range recs {
		if r.Proxied || r.TTL != dnsDefaultTTL {
			t.Fatalf("derived records are DNS-only with the default TTL (ACME HTTP-01 must still reach the gateway): %+v", r)
		}
	}
}

func TestDesiredRecordsAddressesAndWarnings(t *testing.T) {
	s := dnsEnv(t, newFakeDNS("example.com"), "10.0.0.5")
	addProvider(t, s, "cf")
	setRoutes(t, s, "apps.example.com")
	d, _ := s.read()
	recs, warns := dnsDesired(s, d)
	if len(recs) != 1 || recs[0].Content != "10.0.0.5" || len(warns) != 1 || !strings.Contains(warns[0], "private address") {
		t.Fatalf("a private gateway address is published with a warning: %v %v", recs, warns)
	}

	if err := dnsAddressesSet(s, []string{"203.0.113.7", "2001:db8::7", "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.read()
	recs, warns = dnsDesired(s, d)
	var got []string
	for _, r := range recs {
		got = append(got, r.Type+" "+r.Content)
	}
	if !slices.Equal(got, []string{"AAAA 2001:db8::7", "A 203.0.113.7"}) || len(warns) != 0 {
		t.Fatalf("explicit addresses replace the node's own, once each, A and AAAA: %v %v", got, warns)
	}
	if dnsAddressesSet(s, []string{"not-an-ip"}) == nil {
		t.Fatal("an invalid address must be refused")
	}

	hostAddrs = func() []HostAddress { return nil }
	_ = dnsAddressesSet(s, nil)
	d, _ = s.read()
	recs, warns = dnsDesired(s, d)
	if len(recs) != 0 || len(warns) != 1 || !strings.Contains(warns[0], "no gateway address") {
		t.Fatalf("no address: nothing to publish, and say so: %v %v", recs, warns)
	}
}

// ---- plan and apply ----

func TestSyncCreatesOnlyWhatIsMissingAndMarksOwnership(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	setRoutes(t, s, "apps.example.com", "www.example.com")

	plan, err := dnsSyncOnce(s, false, true)
	if err != nil || plan.count("create") != 2 || plan.Changes() != 2 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if len(f.mutations()) != 0 {
		t.Fatalf("a dry run changes nothing: %v", f.mutations())
	}

	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"*.apps.example.com A 203.0.113.10", "www.example.com A 203.0.113.10"}) {
		t.Fatalf("records at the provider: %v", got)
	}
	for _, r := range f.recs["z-example.com"] {
		if r.Comment != dnsMarker() || r.Proxied {
			t.Fatalf("every record carries the ownership comment and is not proxied: %+v", r)
		}
	}
	before := len(f.mutations())
	plan, err = dnsSyncOnce(s, false, false)
	if err != nil || plan.Changes() != 0 || len(f.mutations()) != before {
		t.Fatalf("a second sync is a no-op: %+v %v", plan, f.mutations())
	}
	st, ok := readDNSStatus()
	if !ok || !st.OK || st.Created != 0 {
		t.Fatalf("status of the last sync: %+v", st)
	}
	log, _ := os.ReadFile(auditPath)
	if strings.Count(string(log), "dns create") != 2 || !strings.Contains(string(log), "*.apps.example.com A 203.0.113.10 (cf)") {
		t.Fatalf("every change is audited:\n%s", log)
	}
}

func TestSyncNeverTouchesForeignRecords(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	foreignA := f.seed("z-example.com", DNSRec{Name: "www.example.com", Type: "A", Content: "198.51.100.1", Comment: "mine"})
	f.seed("z-example.com", DNSRec{Name: "mail.example.com", Type: "A", Content: "198.51.100.2"}) // no comment at all
	f.seed("z-example.com", DNSRec{Name: "old.example.com", Type: "A", Content: "198.51.100.3", Comment: "ziro:some-other-cluster"})
	f.seed("z-example.com", DNSRec{Name: "docs.example.com", Type: "CNAME", Content: "x.pages.dev"})
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.example.com", Type: "TXT", Content: "tok", Comment: "ziro-acme:" + dnsOwner()})
	f.seed("z-example.com", DNSRec{Name: "_acme-challenge.apps.example.com", Type: "TXT", Content: "tok2", Comment: dnsMarker()}) // even ours: protected
	setRoutes(t, s, "", "www.example.com", "docs.example.com", "new.example.com")

	plan, err := dnsSyncOnce(s, false, false)
	if err != nil {
		t.Fatalf("%v\n%+v", err, plan)
	}
	if plan.count("create") != 1 || plan.count("skip") != 2 || plan.count("delete") != 0 || plan.count("update") != 0 {
		t.Fatalf("one create (new), two skips (foreign A, foreign CNAME), nothing deleted or updated: %+v", plan.Items)
	}
	for _, it := range plan.Items {
		if it.Action == "skip" && !strings.Contains(it.Reason, "not ziro's") {
			t.Fatalf("a skip says why: %+v", it)
		}
	}
	if got := f.mutations(); len(got) != 1 || got[0] != "create new.example.com A" {
		t.Fatalf("exactly one provider call: %v", got)
	}
	for _, r := range f.recs["z-example.com"] {
		if r.ID == foreignA && (r.Content != "198.51.100.1" || r.Comment != "mine") {
			t.Fatalf("a foreign record was modified: %+v", r)
		}
	}
	if len(f.recs["z-example.com"]) != 7 {
		t.Fatalf("nothing foreign was deleted: %v", f.names("z-example.com"))
	}
}

func TestSyncUpdatesAndDeletesOwnedRecords(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	me := dnsMarker()
	stale := f.seed("z-example.com", DNSRec{Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300, Comment: me}) // gateway moved
	gone := f.seed("z-example.com", DNSRec{Name: "gone.example.com", Type: "A", Content: "192.0.2.2", TTL: 300, Comment: me}) // route deleted
	ttl := f.seed("z-example.com", DNSRec{Name: "ttl.example.com", Type: "A", Content: "203.0.113.10", TTL: 1, Comment: me})  // right address, TTL edited at the provider
	setRoutes(t, s, "", "www.example.com", "ttl.example.com")

	plan, _ := dnsSyncOnce(s, false, true)
	if plan.count("update") != 2 || plan.count("delete") != 1 || plan.count("create") != 0 {
		t.Fatalf("plan: %+v", plan.Items)
	}
	for _, it := range plan.Items {
		if it.Action == "update" && it.Name == "www.example.com" && it.Was != "192.0.2.1" {
			t.Fatalf("an update shows the old content: %+v", it)
		}
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.recs["z-example.com"] {
		switch r.ID {
		case stale:
			if r.Content != "203.0.113.10" || r.Comment != me {
				t.Fatalf("updated in place, keeping the marker: %+v", r)
			}
		case ttl:
			if r.TTL != dnsDefaultTTL {
				t.Fatalf("TTL put back: %+v", r)
			}
		case gone:
			t.Fatal("the deleted route's record must be removed")
		}
	}
	if len(f.recs["z-example.com"]) != 2 {
		t.Fatalf("records: %v", f.names("z-example.com"))
	}
}

func TestSyncSetsAndMultipleAddresses(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	_ = dnsAddressesSet(s, []string{"203.0.113.1", "203.0.113.2"})
	setRoutes(t, s, "apps.example.com")
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"*.apps.example.com A 203.0.113.1", "*.apps.example.com A 203.0.113.2"}) {
		t.Fatalf("one record per address: %v", got)
	}
	_ = dnsAddressesSet(s, []string{"203.0.113.2", "203.0.113.3"})
	plan, _ := dnsSyncOnce(s, false, false)
	if plan.count("update") != 1 || plan.count("create") != 0 || plan.count("delete") != 0 {
		t.Fatalf("a replaced address reuses the record that is no longer wanted: %+v", plan.Items)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"*.apps.example.com A 203.0.113.2", "*.apps.example.com A 203.0.113.3"}) {
		t.Fatalf("after: %v", got)
	}
}

func TestSyncRefusesToDeleteMostOwnedRecords(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	for i := 0; i < 8; i++ {
		f.seed("z-example.com", DNSRec{Name: fmt.Sprintf("h%d.example.com", i), Type: "A", Content: "192.0.2.9", TTL: 300, Comment: dnsMarker()})
	}
	setRoutes(t, s, "") // the route list came back empty: a bad restore, say

	plan, err := dnsSyncOnce(s, false, false)
	if !errors.Is(err, errMassDelete) || plan.count("delete") != 8 {
		t.Fatalf("a sync that deletes 8 of 8 must be refused: %v %+v", err, plan.Items)
	}
	if len(f.mutations()) != 0 || len(f.recs["z-example.com"]) != 8 {
		t.Fatalf("nothing was deleted: %v", f.mutations())
	}
	if st, _ := readDNSStatus(); st.OK || len(st.Errors) == 0 {
		t.Fatalf("the refusal is recorded as a failed sync: %+v", st)
	}
	if _, err := dnsSyncOnce(s, true, false); err != nil || len(f.recs["z-example.com"]) != 0 {
		t.Fatalf("--force goes ahead: %v", err)
	}

	// A few deletions are never "mass".
	for i := 0; i < 3; i++ {
		f.seed("z-example.com", DNSRec{Name: fmt.Sprintf("x%d.example.com", i), Type: "A", Content: "192.0.2.9", TTL: 300, Comment: dnsMarker()})
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil || len(f.recs["z-example.com"]) != 0 {
		t.Fatalf("deleting 3 of 3 is allowed: %v", err)
	}
}

func TestSyncPartialFailureIsReportedAndRetried(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	setRoutes(t, s, "", "a.example.com", "b.example.com")
	f.failOn = "create a.example.com A"
	plan, err := dnsSyncOnce(s, false, false)
	if err == nil || !strings.Contains(err.Error(), "1 of 2 changes failed") {
		t.Fatalf("error: %v", err)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"b.example.com A 203.0.113.10"}) {
		t.Fatalf("the other change still went through: %v", got)
	}
	var failed int
	for _, it := range plan.Items {
		if it.Error != "" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("the failed item carries its error: %+v", plan.Items)
	}
	if st, _ := readDNSStatus(); st.OK {
		t.Fatal("status must say the sync failed")
	}
	f.failOn = ""
	if _, err := dnsSyncOnce(s, false, false); err != nil || len(f.recs["z-example.com"]) != 2 {
		t.Fatalf("the next sync completes it: %v", err)
	}
}

func TestSyncZonesAndProviders(t *testing.T) {
	f := newFakeDNS("example.com", "shop.example.com", "other.org")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf", "example.com", "shop.example.com") // other.org is not managed
	setRoutes(t, s, "", "www.example.com", "a.shop.example.com", "x.other.org", "nozone.net")
	plan, err := dnsSyncOnce(s, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.names("z-example.com"); !slices.Equal(got, []string{"www.example.com A 203.0.113.10"}) {
		t.Fatalf("example.com: %v", got)
	}
	if got := f.names("z-shop.example.com"); !slices.Equal(got, []string{"a.shop.example.com A 203.0.113.10"}) {
		t.Fatalf("the longest zone wins: %v", got)
	}
	if len(f.recs["z-other.org"]) != 0 {
		t.Fatal("a zone outside the allowlist must not be written")
	}
	skips := 0
	for _, it := range plan.Items {
		if it.Action == "skip" && strings.Contains(it.Reason, "no zone") {
			skips++
		}
	}
	if skips != 2 {
		t.Fatalf("names without a managed zone are reported, not failed: %+v", plan.Items)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "list z-other.org") {
			t.Fatal("an unmanaged zone is not even listed")
		}
	}
}

func TestSyncProviderDownLeavesItsRecordsAlone(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	f.seed("z-example.com", DNSRec{Name: "keep.example.com", Type: "A", Content: "192.0.2.9", TTL: 300, Comment: dnsMarker()})
	setRoutes(t, s, "", "www.example.com")
	f.zonesFn = func() ([]DNSZone, error) { return nil, errors.New("cloudflare: HTTP 503") }

	_, err := dnsSyncOnce(s, false, false)
	if err == nil || !strings.Contains(err.Error(), "provider cf") {
		t.Fatalf("an unreachable provider is a failed sync: %v", err)
	}
	if len(f.mutations()) != 0 || len(f.recs["z-example.com"]) != 1 {
		t.Fatalf("nothing may be deleted because the provider could not be read: %v", f.mutations())
	}
	if st, _ := readDNSStatus(); st.OK {
		t.Fatal("recorded as failed")
	}
}

func TestSyncPinnedProviderAndTwoClustersShareAZone(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	addProvider(t, s, "cf")
	f.seed("z-example.com", DNSRec{Name: "other.example.com", Type: "A", Content: "192.0.2.77", TTL: 300, Comment: "ziro:cluster-b"})
	setRoutes(t, s, "")
	if err := dnsRecordAdd(s, DNSCloudRecord{Name: "tunnel.example.com", Type: "cname", Content: "abc.cfargotunnel.com.", Proxied: true}); err != nil {
		t.Fatal(err)
	}
	if err := dnsRecordAdd(s, DNSCloudRecord{Provider: "nope", Name: "x.example.com", Type: "A", Content: "192.0.2.1"}); err == nil {
		t.Fatal("a record pinned to an unknown provider must be refused")
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	var tunnel *DNSRec
	for i, r := range f.recs["z-example.com"] {
		if r.Name == "tunnel.example.com" {
			tunnel = &f.recs["z-example.com"][i]
		}
	}
	if tunnel == nil || !tunnel.Proxied || tunnel.Type != "CNAME" || tunnel.Content != "abc.cfargotunnel.com" || tunnel.Comment != dnsMarker() {
		t.Fatalf("an explicit proxied CNAME is created, normalised and marked: %+v", tunnel)
	}
	if len(f.recs["z-example.com"]) != 2 || f.recs["z-example.com"][0].Content != "192.0.2.77" {
		t.Fatalf("another cluster's record is untouched: %v", f.names("z-example.com"))
	}
	if n, err := dnsRecordRm(s, "tunnel.example.com", ""); err != nil || n != 1 {
		t.Fatal(err)
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil || len(f.recs["z-example.com"]) != 1 {
		t.Fatalf("removing the explicit record deletes it at the provider: %v", err)
	}
	if _, err := dnsRecordRm(s, "tunnel.example.com", ""); err == nil {
		t.Fatal("removing an unknown record must say so")
	}
}

func TestApplyRefusesAForeignRecordEvenIfAPlanSaysOtherwise(t *testing.T) {
	f := newFakeDNS("example.com")
	f.seed("z-example.com", DNSRec{Name: "x.example.com", Type: "A", Content: "192.0.2.1", Comment: "someone else"})
	ss := &dnsSession{owner: "ziro:me"}
	dp := &dnsProv{conf: DNSProviderConf{Name: "cf"}, p: f}
	plan := DNSPlan{Items: []DNSItem{
		{Action: "delete", Name: "x.example.com", Type: "A", prov: dp, zoneID: "z-example.com", rec: f.recs["z-example.com"][0]},
		{Action: "update", Name: "x.example.com", Type: "A", Content: "1.1.1.1", prov: dp, zoneID: "z-example.com", rec: f.recs["z-example.com"][0]},
	}}
	dir := t.TempDir()
	old := auditPath
	auditPath = filepath.Join(dir, "audit.log")
	defer func() { auditPath = old }()
	if err := ss.apply(&plan, true); err == nil {
		t.Fatal("applying a change to a foreign record must fail")
	}
	if len(f.mutations()) != 0 || len(f.recs["z-example.com"]) != 1 || f.recs["z-example.com"][0].Content != "192.0.2.1" {
		t.Fatalf("the foreign record was touched: %v", f.mutations())
	}
}

// ---- configuration ----

func TestProviderAddChecksTheTokenAndSealsIt(t *testing.T) {
	f := newFakeDNS("example.com", "example.org")
	s := dnsEnv(t, f, "203.0.113.10")

	f.zonesFn = func() ([]DNSZone, error) { return nil, errors.New("cloudflare: Invalid API Token (1000)") }
	if _, _, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "bad-token", nil); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a refused token must not be saved: %v", err)
	}
	if _, err := os.Stat(dnsTokenFile("cf")); err == nil {
		t.Fatal("nothing is stored for a refused token")
	}
	f.zonesFn = func() ([]DNSZone, error) { return nil, nil }
	if _, _, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "tok", nil); err == nil || !strings.Contains(err.Error(), "no zones") {
		t.Fatalf("a token that sees no zones is refused: %v", err)
	}
	f.zonesFn = nil
	if _, _, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "tok", []string{"missing.net"}); err == nil {
		t.Fatal("an allowlist that matches no zone is refused")
	}
	if _, _, err := dnsProviderAdd(s, "Bad Name!", dnsKindCloudflare, "tok", nil); err == nil {
		t.Fatal("invalid provider name")
	}
	if _, _, err := dnsProviderAdd(s, "x", "route53", "tok", nil); err == nil {
		t.Fatal("unknown provider kind")
	}

	conf, zones, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "super-secret-token", []string{"Example.com."})
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com" || !slices.Equal(conf.Zones, []string{"example.com"}) {
		t.Fatalf("add: %+v %v %v", conf, zones, err)
	}
	// Without a TPM the "wrapped" token is the token itself (as for `ziroctl cf login`): it is only as
	// private as the file, so the file and its directory must be root-only.
	if fi, err := os.Stat(dnsTokenFile("cf")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	if fi, _ := os.Stat(dnsProviderDir); fi.Mode().Perm() != 0700 {
		t.Fatalf("token directory mode %v", fi.Mode())
	}
	if tok, err := dnsTokenGet(s, "cf"); err != nil || tok != "super-secret-token" {
		t.Fatalf("round trip: %q %v", tok, err)
	}
	view, _ := dnsCloudView(s)
	b, _ := json.Marshal(view)
	if strings.Contains(string(b), "super-secret-token") || len(view.Providers) != 1 {
		t.Fatalf("the view never carries a token: %s", b)
	}

	// Pinned records block removal; then removal drops the token too.
	_ = dnsRecordAdd(s, DNSCloudRecord{Provider: "cf", Name: "a.example.com", Type: "A", Content: "192.0.2.1"})
	if dnsProviderRm(s, "cf") == nil {
		t.Fatal("a provider with pinned records cannot be removed")
	}
	_, _ = dnsRecordRm(s, "a.example.com", "A")
	if err := dnsProviderRm(s, "cf"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dnsTokenFile("cf")); !os.IsNotExist(err) {
		t.Fatal("the sealed token is deleted with the provider")
	}
	if dnsProviderRm(s, "cf") == nil {
		t.Fatal("removing an unknown provider must say so")
	}
}

func TestRecordValidation(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	if err := dnsRecordAdd(s, DNSCloudRecord{Name: "a.example.com", Type: "A", Content: "192.0.2.1"}); err == nil {
		t.Fatal("no provider yet")
	}
	addProvider(t, s, "cf")
	for _, bad := range []DNSCloudRecord{
		{Name: "a.example.com", Type: "A", Content: "not-an-ip"},
		{Name: "a.example.com", Type: "A", Content: "2001:db8::1"},
		{Name: "bad name", Type: "A", Content: "192.0.2.1"},
		{Name: "a.example.com", Type: "MX", Content: "mail.example.com"},
		{Name: "a.example.com", Type: "TXT", Content: "x", Proxied: true},
		{Name: "a.example.com", Type: "A", Content: "192.0.2.1", TTL: 5},
		{Name: "a.example.com", Type: "CNAME", Content: "-bad-"},
	} {
		if err := dnsRecordAdd(s, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	good := DNSCloudRecord{Name: "A.Example.com.", Type: "a", Content: "192.0.2.1"}
	if err := dnsRecordAdd(s, good); err != nil {
		t.Fatal(err)
	}
	if err := dnsRecordAdd(s, good); err == nil {
		t.Fatal("a duplicate must be refused")
	}
	d, _ := s.read()
	if r := d.DNSCloud.Records[0]; r.Name != "a.example.com" || r.Type != "A" {
		t.Fatalf("stored normalised: %+v", r)
	}
}

func TestRouteAndDomainChangesBumpTheEpochOnlyWithAProvider(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	r := GatewayRoute{Name: "web", Hosts: []string{"www.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:8080"}}, TLS: "off"}
	if _, err := putRoute(s, r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(gatewayLocalDir, "routes.json")); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.read(); d.DNSCloud.Epoch != 0 || len(d.DNSCloud.Providers) != 0 {
		t.Fatalf("a host without a provider never moves the epoch: %+v", d.DNSCloud)
	}

	addProvider(t, s, "cf")
	ep := func() int { d, _ := s.read(); return d.DNSCloud.Epoch }
	e0 := ep()
	if _, err := putRoute(s, GatewayRoute{Name: "api", Hosts: []string{"api.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:9090"}}, TLS: "off"}); err != nil {
		t.Fatal(err)
	}
	e1 := ep()
	if err := deleteRoute(s, "api"); err != nil {
		t.Fatal(err)
	}
	e2 := ep()
	if _, err := setGatewayDomain("apps.example.com"); err != nil {
		t.Fatal(err)
	}
	e3 := ep()
	if !(e0 < e1 && e1 < e2 && e2 < e3) {
		t.Fatalf("every route and domain change must move the epoch: %d %d %d %d", e0, e1, e2, e3)
	}

	info := describeDomain(s, GatewayDomain{Name: "apps.example.com"})
	if !slices.Equal(info.Managed, []string{"cf"}) {
		t.Fatalf("describeDomain names the provider that manages the records: %+v", info)
	}
}

// ---- the loop ----

func TestLoopSchedulesOnEpochAndInterval(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	now := time.Now()
	leader, runs, fail := true, 0, error(nil)
	var announced []error
	l := &dnsLoop{
		store:    func() (routeStore, error) { return s, nil },
		leader:   func() bool { return leader },
		sync:     func(routeStore) (DNSPlan, error) { runs++; return DNSPlan{}, fail },
		now:      func() time.Time { return now },
		announce: func(err error) { announced = append(announced, err) },
	}
	if l.tick() || runs != 0 {
		t.Fatal("no provider configured: nothing to do")
	}
	addProvider(t, s, "cf")
	if !l.tick() || runs != 1 {
		t.Fatal("first tick after configuring a provider reconciles")
	}
	if l.tick() || runs != 1 {
		t.Fatal("nothing changed and the interval has not passed")
	}
	_, _ = putRoute(s, GatewayRoute{Name: "web", Hosts: []string{"www.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:8080"}}, TLS: "off"})
	now = now.Add(dnsPollEvery)
	if !l.tick() || runs != 2 {
		t.Fatal("a route change reconciles within a poll")
	}
	now = now.Add(dnsSyncEvery)
	if !l.tick() || runs != 3 {
		t.Fatal("the periodic reconcile")
	}

	leader = false
	_, _ = putRoute(s, GatewayRoute{Name: "api", Hosts: []string{"api.example.com"}, To: []GatewayUpstream{{Address: "127.0.0.1:9090"}}, TLS: "off"})
	now = now.Add(dnsSyncEvery)
	if l.tick() || runs != 3 {
		t.Fatal("a follower never writes")
	}
	leader = true
	fail = errors.New("boom")
	if !l.tick() || runs != 4 || len(announced) != 1 {
		t.Fatal("the new leader reconciles at once, and a failure is announced")
	}
	now = now.Add(dnsPollEvery)
	if l.tick() || runs != 4 {
		t.Fatal("a failed reconcile backs off")
	}
	now = now.Add(dnsRetryAt)
	fail = nil
	if !l.tick() || runs != 5 || l.failing {
		t.Fatal("the retry succeeds and clears the failure")
	}
}

// ---- doctor ----

func TestDNSDoctorCheck(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	now := time.Now()
	if _, ok := dnsDoctorCheck(now); ok {
		t.Fatal("no provider: no row")
	}
	addProvider(t, s, "cf")
	setRoutes(t, s, "", "www.example.com")
	if c, _ := dnsDoctorCheck(now); c.Passed || !strings.Contains(c.Details, "no sync has run yet") || c.fix == nil {
		t.Fatalf("before the first sync: %+v", c)
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	if c, _ := dnsDoctorCheck(time.Now()); !c.Passed {
		t.Fatalf("after a good sync: %+v", c)
	}
	if c, _ := dnsDoctorCheck(time.Now().Add(time.Hour)); c.Passed || !strings.Contains(c.Details, "ago") {
		t.Fatalf("a sync that stopped running: %+v", c)
	}
	f.failOn = "create new.example.com A"
	setRoutes(t, s, "", "www.example.com", "new.example.com")
	_, _ = dnsSyncOnce(s, false, false)
	if c, _ := dnsDoctorCheck(time.Now()); c.Passed || !strings.Contains(c.Details, "last sync failed") {
		t.Fatalf("a failed sync: %+v", c)
	}
	f.failOn = ""
	c, _ := dnsDoctorCheck(time.Now())
	if err := c.fix(); err != nil {
		t.Fatal(err)
	}
	if c, _ := dnsDoctorCheck(time.Now()); !c.Passed {
		t.Fatalf("the fix runs one sync: %+v", c)
	}
	_ = os.Remove(dnsTokenFile("cf"))
	if c, _ := dnsDoctorCheck(time.Now()); c.Passed || c.fix != nil || !strings.Contains(c.Details, "no token") {
		t.Fatalf("a lost token is advice, not a fix: %+v", c)
	}
}

// ---- the Cloudflare client against a fake API ----

type cfFake struct {
	mu       sync.Mutex
	zones    []cfZone
	records  map[string][]cfDNSRecord
	log      []string
	bodies   []map[string]any
	throttle map[string]int // "GET /zones" -> answers to fail with 429 first
	errors5  map[string]int
	auth     string
}

func newCFFake(t *testing.T) (*cfFake, *httptest.Server) {
	f := &cfFake{records: map[string][]cfDNSRecord{}, throttle: map[string]int{}, errors5: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = r.Header.Get("Authorization")
		key := r.Method + " " + r.URL.Path
		f.log = append(f.log, key+"?"+r.URL.RawQuery)
		if f.throttle[key] > 0 {
			f.throttle[key]--
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":971,"message":"rate limited"}]}`)
			return
		}
		if f.errors5[key] > 0 {
			f.errors5[key]--
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "<html>bad gateway</html>")
			return
		}
		reply := func(v any) {
			b, _ := json.Marshal(map[string]any{"success": true, "result": v})
			_, _ = w.Write(b)
		}
		page := func(n int) (int, int) {
			p := 1
			fmt.Sscanf(r.URL.Query().Get("page"), "%d", &p)
			return (p - 1) * n, p * n
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.URL.Path == "/zones" && r.Method == "GET":
			lo, hi := page(50)
			lo, hi = min(lo, len(f.zones)), min(hi, len(f.zones))
			reply(f.zones[lo:hi])
		case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == "GET":
			recs := f.records[parts[1]]
			lo, hi := page(100)
			lo, hi = min(lo, len(recs)), min(hi, len(recs))
			reply(recs[lo:hi])
		case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == "POST":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.bodies = append(f.bodies, body)
			rec := cfDNSRecord{ID: fmt.Sprintf("r%d", len(f.records[parts[1]])+1), Type: body["type"].(string), Name: body["name"].(string), Content: body["content"].(string),
				Comment: fmt.Sprint(body["comment"]), Proxied: body["proxied"] == true, TTL: int(body["ttl"].(float64))}
			f.records[parts[1]] = append(f.records[parts[1]], rec)
			reply(rec)
		case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == "PUT":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.bodies = append(f.bodies, body)
			for i := range f.records[parts[1]] {
				if f.records[parts[1]][i].ID == parts[3] {
					f.records[parts[1]][i].Content, f.records[parts[1]][i].Proxied = body["content"].(string), body["proxied"] == true
				}
			}
			reply(map[string]string{"id": parts[3]})
		case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == "DELETE":
			kept := f.records[parts[1]][:0]
			for _, x := range f.records[parts[1]] {
				if x.ID != parts[3] {
					kept = append(kept, x)
				}
			}
			f.records[parts[1]] = kept
			reply(map[string]string{"id": parts[3]})
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":7003,"message":"no route"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	old := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = old })
	return f, srv
}

func TestCloudflareProviderListsPagesAndFiltersTypes(t *testing.T) {
	f, _ := newCFFake(t)
	for i := 0; i < 120; i++ {
		f.zones = append(f.zones, cfZone{ID: fmt.Sprintf("z%d", i), Name: fmt.Sprintf("Zone%d.Example.com", i)})
	}
	for i := 0; i < 230; i++ {
		f.records["z1"] = append(f.records["z1"], cfDNSRecord{ID: fmt.Sprintf("a%d", i), Type: "A", Name: fmt.Sprintf("H%d.Zone1.example.com", i), Content: "192.0.2.1", Comment: "ziro:c"})
	}
	f.records["z1"] = append(f.records["z1"], cfDNSRecord{ID: "mx", Type: "MX", Name: "zone1.example.com", Content: "mail"},
		cfDNSRecord{ID: "txt", Type: "TXT", Name: "t.zone1.example.com", Content: `"quoted value"`})
	p := newCFDNSProvider("tok-1")

	zones, err := p.Zones()
	if err != nil || len(zones) != 120 || zones[0].Name != "zone0.example.com" {
		t.Fatalf("every page of zones, lower-cased: %d %v", len(zones), err)
	}
	if f.auth != "Bearer tok-1" {
		t.Fatalf("bearer token: %q", f.auth)
	}
	recs, err := p.List("z1")
	if err != nil || len(recs) != 231 {
		t.Fatalf("230 A records and the TXT, not the MX: %d %v", len(recs), err)
	}
	if recs[0].Name != "h0.zone1.example.com" || recs[len(recs)-1].Content != "quoted value" || recs[0].Comment != "ziro:c" {
		t.Fatalf("names normalised, TXT unquoted, comment kept: %+v %+v", recs[0], recs[len(recs)-1])
	}
}

func TestCloudflareProviderWritesRecords(t *testing.T) {
	f, _ := newCFFake(t)
	f.zones = []cfZone{{ID: "z1", Name: "example.com"}}
	p := newCFDNSProvider("tok")
	if err := p.Upsert("z1", DNSRec{Name: "a.example.com", Type: "A", Content: "192.0.2.1", TTL: 300, Comment: "ziro:c"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Upsert("z1", DNSRec{Name: "t.example.com", Type: "CNAME", Content: "x.example.net", TTL: 300, Proxied: true, Comment: "ziro:c"}); err != nil {
		t.Fatal(err)
	}
	b := f.bodies[0]
	if b["comment"] != "ziro:c" || b["proxied"] != false || b["ttl"] != float64(300) {
		t.Fatalf("create body: %v", b)
	}
	if f.bodies[1]["ttl"] != float64(1) || f.bodies[1]["proxied"] != true {
		t.Fatalf("a proxied record is sent with automatic TTL: %v", f.bodies[1])
	}
	// A replace always carries the proxied flag: leaving it out would silently turn proxying off.
	if err := p.Upsert("z1", DNSRec{ID: "r2", Name: "t.example.com", Type: "CNAME", Content: "y.example.net", Proxied: true, Comment: "ziro:c"}); err != nil {
		t.Fatal(err)
	}
	if b := f.bodies[2]; b["proxied"] != true || b["content"] != "y.example.net" {
		t.Fatalf("replace body: %v", b)
	}
	if err := p.Delete("z1", "r1"); err != nil || len(f.records["z1"]) != 1 {
		t.Fatalf("delete: %v %v", err, f.records["z1"])
	}
}

func TestCloudflareClientRetriesThrottlingAndServerErrors(t *testing.T) {
	f, _ := newCFFake(t)
	f.zones = []cfZone{{ID: "z1", Name: "example.com"}}
	c := &cfClient{token: "t", retries: 4}
	var waits []time.Duration
	c.sleep = func(d time.Duration) { waits = append(waits, d) }

	f.throttle["GET /zones"] = 2
	zs, err := c.zones()
	if err != nil || len(zs) != 1 || len(waits) != 2 || waits[0] != 2*time.Second {
		t.Fatalf("429 honours Retry-After and then succeeds: %v %v %v", zs, err, waits)
	}

	waits = nil
	f.errors5["GET /zones"] = 2
	if _, err := c.zones(); err != nil || len(waits) != 2 {
		t.Fatalf("5xx on a GET is retried: %v %v", err, waits)
	}
	if waits[1] < 2*time.Second || waits[1] > 3*time.Second+time.Millisecond {
		t.Fatalf("exponential backoff with jitter (1s, 2s + up to 50%%): %v", waits)
	}

	// A POST that may have been applied is never retried after a 5xx, but a 429 means it was not.
	waits = nil
	f.errors5["POST /zones/z1/dns_records"] = 1
	if err := c.createDNS("z1", cfDNSRecord{Type: "A", Name: "a.example.com", Content: "192.0.2.1"}); err == nil || len(waits) != 0 || len(f.records["z1"]) != 0 {
		t.Fatalf("a POST answered 502 must not be repeated (it could have been created): %v %v", err, waits)
	}
	f.throttle["POST /zones/z1/dns_records"] = 1
	if err := c.createDNS("z1", cfDNSRecord{Type: "A", Name: "a.example.com", Content: "192.0.2.1"}); err != nil || len(f.records["z1"]) != 1 {
		t.Fatalf("a POST answered 429 is retried: %v", err)
	}

	waits = nil
	f.throttle["GET /zones"] = 99
	if _, err := c.zones(); err == nil || len(waits) != 4 {
		t.Fatalf("retries are bounded: %v %v", err, waits)
	}

	// The `cf` commands keep their old, single-attempt behaviour.
	f.throttle["GET /zones"] = 1
	if _, err := (&cfClient{token: "t"}).zones(); err == nil {
		t.Fatal("without retries a 429 is an error")
	}
}

func TestEndToEndSyncAgainstTheCloudflareFake(t *testing.T) {
	f, _ := newCFFake(t)
	f.zones = []cfZone{{ID: "z1", Name: "example.com"}}
	f.records["z1"] = []cfDNSRecord{{ID: "foreign", Type: "A", Name: "mail.example.com", Content: "198.51.100.2"}}
	root := t.TempDir()
	oldHost := hostAddrs
	oldLocal, oldDir, oldStatus, oldAudit, oldCluster := gatewayLocalDir, dnsProviderDir, dnsStatusDir, auditPath, clusterDir
	gatewayLocalDir, dnsProviderDir, dnsStatusDir = filepath.Join(root, "gw"), filepath.Join(root, "tokens"), filepath.Join(root, "status")
	auditPath, clusterDir = filepath.Join(root, "audit.log"), filepath.Join(root, "cluster")
	hostAddrs = func() []HostAddress { return []HostAddress{{IP: "203.0.113.10"}} }
	t.Cleanup(func() {
		hostAddrs = oldHost
		gatewayLocalDir, dnsProviderDir, dnsStatusDir, auditPath, clusterDir = oldLocal, oldDir, oldStatus, oldAudit, oldCluster
	})
	s := localRouteStore{dir: gatewayLocalDir}

	if _, _, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "real-token", nil); err != nil { // the real factory, the fake API
		t.Fatal(err)
	}
	setRoutes(t, s, "apps.example.com", "www.example.com")
	if _, err := dnsSyncOnce(s, false, false); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range f.records["z1"] {
		names = append(names, r.Name)
		if r.ID != "foreign" && (r.Comment != dnsMarker() || r.Proxied) {
			t.Fatalf("created record: %+v", r)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"*.apps.example.com", "mail.example.com", "www.example.com"}) {
		t.Fatalf("records at Cloudflare: %v", names)
	}
	if f.auth != "Bearer real-token" {
		t.Fatalf("the stored token is the one used: %q", f.auth)
	}
	// Steady state is one listing per zone and no writes.
	f.log = nil
	if plan, err := dnsSyncOnce(s, false, false); err != nil || plan.Changes() != 0 {
		t.Fatalf("%v %+v", err, plan)
	}
	writes := 0
	for _, l := range f.log {
		if !strings.HasPrefix(l, "GET ") {
			writes++
		}
	}
	if writes != 0 {
		t.Fatalf("a steady-state sync only reads: %v", f.log)
	}
}

// ---- the API ----

func TestDNSCloudAPIRolesAndSecrecy(t *testing.T) {
	f := newFakeDNS("example.com")
	s := dnsEnv(t, f, "203.0.113.10")
	_ = s
	h := newAPIHarness(t)
	// dnsEnv replaced auditPath; the harness set its own: keep the harness's for the API audit.

	for _, c := range []struct {
		role, method, path string
		want               int
	}{
		{"", "GET", "/api/v1/dns/cloud", 401},
		{"viewer", "GET", "/api/v1/dns/cloud", 200},
		{"viewer", "GET", "/api/v1/dns/cloud/plan", 403},
		{"operator", "POST", "/api/v1/dns/cloud/sync", 403},
		{"operator", "PUT", "/api/v1/dns/cloud/providers/cf", 403},
		{"operator", "DELETE", "/api/v1/dns/cloud/providers/cf", 403},
		{"operator", "POST", "/api/v1/dns/cloud/records", 403},
		{"operator", "DELETE", "/api/v1/dns/cloud/records?name=a.example.com", 403},
		{"operator", "PUT", "/api/v1/dns/cloud/addresses", 403},
	} {
		if got := h.code(c.role, c.method, c.path, `{}`); got != c.want {
			t.Errorf("%s %s as %q: %d, want %d", c.method, c.path, c.role, got, c.want)
		}
	}

	if rec := h.req("admin", "PUT", "/api/v1/dns/cloud/providers/cf", `{"kind":"cloudflare","token":"has space"}`); rec.Code != 400 {
		t.Fatalf("a malformed token: %d %s", rec.Code, rec.Body)
	}
	rec := h.req("admin", "PUT", "/api/v1/dns/cloud/providers/cf", `{"token":"api-secret-123"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "api-secret-123") {
		t.Fatalf("add provider: %d %s", rec.Code, rec.Body)
	}
	if log, _ := os.ReadFile(auditPath); strings.Contains(string(log), "api-secret-123") || !strings.Contains(string(log), "dns provider add") {
		t.Fatalf("the audit log records the change, never the token:\n%s", log)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/records", `{"name":"www.example.com","type":"CNAME","content":"app.example.com"}`); rec.Code != 200 {
		t.Fatalf("add record: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/records", `{"name":"www.example.com","type":"CNAME","content":"app.example.com","extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown fields are refused: %d", rec.Code)
	}
	if rec := h.req("admin", "PUT", "/api/v1/dns/cloud/addresses", `{"addresses":["203.0.113.9"]}`); rec.Code != 200 {
		t.Fatalf("addresses: %d %s", rec.Code, rec.Body)
	}
	view := h.req("viewer", "GET", "/api/v1/dns/cloud", "")
	if view.Code != 200 || strings.Contains(view.Body.String(), "api-secret-123") || !strings.Contains(view.Body.String(), "www.example.com") || !strings.Contains(view.Body.String(), "203.0.113.9") {
		t.Fatalf("the view: %d %s", view.Code, view.Body)
	}
	if rec := h.req("admin", "GET", "/api/v1/dns/cloud/plan", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"create"`) || len(f.mutations()) != 0 {
		t.Fatalf("plan: %d %s %v", rec.Code, rec.Body, f.mutations())
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/sync", ""); rec.Code != 200 || len(f.recs["z-example.com"]) != 1 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "DELETE", "/api/v1/dns/cloud/records", ""); rec.Code != 400 {
		t.Fatalf("a delete without a name: %d", rec.Code)
	}
	if rec := h.req("admin", "DELETE", "/api/v1/dns/cloud/records?name=www.example.com&type=CNAME", ""); rec.Code != 200 {
		t.Fatalf("delete record: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "DELETE", "/api/v1/dns/cloud/providers/cf", ""); rec.Code != 200 {
		t.Fatalf("delete provider: %d %s", rec.Code, rec.Body)
	}
	if rec := h.req("admin", "POST", "/api/v1/dns/cloud/sync", ""); rec.Code == 200 {
		t.Fatal("syncing without a provider must be an error")
	}
}

// ---- cluster ----

func TestClusterStoreKeepsDNSConfigAndTheTokenAsASecret(t *testing.T) {
	f := newFakeDNS("example.com")
	_ = dnsEnv(t, f, "203.0.113.10")
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c-123", Role: "master", NodeID: "m1"}); err != nil {
		t.Fatal(err)
	}
	if !socketIsLeader() {
		t.Fatal("a master that does not run Raft yet is its own leader")
	}
	s, err := gatewayStore()
	if err != nil || s.name() != "cluster" {
		t.Fatalf("store: %v %v", s, err)
	}
	if dnsMarker() != "ziro:c-123" {
		t.Fatalf("the marker names the cluster: %s", dnsMarker())
	}

	if _, _, err := dnsProviderAdd(s, "cf", dnsKindCloudflare, "cluster-token", nil); err != nil {
		t.Fatal(err)
	}
	if err := dnsRecordAdd(s, DNSCloudRecord{Name: "a.example.com", Type: "A", Content: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	st, err := readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.DNSCloud.Providers) != 1 || len(st.DNSCloud.Records) != 1 || st.DNSCloud.Epoch < 2 {
		t.Fatalf("the configuration replicates with the cluster state: %+v", st.DNSCloud)
	}
	if st.Secrets[dnsSecretPrefix+"cf"]["token"] != "cluster-token" {
		t.Fatalf("the token is a cluster secret (sealed at rest, replicated, so a new leader keeps syncing): %v", st.Secrets)
	}
	if _, err := os.Stat(dnsTokenFile("cf")); err == nil {
		t.Fatal("a cluster keeps no token file")
	}
	if tok, err := dnsTokenGet(s, "cf"); err != nil || tok != "cluster-token" {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := dnsSyncOnce(s, false, false); err != nil || len(f.recs["z-example.com"]) != 1 || f.recs["z-example.com"][0].Comment != "ziro:c-123" {
		t.Fatalf("sync through the cluster store: %v %v", err, f.recs)
	}
	if err := dnsProviderRm(s, "cf"); err != nil {
		t.Fatal(err)
	}
	if st, _ := readState(); st.Secrets[dnsSecretPrefix+"cf"] != nil || len(st.DNSCloud.Providers) != 0 {
		t.Fatalf("removal drops the secret too: %+v", st.Secrets)
	}
}

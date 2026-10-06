package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The reconciler: derive what the gateway wants published (dnsDesired), read what the provider
// holds, and create, update or delete the difference.
//
// Ownership is the safety rule. Every record it creates carries the comment "ziro:<cluster id>",
// and only records with exactly that comment are ever updated or deleted. A record somebody else
// made at the same name is left alone and reported. A sync that would delete most of what it owns
// (an empty route list after a bad restore, a gateway node that vanished from the state) is
// refused unless an operator forces it; the daemon never does.

const (
	dnsMassDeleteMin = 3 // deleting this many or fewer records is never "mass"
	dnsStatusMax     = 20
)

// DNSItem is one step of a plan.
type DNSItem struct {
	Action   string `json:"action"` // create, update, delete, skip
	Provider string `json:"provider"`
	Zone     string `json:"zone,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Proxied  bool   `json:"proxied,omitempty"`
	Was      string `json:"was,omitempty"`    // update: the content at the provider now
	Reason   string `json:"reason,omitempty"` // skip: why
	Error    string `json:"error,omitempty"`  // apply: what failed

	zoneID string
	rec    DNSRec // the provider's record (update, delete)
	prov   *dnsProv
}

// DNSPlan is the difference between the desired records and the provider.
type DNSPlan struct {
	Items    []DNSItem `json:"items"`
	Warnings []string  `json:"warnings,omitempty"`
	Owned    int       `json:"owned"` // records at the providers carrying our marker
}

func (p DNSPlan) count(action string) int {
	n := 0
	for _, it := range p.Items {
		if it.Action == action {
			n++
		}
	}
	return n
}

// Changes is the number of creates, updates and deletes.
func (p DNSPlan) Changes() int { return p.count("create") + p.count("update") + p.count("delete") }

// dnsProv is a provider opened for one reconcile: its zones and, fetched at most once each, the
// records of those zones.
type dnsProv struct {
	conf  DNSProviderConf
	p     DNSProvider
	zones []DNSZone
	recs  map[string][]DNSRec
	bad   map[string]bool // zones whose records could not be read: left untouched
}

func (dp *dnsProv) records(zoneID string) ([]DNSRec, error) {
	if r, ok := dp.recs[zoneID]; ok {
		return r, nil
	}
	r, err := dp.p.List(zoneID)
	if err != nil {
		dp.bad[zoneID] = true
		return nil, err
	}
	dp.recs[zoneID] = r
	return r, nil
}

// managedZones are the zones of all that conf may manage (its allowlist, or all of them).
func managedZones(conf DNSProviderConf, all []DNSZone) []DNSZone {
	if len(conf.Zones) == 0 {
		return all
	}
	var out []DNSZone
	for _, z := range all {
		for _, want := range conf.Zones {
			if z.Name == want {
				out = append(out, z)
			}
		}
	}
	return out
}

// zoneOf is the longest managed zone that holds name.
func zoneOf(zones []DNSZone, name string) *DNSZone {
	name = strings.TrimPrefix(name, "*.")
	var best *DNSZone
	for i := range zones {
		z := &zones[i]
		if (name == z.Name || strings.HasSuffix(name, "."+z.Name)) && (best == nil || len(z.Name) > len(best.Name)) {
			best = z
		}
	}
	return best
}

type dnsSession struct {
	owner string
	provs []*dnsProv
	warns []string
	// failed is set when a provider could not be opened: its zones are left untouched.
	failed bool
}

// openDNSSession opens every configured provider. One that cannot be opened (token revoked, API
// down) is reported and left alone; the rest are still reconciled.
func openDNSSession(s routeStore, d *gatewayData) *dnsSession {
	ss := &dnsSession{owner: dnsMarker()}
	for _, conf := range d.DNSCloud.Providers {
		tok, err := dnsTokenGet(s, conf.Name)
		var p DNSProvider
		if err == nil {
			p, err = dnsProviderFactory(conf, tok)
		}
		var zones []DNSZone
		if err == nil {
			var all []DNSZone
			if all, err = p.Zones(); err == nil {
				zones = managedZones(conf, all)
			}
		}
		if err != nil {
			ss.warns = append(ss.warns, fmt.Sprintf("provider %s: %v (its records are left as they are)", conf.Name, err))
			ss.failed = true
			continue
		}
		ss.provs = append(ss.provs, &dnsProv{conf: conf, p: p, zones: zones, recs: map[string][]DNSRec{}, bad: map[string]bool{}})
	}
	return ss
}

type dnsGroup struct {
	prov  *dnsProv
	zone  DNSZone
	name  string
	typ   string
	wants []desiredRec
}

// sameRec: the provider's record already is what is wanted (a proxied record's TTL is the
// provider's, so it is not compared).
func sameRec(r DNSRec, w desiredRec) bool {
	return normDNSContent(r.Type, r.Content) == normDNSContent(w.Type, w.Content) && r.Proxied == w.Proxied && (w.Proxied || r.TTL == w.TTL)
}

// plan computes what to do. It reads the providers (one listing per zone) and changes nothing.
func (ss *dnsSession) plan(desired []desiredRec) DNSPlan {
	plan := DNSPlan{Warnings: append([]string(nil), ss.warns...)}
	var order []string
	groups := map[string]*dnsGroup{}
	skip := func(w desiredRec, prov, zone, reason string) {
		plan.Items = append(plan.Items, DNSItem{Action: "skip", Provider: prov, Zone: zone, Name: w.Name, Type: w.Type, Content: w.Content, Reason: reason})
	}

	for _, w := range desired {
		var dp *dnsProv
		var z *DNSZone
		for _, c := range ss.provs {
			if w.Provider != "" && c.conf.Name != w.Provider {
				continue
			}
			if z = zoneOf(c.zones, w.Name); z != nil {
				dp = c
				break
			}
		}
		switch {
		case dp == nil && w.Provider != "" && !ss.hasProvider(w.Provider):
			// the provider could not be opened (reported already) or was removed: nothing to do
		case dp == nil:
			skip(w, w.Provider, "", "no zone for this name at any provider (the token must see its zone)")
		default:
			k := dp.conf.Name + "|" + z.ID + "|" + w.Name + "|" + w.Type
			if groups[k] == nil {
				groups[k] = &dnsGroup{prov: dp, zone: *z, name: w.Name, typ: w.Type}
				order = append(order, k)
			}
			groups[k].wants = append(groups[k].wants, w)
		}
	}

	for _, k := range order {
		g := groups[k]
		recs, err := g.prov.records(g.zone.ID)
		if err != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("zone %s: %v (left as it is)", g.zone.Name, err))
			ss.failed = true
			continue
		}
		var owned, foreign, conflict []DNSRec
		for _, r := range recs {
			if r.Name != g.name {
				continue
			}
			switch {
			case r.Type == g.typ && r.Comment == ss.owner:
				owned = append(owned, r)
			case r.Type == g.typ:
				foreign = append(foreign, r)
			case r.Comment != ss.owner && (r.Type == "CNAME" || g.typ == "CNAME"):
				conflict = append(conflict, r) // a CNAME excludes every other record at its name
			}
		}
		item := func(action string, w desiredRec) DNSItem {
			return DNSItem{Action: action, Provider: g.prov.conf.Name, Zone: g.zone.Name, Name: w.Name, Type: w.Type,
				Content: w.Content, TTL: w.TTL, Proxied: w.Proxied, zoneID: g.zone.ID, prov: g.prov}
		}
		switch {
		case len(conflict) > 0:
			for _, w := range g.wants {
				skip(w, g.prov.conf.Name, g.zone.Name, fmt.Sprintf("a %s record that is not ziro's is at this name", conflict[0].Type))
			}
			continue
		case len(foreign) > 0 && len(owned) == 0:
			for _, w := range g.wants {
				skip(w, g.prov.conf.Name, g.zone.Name, "a record that is not ziro's is already at this name; left as it is")
			}
			continue
		}

		used := make([]bool, len(owned))
		var pending []desiredRec
		for _, w := range g.wants { // 1. already right
			hit := false
			for i, r := range owned {
				if !used[i] && sameRec(r, w) {
					used[i], hit = true, true
					break
				}
			}
			if !hit {
				pending = append(pending, w)
			}
		}
		var rest []desiredRec
		for _, w := range pending { // 2. same content, other TTL or proxy flag: update in place
			hit := false
			for i, r := range owned {
				if !used[i] && normDNSContent(r.Type, r.Content) == normDNSContent(w.Type, w.Content) {
					it := item("update", w)
					it.rec, it.Was = r, r.Content
					plan.Items = append(plan.Items, it)
					used[i], hit = true, true
					break
				}
			}
			if !hit {
				rest = append(rest, w)
			}
		}
		for _, w := range rest { // 3. reuse a leftover owned record (new address), else create
			hit := false
			for i, r := range owned {
				if !used[i] {
					it := item("update", w)
					it.rec, it.Was = r, r.Content
					plan.Items = append(plan.Items, it)
					used[i], hit = true, true
					break
				}
			}
			if !hit {
				plan.Items = append(plan.Items, item("create", w))
			}
		}
		for i, r := range owned { // 4. owned records nobody wants any more
			if !used[i] {
				plan.Items = append(plan.Items, DNSItem{Action: "delete", Provider: g.prov.conf.Name, Zone: g.zone.Name, Name: r.Name, Type: r.Type,
					Content: r.Content, zoneID: g.zone.ID, rec: r, prov: g.prov})
			}
		}
	}

	// Sweep: owned records in a managed zone whose name and type nobody wants at all.
	wanted := map[string]bool{}
	for _, k := range order {
		g := groups[k]
		wanted[g.prov.conf.Name+"|"+g.zone.ID+"|"+g.name+"|"+g.typ] = true
	}
	for _, dp := range ss.provs {
		for _, z := range dp.zones {
			recs, err := dp.records(z.ID)
			if err != nil {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("zone %s: %v (left as it is)", z.Name, err))
				ss.failed = true
				continue
			}
			for _, r := range recs {
				if r.Comment != ss.owner {
					continue
				}
				plan.Owned++
				if strings.HasPrefix(r.Name, "_acme-challenge.") || wanted[dp.conf.Name+"|"+z.ID+"|"+r.Name+"|"+r.Type] {
					continue
				}
				plan.Items = append(plan.Items, DNSItem{Action: "delete", Provider: dp.conf.Name, Zone: z.Name, Name: r.Name, Type: r.Type,
					Content: r.Content, zoneID: z.ID, rec: r, prov: dp})
			}
		}
	}
	sort.SliceStable(plan.Items, func(i, j int) bool {
		a, b := plan.Items[i], plan.Items[j]
		if ra, rb := dnsActionRank[a.Action], dnsActionRank[b.Action]; ra != rb {
			return ra < rb
		}
		return a.Name+"|"+a.Type+"|"+a.Content < b.Name+"|"+b.Type+"|"+b.Content
	})
	return plan
}

// creates and updates first, so a name is never without an address while it changes
var dnsActionRank = map[string]int{"create": 0, "update": 1, "delete": 2, "skip": 3}

func (ss *dnsSession) hasProvider(name string) bool {
	for _, dp := range ss.provs {
		if dp.conf.Name == name {
			return true
		}
	}
	return false
}

var errMassDelete = errors.New("refusing to delete most of the records this cluster owns")

// apply executes a plan. It never touches a record that does not carry the ownership marker, and
// refuses a sync that deletes most of what it owns unless force is set. Every change is audited.
func (ss *dnsSession) apply(plan *DNSPlan, force bool) error {
	if dels := plan.count("delete"); !force && dels > dnsMassDeleteMin && dels*2 > plan.Owned {
		return fmt.Errorf("%w: %d of %d (run ziroctl dns cloud plan to look, ziroctl dns cloud sync --force to go ahead)", errMassDelete, dels, plan.Owned)
	}
	var errs []string
	for i := range plan.Items {
		it := &plan.Items[i]
		if it.Action == "skip" {
			continue
		}
		var err error
		switch it.Action {
		case "create":
			err = it.prov.p.Upsert(it.zoneID, DNSRec{Name: it.Name, Type: it.Type, Content: it.Content, TTL: it.TTL, Proxied: it.Proxied, Comment: ss.owner})
		case "update":
			if it.rec.Comment != ss.owner { // defense in depth: the plan only holds owned records
				err = errors.New("not a ziro record")
				break
			}
			err = it.prov.p.Upsert(it.zoneID, DNSRec{ID: it.rec.ID, Name: it.Name, Type: it.Type, Content: it.Content, TTL: it.TTL, Proxied: it.Proxied, Comment: ss.owner})
		case "delete":
			if it.rec.Comment != ss.owner {
				err = errors.New("not a ziro record")
				break
			}
			err = it.prov.p.Delete(it.zoneID, it.rec.ID)
		}
		target := fmt.Sprintf("%s %s %s (%s)", it.Name, it.Type, it.Content, it.Provider)
		if auditErr := auditLog("dns-sync", "dnsprovider", "dns "+it.Action, target, err); auditErr != nil {
			fmt.Printf("[dns] audit log: %v\n", auditErr)
		}
		if err != nil {
			it.Error = err.Error()
			errs = append(errs, fmt.Sprintf("%s %s: %v", it.Action, target, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d changes failed: %s", len(errs), plan.Changes(), strings.Join(errs, "; "))
	}
	return nil
}

// ---- status ----

// DNSSyncStatus is the last reconcile on this host (doctor and `dns cloud status` read it).
type DNSSyncStatus struct {
	Time     string   `json:"time"`
	OK       bool     `json:"ok"`
	Created  int      `json:"created"`
	Updated  int      `json:"updated"`
	Deleted  int      `json:"deleted"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func dnsStatusPath() string { return filepath.Join(dnsStatusDir, "status.json") }

func writeDNSStatus(st DNSSyncStatus) {
	b, _ := json.Marshal(st)
	if err := os.MkdirAll(dnsStatusDir, 0755); err == nil {
		_ = writeFileAtomic(dnsStatusPath(), b, 0644)
	}
}

func readDNSStatus() (DNSSyncStatus, bool) {
	var st DNSSyncStatus
	b, err := os.ReadFile(dnsStatusPath())
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

// dnsPlanNow computes the plan for the current gateway data without changing anything.
func dnsPlanNow(s routeStore) (DNSPlan, *dnsSession, error) {
	d, err := s.read()
	if err != nil {
		return DNSPlan{}, nil, err
	}
	if len(d.DNSCloud.Providers) == 0 {
		return DNSPlan{}, nil, errors.New("no DNS provider: ziroctl dns provider add cloudflare --token-file …")
	}
	desired, warns := dnsDesired(s, d)
	ss := openDNSSession(s, d)
	plan := ss.plan(desired)
	plan.Warnings = append(warns, plan.Warnings...)
	return plan, ss, nil
}

// dnsSyncOnce plans and applies, and records the outcome. dry stops after the plan.
func dnsSyncOnce(s routeStore, force, dry bool) (DNSPlan, error) {
	plan, ss, err := dnsPlanNow(s)
	if err != nil {
		return plan, err
	}
	if dry {
		return plan, nil
	}
	err = ss.apply(&plan, force)
	st := DNSSyncStatus{Time: time.Now().UTC().Format(time.RFC3339), OK: err == nil && !ss.failed,
		Created: plan.count("create"), Updated: plan.count("update"), Deleted: plan.count("delete"), Skipped: plan.count("skip"),
		Warnings: truncateList(plan.Warnings, dnsStatusMax)}
	if err != nil {
		st.Errors = []string{err.Error()}
	}
	for _, w := range plan.Warnings {
		if ss.failed && strings.HasPrefix(w, "provider ") && len(st.Errors) < dnsStatusMax {
			st.Errors = append(st.Errors, w)
		}
	}
	if ss.failed && err == nil && len(st.Errors) == 0 {
		st.Errors = []string{"a provider or zone could not be read; see warnings"}
	}
	writeDNSStatus(st)
	if err == nil && ss.failed {
		err = errors.New(strings.Join(st.Errors, "; "))
	}
	return plan, err
}

func truncateList(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// ---- the daemon ----

const (
	dnsSyncEvery = 5 * time.Minute  // a full reconcile even when nothing was announced
	dnsPollEvery = 10 * time.Second // how often the loop looks for a route or domain change
	dnsRetryAt   = time.Minute      // after a failed reconcile
)

// dnsLoop reconciles when the gateway's Epoch moves and every dnsSyncEvery. leader gates it: in a
// cluster only the leader writes, so there is exactly one writer. The funcs are seams for tests.
type dnsLoop struct {
	store    func() (routeStore, error)
	leader   func() bool
	sync     func(s routeStore) (DNSPlan, error)
	now      func() time.Time
	lastRun  time.Time
	nextTry  time.Time
	lastEp   int
	failing  bool
	announce func(err error)
}

// tick runs one look and reports whether it reconciled.
func (l *dnsLoop) tick() bool {
	if !l.leader() {
		return false
	}
	s, err := l.store()
	if err != nil {
		return false
	}
	d, err := s.read()
	if err != nil || len(d.DNSCloud.Providers) == 0 {
		return false
	}
	now := l.now()
	due := d.DNSCloud.Epoch != l.lastEp || now.Sub(l.lastRun) >= dnsSyncEvery
	if !due || now.Before(l.nextTry) {
		return false
	}
	_, err = l.sync(s)
	if err != nil {
		// Stay due (the epoch is not recorded), so the retry comes after dnsRetryAt rather than at
		// the next full interval.
		l.lastRun, l.lastEp = time.Time{}, -1
		l.nextTry = now.Add(dnsRetryAt)
		l.failing = true
		l.announce(err)
		return true
	}
	l.lastRun, l.lastEp = now, d.DNSCloud.Epoch
	l.nextTry, l.failing = time.Time{}, false
	return true
}

// socketIsLeader asks this host's cluster-master whether it is the Raft leader. Before the control
// plane runs Raft (a single master from an older release) the master is the leader.
func socketIsLeader() bool {
	if !raftMode() {
		return true
	}
	var out struct {
		Leader bool `json:"leader"`
	}
	_, err := socketCall("GET", "/leader", nil, &out)
	return err == nil && out.Leader
}

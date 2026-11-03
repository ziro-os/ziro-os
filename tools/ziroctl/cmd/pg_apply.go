package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Declarative clusters (`ziroctl pg apply -f shop.yaml`, RFC 0005 "Declarative clusters"). The file
// describes a cluster as it should be (schema.PostgresConfig). Planning runs the same operations as the
// pg commands (pgCreate, pgSetReplicas, pgSetParams, pgBackupEnable, ...) against a copy of the cluster
// state, so the plan reports exactly what an apply would do and what it would refuse; applying runs
// them against the real state in one transaction, all or nothing. A field left out of the file keeps
// its current value, and applying the same file twice changes nothing.

type PostgresConfig = schema.PostgresConfig

// pgChange is one line of a plan.
type pgChange struct {
	Section string `json:"section"`
	Item    string `json:"item,omitempty"`
	Action  string `json:"action"` // create, update, unchanged, remove, refused
	Detail  string `json:"detail,omitempty"`
}

// pgPlan is what applying a file does to one cluster.
type pgPlan struct {
	Cluster string     `json:"cluster"`
	Changes []pgChange `json:"changes"`
	Applied bool       `json:"applied"`
}

func (p *pgPlan) refused() []string {
	var out []string
	for _, c := range p.Changes {
		if c.Action == "refused" {
			out = append(out, c.Section+": "+c.Detail)
		}
	}
	return out
}

func (p *pgPlan) changed() bool {
	for _, c := range p.Changes {
		if c.Action != "unchanged" {
			return true
		}
	}
	return false
}

// pgApplyKeys are the backup repository's keys for a file that turns backups on (never in the file).
type pgApplyKeys struct{ KeyID, Secret string }

// pgPlanner records the changes while it makes them.
type pgPlanner struct {
	st   *ClusterState
	now  time.Time
	name string
	plan *pgPlan
}

// step runs one operation and records it; a failed operation is recorded as refused.
func (p *pgPlanner) step(section, item, action, detail string, op func() error) {
	ch := pgChange{Section: section, Item: item, Action: action, Detail: detail}
	if op != nil {
		if err := op(); err != nil {
			ch.Action, ch.Detail = "refused", err.Error()
		}
	}
	p.plan.Changes = append(p.plan.Changes, ch)
}

func (p *pgPlanner) same(section, item string) { p.step(section, item, "unchanged", "", nil) }

func (p *pgPlanner) refuse(section, detail string) { p.step(section, "", "refused", detail, nil) }

// pgApplySpec reconciles st toward the file: it creates the cluster if it does not exist, then brings
// each field the file sets to its value. It changes st; callers plan on a copy.
func pgApplySpec(st *ClusterState, cfg PostgresConfig, keys pgApplyKeys, now time.Time) *pgPlan {
	s := cfg.Postgres
	p := &pgPlanner{st: st, now: now, name: s.Name, plan: &pgPlan{Cluster: s.Name, Changes: []pgChange{}}}
	c := st.PG[s.Name]
	if c == nil {
		o := pgCreateOpts{Name: s.Name, Version: s.PGVersion, Image: s.Image, Replicas: 2, Sync: s.Sync, Shards: s.Shards,
			Citus: s.CitusImage, Resources: s.Resources, Database: s.Database, User: s.User, AllowFrom: s.AllowFrom}
		if s.Replicas != nil {
			o.Replicas = *s.Replicas
		}
		if s.Colocate != nil {
			o.Colocate = *s.Colocate
		}
		if s.Pooler != nil && !s.Pooler.Enabled {
			o.NoPooler = true
		}
		var err error
		c, err = pgCreate(st, o, now)
		if err != nil {
			p.refuse("cluster", err.Error())
			return p.plan
		}
		detail := fmt.Sprintf("postgres %s, %d replica(s) per group, %s replication", c.Version, c.Replicas, c.Sync)
		if c.Citus != "" {
			detail += fmt.Sprintf(", %d shard(s)", len(c.Groups)-1)
		}
		p.step("cluster", c.Name, "create", detail, nil)
	} else {
		p.immutable(c, s)
	}
	p.reconcile(c, s, keys)
	return p.plan
}

// immutable refuses changes to what is fixed at creation.
func (p *pgPlanner) immutable(c *PGCluster, s schema.PostgresSpec) {
	check := func(field, want, cur, why string) {
		if want != "" && want != cur {
			p.refuse(field, fmt.Sprintf("%s -> %s: %s", cur, want, why))
		}
	}
	check("postgres", s.PGVersion, c.Version, "a major upgrade is a dump and restore into a new cluster")
	check("sync", s.Sync, c.Sync, "set at creation")
	check("database", s.Database, c.Database, "set at creation")
	check("user", s.User, c.User, "set at creation")
	if s.Colocate != nil && *s.Colocate != c.Colocate {
		p.refuse("colocate", "set at creation")
	}
	shards := 0
	if c.Citus != "" {
		shards = len(c.Groups) - 1
	}
	switch {
	case s.Shards == 0 && shards == 0:
	case shards == 0:
		p.refuse("shards", "a plain cluster cannot become a sharded one: create a new cluster")
	case s.Shards < shards:
		p.refuse("shards", fmt.Sprintf("%d -> %d: worker groups cannot be removed yet", shards, s.Shards))
	case s.Shards > shards:
		for i := shards; i < s.Shards; i++ {
			var g string
			p.step("shards", "", "create", "", func() error {
				var err error
				g, err = pgAddShard(p.st, c.Name, p.now)
				return err
			})
			p.plan.Changes[len(p.plan.Changes)-1].Item = g
		}
	default:
		p.same("shards", strconv.Itoa(shards))
	}
}

// reconcile brings every field the file sets to its value.
func (p *pgPlanner) reconcile(c *PGCluster, s schema.PostgresSpec, keys pgApplyKeys) {
	name := c.Name
	// The image first: turning backups on needs one with pgBackRest.
	img, cur := s.Image, c.Image
	if c.Citus != "" {
		img, cur = s.CitusImage, c.Citus
	}
	switch {
	case img == "":
	case img == cur:
		p.same("image", img)
	default:
		p.step("image", img, "update", "rolling restart: "+cur+" -> "+img, func() error { return pgUpgradeImage(p.st, name, img) })
	}
	if s.Replicas != nil {
		if *s.Replicas == c.Replicas {
			p.same("replicas", strconv.Itoa(c.Replicas))
		} else {
			from := c.Replicas
			p.step("replicas", strconv.Itoa(*s.Replicas), "update", fmt.Sprintf("%d -> %d per group", from, *s.Replicas),
				func() error { return pgSetReplicas(p.st, name, *s.Replicas) })
		}
	}
	if s.Resources != nil {
		want := s.Resources
		if *want == (Resources{}) {
			want = nil
		}
		if reflect.DeepEqual(want, c.Resources) {
			p.same("resources", pgResourcesLabel(c.Resources))
		} else {
			p.step("resources", pgResourcesLabel(want), "update", "rolling restart, from "+pgResourcesLabel(c.Resources),
				func() error { return pgResize(p.st, name, want) })
		}
	}
	if s.AllowFrom != nil {
		want := append([]string{}, s.AllowFrom...)
		sort.Strings(want)
		have := append([]string{}, c.AllowFrom...)
		sort.Strings(have)
		if strings.Join(want, ",") == strings.Join(have, ",") {
			p.same("allow_from", strings.Join(want, ", "))
		} else {
			p.step("allow_from", strings.Join(want, ", "), "update", "from "+strings.Join(have, ", "), func() error {
				c.AllowFrom = want
				return c.Validate()
			})
		}
	}
	if s.Params != nil {
		p.params(c, s.Params)
	}
	if pl := s.Pooler; pl != nil {
		want := PGPooler{Enabled: pl.Enabled, Mode: pl.Mode, Size: pl.Size}
		have := PGPooler{Mode: "transaction", Size: 20}
		if c.Pooler != nil {
			have = *c.Pooler
		}
		if want.Mode == "" {
			want.Mode = have.Mode
		}
		if want.Size == 0 {
			want.Size = have.Size
		}
		want.Image = have.Image
		label := func(x PGPooler) string {
			if !x.Enabled {
				return "off"
			}
			return fmt.Sprintf("%s, %d", x.Mode, x.Size)
		}
		if want == have {
			p.same("pooler", label(have))
		} else {
			action := "update"
			if want.Enabled && !have.Enabled {
				action = "create"
			} else if !want.Enabled {
				action = "remove"
			}
			p.step("pooler", label(want), action, "from "+label(have), func() error {
				return pgSetPooler(p.st, name, &want.Enabled, want.Mode, want.Size)
			})
		}
	}
	if b := s.Backup; b != nil {
		p.backup(c, b, keys)
	}
	if m := s.Maintenance; m != nil {
		var want *PGMaintenance
		if m.Window != "" {
			want = &PGMaintenance{Window: m.Window, Duration: m.Duration}
			if want.Duration == "" {
				want.Duration = "2h"
			}
		}
		label := func(x *PGMaintenance) string {
			if x == nil {
				return "none"
			}
			return x.Window + " for " + x.Duration
		}
		switch {
		case reflect.DeepEqual(want, c.Maintenance):
			p.same("maintenance", label(want))
		case want == nil:
			p.step("maintenance", "", "remove", "changes roll out at once", func() error { return pgSetMaintenance(p.st, name, "", "") })
		default:
			action := "update"
			if c.Maintenance == nil {
				action = "create"
			}
			p.step("maintenance", label(want), action, "from "+label(c.Maintenance), func() error {
				return pgSetMaintenance(p.st, name, want.Window, want.Duration)
			})
		}
	}
	if s.Roles != nil || s.Databases != nil {
		p.rolesAndDatabases(c, s)
	}
	if s.Paused != nil {
		if *s.Paused == c.Paused {
			p.same("paused", strconv.FormatBool(c.Paused))
		} else {
			p.step("paused", strconv.FormatBool(*s.Paused), "update", "", func() error {
				c.Paused = *s.Paused
				return nil
			})
		}
	}
}

// pgPendingOp is a role or database change waiting for the ones it depends on.
type pgPendingOp struct {
	change pgChange
	op     func() error
	err    error
}

// rolesAndDatabases sets the file's roles and databases. A role may connect to a database the file adds,
// and a database may be owned by a role the file adds, so the changes run in rounds until none can make
// progress; what is left is refused with its reason.
func (p *pgPlanner) rolesAndDatabases(c *PGCluster, s schema.PostgresSpec) {
	var ops []*pgPendingOp
	add := func(section, item, action, detail string, op func() error) {
		ops = append(ops, &pgPendingOp{change: pgChange{Section: section, Item: item, Action: action, Detail: detail}, op: op})
	}
	if s.Databases != nil {
		want := map[string]bool{}
		for _, d := range s.Databases {
			want[d.Name] = true
			d := PGDatabase{Name: d.Name, Owner: d.Owner, Extensions: append([]string{}, d.Extensions...)}
			sort.Strings(d.Extensions)
			d.Extensions = slices.Compact(d.Extensions)
			label := pgDatabaseLabel(c, d)
			cur := c.database(d.Name)
			switch {
			case cur != nil && pgDatabaseLabel(c, *cur) == label:
				p.same("database", d.Name+" ("+label+")")
			case cur != nil:
				add("database", d.Name+" ("+label+")", "update", "from "+pgDatabaseLabel(c, *cur), func() error { return pgSetDatabase(p.st, c.Name, d) })
			default:
				add("database", d.Name+" ("+label+")", "create", "", func() error { return pgSetDatabase(p.st, c.Name, d) })
			}
		}
		for _, d := range slices.Clone(c.Databases) {
			if !want[d.Name] {
				add("database", d.Name, "remove", "no longer managed; the database is kept", func() error { return pgRemoveDatabase(p.st, c.Name, d.Name) })
			}
		}
	}
	if s.Roles != nil {
		want := map[string]bool{}
		for _, r := range s.Roles {
			want[r.Name] = true
			r := PGRole{Name: r.Name, Access: r.Access, Database: r.Database}
			if r.Access == "" {
				r.Access = "readwrite"
			}
			label := r.Access
			if r.Database != "" {
				label += ", " + r.Database
			}
			cur := c.role(r.Name)
			switch {
			case cur != nil && *cur == r:
				p.same("role", r.Name+" ("+label+")")
			case cur != nil:
				add("role", r.Name+" ("+label+")", "update", "", func() error { return pgSetRole(p.st, c.Name, r) })
			default:
				add("role", r.Name+" ("+label+")", "create", "a generated password in secret "+c.roleSecret(r.Name), func() error { return pgSetRole(p.st, c.Name, r) })
			}
		}
		for _, r := range slices.Clone(c.Roles) {
			if !want[r.Name] {
				add("role", r.Name, "remove", "it can no longer log in; its objects stay", func() error { return pgRemoveRole(p.st, c.Name, r.Name) })
			}
		}
	}
	for progress := true; progress; {
		progress = false
		for _, o := range ops {
			if o.op == nil {
				continue
			}
			if o.err = o.op(); o.err == nil {
				p.plan.Changes = append(p.plan.Changes, o.change)
				o.op, progress = nil, true
			}
		}
	}
	for _, o := range ops {
		if o.op != nil {
			o.change.Action, o.change.Detail = "refused", o.err.Error()
			p.plan.Changes = append(p.plan.Changes, o.change)
		}
	}
}

func pgDatabaseLabel(c *PGCluster, d PGDatabase) string {
	owner := d.Owner
	if owner == "" {
		owner = c.User
	}
	l := "owner " + owner
	if len(d.Extensions) > 0 {
		l += ", " + strings.Join(d.Extensions, ", ")
	}
	return l
}

// params sets the file's parameters exactly: one left out goes back to its default.
func (p *pgPlanner) params(c *PGCluster, want map[string]string) {
	names := map[string]bool{}
	for k := range want {
		names[k] = true
	}
	for k := range c.Params {
		names[k] = true
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, ok := want[k]
		cur, had := c.Params[k]
		switch {
		case ok && had && v == cur:
			p.same("param", k+"="+v)
		case ok:
			action, detail := "create", ""
			if had {
				action, detail = "update", "from "+cur
			}
			if d, known := pgParamDefs[k]; known && d.kind == pgRestart {
				detail = strings.TrimSpace(detail + " (rolling restart)")
			}
			p.step("param", k+"="+v, action, detail, func() error { return pgSetParams(p.st, c.Name, map[string]string{k: v}) })
		default:
			p.step("param", k, "remove", "back to the default (was "+cur+")", func() error {
				return pgSetParams(p.st, c.Name, map[string]string{k: ""})
			})
		}
	}
}

// backup turns backups on or off, or changes the repository and schedule. The keys stay unless the
// command that applies the file has new ones.
func (p *pgPlanner) backup(c *PGCluster, b *schema.PostgresBackup, keys pgApplyKeys) {
	if b.Enabled != nil && !*b.Enabled {
		if c.Backup == nil {
			p.same("backup", "off")
			return
		}
		p.step("backup", "", "remove", "archiving and the schedule stop; the backups stay in the bucket",
			func() error { return pgBackupDisable(p.st, c.Name) })
		return
	}
	want := PGBackup{Endpoint: b.Endpoint, Bucket: b.Bucket, Region: b.Region, Path: b.Path, URIStyle: b.URIStyle,
		NoVerifyTLS: b.NoVerifyTLS, Retention: b.Retention}
	if want.Region == "" {
		want.Region = "us-east-1"
	}
	if want.Path == "" {
		want.Path = "/ziro"
	}
	if want.Retention == 0 {
		want.Retention = 4
	}
	want.Full, want.Diff, want.Incr = "0 1 * * 0", "0 1 * * 1-6", "30 * * * *"
	if sc := b.Schedule; sc != nil {
		if sc.Full != "" {
			want.Full = sc.Full
		}
		if sc.Diff != "" {
			want.Diff = sc.Diff
		}
		if sc.Incr != "" {
			want.Incr = sc.Incr
		}
	}
	repo := "s3://" + want.Bucket + strings.TrimRight(want.Path, "/") + "/" + c.Name
	if c.Backup != nil {
		have := *c.Backup
		have.Restore = nil
		if want.URIStyle == "" {
			want.URIStyle = have.URIStyle
		}
		if reflect.DeepEqual(want, have) && keys.KeyID == "" {
			p.same("backup", repo)
			return
		}
	}
	action, detail := "update", "the repository or schedule changes"
	if c.Backup == nil {
		action, detail = "create", "WAL archiving starts with a rolling restart, then the first full backup"
	}
	p.step("backup", repo, action, detail, func() error {
		return pgBackupEnable(p.st, c.Name, want, keys.KeyID, keys.Secret, "")
	})
}

func pgResourcesLabel(r *Resources) string {
	if r == nil {
		return "no limits"
	}
	var parts []string
	if r.Memory != "" {
		parts = append(parts, "memory "+r.Memory)
	}
	if r.CPUs > 0 {
		parts = append(parts, "cpus "+strconv.FormatFloat(r.CPUs, 'f', -1, 64))
	}
	if r.PIDs > 0 {
		parts = append(parts, "pids "+strconv.Itoa(r.PIDs))
	}
	if len(parts) == 0 {
		return "no limits"
	}
	return strings.Join(parts, ", ")
}

// pgSpecOf is the file that describes a cluster as it is (pg get): applying it changes nothing.
func pgSpecOf(c *PGCluster) PostgresConfig {
	s := schema.PostgresSpec{Version: 1, Name: c.Name, PGVersion: c.Version, Image: c.Image, Sync: c.Sync, Database: c.Database, User: c.User}
	replicas, paused, colocate := c.Replicas, c.Paused, c.Colocate
	s.Replicas, s.Paused, s.Colocate = &replicas, &paused, &colocate
	if c.Citus != "" {
		s.Shards, s.CitusImage = len(c.Groups)-1, c.Citus
	}
	s.Resources = &Resources{}
	if c.Resources != nil {
		r := *c.Resources
		s.Resources = &r
	}
	s.AllowFrom = append([]string{}, c.AllowFrom...)
	s.Params = map[string]string{}
	for k, v := range c.Params {
		s.Params[k] = v
	}
	s.Pooler = &schema.PostgresPooler{}
	if p := c.Pooler; p != nil {
		s.Pooler = &schema.PostgresPooler{Enabled: p.Enabled, Mode: p.Mode, Size: p.Size}
	}
	off := false
	s.Backup = &schema.PostgresBackup{Enabled: &off}
	if b := c.Backup; b != nil {
		on := true
		s.Backup = &schema.PostgresBackup{Enabled: &on, Endpoint: b.Endpoint, Bucket: b.Bucket, Region: b.Region, Path: b.Path,
			URIStyle: b.URIStyle, NoVerifyTLS: b.NoVerifyTLS, Retention: b.Retention,
			Schedule: &schema.PostgresBackupSchedule{Full: b.Full, Diff: b.Diff, Incr: b.Incr}}
	}
	s.Maintenance = &schema.PostgresMaintenance{}
	if m := c.Maintenance; m != nil {
		s.Maintenance = &schema.PostgresMaintenance{Window: m.Window, Duration: m.Duration}
	}
	s.Roles = []schema.PostgresRole{}
	for _, r := range c.Roles {
		s.Roles = append(s.Roles, schema.PostgresRole{Name: r.Name, Access: r.Access, Database: r.Database})
	}
	s.Databases = []schema.PostgresDatabase{}
	for _, d := range c.Databases {
		s.Databases = append(s.Databases, schema.PostgresDatabase{Name: d.Name, Owner: d.Owner, Extensions: append([]string{}, d.Extensions...)})
	}
	return PostgresConfig{Postgres: s}
}

// pgCloneState is a deep copy of the state to plan on.
func pgCloneState(st *ClusterState) (*ClusterState, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	var cp ClusterState
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

// pgPlanFile plans a file without changing anything.
func pgPlanFile(st *ClusterState, cfg PostgresConfig, keys pgApplyKeys, now time.Time) (*pgPlan, error) {
	cp, err := pgCloneState(st)
	if err != nil {
		return nil, err
	}
	return pgApplySpec(cp, cfg, keys, now), nil
}

// pgApplyFile applies a file in one transaction: nothing changes if any part is refused.
func pgApplyFile(cfg PostgresConfig, keys pgApplyKeys, audit string) (*pgPlan, error) {
	var plan *pgPlan
	err := withState(func(st *ClusterState) error {
		plan = pgApplySpec(st, cfg, keys, time.Now())
		if r := plan.refused(); len(r) > 0 {
			return fmt.Errorf("nothing was changed, the file asks for what cannot be done: %s", strings.Join(r, "; "))
		}
		return nil
	})
	if err == nil {
		plan.Applied = true
	}
	_ = auditLog("cli", "cli", audit, cfg.Postgres.Name, err)
	return plan, err
}

// ---- commands ----

var pgApplyFlags struct {
	file, output string
	dryRun       bool
}

func pgReadFile(path string) (PostgresConfig, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return PostgresConfig{}, err
	}
	if kind, _ := schema.Kind(b); kind != "postgres" {
		return PostgresConfig{}, fmt.Errorf("%s is not a postgres file (a top-level postgres: section)", path)
	}
	return schema.ParsePostgresConfig(b)
}

func printPGPlan(p *pgPlan) {
	sym := map[string]string{"create": "+", "update": "~", "unchanged": "=", "remove": "-", "refused": "!"}
	fmt.Printf("postgres cluster %s:\n", p.Cluster)
	for _, c := range p.Changes {
		line := fmt.Sprintf("  %s %-12s %s", sym[c.Action], c.Section, c.Item)
		if c.Detail != "" {
			line += "  (" + c.Detail + ")"
		}
		fmt.Println(strings.TrimRight(line, " "))
	}
}

var pgApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Create or change a cluster from a file",
	Long: `Brings a cluster to what a file describes (a top-level postgres: section; see docs/postgres.md, "Declarative
clusters"): it creates the cluster if it does not exist, then changes what differs. It prints the plan first
(+ create, ~ update, = unchanged, - remove, ! refused); --dry-run stops there. The whole file applies in one
step or not at all: if any part is refused (a different major version, fewer shards), nothing changes. A field
left out keeps its current value. Backup keys come from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.`,
	Example: "  ziroctl pg apply -f shop.yaml --dry-run\n  ziroctl pg apply -f shop.yaml\n  ziroctl pg get shop > shop.yaml",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pgApplyFlags.file == "" {
			return fmt.Errorf("-f <file> is required")
		}
		cfg, err := pgReadFile(pgApplyFlags.file)
		if err != nil {
			return err
		}
		if _, err := requireMaster(); err != nil {
			return err
		}
		keys := pgApplyKeys{KeyID: os.Getenv("AWS_ACCESS_KEY_ID"), Secret: os.Getenv("AWS_SECRET_ACCESS_KEY")}
		if pgApplyFlags.dryRun {
			st, err := readState()
			if err != nil {
				return err
			}
			plan, err := pgPlanFile(st, cfg, keys, time.Now())
			if err != nil {
				return err
			}
			if err := printResult(plan, func() { printPGPlan(plan) }); err != nil {
				return err
			}
			if r := plan.refused(); len(r) > 0 {
				return fmt.Errorf("the file asks for what cannot be done: %s", strings.Join(r, "; "))
			}
			return nil
		}
		plan, err := pgApplyFile(cfg, keys, "pg apply")
		if plan != nil {
			if perr := printResult(plan, func() { printPGPlan(plan) }); perr != nil {
				return perr
			}
		}
		if err != nil {
			return err
		}
		if !jsonOutput {
			if plan.changed() {
				fmt.Printf("✓ applied. Follow it with: ziroctl pg status %s\n", plan.Cluster)
			} else {
				fmt.Println("✓ nothing to change")
			}
		}
		return nil
	},
}

var pgDiffCmd = &cobra.Command{
	Use:     "diff",
	Short:   "Show what applying a file would change",
	Long:    `The same as pg apply --dry-run: prints the plan for a file and changes nothing.`,
	Example: "  ziroctl pg diff -f shop.yaml",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pgApplyFlags.dryRun = true
		return pgApplyCmd.RunE(cmd, args)
	},
}

var pgGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Print a cluster as a file for pg apply",
	Long: `Prints the cluster as a declarative file (YAML, or JSON with -o json): every setting it has now. Applying it
changes nothing; edit it and apply it to change the cluster. No secret is in it.`,
	Example: "  ziroctl pg get shop > shop.yaml\n  ziroctl pg get shop -o json",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		c, err := pgCluster(st, args[0])
		if err != nil {
			return err
		}
		spec := pgSpecOf(c)
		if jsonOutput || pgApplyFlags.output == "json" {
			b, err := json.MarshalIndent(spec, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		if pgApplyFlags.output != "" && pgApplyFlags.output != "yaml" {
			return fmt.Errorf("-o: yaml or json")
		}
		b, err := schema.ToYAML(spec)
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil
	},
}

// registerPGApplyRoutes: GET /api/v1/pg/{name}/spec (viewer), POST /api/v1/pg-plan (operator: it changes
// nothing, but planning changes is an operator's job) and POST /api/v1/pg-apply (admin: it can create a
// cluster and change its backups).
func registerPGApplyRoutes(a *apiRouter) {
	a.get("/api/v1/pg/{name}/spec", "viewer", func(w http.ResponseWriter, r *http.Request) {
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		c, err := pgCluster(st, r.PathValue("name"))
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, pgSpecOf(c))
	})
	type applyReq struct {
		Spec            json.RawMessage `json:"spec"`
		AccessKeyID     string          `json:"access_key_id"`
		SecretAccessKey string          `json:"secret_access_key"`
	}
	read := func(w http.ResponseWriter, r *http.Request) (PostgresConfig, pgApplyKeys, bool) {
		var req applyReq
		if err := decodeStrict(w, r, &req, 256<<10); err != nil {
			apiReply(w, err, nil)
			return PostgresConfig{}, pgApplyKeys{}, false
		}
		cfg, err := schema.ParsePostgresConfig(req.Spec)
		if err != nil {
			apiReply(w, fmt.Errorf("spec: %v", err), nil)
			return PostgresConfig{}, pgApplyKeys{}, false
		}
		return cfg, pgApplyKeys{KeyID: req.AccessKeyID, Secret: req.SecretAccessKey}, true
	}
	a.post("/api/v1/pg-plan", "operator", func(w http.ResponseWriter, r *http.Request) {
		cfg, keys, ok := read(w, r)
		if !ok {
			return
		}
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		plan, err := pgPlanFile(st, cfg, keys, time.Now())
		apiReply(w, err, plan)
	})
	a.post("/api/v1/pg-apply", "admin", func(w http.ResponseWriter, r *http.Request) {
		cfg, keys, ok := read(w, r)
		if !ok {
			return
		}
		var plan *pgPlan
		err := withState(func(st *ClusterState) error {
			plan = pgApplySpec(st, cfg, keys, time.Now())
			if rf := plan.refused(); len(rf) > 0 {
				return fmt.Errorf("nothing was changed, the spec asks for what cannot be done: %s", strings.Join(rf, "; "))
			}
			return nil
		})
		if err == nil {
			plan.Applied = true
		}
		apiReply(w, err, plan)
	})
}

func init() {
	for _, c := range []*cobra.Command{pgApplyCmd, pgDiffCmd} {
		c.Flags().StringVarP(&pgApplyFlags.file, "file", "f", "", "The cluster file (YAML or JSON; - reads stdin)")
	}
	pgApplyCmd.Flags().BoolVar(&pgApplyFlags.dryRun, "dry-run", false, "Print the plan and change nothing")
	pgGetCmd.Flags().StringVarP(&pgApplyFlags.output, "output", "o", "yaml", "yaml or json")
	pgCmd.AddCommand(pgApplyCmd, pgDiffCmd, pgGetCmd)
}

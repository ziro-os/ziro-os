package schema

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PostgresConfig is a declarative Postgres cluster for `ziroctl pg apply -f`: a top-level `postgres:`
// section (RFC 0005, "Declarative clusters"). The file describes the cluster as it should be; ziroctl
// plans the difference against the running cluster and applies it with the same operations as the
// pg commands. Secrets never go in the file: passwords are generated, and the backup repository's keys
// come from the environment of the command that applies it.
type PostgresConfig struct {
	Postgres PostgresSpec `json:"postgres"`
}

// PostgresSpec is one cluster. A field left out keeps its current value (its default when the cluster is
// created), so a short file never scales a cluster down or resumes it by accident. Fields marked "at
// creation" cannot change later: a different value is refused in the plan. params and allow_from, when
// given, are the whole list: a parameter left out goes back to its default.
type PostgresSpec struct {
	Version    int    `json:"version"`               // file format, 1
	Name       string `json:"name"`                  // 1-16 lower-case letters and digits
	PGVersion  string `json:"postgres,omitempty"`    // major version, at creation: 16, 17 or 18 (default 17)
	Image      string `json:"image,omitempty"`       // member image pinned by digest (default: the built-in one)
	Replicas   *int   `json:"replicas,omitempty"`    // replicas per group (default 2)
	Sync       string `json:"sync,omitempty"`        // quorum (default) or off, at creation
	Shards     int    `json:"shards,omitempty"`      // Citus worker groups; set at creation, then can only grow
	CitusImage string `json:"citus_image,omitempty"` // with shards: the Citus member image, pinned by digest
	Database   string `json:"database,omitempty"`    // the application database, at creation (default app)
	User       string `json:"user,omitempty"`        // its owner, at creation (default app)
	Colocate   *bool  `json:"colocate,omitempty"`    // members of a group may share a node (development), at creation

	Resources   *Resources           `json:"resources,omitempty"`   // per member
	AllowFrom   []string             `json:"allow_from,omitempty"`  // apps allowed to connect
	Params      map[string]string    `json:"params,omitempty"`      // server parameters (ziroctl pg set)
	Pooler      *PostgresPooler      `json:"pooler,omitempty"`      // new clusters: on, transaction mode, 20
	Backup      *PostgresBackup      `json:"backup,omitempty"`      // new clusters: none
	Maintenance *PostgresMaintenance `json:"maintenance,omitempty"` // new clusters: none, changes roll out at once
	Paused      *bool                `json:"paused,omitempty"`      // the controller leaves roles alone
	Roles       []PostgresRole       `json:"roles,omitempty"`       // login roles for apps; the whole list when given
	Databases   []PostgresDatabase   `json:"databases,omitempty"`   // managed databases; the whole list when given
}

// PostgresRole is a login role for apps, with a generated password in its own cluster secret. A role
// left out of a list that is given can no longer log in; its objects stay.
type PostgresRole struct {
	Name     string `json:"name"`
	Access   string `json:"access,omitempty"`   // readwrite (default) or readonly
	Database string `json:"database,omitempty"` // the database its connection strings name (default: the cluster's)
}

// PostgresDatabase is a database the cluster creates and keeps: its owner and extensions. A database
// left out of a list that is given is no longer managed; it is never dropped.
type PostgresDatabase struct {
	Name       string   `json:"name"`
	Owner      string   `json:"owner,omitempty"` // a role, or the application user (default)
	Extensions []string `json:"extensions,omitempty"`
}

// PostgresPooler is the PgBouncer in front of the cluster.
type PostgresPooler struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // transaction (default) or session
	Size    int    `json:"size,omitempty"` // server connections per database and user (default 20)
}

// PostgresBackup is the backup repository and schedule. The keys are not here: they come from
// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY when the file is applied (or stay as they are).
type PostgresBackup struct {
	Enabled     *bool                   `json:"enabled,omitempty"` // false turns backups off (the bucket keeps them)
	Endpoint    string                  `json:"endpoint,omitempty"`
	Bucket      string                  `json:"bucket,omitempty"`
	Region      string                  `json:"region,omitempty"`    // default us-east-1
	Path        string                  `json:"path,omitempty"`      // default /ziro
	URIStyle    string                  `json:"uri_style,omitempty"` // host (default) or path
	NoVerifyTLS bool                    `json:"no_verify_tls,omitempty"`
	Retention   int                     `json:"retention,omitempty"` // full backups kept (default 4)
	Schedule    *PostgresBackupSchedule `json:"schedule,omitempty"`
}

// PostgresBackupSchedule holds cron expressions in UTC; absent ones take the defaults.
type PostgresBackupSchedule struct {
	Full string `json:"full,omitempty"`
	Diff string `json:"diff,omitempty"`
	Incr string `json:"incr,omitempty"`
}

// PostgresMaintenance is when changes that restart members may roll out: a window that opens on a cron
// schedule (UTC) and stays open for Duration. Failover and repairs never wait for it. An empty one
// (`maintenance: {}`) removes the window.
type PostgresMaintenance struct {
	Window   string `json:"window,omitempty"`   // cron, UTC: "0 2 * * 0" opens at 02:00 on Sundays
	Duration string `json:"duration,omitempty"` // how long it stays open: 30m to 24h (default 2h)
}

var (
	pgClusterNameRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
	pgIdentRe       = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	cronFieldsRe    = regexp.MustCompile(`^[0-9*/,\- ]+$`)
	pgParamNameRe   = regexp.MustCompile(`^[a-z_][a-z0-9_.]{0,62}$`)
	pgExtensionRe   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

// ParsePostgresConfig reads a declarative Postgres file (YAML or JSON) strictly and checks its shape.
// The values that depend on the cluster (parameters, images, the schedule) are checked when applied.
func ParsePostgresConfig(b []byte) (PostgresConfig, error) {
	var c PostgresConfig
	if err := DecodeStrict(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func (c PostgresConfig) Validate() error {
	s := c.Postgres
	if s.Version != 1 {
		return fmt.Errorf("unsupported postgres file version %d (want 1)", s.Version)
	}
	if !pgClusterNameRe.MatchString(s.Name) {
		return fmt.Errorf("name %q: 1-16 lower-case letters and digits, starting with a letter", s.Name)
	}
	if s.PGVersion != "" && s.PGVersion != "16" && s.PGVersion != "17" && s.PGVersion != "18" {
		return fmt.Errorf("postgres: 16, 17 or 18")
	}
	for field, img := range map[string]string{"image": s.Image, "citus_image": s.CitusImage} {
		if img != "" && (!strings.Contains(img, "@sha256:") || strings.ContainsAny(img, " \t\r\n") || len(img) > 512) {
			return fmt.Errorf("%s must be pinned by digest (name:tag@sha256:...)", field)
		}
	}
	if s.Replicas != nil && (*s.Replicas < 0 || *s.Replicas > 8) {
		return fmt.Errorf("replicas: 0-8")
	}
	if s.Sync != "" && s.Sync != "quorum" && s.Sync != "off" {
		return fmt.Errorf("sync: quorum or off")
	}
	if s.Shards < 0 || s.Shards > 32 {
		return fmt.Errorf("shards: 0-32")
	}
	if s.Shards > 0 && s.CitusImage == "" {
		return fmt.Errorf("shards need citus_image")
	}
	for field, id := range map[string]string{"database": s.Database, "user": s.User} {
		if id != "" && !pgIdentRe.MatchString(id) {
			return fmt.Errorf("%s %q: a lower-case identifier", field, id)
		}
	}
	if err := s.Resources.Validate(); err != nil {
		return fmt.Errorf("resources: %w", err)
	}
	for _, a := range s.AllowFrom {
		if err := ValidName(a); err != nil {
			return fmt.Errorf("allow_from: %w", err)
		}
	}
	for k := range s.Params {
		if !pgParamNameRe.MatchString(k) {
			return fmt.Errorf("params: bad parameter name %q", k)
		}
	}
	if p := s.Pooler; p != nil {
		if p.Mode != "" && p.Mode != "transaction" && p.Mode != "session" {
			return fmt.Errorf("pooler.mode: transaction or session")
		}
		if p.Size < 0 || p.Size > 500 {
			return fmt.Errorf("pooler.size: 1-500")
		}
	}
	if b := s.Backup; b != nil && (b.Enabled == nil || *b.Enabled) {
		if b.Endpoint == "" || b.Bucket == "" {
			return fmt.Errorf("backup needs endpoint and bucket")
		}
		if b.URIStyle != "" && b.URIStyle != "host" && b.URIStyle != "path" {
			return fmt.Errorf("backup.uri_style: host or path")
		}
		if b.Retention < 0 || b.Retention > 100 {
			return fmt.Errorf("backup.retention: 1-100")
		}
		if sc := b.Schedule; sc != nil {
			for _, x := range []string{sc.Full, sc.Diff, sc.Incr} {
				if x != "" && (len(strings.Fields(x)) != 5 || !cronFieldsRe.MatchString(x)) {
					return fmt.Errorf("backup.schedule: %q is not a five-field cron expression", x)
				}
			}
		}
	}
	if m := s.Maintenance; m != nil && (m.Window != "" || m.Duration != "") {
		if len(strings.Fields(m.Window)) != 5 || !cronFieldsRe.MatchString(m.Window) {
			return fmt.Errorf("maintenance.window: %q is not a five-field cron expression", m.Window)
		}
		if m.Duration != "" {
			d, err := time.ParseDuration(m.Duration)
			if err != nil || d < 30*time.Minute || d > 24*time.Hour {
				return fmt.Errorf("maintenance.duration: 30m to 24h")
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range s.Roles {
		if !pgIdentRe.MatchString(r.Name) || seen["r:"+r.Name] {
			return fmt.Errorf("roles: invalid or repeated name %q", r.Name)
		}
		seen["r:"+r.Name] = true
		if r.Access != "" && r.Access != "readwrite" && r.Access != "readonly" {
			return fmt.Errorf("role %s: access is readwrite or readonly", r.Name)
		}
		if r.Database != "" && !pgIdentRe.MatchString(r.Database) {
			return fmt.Errorf("role %s: bad database %q", r.Name, r.Database)
		}
	}
	for _, d := range s.Databases {
		if !pgIdentRe.MatchString(d.Name) || seen["d:"+d.Name] {
			return fmt.Errorf("databases: invalid or repeated name %q", d.Name)
		}
		seen["d:"+d.Name] = true
		if d.Owner != "" && !pgIdentRe.MatchString(d.Owner) {
			return fmt.Errorf("database %s: bad owner %q", d.Name, d.Owner)
		}
		for _, e := range d.Extensions {
			if !pgExtensionRe.MatchString(e) {
				return fmt.Errorf("database %s: bad extension name %q", d.Name, e)
			}
		}
	}
	return nil
}

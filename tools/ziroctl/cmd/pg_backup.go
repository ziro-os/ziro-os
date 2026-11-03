package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Backups and point-in-time recovery with pgBackRest, into S3-compatible object storage.
//
// With backups on, every member runs the Ziro Postgres image (the official one plus pgBackRest,
// images/postgres) and archives WAL to the repository as it is written (archive_mode, archive-push with
// an asynchronous spool, at least once a minute while there are writes: archive_timeout). The controller
// takes the backups the schedule asks for on the group's primary: full, differential (changes since the
// last full) and incremental (changes since the last backup), each compressed (zstd) and encrypted
// (AES-256, a passphrase generated per cluster); pgBackRest keeps the configured number of full backups
// and the WAL they need, and expires the rest. Replicas fetch WAL from the repository when their slot no
// longer has it, so a long-lagging replica catches up instead of being rebuilt.
//
// A restore makes a new cluster from the repository: the latest state, or any moment since the oldest
// backup (pg restore). The repository is the copy that survives losing every node, so the restore also
// works when the cluster that wrote it is gone.
//
// Each group is a stanza (main; coord and w1.. for Citus) under <path>/<cluster> in the bucket.
//
// Known limitation: backups run on the primary (pgBackRest's backup from a standby needs its TLS server);
// a sharded (Citus) cluster is backed up per group but restored only group by group, without a common
// restore point; `pgbackrest verify` is not scheduled.

// pgBackupImages are the Ziro Postgres images with pgBackRest, pinned by digest once published by
// .github/workflows/pg-images.yml (scripts/pg-image-digests.sh, after each run that publishes). An
// empty entry would mean the version is not published, and `pg backup enable` would need --image.
var pgBackupImages = map[string]string{
	"16": "ghcr.io/ziro-os/postgres:16-pgbackrest@sha256:a546bed98256d6dd6f4df5cb2b5322022925896dac6ff63637017daf9779ae5a",
	"17": "ghcr.io/ziro-os/postgres:17-pgbackrest@sha256:f26eafe041410bae2105ab08dd4f141a5680884ec89f1e124460e75a0b285fb7",
	"18": "ghcr.io/ziro-os/postgres:18-pgbackrest@sha256:f3944657932a8bbc27d354031697eab5f84d142ff5762aca5157eb3ac7bd2a6f",
}

const (
	pgBackrestConf  = pgConfigMountPoint + "/pgbackrest.conf"
	pgBackrestDir   = pgDataPath + "/ziro-pgbackrest" // logs and the archive spool, on the data volume
	pgBackupTimeout = 12 * time.Hour                  // a backup not finished by then is reported as failed
	pgInfoEvery     = time.Minute
)

// PGBackup is a cluster's backup configuration (the keys are in the cluster secret pg-<name>-backup).
type PGBackup struct {
	Endpoint    string `json:"endpoint"`            // S3 endpoint host, e.g. s3.eu-west-1.amazonaws.com
	Bucket      string `json:"bucket"`              //
	Region      string `json:"region"`              //
	Path        string `json:"path"`                // prefix in the bucket; the cluster's repository is <path>/<cluster>
	URIStyle    string `json:"uri_style,omitempty"` // host (default) or path (MinIO and most others)
	NoVerifyTLS bool   `json:"no_verify_tls,omitempty"`
	Retention   int    `json:"retention"` // full backups kept
	Full        string `json:"full"`      // schedules (cron, UTC)
	Diff        string `json:"diff,omitempty"`
	Incr        string `json:"incr,omitempty"`
	// Restore, set on a cluster created from a repository: where its primary's data comes from.
	Restore *PGRestore `json:"restore,omitempty"`
}

// PGRestore is where a restored cluster comes from.
type PGRestore struct {
	Path   string `json:"path"`             // the source repository (bucket prefix)
	Stanza string `json:"stanza"`           // the source group
	Target string `json:"target,omitempty"` // RFC 3339 time; "" = the latest state
	Secret string `json:"secret"`           // the secret with the source repository's keys
}

// PGGroupBackup is what the controller knows of a group's backups (from its orders and the reports).
type PGGroupBackup struct {
	Stanza  bool                 `json:"stanza,omitempty"`  // the stanza exists in the repository
	Started map[string]time.Time `json:"started,omitempty"` // type -> when the last one was started
	Info    *PGBackupInfo        `json:"info,omitempty"`    // the repository's view, from the primary
	Failed  int64                `json:"failed,omitempty"`  // archive failures last seen (pg_stat_archiver)
	Now     string               `json:"now,omitempty"`     // a backup asked for with pg backup now
}

// PGBackupInfo is the summary of `pgbackrest info` the agent reports.
type PGBackupInfo struct {
	At      time.Time         `json:"at"`
	Running bool              `json:"running,omitempty"`
	Status  string            `json:"status,omitempty"` // pgBackRest's status message ("ok", "no valid backups", ...)
	Backups []PGBackupSummary `json:"backups,omitempty"`
	LastLog string            `json:"last_log,omitempty"` // the last line of the backup log (why one failed)
}

// PGBackupSummary is one backup in the repository.
type PGBackupSummary struct {
	Label string    `json:"label"`
	Type  string    `json:"type"`
	Start time.Time `json:"start"`
	Stop  time.Time `json:"stop"`
	Size  int64     `json:"size"`      // database size
	Repo  int64     `json:"repo_size"` // size in the repository (compressed, without the WAL)
}

func (c *PGCluster) backupSecret() string { return pgSecretPrefix + c.Name + "-backup" }
func (c *PGCluster) backupsOn() bool      { return c.Backup != nil }
func (c *PGCluster) repoPath() string {
	return strings.TrimRight(c.Backup.Path, "/") + "/" + c.Name
}

var (
	pgHostRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	pgBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	pgRegionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	pgPathRe   = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*/?$`)
	pgKeyRe    = regexp.MustCompile(`^[A-Za-z0-9/+=._-]{1,256}$`)
	// A pgBackRest backup label: 20261103-010000F, or 20261103-010000F_20261104-010000D for one based on it.
	pgBackupLabelRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F(_[0-9]{8}-[0-9]{6}[DI])?$`)
)

func (b *PGBackup) validate() error {
	switch {
	case !pgHostRe.MatchString(b.Endpoint):
		return fmt.Errorf("invalid S3 endpoint %q (a host name, optionally :port)", b.Endpoint)
	case !pgBucketRe.MatchString(b.Bucket):
		return fmt.Errorf("invalid bucket name %q", b.Bucket)
	case !pgRegionRe.MatchString(b.Region):
		return fmt.Errorf("invalid region %q", b.Region)
	case !pgPathRe.MatchString(b.Path) || b.Path == "":
		return fmt.Errorf("invalid path %q (/prefix)", b.Path)
	case b.URIStyle != "" && b.URIStyle != "host" && b.URIStyle != "path":
		return fmt.Errorf("uri style must be host or path")
	case b.Retention < 1 || b.Retention > 100:
		return fmt.Errorf("retention must be 1-100 full backups")
	}
	for _, s := range []string{b.Full, b.Diff, b.Incr} {
		if s == "" {
			continue
		}
		if _, err := pgParseCron(s); err != nil {
			return err
		}
	}
	if b.Full == "" {
		return fmt.Errorf("a full backup schedule is required")
	}
	if r := b.Restore; r != nil {
		if !pgPathRe.MatchString(r.Path) || !pgGroupRe.MatchString(r.Stanza) {
			return fmt.Errorf("invalid restore source")
		}
		if r.Target != "" {
			if _, err := time.Parse(time.RFC3339, r.Target); err != nil {
				return fmt.Errorf("the restore target must be an RFC 3339 time (2026-11-03T08:00:00Z)")
			}
		}
	}
	return nil
}

// pgBackrestConfig is the member's pgbackrest.conf for its group (the keys come from the environment:
// PGBACKREST_REPO1_S3_KEY, PGBACKREST_REPO1_S3_KEY_SECRET, PGBACKREST_REPO1_CIPHER_PASS).
func pgBackrestConfig(c *PGCluster, g *PGGroup, res *Resources) string {
	b := c.Backup
	cpus := 2.0
	if res != nil && res.CPUs > 0 {
		cpus = res.CPUs
	}
	uri := b.URIStyle
	if uri == "" {
		uri = "host"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "# Generated by ziroctl (pg backup); the keys are in the environment.\n[global]\n")
	fmt.Fprintf(&s, "repo1-type=s3\nrepo1-s3-endpoint=%s\nrepo1-s3-bucket=%s\nrepo1-s3-region=%s\nrepo1-s3-uri-style=%s\n", b.Endpoint, b.Bucket, b.Region, uri)
	if b.NoVerifyTLS {
		s.WriteString("repo1-storage-verify-tls=n\n")
	}
	fmt.Fprintf(&s, "repo1-path=%s\nrepo1-cipher-type=aes-256-cbc\nrepo1-retention-full=%d\nrepo1-retention-full-type=count\n", c.repoPath(), b.Retention)
	fmt.Fprintf(&s, "compress-type=zst\ncompress-level=3\nprocess-max=%d\nstart-fast=y\ndelta=y\n", int(max(1, min(cpus, 16))))
	fmt.Fprintf(&s, "archive-async=y\narchive-push-queue-max=8GiB\nspool-path=%s/spool\nlog-path=%s/log\nlog-level-console=warn\nlog-level-file=info\nlock-path=%s/lock\n",
		pgBackrestDir, pgBackrestDir, pgBackrestDir)
	fmt.Fprintf(&s, "\n[%s]\npg1-path=%s\npg1-socket-path=/var/run/postgresql\npg1-port=5432\npg1-user=postgres\n", g.Name, pgDataDirIn)
	return s.String()
}

// pgBackupEnv adds what a member's container needs for backups to its environment.
func pgBackupEnv(c *PGCluster, g *PGGroup, env map[string]string) {
	if !c.backupsOn() {
		return
	}
	env["PGBACKREST_CONFIG"] = pgBackrestConf
	env["ZIRO_PG_STANZA"] = g.Name
	if r := c.Backup.Restore; r != nil {
		env["ZIRO_PG_RESTORE_PATH"] = r.Path
		env["ZIRO_PG_RESTORE_STANZA"] = r.Stanza
		env["ZIRO_PG_RESTORE_TARGET"] = r.Target
	}
}

// pgBackupEnable turns backups on (or changes their configuration).
func pgBackupEnable(st *ClusterState, name string, b PGBackup, keyID, secretKey, image string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if b.Retention == 0 {
		b.Retention = 4
	}
	if b.Full == "" {
		b.Full, b.Diff, b.Incr = "0 1 * * 0", "0 1 * * 1-6", "30 * * * *"
	}
	if c.Backup != nil {
		b.Restore = c.Backup.Restore
	}
	if err := b.validate(); err != nil {
		return err
	}
	sec := st.Secrets[c.backupSecret()]
	if sec == nil {
		pass, err := genSecret("alnum:48")
		if err != nil {
			return err
		}
		sec = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": pass}
	}
	if keyID != "" || secretKey != "" {
		if !pgKeyRe.MatchString(keyID) || !pgKeyRe.MatchString(secretKey) {
			return fmt.Errorf("invalid access key")
		}
		sec["PGBACKREST_REPO1_S3_KEY"], sec["PGBACKREST_REPO1_S3_KEY_SECRET"] = keyID, secretKey
	}
	if sec["PGBACKREST_REPO1_S3_KEY"] == "" {
		return fmt.Errorf("the repository's access key is required (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)")
	}
	if err := pgUseBackupImage(c, image); err != nil {
		return err
	}
	st.Secrets[c.backupSecret()] = sec
	c.Backup = &b
	return nil
}

// pgUseBackupImage moves the cluster to an image with pgBackRest: the given one, or the pinned Ziro image.
func pgUseBackupImage(c *PGCluster, image string) error {
	if image == "" {
		if strings.Contains(c.Image, "pgbackrest") || c.Citus != "" && strings.Contains(c.Citus, "pgbackrest") {
			return nil
		}
		image = pgBackupImages[c.Version]
		if image == "" {
			return fmt.Errorf("the Ziro Postgres images with pgBackRest are not pinned in this ziroctl yet: pass --image <an image with pgbackrest, pinned by digest>")
		}
	}
	if !strings.Contains(image, "@sha256:") || strings.ContainsAny(image, " \t\r\n") || len(image) > 512 {
		return fmt.Errorf("the image must be pinned by digest")
	}
	if c.Citus != "" {
		c.Citus = image
	} else {
		c.Image = image
	}
	return nil
}

// pgBackupDisable stops archiving and scheduled backups. The repository and its backups stay.
func pgBackupDisable(st *ClusterState, name string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if c.Backup == nil {
		return fmt.Errorf("backups are not on for %s", name)
	}
	c.Backup = nil
	for gi := range c.Groups {
		c.Groups[gi].Backup = nil
	}
	return nil
}

// pgBackupNow asks for a backup of every group (or one) on the next pass.
func pgBackupNow(st *ClusterState, name, group, typ string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if !c.backupsOn() {
		return fmt.Errorf("backups are not on for %s: run ziroctl pg backup enable %s first", name, name)
	}
	if typ != "full" && typ != "diff" && typ != "incr" {
		return fmt.Errorf("type must be full, diff or incr")
	}
	for gi := range c.Groups {
		g := &c.Groups[gi]
		if group != "" && g.Name != group {
			continue
		}
		if g.Backup == nil {
			g.Backup = &PGGroupBackup{}
		}
		g.Backup.Now = typ
	}
	return nil
}

// pgBackupDue is the type of backup the schedule asks for now ("" = none): a full first, then the
// highest one whose last firing has not been taken yet.
func pgBackupDue(b *PGBackup, gb *PGGroupBackup, now time.Time) string {
	if gb.Now != "" {
		return gb.Now
	}
	if gb.Started["full"].IsZero() {
		return "full"
	}
	for _, t := range []struct{ typ, spec string }{{"full", b.Full}, {"diff", b.Diff}, {"incr", b.Incr}} {
		if t.spec == "" {
			continue
		}
		s, err := pgParseCron(t.spec)
		if err != nil {
			continue
		}
		if fire := s.prev(now); !fire.IsZero() && gb.Started[t.typ].Before(fire) {
			return t.typ
		}
	}
	return ""
}

// pgBackupPass creates the stanza, takes the backups the schedule asks for, and warns of missed backups
// and failing archiving.
func pgBackupPass(c *PGCluster, g *PGGroup, now time.Time) {
	if !c.backupsOn() {
		return
	}
	if g.Backup == nil {
		g.Backup = &PGGroupBackup{}
	}
	gb := g.Backup
	p := g.primary()
	if p == nil || !p.fresh(now) || p.Probe.Recovery {
		return
	}
	if !gb.Stanza {
		// Until the stanza exists every archive attempt fails: those failures are expected.
		gb.Failed = p.Probe.ArchiveFailed
		if p.Cmd == nil {
			p.issue(opStanza, g.Name, g.Epoch, now)
		}
		return
	}
	// Archiving failures (pg_stat_archiver, a counter since the server started): WAL piles up on the
	// primary until they stop.
	if f := p.Probe.ArchiveFailed; f > gb.Failed {
		if g.last(now, 30*time.Minute, "archive-fail") {
			g.alert(now, "high", "WAL archiving to the backup repository fails (%d failures): check the bucket, the keys and the endpoint (ziroctl pg backups %s)", f-gb.Failed, c.Name)
		}
		gb.Failed = f
	} else if f < gb.Failed {
		gb.Failed = f // the server restarted (or the primary changed)
	}
	if p.Cmd != nil {
		return
	}
	if info := gb.Info; info != nil && info.Running {
		return
	}
	if typ := pgBackupDue(c.Backup, gb, now); typ != "" {
		started := gb.Started[typ]
		if !started.IsZero() && now.Sub(started) < 5*time.Minute && gb.Now == "" {
			return // just started one: the report has not caught up yet
		}
		p.issue(opBackup, typ, g.Epoch, now)
	}
	pgBackupLate(c, g, now)
}

// pgBackupLate warns when the newest backup is older than the schedule allows.
func pgBackupLate(c *PGCluster, g *PGGroup, now time.Time) {
	gb := g.Backup
	if gb.Info == nil || gb.Started["full"].IsZero() || now.Sub(gb.Started["full"]) < 6*time.Hour {
		return // the first backup is still on its way
	}
	var newest time.Time
	for _, b := range gb.Info.Backups {
		if b.Stop.After(newest) {
			newest = b.Stop
		}
	}
	allowed := 26 * time.Hour
	for _, spec := range []string{c.Backup.Incr, c.Backup.Diff, c.Backup.Full} {
		if s, err := pgParseCron(spec); spec != "" && err == nil {
			allowed = min(allowed, 2*s.gap(now)+time.Hour)
		}
	}
	if now.Sub(newest) > allowed && g.last(now, 6*time.Hour, "backup-late") {
		msg := "no backup finished since " + newest.Format(time.RFC3339)
		if newest.IsZero() {
			msg = "no backup has finished yet"
		}
		if gb.Info.LastLog != "" {
			msg += ": " + gb.Info.LastLog
		}
		g.alert(now, "high", "group %s: %s", g.Name, msg)
	}
}

// pgBackupSettle records a backup order's outcome.
func pgBackupSettle(g *PGGroup, cmd *PGCommand, now time.Time) {
	if g.Backup == nil {
		return
	}
	gb := g.Backup
	switch cmd.Op {
	case opStanza:
		if cmd.OK {
			gb.Stanza = true
			g.note(now, "the backup repository is ready (stanza %s)", g.Name)
		}
	case opBackup:
		if !cmd.OK {
			return
		}
		if gb.Started == nil {
			gb.Started = map[string]time.Time{}
		}
		// A full backup also stands for the differential and incremental due at the same time.
		switch cmd.Arg {
		case "full":
			gb.Started["full"], gb.Started["diff"], gb.Started["incr"] = now, now, now
		case "diff":
			gb.Started["diff"], gb.Started["incr"] = now, now
		default:
			gb.Started["incr"] = now
		}
		if gb.Now == cmd.Arg {
			gb.Now = ""
		}
		g.note(now, "%s backup started", cmd.Arg)
	}
}

// ---- the agent's part: what `pgbackrest info` says ----

// parseBackrestInfo reads `pgbackrest info --output=json` for one stanza.
func parseBackrestInfo(out string) (*PGBackupInfo, error) {
	var stanzas []struct {
		Name   string `json:"name"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Lock    struct {
				Backup struct {
					Held bool `json:"held"`
				} `json:"backup"`
			} `json:"lock"`
		} `json:"status"`
		Backup []struct {
			Label     string `json:"label"`
			Type      string `json:"type"`
			Timestamp struct {
				Start int64 `json:"start"`
				Stop  int64 `json:"stop"`
			} `json:"timestamp"`
			Info struct {
				Size       int64 `json:"size"`
				Repository struct {
					Delta int64 `json:"delta"`
					Size  int64 `json:"size"`
				} `json:"repository"`
			} `json:"info"`
		} `json:"backup"`
	}
	if err := json.Unmarshal([]byte(out), &stanzas); err != nil || len(stanzas) != 1 {
		return nil, fmt.Errorf("unexpected pgbackrest info output")
	}
	s := stanzas[0]
	info := &PGBackupInfo{Running: s.Status.Lock.Backup.Held, Status: sanitizeLabel(s.Status.Message, 120)}
	for _, b := range s.Backup {
		if !pgBackupLabelRe.MatchString(b.Label) {
			continue
		}
		info.Backups = append(info.Backups, PGBackupSummary{Label: b.Label, Type: b.Type, Start: time.Unix(b.Timestamp.Start, 0).UTC(),
			Stop: time.Unix(b.Timestamp.Stop, 0).UTC(), Size: b.Info.Size, Repo: b.Info.Repository.Delta})
	}
	sort.Slice(info.Backups, func(i, j int) bool { return info.Backups[i].Start.Before(info.Backups[j].Start) })
	if len(info.Backups) > 50 {
		info.Backups = info.Backups[len(info.Backups)-50:]
	}
	return info, nil
}

// pgRecoverable is the window a restore can target: from the end of the oldest backup to the newest
// archived WAL (about the last report while archiving works).
func pgRecoverable(g *PGGroup) (from, to time.Time, ok bool) {
	if g.Backup == nil || g.Backup.Info == nil || len(g.Backup.Info.Backups) == 0 {
		return time.Time{}, time.Time{}, false
	}
	from = g.Backup.Info.Backups[0].Stop
	to = g.Backup.Info.At
	if p := g.primary(); p != nil && p.Probe.ArchivedAgo >= 0 && p.Probe.OK {
		to = p.Probe.At.Add(-time.Duration(p.Probe.ArchivedAgo) * time.Second)
	}
	return from, to, true
}

// ---- restore ----

// pgRestoreOpts makes a cluster from a backup repository.
type pgRestoreOpts struct {
	Name     string
	From     string // an existing cluster with backups ("" = the repository below)
	Target   string // RFC 3339 time, or "" for the latest state
	Replicas int
	// The repository, when it is not an existing cluster's (disaster recovery):
	Repo                    *PGBackup
	Stanza                  string
	KeyID, Secret, Passkey  string
	Version, Database, User string
	Image                   string
}

func pgRestore(st *ClusterState, o pgRestoreOpts, now time.Time) (*PGCluster, error) {
	if o.Target == "latest" {
		o.Target = ""
	}
	if o.Target != "" {
		if _, err := time.Parse(time.RFC3339, o.Target); err != nil {
			return nil, fmt.Errorf("--to must be an RFC 3339 time (2026-11-03T08:00:00Z) or latest")
		}
	}
	var repo PGBackup
	var keys map[string]string
	var srcPath, stanza string
	opts := pgCreateOpts{Name: o.Name, Replicas: o.Replicas}
	if o.From != "" {
		src, err := pgCluster(st, o.From)
		if err != nil {
			return nil, err
		}
		if !src.backupsOn() {
			return nil, fmt.Errorf("%s has no backups", o.From)
		}
		if src.Citus != "" {
			return nil, fmt.Errorf("restoring a sharded cluster is not supported yet: restore its groups one by one")
		}
		repo, keys, srcPath, stanza = *src.Backup, st.Secrets[src.backupSecret()], src.repoPath(), src.entryGroup()
		opts.Version, opts.Database, opts.User, opts.Image, opts.Resources = src.Version, src.Database, src.User, src.Image, src.Resources
	} else {
		if o.Repo == nil {
			return nil, fmt.Errorf("restore from what? --from <cluster>, or the repository (--s3-endpoint, --bucket, --path)")
		}
		repo = *o.Repo
		srcPath, stanza = strings.TrimRight(repo.Path, "/"), o.Stanza
		if stanza == "" {
			stanza = "main"
		}
		if !pgKeyRe.MatchString(o.KeyID) || !pgKeyRe.MatchString(o.Secret) || o.Passkey == "" || len(o.Passkey) > 512 {
			return nil, fmt.Errorf("the repository's access key and its encryption passphrase are required")
		}
		keys = map[string]string{"PGBACKREST_REPO1_S3_KEY": o.KeyID, "PGBACKREST_REPO1_S3_KEY_SECRET": o.Secret, "PGBACKREST_REPO1_CIPHER_PASS": o.Passkey}
		opts.Version, opts.Database, opts.User, opts.Image = o.Version, o.Database, o.User, o.Image
		if opts.Version == "" {
			opts.Version = "17"
		}
	}
	c, err := pgCreate(st, opts, now)
	if err != nil {
		return nil, err
	}
	// The new cluster writes its own backups under its own name, with the source's settings and keys.
	repo.Restore = &PGRestore{Path: srcPath, Stanza: stanza, Target: o.Target, Secret: c.backupSecret()}
	if err := repo.validate(); err != nil {
		delete(st.PG, c.Name)
		return nil, err
	}
	sec := map[string]string{}
	for k, v := range keys {
		sec[k] = v
	}
	st.Secrets[c.backupSecret()] = sec
	if err := pgUseBackupImage(c, o.Image); err != nil {
		delete(st.PG, c.Name)
		return nil, err
	}
	c.Backup = &repo
	for gi := range c.Groups {
		for mi := range c.Groups[gi].Members {
			if m := &c.Groups[gi].Members[mi]; m.Init == pgPrimary {
				m.Init = pgRestoreInit
			}
		}
	}
	return c, nil
}

// pgRestoreInit is how the primary of a restored cluster initialises an empty data directory.
const pgRestoreInit = "restore"

// pgBackupView is the backups part of `pg status` and `pg backups`.
type pgBackupView struct {
	Group           string            `json:"group"`
	Repository      string            `json:"repository"`
	Status          string            `json:"status,omitempty"`
	Running         bool              `json:"running,omitempty"`
	Backups         []PGBackupSummary `json:"backups,omitempty"`
	RecoverableFrom string            `json:"recoverable_from,omitempty"`
	RecoverableTo   string            `json:"recoverable_to,omitempty"`
	LastLog         string            `json:"last_log,omitempty"`
}

func pgBackupViews(c *PGCluster) []pgBackupView {
	if !c.backupsOn() {
		return nil
	}
	u := url.URL{Scheme: "s3", Host: c.Backup.Bucket, Path: c.repoPath()}
	var out []pgBackupView
	for gi := range c.Groups {
		g := &c.Groups[gi]
		v := pgBackupView{Group: g.Name, Repository: u.String() + " (stanza " + g.Name + ")"}
		if g.Backup != nil && g.Backup.Info != nil {
			i := g.Backup.Info
			v.Status, v.Running, v.Backups, v.LastLog = i.Status, i.Running, i.Backups, i.LastLog
		}
		if from, to, ok := pgRecoverable(g); ok {
			v.RecoverableFrom, v.RecoverableTo = from.Format(time.RFC3339), to.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GiB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MiB"
	}
	return strconv.FormatInt(n>>10, 10) + " KiB"
}

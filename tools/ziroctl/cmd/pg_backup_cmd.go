package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var pgBackupFlags struct {
	endpoint, bucket, region, path, uriStyle, full, diff, incr, image, typ, group, from, to, stanza string
	version, database, user                                                                         string
	noVerifyTLS                                                                                     bool
	retention, replicas                                                                             int
}

var pgBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backups to S3-compatible storage and WAL archiving",
	Long: `Backups with pgBackRest into an S3-compatible bucket (AWS S3, Cloudflare R2, Backblaze B2, MinIO, ...): full,
differential and incremental backups on a schedule, compressed and encrypted, plus continuous WAL archiving
for point-in-time recovery (ziroctl pg restore). See docs/postgres.md, "Backups and recovery".`,
	Example: "  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... ziroctl pg backup enable shop --s3-endpoint s3.eu-west-1.amazonaws.com --bucket acme-db --region eu-west-1\n  ziroctl pg backup now shop --type full",
}

var pgBackupEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Turn on backups and WAL archiving",
	Long: `Turns on scheduled backups and continuous WAL archiving. The repository's keys come from AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY (never from the command line). The members move to the Ziro Postgres image with
pgBackRest (or --image) and restart one at a time. Schedules are cron expressions in UTC; by default a full
backup on Sundays at 01:00, a differential on the other days at 01:00 and an incremental every hour.
Keep the repository passphrase (ziroctl pg backup passphrase) outside the cluster: a restore needs it.`,
	Example: "  ziroctl pg backup enable shop --s3-endpoint s3.eu-west-1.amazonaws.com --bucket acme-db --region eu-west-1\n  ziroctl pg backup enable shop --s3-endpoint minio.lan:9000 --bucket db --uri-style path --retention 8",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f := pgBackupFlags
		b := PGBackup{Endpoint: f.endpoint, Bucket: f.bucket, Region: f.region, Path: f.path, URIStyle: f.uriStyle, NoVerifyTLS: f.noVerifyTLS,
			Retention: f.retention, Full: f.full, Diff: f.diff, Incr: f.incr}
		if (f.diff != "" || f.incr != "") && f.full == "" {
			return fmt.Errorf("--diff and --incr need --full")
		}
		if err := pgEdit("pg backup enable", args[0], func(st *ClusterState, now time.Time) error {
			return pgBackupEnable(st, args[0], b, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), f.image)
		}); err != nil {
			return err
		}
		fmt.Printf("✓ backups are on for %s: the members restart on the new image one at a time, then the first full backup starts\n", args[0])
		fmt.Printf("  Keep the repository passphrase outside the cluster (a restore needs it): ziroctl pg backup passphrase %s\n", args[0])
		return nil
	},
}

var pgBackupDisableCmd = &cobra.Command{
	Use:     "disable <name>",
	Short:   "Stop WAL archiving and scheduled backups",
	Long:    `Stops archiving and the schedule; the repository and the backups in it stay (delete them in the bucket).`,
	Example: "  ziroctl pg backup disable shop",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg backup disable", args[0], func(st *ClusterState, now time.Time) error {
			return pgBackupDisable(st, args[0])
		}); err != nil {
			return err
		}
		fmt.Printf("✓ backups are off for %s\n", args[0])
		return nil
	},
}

var pgBackupNowCmd = &cobra.Command{
	Use:     "now <name>",
	Short:   "Take a backup now",
	Example: "  ziroctl pg backup now shop\n  ziroctl pg backup now shop --type full",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg backup now", args[0], func(st *ClusterState, now time.Time) error {
			return pgBackupNow(st, args[0], pgBackupFlags.group, pgBackupFlags.typ)
		}); err != nil {
			return err
		}
		fmt.Printf("✓ a %s backup of %s starts within a heartbeat. Follow it with: ziroctl pg backups %s\n", pgBackupFlags.typ, args[0], args[0])
		return nil
	},
}

var pgBackupPassphraseCmd = &cobra.Command{
	Use:   "passphrase <name>",
	Short: "Print the repository's encryption passphrase",
	Long: `Prints the passphrase that encrypts the cluster's backups. Store it outside the cluster (a password manager): if
the cluster is lost, a restore from the repository needs it (ziroctl pg restore ... with PG_BACKUP_PASSPHRASE).
Only on the master, never over the API.`,
	Example: "  ziroctl pg backup passphrase shop",
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
		pass := st.Secrets[c.backupSecret()]["PGBACKREST_REPO1_CIPHER_PASS"]
		if pass == "" {
			return fmt.Errorf("backups are not on for %s", args[0])
		}
		fmt.Println(pass)
		return nil
	},
}

var pgBackupsCmd = &cobra.Command{
	Use:     "backups <name>",
	Short:   "List a cluster's backups and the time it can be restored to",
	Example: "  ziroctl pg backups shop",
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
		views := pgBackupViews(c)
		if views == nil {
			return fmt.Errorf("backups are not on for %s: run ziroctl pg backup enable %s first", args[0], args[0])
		}
		return printResult(views, func() {
			for _, v := range views {
				fmt.Printf("%s: %s\n", v.Group, v.Repository)
				if v.Status != "" {
					fmt.Printf("  status: %s", v.Status)
					if v.Running {
						fmt.Print(" (a backup is running)")
					}
					fmt.Println()
				}
				if v.RecoverableFrom != "" {
					fmt.Printf("  restorable from %s to %s\n", v.RecoverableFrom, v.RecoverableTo)
				}
				if v.LastLog != "" {
					fmt.Printf("  last error: %s\n", v.LastLog)
				}
				if len(v.Backups) > 0 {
					fmt.Printf("  %-26s %-5s %-20s %-9s %-10s %s\n", "LABEL", "TYPE", "FINISHED", "TOOK", "DATABASE", "STORED")
				}
				for _, b := range v.Backups {
					fmt.Printf("  %-26s %-5s %-20s %-9s %-10s %s\n", b.Label, b.Type, b.Stop.Format("2006-01-02 15:04:05"),
						b.Stop.Sub(b.Start).Round(time.Second), humanSize(b.Size), humanSize(b.Repo))
				}
			}
		})
	},
}

var pgRestoreCmd = &cobra.Command{
	Use:   "restore <new-name>",
	Short: "Make a new cluster from a backup, at any point in time",
	Long: `Creates a cluster from a backup repository: the latest state, or the state at --to (RFC 3339, UTC), any moment
since the oldest backup that is kept. From a cluster that has backups use --from; when the cluster is gone
(disaster recovery) give its repository instead: --s3-endpoint, --bucket, --region, --path <prefix>/<old name>,
with AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and PG_BACKUP_PASSPHRASE in the environment. The new cluster
backs itself up to its own place in the same bucket. Apps move to it by connecting to <new-name>-rw.`,
	Example: "  ziroctl pg restore shop2 --from shop --to 2026-11-03T08:00:00Z\n  ziroctl pg restore shop --s3-endpoint s3.eu-west-1.amazonaws.com --bucket acme-db --region eu-west-1 --path /ziro/shop",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f := pgBackupFlags
		to := f.to
		if to == "latest" {
			to = ""
		}
		o := pgRestoreOpts{Name: args[0], From: f.from, Target: to, Replicas: f.replicas, Version: f.version, Database: f.database, User: f.user, Image: f.image}
		if f.from == "" {
			path := strings.TrimRight(f.path, "/")
			o.Repo = &PGBackup{Endpoint: f.endpoint, Bucket: f.bucket, Region: f.region, Path: path, URIStyle: f.uriStyle,
				NoVerifyTLS: f.noVerifyTLS, Retention: 4, Full: "0 1 * * 0", Diff: "0 1 * * 1-6", Incr: "30 * * * *"}
			o.Stanza, o.KeyID, o.Secret, o.Passkey = f.stanza, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("PG_BACKUP_PASSPHRASE")
		}
		var created *PGCluster
		if err := pgEdit("pg restore", args[0], func(st *ClusterState, now time.Time) error {
			c, err := pgRestore(st, o, now)
			created = c
			return err
		}); err != nil {
			return err
		}
		target := "the latest state"
		if to != "" {
			target = to
		}
		fmt.Printf("✓ %s is being restored (%s). Watch: ziroctl pg status %s\n", created.Name, target, created.Name)
		return nil
	},
}

func init() {
	f := pgBackupEnableCmd.Flags()
	f.StringVar(&pgBackupFlags.endpoint, "s3-endpoint", "", "S3 endpoint host (s3.eu-west-1.amazonaws.com, <account>.r2.cloudflarestorage.com, minio:9000)")
	f.StringVar(&pgBackupFlags.bucket, "bucket", "", "Bucket")
	f.StringVar(&pgBackupFlags.region, "region", "us-east-1", "Region")
	f.StringVar(&pgBackupFlags.path, "path", "/ziro", "Prefix in the bucket (the cluster's repository is <path>/<name>)")
	f.StringVar(&pgBackupFlags.uriStyle, "uri-style", "host", "host (AWS) or path (MinIO and most others)")
	f.BoolVar(&pgBackupFlags.noVerifyTLS, "no-verify-tls", false, "Do not check the endpoint's certificate (a test MinIO)")
	f.IntVar(&pgBackupFlags.retention, "retention", 4, "Full backups to keep (with the differentials, incrementals and WAL they need)")
	f.StringVar(&pgBackupFlags.full, "full", "", "Full backup schedule (cron, UTC; default \"0 1 * * 0\")")
	f.StringVar(&pgBackupFlags.diff, "diff", "", "Differential backup schedule (default \"0 1 * * 1-6\")")
	f.StringVar(&pgBackupFlags.incr, "incr", "", "Incremental backup schedule (default \"30 * * * *\")")
	f.StringVar(&pgBackupFlags.image, "image", "", "Member image with pgBackRest, pinned by digest (default: the Ziro image)")
	pgBackupNowCmd.Flags().StringVar(&pgBackupFlags.typ, "type", "incr", "full, diff or incr")
	pgBackupNowCmd.Flags().StringVar(&pgBackupFlags.group, "group", "", "Only this group (Citus)")
	r := pgRestoreCmd.Flags()
	r.StringVar(&pgBackupFlags.from, "from", "", "The cluster whose backups to restore")
	r.StringVar(&pgBackupFlags.to, "to", "latest", "The moment to restore to (RFC 3339, UTC) or latest")
	r.IntVar(&pgBackupFlags.replicas, "replicas", 2, "Replicas of the new cluster")
	r.StringVar(&pgBackupFlags.endpoint, "s3-endpoint", "", "Without --from: the repository's S3 endpoint")
	r.StringVar(&pgBackupFlags.bucket, "bucket", "", "Without --from: its bucket")
	r.StringVar(&pgBackupFlags.region, "region", "us-east-1", "Without --from: its region")
	r.StringVar(&pgBackupFlags.path, "path", "", "Without --from: the old cluster's repository (<prefix>/<old name>)")
	r.StringVar(&pgBackupFlags.uriStyle, "uri-style", "host", "Without --from: host or path")
	r.BoolVar(&pgBackupFlags.noVerifyTLS, "no-verify-tls", false, "Without --from: do not check the endpoint's certificate")
	r.StringVar(&pgBackupFlags.stanza, "stanza", "main", "Without --from: the group to restore")
	r.StringVar(&pgBackupFlags.version, "version", "17", "Without --from: the PostgreSQL major version of the backup")
	r.StringVar(&pgBackupFlags.database, "database", "app", "Without --from: the application database")
	r.StringVar(&pgBackupFlags.user, "user", "app", "Without --from: its owner")
	r.StringVar(&pgBackupFlags.image, "image", "", "Member image with pgBackRest, pinned by digest (default: the Ziro image)")
	pgBackupCmd.AddCommand(pgBackupEnableCmd, pgBackupDisableCmd, pgBackupNowCmd, pgBackupPassphraseCmd)
	pgCmd.AddCommand(pgBackupCmd, pgBackupsCmd, pgRestoreCmd)
}

// registerPGBackupRoutes adds the backup API: the configuration (admin: it carries the repository's
// keys), the list (viewer) and restore (admin: it creates a cluster). The passphrase is never served.
func registerPGBackupRoutes(a *apiRouter) {
	a.get("/api/v1/pg/{name}/backups", "viewer", func(w http.ResponseWriter, r *http.Request) {
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
		apiReply(w, nil, pgBackupViews(c))
	})
	a.post("/api/v1/pg/{name}/backup-config", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled         bool     `json:"enabled"`
			Config          PGBackup `json:"config"`
			AccessKeyID     string   `json:"access_key_id"`
			SecretAccessKey string   `json:"secret_access_key"`
			Image           string   `json:"image"`
		}
		if r.ContentLength != 0 && !decodeBody(w, r, &req) {
			return
		}
		name := r.PathValue("name")
		err := withState(func(st *ClusterState) error {
			if !req.Enabled {
				return pgBackupDisable(st, name)
			}
			req.Config.Restore = nil
			return pgBackupEnable(st, name, req.Config, req.AccessKeyID, req.SecretAccessKey, req.Image)
		})
		apiReply(w, err, APIMessage{Status: "ok", Message: "backup configuration changed"})
	})
	a.post("/api/v1/pg-restore", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name            string    `json:"name"`
			From            string    `json:"from"`
			To              string    `json:"to"`
			Replicas        int       `json:"replicas"`
			Repo            *PGBackup `json:"repository"`
			Stanza          string    `json:"stanza"`
			AccessKeyID     string    `json:"access_key_id"`
			SecretAccessKey string    `json:"secret_access_key"`
			Passphrase      string    `json:"passphrase"`
			Version         string    `json:"version"`
			Database        string    `json:"database"`
			User            string    `json:"user"`
			Image           string    `json:"image"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		var view pgView
		err := withState(func(st *ClusterState) error {
			if req.Repo != nil {
				req.Repo.Restore = nil
				if req.Repo.Retention == 0 {
					req.Repo.Retention = 4
				}
				if req.Repo.Full == "" {
					req.Repo.Full, req.Repo.Diff, req.Repo.Incr = "0 1 * * 0", "0 1 * * 1-6", "30 * * * *"
				}
			}
			c, err := pgRestore(st, pgRestoreOpts{Name: req.Name, From: req.From, Target: req.To, Replicas: req.Replicas, Repo: req.Repo, Stanza: req.Stanza,
				KeyID: req.AccessKeyID, Secret: req.SecretAccessKey, Passkey: req.Passphrase, Version: req.Version, Database: req.Database, User: req.User, Image: req.Image}, time.Now())
			if err == nil {
				view = pgViewOf(st, c, time.Now())
			}
			return err
		})
		apiReply(w, err, view)
	})
}

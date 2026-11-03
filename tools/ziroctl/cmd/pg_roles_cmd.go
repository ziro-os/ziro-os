package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var pgRoleFlags struct {
	access, database, owner string
	extensions              []string
	rm                      bool
}

var pgRoleCmd = &cobra.Command{
	Use:   "role <cluster> <role>",
	Short: "Add a login role for an app, or change or remove it",
	Long: `Adds a login role with its own generated password: readwrite reads and writes every table, readonly only reads.
The connection strings are in the cluster secret pg-<cluster>-role-<role> (ziroctl pg credentials <cluster>
--role <role>, or apps deploy --pg <cluster>:<role>). The primary receives only the password's SCRAM verifier.
--rm takes the role off: it can no longer log in and its credentials are deleted; its objects and grants stay.`,
	Example: "  ziroctl pg role shop web\n  ziroctl pg role shop reports --access readonly\n  ziroctl pg role shop reports --rm",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg role", args[0], func(st *ClusterState, now time.Time) error {
			if pgRoleFlags.rm {
				return pgRemoveRole(st, args[0], args[1])
			}
			return pgSetRole(st, args[0], PGRole{Name: args[1], Access: pgRoleFlags.access, Database: pgRoleFlags.database})
		}); err != nil {
			return err
		}
		if pgRoleFlags.rm {
			fmt.Printf("✓ role %s is taken off %s: it can no longer log in\n", args[1], args[0])
		} else {
			fmt.Printf("✓ role %s (%s) is applied on the primary within a few seconds. Credentials: ziroctl pg credentials %s --role %s\n",
				args[1], pgRoleFlags.access, args[0], args[1])
		}
		return nil
	},
}

var pgDBCmd = &cobra.Command{
	Use:   "db <cluster> <database>",
	Short: "Add a database, or change its owner and extensions",
	Long: `Creates a database if it does not exist and keeps its owner (the application user, or a role from pg role) and
extensions. --extension adds one from the extensions the image ships that need no preloading (pg_trgm, pgcrypto,
citext, uuid-ossp, hstore, ...); the list given is the whole list. The cluster's own database can get extensions
too. --rm stops managing a database: it is never dropped.`,
	Example: "  ziroctl pg db shop analytics --owner reports --extension pg_trgm\n  ziroctl pg db shop app --extension pgcrypto --extension citext\n  ziroctl pg db shop analytics --rm",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg db", args[0], func(st *ClusterState, now time.Time) error {
			if pgRoleFlags.rm {
				return pgRemoveDatabase(st, args[0], args[1])
			}
			return pgSetDatabase(st, args[0], PGDatabase{Name: args[1], Owner: pgRoleFlags.owner, Extensions: pgRoleFlags.extensions})
		}); err != nil {
			return err
		}
		if pgRoleFlags.rm {
			fmt.Printf("✓ %s no longer manages database %s (it is kept)\n", args[0], args[1])
		} else {
			fmt.Printf("✓ database %s is applied on the primary within a few seconds (ziroctl pg roles %s)\n", args[1], args[0])
		}
		return nil
	},
}

// pgRoleRow is one role or database in pg roles.
type pgRoleRow struct {
	Kind   string `json:"kind"` // role or database
	Name   string `json:"name"`
	Detail string `json:"detail"`
	State  string `json:"state"` // ready, pending or failing
	Secret string `json:"secret,omitempty"`
}

func pgRoleRows(st *ClusterState, c *PGCluster) []pgRoleRow {
	out := []pgRoleRow{{Kind: "role", Name: c.User, Detail: "application user, owns " + c.Database, State: "ready", Secret: c.urlSecret()}}
	for _, r := range c.Roles {
		key, hash, _ := pgRoleWant(st, c, r)
		db := r.Database
		if db == "" {
			db = c.Database
		}
		out = append(out, pgRoleRow{Kind: "role", Name: r.Name, Detail: r.Access + ", connects to " + db, State: pgRoleState(st, c, key, hash), Secret: c.roleSecret(r.Name)})
	}
	for _, d := range c.Databases {
		key, hash, owner := pgDatabaseWant(c, d)
		detail := "owner " + owner
		if len(d.Extensions) > 0 {
			detail += ", extensions " + strings.Join(d.Extensions, ", ")
		}
		out = append(out, pgRoleRow{Kind: "database", Name: d.Name, Detail: detail, State: pgRoleState(st, c, key, hash)})
	}
	for _, r := range c.RolesOff {
		out = append(out, pgRoleRow{Kind: "role", Name: r, Detail: "removed: being locked out", State: "pending"})
	}
	return out
}

var pgRolesCmd = &cobra.Command{
	Use:     "roles <cluster>",
	Short:   "List a cluster's roles and databases",
	Example: "  ziroctl pg roles shop",
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
		rows := pgRoleRows(st, c)
		return printResult(rows, func() {
			fmt.Printf("%-9s %-20s %-8s %-28s %s\n", "KIND", "NAME", "STATE", "SECRET", "DETAIL")
			for _, r := range rows {
				fmt.Printf("%-9s %-20s %-8s %-28s %s\n", r.Kind, r.Name, r.State, r.Secret, r.Detail)
			}
		})
	},
}

func init() {
	pgRoleCmd.Flags().StringVar(&pgRoleFlags.access, "access", "readwrite", "readwrite or readonly")
	pgRoleCmd.Flags().StringVar(&pgRoleFlags.database, "database", "", "The database its connection strings name (default: the cluster's)")
	pgRoleCmd.Flags().BoolVar(&pgRoleFlags.rm, "rm", false, "Take the role off: it can no longer log in")
	pgDBCmd.Flags().StringVar(&pgRoleFlags.owner, "owner", "", "Owner: a role from pg role (default: the application user)")
	pgDBCmd.Flags().StringArrayVar(&pgRoleFlags.extensions, "extension", nil, "An extension to create in it (repeatable)")
	pgDBCmd.Flags().BoolVar(&pgRoleFlags.rm, "rm", false, "Stop managing it (it is never dropped)")
	pgCmd.AddCommand(pgRoleCmd, pgDBCmd, pgRolesCmd)
}

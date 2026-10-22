package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// `ziroctl pg` and /api/v1/pg: declare and operate Postgres clusters (RFC 0005, docs/postgres.md).
// Every command edits ClusterState.PG inside one withState; the controller does the work.

var pgCmd = &cobra.Command{
	Use:   "pg",
	Short: "Run Postgres clusters with replicas, failover and sharding",
	Long: `A Postgres cluster is a primary and replicas on different nodes. The controller on the cluster master
fails over automatically, adds and removes replicas without interrupting the primary, and, with Citus,
spreads tables over several primaries. Clients use <name>-rw.cluster.ziro for writes and <name>-ro.cluster.ziro for reads.`,
	Example: "  ziroctl pg create shop --replicas 2 --memory 4Gi --cpus 2\n  ziroctl pg status shop",
}

var pgFlags struct {
	version, image, sync, database, user, citus, node, from, group, to string
	replicas, shards, port                                             int
	memory                                                             string
	cpus                                                               float64
	allowFrom, allow                                                   []string
	colocate, purge, ro                                                bool
}

// pgEdit runs one change of the Postgres state on the master.
func pgEdit(audit, target string, fn func(st *ClusterState, now time.Time) error) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	err := withState(func(st *ClusterState) error { return fn(st, time.Now()) })
	_ = auditLog("cli", "cli", audit, target, err)
	return err
}

var pgCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a Postgres cluster",
	Long: `Creates a primary and --replicas replicas, each on its own node. Quorum synchronous replication is used
with two or more replicas, so a failover loses no acknowledged write. --shards N adds N worker groups
(each a primary with replicas) behind a Citus coordinator for multiple writers; it needs --citus-image.`,
	Example: `  ziroctl pg create shop --replicas 2 --memory 4Gi --cpus 2
  ziroctl pg create events --replicas 1 --shards 3 --citus-image docker.io/citusdata/citus:13.2.0@sha256:<digest>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f := pgFlags
		var res *Resources
		if f.memory != "" || f.cpus > 0 {
			res = &Resources{Memory: f.memory, CPUs: f.cpus}
		}
		var created *PGCluster
		err := pgEdit("pg create", args[0], func(st *ClusterState, now time.Time) error {
			c, err := pgCreate(st, pgCreateOpts{Name: args[0], Version: f.version, Image: f.image, Replicas: f.replicas, Sync: f.sync,
				Shards: f.shards, Citus: f.citus, Resources: res, Database: f.database, User: f.user, AllowFrom: f.allowFrom, Colocate: f.colocate}, now)
			created = c
			return err
		})
		if err != nil {
			return err
		}
		fmt.Printf("✓ Postgres cluster %s: %d members per group on %d group(s). Watch: ziroctl pg status %s\n",
			created.Name, created.Replicas+1, len(created.Groups), created.Name)
		fmt.Printf("  Connection details: ziroctl pg credentials %s\n", created.Name)
		return nil
	},
}

var pgLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List Postgres clusters",
	Example: "  ziroctl pg ls",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		views := pgViews(st, time.Now())
		return printResult(views, func() {
			if len(views) == 0 {
				fmt.Println("No Postgres clusters. Create one: ziroctl pg create <name> --replicas 2")
				return
			}
			fmt.Printf("%-14s %-8s %-8s %-9s %-8s %s\n", "NAME", "VERSION", "GROUPS", "REPLICAS", "SYNC", "PRIMARY")
			for _, v := range views {
				var prim []string
				for _, g := range v.Groups {
					prim = append(prim, g.Name+"="+g.Primary)
				}
				sync := v.Sync
				fmt.Printf("%-14s %-8s %-8d %-9d %-8s %s\n", v.Name, v.Version, len(v.Groups), v.Replicas, sync, strings.Join(prim, " "))
			}
		})
	},
}

var pgStatusCmd = &cobra.Command{
	Use:     "status <name>",
	Short:   "Show members, roles, replication and recent events",
	Example: "  ziroctl pg status shop",
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
		v := pgViewOf(st, c, time.Now())
		return printResult(v, func() {
			fmt.Printf("%s: PostgreSQL %s, sync %s\n  writes: %s\n  reads:  %s\n", v.Name, v.Version, v.Sync, v.Endpoints.RW, v.Endpoints.RO)
			for _, g := range v.Groups {
				fmt.Printf("\ngroup %s (epoch %d", g.Name, g.Epoch)
				if g.Sync != "" {
					fmt.Printf(", sync %s", g.Sync)
				}
				fmt.Println(")")
				fmt.Printf("  %-5s %-14s %-9s %-12s %-12s %s\n", "ID", "NODE", "ROLE", "STATE", "LSN", "LAG")
				for _, m := range g.Members {
					lag := "-"
					if m.Role != pgPrimary && m.LSN != "" {
						lag = fmt.Sprintf("%dms", m.LagMs)
					}
					fmt.Printf("  %-5s %-14s %-9s %-12s %-12s %s\n", m.ID, m.Node, m.Role, m.State, m.LSN, lag)
				}
				for _, e := range g.Events {
					fmt.Printf("  · %s\n", e)
				}
			}
		})
	},
}

var pgCredentialsCmd = &cobra.Command{
	Use:   "credentials <name>",
	Short: "Print connection strings",
	Long:  `Prints the write and read connection strings. They hold the password, so they are only available on the master and never over the API.`,
	Example: `  ziroctl pg credentials shop
  psql "$(ziroctl pg credentials shop --ro)"`,
	Args: cobra.ExactArgs(1),
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
		if pgFlags.ro {
			fmt.Println(pgConnString(st, c, true))
			return nil
		}
		fmt.Printf("write: %s\nread:  %s\n", pgConnString(st, c, false), pgConnString(st, c, true))
		return nil
	},
}

var pgScaleCmd = &cobra.Command{
	Use:     "scale <name>",
	Short:   "Set how many replicas every group has",
	Long:    `Adds replicas (each takes a base backup from the primary without interrupting it) or drains the surplus ones.`,
	Example: "  ziroctl pg scale shop --replicas 4",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("replicas") {
			return fmt.Errorf("--replicas is required")
		}
		if err := pgEdit("pg scale", args[0], func(st *ClusterState, now time.Time) error {
			return pgSetReplicas(st, args[0], pgFlags.replicas)
		}); err != nil {
			return err
		}
		fmt.Printf("✓ %s: %d replicas per group. Watch: ziroctl pg status %s\n", args[0], pgFlags.replicas, args[0])
		return nil
	},
}

var pgAddReplicaCmd = &cobra.Command{
	Use:   "add-replica <name>",
	Short: "Add one replica without interrupting the primary",
	Long: `Adds a replica to a group on a node that holds no member of it (or --node). It takes a base backup from the
primary, or from --from to spare the primary, and serves reads once it has caught up.`,
	Example: "  ziroctl pg add-replica shop\n  ziroctl pg add-replica shop --node worker-3 --from m2",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var id string
		err := pgEdit("pg add-replica", args[0], func(st *ClusterState, now time.Time) error {
			var err error
			id, err = pgAddReplica(st, args[0], pgFlags.group, pgFlags.node, pgFlags.from)
			return err
		})
		if err != nil {
			return err
		}
		fmt.Printf("✓ replica %s is being created. Watch: ziroctl pg status %s\n", id, args[0])
		return nil
	},
}

var pgRmReplicaCmd = &cobra.Command{
	Use:     "rm-replica <name> <member>",
	Short:   "Remove a replica",
	Example: "  ziroctl pg rm-replica shop m3",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg rm-replica", args[0]+"/"+args[1], func(st *ClusterState, now time.Time) error {
			return pgRemoveReplica(st, args[0], pgFlags.group, args[1])
		}); err != nil {
			return err
		}
		fmt.Printf("✓ %s is draining; it leaves once the primary no longer waits for it\n", args[1])
		return nil
	},
}

var pgSwitchoverCmd = &cobra.Command{
	Use:   "switchover <name>",
	Short: "Move the primary to a replica without losing data",
	Long: `Makes the primary read-only, waits for the chosen replica (default: the one furthest ahead) to replay
everything, promotes it and turns the old primary into a replica. Writes pause for a few seconds.`,
	Example: "  ziroctl pg switchover shop\n  ziroctl pg switchover shop --to m2",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg switchover", args[0], func(st *ClusterState, now time.Time) error {
			return pgRequestSwitchover(st, args[0], pgFlags.group, pgFlags.to, now)
		}); err != nil {
			return err
		}
		fmt.Printf("✓ switchover started. Watch: ziroctl pg status %s\n", args[0])
		return nil
	},
}

var pgAddShardCmd = &cobra.Command{
	Use:   "add-shard <name>",
	Short: "Add a Citus worker group and rebalance shards onto it",
	Long: `Creates another group (primary and replicas), registers it with the coordinator and starts Citus's online
shard rebalance. Reads and writes continue while shards move.`,
	Example: "  ziroctl pg add-shard events",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var g string
		if err := pgEdit("pg add-shard", args[0], func(st *ClusterState, now time.Time) error {
			var err error
			g, err = pgAddShard(st, args[0], now)
			return err
		}); err != nil {
			return err
		}
		fmt.Printf("✓ group %s is being created. Watch: ziroctl pg status %s\n", g, args[0])
		return nil
	},
}

var pgExposeCmd = &cobra.Command{
	Use:   "expose <name>",
	Short: "Publish the cluster through the gateway on a TCP port",
	Long: `Creates a gateway TCP route to the cluster's read-write name (or the read-only one with --ro). Restrict who
may connect with --allow (CIDRs); the host firewall opens the port.`,
	Example: "  ziroctl pg expose shop --port 5432 --allow 203.0.113.0/24",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if pgFlags.port <= 0 {
			return fmt.Errorf("--port is required")
		}
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
		target, name := c.Name+"-rw", "pg-"+c.Name
		if pgFlags.ro {
			target, name = c.Name+"-ro", "pg-"+c.Name+"-ro"
		}
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		_, err = putRoute(s, GatewayRoute{Name: name, Kind: "tcp", Listen: pgFlags.port, AllowCIDRs: pgFlags.allow,
			To: []GatewayUpstream{{App: target, Weight: 1}}})
		_ = auditLog("cli", "cli", "pg expose", args[0], err)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %s is published on port %d (gateway route %s)\n", target, pgFlags.port, name)
		return nil
	},
}

var pgPauseCmd = &cobra.Command{
	Use:     "pause <name>",
	Short:   "Stop the controller from changing roles",
	Example: "  ziroctl pg pause shop",
	Args:    cobra.ExactArgs(1),
	RunE:    func(cmd *cobra.Command, args []string) error { return pgSetPaused(args[0], true) },
}

var pgResumeCmd = &cobra.Command{
	Use:     "resume <name>",
	Short:   "Let the controller manage roles again",
	Example: "  ziroctl pg resume shop",
	Args:    cobra.ExactArgs(1),
	RunE:    func(cmd *cobra.Command, args []string) error { return pgSetPaused(args[0], false) },
}

func pgSetPaused(name string, paused bool) error {
	if err := pgEdit("pg pause", name, func(st *ClusterState, now time.Time) error {
		c, err := pgCluster(st, name)
		if err != nil {
			return err
		}
		c.Paused = paused
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("✓ %s: controller paused=%v\n", name, paused)
	return nil
}

var pgRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a cluster",
	Long: `Removes the cluster's members; --purge also deletes its data and credentials. Without --purge the data stays on the nodes (/var/lib/ziro/apps/pgc-<name>-*)
and the credentials stay in the cluster, so nothing is lost by mistake.`,
	Example: "  ziroctl pg rm shop --purge",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := pgEdit("pg rm", args[0], func(st *ClusterState, now time.Time) error {
			return pgDelete(st, args[0], pgFlags.purge)
		}); err != nil {
			return err
		}
		fmt.Printf("✓ %s removed\n", args[0])
		return nil
	},
}

func init() {
	f := pgCreateCmd.Flags()
	f.StringVar(&pgFlags.version, "version", "17", "PostgreSQL major version: 16, 17 or 18")
	f.StringVar(&pgFlags.image, "image", "", "Member image (default: the pinned official image of --version)")
	f.IntVar(&pgFlags.replicas, "replicas", 1, "Replicas per group")
	f.StringVar(&pgFlags.sync, "sync", pgSyncQuorum, "Replication: quorum (synchronous with two or more replicas) or off")
	f.StringVar(&pgFlags.memory, "memory", "", "Memory limit per member (4Gi); tunes shared_buffers and the cache estimate")
	f.Float64Var(&pgFlags.cpus, "cpus", 0, "CPU limit per member")
	f.StringVar(&pgFlags.database, "database", "app", "Database created on the first primary")
	f.StringVar(&pgFlags.user, "user", "app", "Its owner")
	f.StringSliceVar(&pgFlags.allowFrom, "allow-from", nil, "Cluster apps allowed to connect ('*' = any)")
	f.IntVar(&pgFlags.shards, "shards", 0, "Worker groups for Citus sharding (0 = a plain cluster)")
	f.StringVar(&pgFlags.citus, "citus-image", "", "Citus member image, digest-pinned (needed with --shards)")
	f.BoolVar(&pgFlags.colocate, "colocate", false, "Allow members of a group to share a node (development only)")
	pgScaleCmd.Flags().IntVar(&pgFlags.replicas, "replicas", 0, "Replicas per group")
	for _, c := range []*cobra.Command{pgAddReplicaCmd, pgRmReplicaCmd, pgSwitchoverCmd} {
		c.Flags().StringVar(&pgFlags.group, "group", "", "Group (default: the only one, or the Citus coordinator)")
	}
	pgAddReplicaCmd.Flags().StringVar(&pgFlags.node, "node", "", "Node for the new replica (default: the least loaded without a member)")
	pgAddReplicaCmd.Flags().StringVar(&pgFlags.from, "from", "", "Member to copy from (default: the primary)")
	pgSwitchoverCmd.Flags().StringVar(&pgFlags.to, "to", "", "Replica to promote (default: the one furthest ahead)")
	pgExposeCmd.Flags().IntVar(&pgFlags.port, "port", 0, "TCP port on the gateway")
	pgExposeCmd.Flags().StringSliceVar(&pgFlags.allow, "allow", nil, "CIDRs allowed to connect")
	pgExposeCmd.Flags().BoolVar(&pgFlags.ro, "ro", false, "Route to the read-only name")
	pgCredentialsCmd.Flags().BoolVar(&pgFlags.ro, "ro", false, "Print only the read-only connection string")
	pgRmCmd.Flags().BoolVar(&pgFlags.purge, "purge", false, "Also delete the data on every node and the credentials")
	pgCmd.AddCommand(pgCreateCmd, pgLsCmd, pgStatusCmd, pgCredentialsCmd, pgScaleCmd, pgAddReplicaCmd, pgRmReplicaCmd,
		pgSwitchoverCmd, pgAddShardCmd, pgExposeCmd, pgPauseCmd, pgResumeCmd, pgRmCmd)
	rootCmd.AddCommand(pgCmd)
}

// ---- API ----

// registerPGRoutes: reading is for any token; changing members needs operator; creating and removing
// clusters needs admin. Credentials are never served over the API.
func registerPGRoutes(a *apiRouter) {
	a.get("/api/v1/pg", "viewer", func(w http.ResponseWriter, r *http.Request) {
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, pgViews(st, time.Now()))
	})
	a.get("/api/v1/pg/{name}", "viewer", func(w http.ResponseWriter, r *http.Request) {
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
		apiReply(w, nil, pgViewOf(st, c, time.Now()))
	})
	a.post("/api/v1/pg", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string     `json:"name"`
			Version   string     `json:"version"`
			Image     string     `json:"image"`
			Replicas  int        `json:"replicas"`
			Sync      string     `json:"sync"`
			Shards    int        `json:"shards"`
			CitusImg  string     `json:"citus_image"`
			Resources *Resources `json:"resources"`
			Database  string     `json:"database"`
			User      string     `json:"user"`
			AllowFrom []string   `json:"allow_from"`
			Colocate  bool       `json:"colocate"`
		}
		if err := decodeStrict(w, r, &req, 64<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		var view pgView
		err := withState(func(st *ClusterState) error {
			c, err := pgCreate(st, pgCreateOpts{Name: req.Name, Version: req.Version, Image: req.Image, Replicas: req.Replicas, Sync: req.Sync,
				Shards: req.Shards, Citus: req.CitusImg, Resources: req.Resources, Database: req.Database, User: req.User,
				AllowFrom: req.AllowFrom, Colocate: req.Colocate}, time.Now())
			if err == nil {
				view = pgViewOf(st, c, time.Now())
			}
			return err
		})
		apiReply(w, err, view)
	})
	a.delete("/api/v1/pg/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		purge := r.URL.Query().Get("purge") == "true"
		err := withState(func(st *ClusterState) error { return pgDelete(st, r.PathValue("name"), purge) })
		apiReply(w, err, APIMessage{Status: "ok", Message: "removed"})
	})
	a.post("/api/v1/pg/{name}/{action}", "operator", func(w http.ResponseWriter, r *http.Request) {
		name, action := r.PathValue("name"), r.PathValue("action")
		var req struct {
			Replicas *int   `json:"replicas"`
			Group    string `json:"group"`
			Node     string `json:"node"`
			From     string `json:"from"`
			Member   string `json:"member"`
			To       string `json:"to"`
		}
		if r.ContentLength != 0 && !decodeBody(w, r, &req) {
			return
		}
		var out any = APIMessage{Status: "ok", Message: action + " requested"}
		err := withState(func(st *ClusterState) error {
			now := time.Now()
			switch action {
			case "scale":
				if req.Replicas == nil {
					return fmt.Errorf("replicas is required")
				}
				return pgSetReplicas(st, name, *req.Replicas)
			case "add-replica":
				id, err := pgAddReplica(st, name, req.Group, req.Node, req.From)
				out = map[string]string{"member": id}
				return err
			case "rm-replica":
				return pgRemoveReplica(st, name, req.Group, req.Member)
			case "switchover":
				return pgRequestSwitchover(st, name, req.Group, req.To, now)
			case "add-shard":
				g, err := pgAddShard(st, name, now)
				out = map[string]string{"group": g}
				return err
			case "pause", "resume":
				c, err := pgCluster(st, name)
				if err == nil {
					c.Paused = action == "pause"
				}
				return err
			}
			return errNotFound("unknown action " + action)
		})
		apiReply(w, err, out)
	})
}

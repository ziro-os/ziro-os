package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Cluster storage: NFSv4.2 shares served by one node over the WireGuard mesh (encrypted).
//
//   ziroctl cluster storage add media --node storage-1
//   ziroctl cluster deploy --name web --volume media:/usr/share/nginx/html:ro
//
// The storage node's agent installs the NFS server on demand and exports the share only to the
// mesh IPs of nodes that run an app using it; in deny mode the mesh policy opens 2049/tcp to exactly
// those nodes. Consumer nodes mount the share before starting its containers (a replica whose share
// isn't mounted is not started, and the empty mount point is immutable), and bind-mount it in.
//
// ponytail: no replication. `failover` re-points a share at another node (for data on shared or
// restored storage) and restarts its consumers; replicated storage is a future module.

const (
	storageRoot = "/var/lib/ziro/storage" // on the storage node
	volumeRoot  = "/var/lib/ziro/volumes" // mount points on consumer nodes
)

type ClusterShare struct {
	Name    string `json:"name"`
	Node    string `json:"node"`
	Standby string `json:"standby,omitempty"`
	Created string `json:"created"`
}

type clusterExport struct {
	Share   string   `json:"share"`
	Path    string   `json:"path"`
	Clients []string `json:"clients"`
}

type clusterMount struct {
	Share  string `json:"share"`
	Server string `json:"server"` // storage node mesh IP
	Path   string `json:"path"`
}

var shareNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// parseVolume: "share:/container/path[:ro]".
func parseVolume(v string) (share, target string, ro bool, err error) {
	parts := strings.Split(v, ":")
	if len(parts) == 3 && parts[2] == "ro" {
		ro = true
		parts = parts[:2]
	}
	if len(parts) != 2 || !shareNameRe.MatchString(parts[0]) || !filepath.IsAbs(parts[1]) || filepath.Clean(parts[1]) != parts[1] || parts[1] == "/" {
		return "", "", false, fmt.Errorf("invalid volume %q (want share:/path[:ro])", v)
	}
	return parts[0], parts[1], ro, nil
}

func validateVolumes(a *ClusteredApp) error {
	if len(a.Volumes) > 16 {
		return errors.New("too many volumes (max 16)")
	}
	targets := map[string]bool{}
	for _, v := range a.Volumes {
		_, t, _, err := parseVolume(v)
		if err != nil {
			return err
		}
		if targets[t] {
			return fmt.Errorf("two volumes mounted at %s", t)
		}
		targets[t] = true
	}
	return nil
}

func (st *ClusterState) share(name string) *ClusterShare {
	for i := range st.Shares {
		if st.Shares[i].Name == name {
			return &st.Shares[i]
		}
	}
	return nil
}

func appUsesShare(a ClusteredApp, share string) bool {
	for _, v := range a.Volumes {
		if s, _, _, err := parseVolume(v); err == nil && s == share {
			return true
		}
	}
	return false
}

// shareClients: mesh IPs of nodes with a placed replica of an app using the share.
func shareClients(st *ClusterState, share string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range st.Replicas {
		a := st.app(r.App)
		if r.Node == "" || a == nil || !appUsesShare(*a, share) {
			continue
		}
		if n := st.node(r.Node); n != nil && n.MeshIP != "" && !seen[n.MeshIP] {
			seen[n.MeshIP] = true
			out = append(out, n.MeshIP)
		}
	}
	sort.Strings(out)
	return out
}

// storageFor computes what a node exports and mounts.
func storageFor(st *ClusterState, nodeID string) (exports []clusterExport, mounts []clusterMount) {
	for _, s := range st.Shares {
		if s.Node == nodeID {
			if c := shareClients(st, s.Name); len(c) > 0 {
				exports = append(exports, clusterExport{Share: s.Name, Path: filepath.Join(storageRoot, s.Name), Clients: c})
			}
		}
	}
	used := map[string]bool{}
	for _, r := range st.Replicas {
		a := st.app(r.App)
		if r.Node != nodeID || a == nil {
			continue
		}
		for _, v := range a.Volumes {
			if s, _, _, err := parseVolume(v); err == nil {
				used[s] = true
			}
		}
	}
	for name := range used {
		s := st.share(name)
		if s == nil {
			continue
		}
		if n := st.node(s.Node); n != nil && n.MeshIP != "" {
			mounts = append(mounts, clusterMount{Share: name, Server: n.MeshIP, Path: filepath.Join(storageRoot, name)})
		}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Share < mounts[j].Share })
	return exports, mounts
}

// storagePolicyRule opens 2049/tcp on the storage node to its consumers (deny-mode mesh policy).
func storagePolicyRule(st *ClusterState, nodeID string) *MeshRule {
	exports, _ := storageFor(st, nodeID)
	seen := map[string]bool{}
	var src []string
	for _, e := range exports {
		for _, c := range e.Clients {
			if !seen[c] {
				seen[c] = true
				src = append(src, c)
			}
		}
	}
	if len(src) == 0 {
		return nil
	}
	sort.Strings(src)
	return &MeshRule{App: "nfs", Port: 2049, Proto: "tcp", Sources: src}
}

// volumeArgs turns an app's volumes into bind mounts of the node's NFS mount points.
func volumeArgs(volumes []string) []string {
	var out []string
	for _, v := range volumes {
		s, t, ro, err := parseVolume(v)
		if err != nil {
			continue
		}
		spec := filepath.Join(volumeRoot, s) + ":" + t
		if ro {
			spec += ":ro"
		}
		out = append(out, spec)
	}
	return out
}

// ---- agent side ----

// applyStorage exports this node's shares and mounts the ones its replicas use. It returns the
// shares that are NOT usable here, so their replicas are held back (never started on an empty
// local directory).
func applyStorage(exports []clusterExport, mounts []clusterMount) (unavailable map[string]bool, err error) {
	var errs []string
	var nfsExports []NFSExport
	for _, e := range exports {
		if !shareNameRe.MatchString(e.Share) || e.Path != filepath.Join(storageRoot, e.Share) {
			errs = append(errs, "invalid export "+e.Share)
			continue
		}
		if err := os.MkdirAll(e.Path, 0755); err == nil {
			// root_squash: container root writes as nobody. No sticky bit: with
			// fs.protected_regular=2 it would refuse root opening its own (nobody-owned) files.
			_ = os.Chmod(e.Path, 0777)
		}
		nfsExports = append(nfsExports, NFSExport{Path: e.Path, Clients: e.Clients})
	}
	if len(nfsExports) > 0 || fileExists(nfsClusterFile) {
		if perr := publishExports(nfsClusterFile, nfsExports); perr != nil {
			errs = append(errs, "exports: "+perr.Error())
		}
	}
	unavailable = map[string]bool{}
	want := map[string]bool{}
	for _, m := range mounts {
		want[m.Share] = true
		if !shareNameRe.MatchString(m.Share) {
			unavailable[m.Share] = true
			continue
		}
		if merr := mountNFS(NFSMount{Server: m.Server, Path: m.Path, Target: filepath.Join(volumeRoot, m.Share)}); merr != nil {
			unavailable[m.Share] = true
			errs = append(errs, fmt.Sprintf("mount %s: %v", m.Share, merr))
		}
	}
	// Shares no replica here uses any more are unmounted.
	if ents, rerr := os.ReadDir(volumeRoot); rerr == nil {
		for _, e := range ents {
			if !want[e.Name()] {
				_ = umountNFS(filepath.Join(volumeRoot, e.Name()))
			}
		}
	}
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, "; "))
	}
	return unavailable, err
}

// holdBack drops assignments whose volumes are unavailable on this node.
func holdBack(as []Assignment, unavailable map[string]bool) []Assignment {
	if len(unavailable) == 0 {
		return as
	}
	kept := as[:0:0]
	for _, a := range as {
		ok := true
		for _, v := range a.Volumes {
			hostPath, _, _ := strings.Cut(v, ":")
			if unavailable[filepath.Base(hostPath)] {
				ok = false
			}
		}
		if ok {
			kept = append(kept, a)
		}
	}
	return kept
}

// ---- CLI (master) ----

var (
	storageNode, storageStandby, storageTo string
)

var clusterStorageCmd = &cobra.Command{Use: "storage", Short: "Cluster NFS shares (served over the WireGuard mesh)"}

var clusterStorageAddCmd = &cobra.Command{
	Use:     "add <share>",
	Short:   "Create a share on a node (apps use it with --volume <share>:/path)",
	Example: `  ziroctl cluster storage add media --node storage-1 --standby storage-2`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if !shareNameRe.MatchString(args[0]) {
			return fmt.Errorf("invalid share name %q (a-z 0-9 -, max 32)", args[0])
		}
		return withState(func(st *ClusterState) error {
			if st.share(args[0]) != nil {
				return fmt.Errorf("share %q exists", args[0])
			}
			for _, id := range []string{storageNode, storageStandby} {
				if id != "" && st.node(id) == nil {
					return fmt.Errorf("node %q not found", id)
				}
			}
			if storageNode == "" {
				return errors.New("--node is required")
			}
			st.Shares = append(st.Shares, ClusterShare{Name: args[0], Node: storageNode, Standby: storageStandby,
				Created: time.Now().UTC().Format(time.RFC3339)})
			fmt.Printf("✓ share %s on %s (%s/%s); use it: ziroctl cluster deploy ... --volume %s:/data\n",
				args[0], storageNode, storageRoot, args[0], args[0])
			return nil
		})
	},
}

var clusterStorageRmCmd = &cobra.Command{
	Use:   "rm <share>",
	Short: "Remove a share (refused while an app uses it; the data stays on the node)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			for _, a := range st.Apps {
				if appUsesShare(a, args[0]) {
					return fmt.Errorf("share %s is used by app %s", args[0], a.Name)
				}
			}
			for i, s := range st.Shares {
				if s.Name == args[0] {
					st.Shares = append(st.Shares[:i], st.Shares[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("share %q not found", args[0])
		})
	},
}

var clusterStorageLsCmd = &cobra.Command{
	Use: "ls", Short: "List shares, their node and consumers",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		type row struct {
			ClusterShare
			Apps    []string `json:"apps"`
			Clients []string `json:"clients"`
		}
		var rows []row
		for _, s := range st.Shares {
			r := row{ClusterShare: s, Clients: shareClients(st, s.Name)}
			for _, a := range st.Apps {
				if appUsesShare(a, s.Name) {
					r.Apps = append(r.Apps, a.Name)
				}
			}
			rows = append(rows, r)
		}
		return printResult(rows, func() {
			fmt.Printf("%-16s %-14s %-14s %-20s %s\n", "SHARE", "NODE", "STANDBY", "APPS", "CLIENT NODES")
			for _, r := range rows {
				fmt.Printf("%-16s %-14s %-14s %-20s %s\n", r.Name, r.Node, r.Standby, strings.Join(r.Apps, ","), strings.Join(r.Clients, ","))
			}
		})
	},
}

var clusterStorageFailoverCmd = &cobra.Command{
	Use:   "failover <share>",
	Short: "Serve a share from another node (its data must be there) and restart its consumers",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			s := st.share(args[0])
			if s == nil {
				return fmt.Errorf("share %q not found", args[0])
			}
			to := storageTo
			if to == "" {
				to = s.Standby
			}
			n := st.node(to)
			if n == nil || to == s.Node {
				return fmt.Errorf("pick another node with --to (standby: %q)", s.Standby)
			}
			if n.Status != "Ready" {
				return fmt.Errorf("node %s is %s", to, n.Status)
			}
			s.Node, s.Standby = to, s.Node
			// Consumers roll: new containers bind the remounted share (old ones hold the old mount).
			for i := range st.Apps {
				if appUsesShare(st.Apps[i], s.Name) {
					a := st.Apps[i]
					a.VolumeEpoch++
					upsertApp(st, a)
				}
			}
			scheduleReplicas(st, time.Now())
			fmt.Printf("✓ share %s now served by %s (standby %s); consumers restart one replica at a time\n", s.Name, s.Node, s.Standby)
			return nil
		})
	},
}

func init() {
	clusterStorageAddCmd.Flags().StringVar(&storageNode, "node", "", "Node that serves the share")
	clusterStorageAddCmd.Flags().StringVar(&storageStandby, "standby", "", "Node to fail over to")
	clusterStorageFailoverCmd.Flags().StringVar(&storageTo, "to", "", "Node to serve from (default: the standby)")
	clusterStorageCmd.AddCommand(clusterStorageAddCmd, clusterStorageRmCmd, clusterStorageLsCmd, clusterStorageFailoverCmd)
	clusterCmd.AddCommand(clusterStorageCmd)
}

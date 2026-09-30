package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// NFS: NFSv4.2-only file sharing. The server side is the `nfs` module (nfs-utils is installed on
// demand, never preinstalled); clients need no package: the kernel mounts NFSv4 directly.
// Exports always root_squash, sync, no_subtree_check; port 2049/tcp is opened only to the listed
// clients. Cluster shares (cluster_storage.go) reuse all of this over the WireGuard mesh.

var (
	nfsConfigPath  = "/etc/ziro/nfs.json"
	nfsExportsFile = "/etc/exports.d/ziro.exports"         // standalone exports
	nfsClusterFile = "/etc/exports.d/ziro-cluster.exports" // cluster shares (the agent)
)

type NFSExport struct {
	Path     string   `json:"path"`
	Clients  []string `json:"clients"` // IPv4 addresses or CIDRs
	ReadOnly bool     `json:"read_only,omitempty"`
}

type NFSMount struct {
	Server   string `json:"server"` // IPv4 address
	Path     string `json:"path"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type NFSConfig struct {
	Exports []NFSExport `json:"exports,omitempty"`
	Mounts  []NFSMount  `json:"mounts,omitempty"`
}

// Exporting these would hand out the OS itself.
var nfsForbidden = []string{"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var", "/var/lib", "/var/lib/ziro"}

func validateExportPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\"\\ \t\n") {
		return fmt.Errorf("export path %q must be an absolute, clean path without spaces or quotes", p)
	}
	for _, f := range nfsForbidden {
		if p == f {
			return fmt.Errorf("refusing to export system path %s", p)
		}
	}
	for _, f := range []string{"/etc/", "/proc/", "/sys/", "/dev/", "/boot/", "/usr/", "/root/"} {
		if strings.HasPrefix(p+"/", f) {
			return fmt.Errorf("refusing to export system path %s", p)
		}
	}
	return nil
}

func normalizeClients(clients []string) ([]string, error) {
	if len(clients) == 0 {
		return nil, errors.New("an export needs at least one client network (--clients)")
	}
	var out []string
	for _, c := range clients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, fmt.Errorf("invalid client %q (IPv4 address or CIDR)", c)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("client %q: IPv4 only", c)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("client %q would export to everyone", c)
		}
		out = append(out, p.Masked().String())
	}
	sort.Strings(out)
	return out, nil
}

// renderExports writes exports(5) lines. fsid is derived from the path so it is stable.
func renderExports(exports []NFSExport) (string, error) {
	var b strings.Builder
	b.WriteString("# Managed by ziroctl; edits are overwritten\n")
	for _, e := range exports {
		if err := validateExportPath(e.Path); err != nil {
			return "", err
		}
		clients, err := normalizeClients(e.Clients)
		if err != nil {
			return "", err
		}
		mode := "rw"
		if e.ReadOnly {
			mode = "ro"
		}
		opts := fmt.Sprintf("%s,sync,no_subtree_check,root_squash,sec=sys,fsid=%d", mode, crc32.ChecksumIEEE([]byte(e.Path))&0x7fffffff)
		b.WriteString(e.Path)
		for _, c := range clients {
			b.WriteString(" " + c + "(" + opts + ")")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func loadNFSConfig() (*NFSConfig, error) {
	c := &NFSConfig{}
	b, err := os.ReadFile(nfsConfigPath)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, c)
}

func saveNFSConfig(c *NFSConfig) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(nfsConfigPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(nfsConfigPath, b, 0644)
}

// nfsServerReady makes sure the nfs module (server) is enabled; the first export installs it.
var nfsServerReady = func() error {
	if s := enabledModules()["nfs"]; s != nil && s.Status == "enabled" {
		return nil
	}
	fmt.Println("Enabling the nfs module (NFS server) ...")
	return enableModule("nfs", moduleOpts{Auto: true})
}

var nfsExec = func(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// publishExports writes one exports file and reloads the export table.
func publishExports(file string, exports []NFSExport) error {
	content, err := renderExports(exports)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(file); err == nil && string(cur) == content {
		return nil
	}
	if len(exports) > 0 {
		if err := nfsServerReady(); err != nil {
			return err
		}
	}
	for _, e := range exports {
		if err := os.MkdirAll(e.Path, 0755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		return err
	}
	if err := writeFileAtomic(file, []byte(content), 0644); err != nil {
		return err
	}
	if _, err := os.Stat("/usr/sbin/exportfs"); err != nil {
		return nil // server not installed: nothing to reload (no exports left)
	}
	return nfsExec("/usr/sbin/exportfs", "-ra")
}

// syncNFSFirewall opens 2049/tcp to exactly the standalone export clients.
func syncNFSFirewall(exports []NFSExport) error {
	fw := loadFirewallConfig()
	kept := fw.AllowedPorts[:0]
	for _, r := range fw.AllowedPorts {
		if r.Comment != "nfs" {
			kept = append(kept, r)
		}
	}
	fw.AllowedPorts = kept
	seen := map[string]bool{}
	for _, e := range exports {
		clients, err := normalizeClients(e.Clients)
		if err != nil {
			return err
		}
		for _, c := range clients {
			if !seen[c] {
				seen[c] = true
				fw.AllowedPorts = append(fw.AllowedPorts, FirewallRule{Port: 2049, Protocol: "tcp", Comment: "nfs", Source: c})
			}
		}
	}
	if err := saveFirewallConfig(fw); err != nil {
		return err
	}
	if fw.Enabled {
		return applyFirewallRules(fw)
	}
	return nil
}

func nfsMountOptions(server string, ro bool) string {
	o := "vers=4.2,proto=tcp,hard,timeo=600,retrans=2,noatime,nodev,nosuid,nconnect=4,rsize=1048576,wsize=1048576,addr=" + server
	if ro {
		o += ",ro"
	}
	return o
}

// mountEntry returns the source and type mounted at path (the last mount wins).
func mountEntry(path string) (src, fstype string) {
	b, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return "", ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		pre, post, ok := strings.Cut(l, " - ")
		f, t := strings.Fields(pre), strings.Fields(post)
		if ok && len(f) >= 5 && len(t) >= 2 && f[4] == path {
			src, fstype = t[1], t[0]
		}
	}
	return src, fstype
}

// mountNFS mounts server:path at target (remounting when the server changed). The empty mount point
// is made immutable, so nothing can be written to the local disk while the share is not mounted.
func mountNFS(m NFSMount) error {
	a, err := netip.ParseAddr(m.Server)
	if err != nil || !a.Is4() {
		return fmt.Errorf("invalid NFS server %q (IPv4 address)", m.Server)
	}
	if !filepath.IsAbs(m.Path) || filepath.Clean(m.Path) != m.Path || !filepath.IsAbs(m.Target) || filepath.Clean(m.Target) != m.Target {
		return fmt.Errorf("NFS paths must be absolute and clean")
	}
	want := a.String() + ":" + m.Path
	src, fstype := mountEntry(m.Target)
	if fstype == "nfs4" && src == want {
		return nil
	}
	if strings.HasPrefix(fstype, "nfs") { // a different server (failover): detach the old one
		_ = nfsExec("umount", "-l", m.Target)
	}
	if err := os.MkdirAll(m.Target, 0755); err != nil {
		return err
	}
	_ = exec.Command("chattr", "+i", m.Target).Run() // best effort: needs an ext* parent filesystem
	return nfsExec("mount", "-t", "nfs4", "-o", nfsMountOptions(a.String(), m.ReadOnly), want, m.Target)
}

func umountNFS(target string) error {
	if _, fstype := mountEntry(target); !strings.HasPrefix(fstype, "nfs") {
		return nil
	}
	return nfsExec("umount", "-l", target)
}

// nfsBoot re-mounts standalone NFS mounts (service boot, after the network).
func nfsBoot() {
	c, err := loadNFSConfig()
	if err != nil {
		return
	}
	for _, m := range c.Mounts {
		if err := mountNFS(m); err != nil {
			fmt.Printf("[nfs] %s: %v\n", m.Target, err)
		}
	}
}

// ---- CLI ----

var (
	nfsClients []string
	nfsRO      bool
)

var nfsCmd = &cobra.Command{
	Use:   "nfs",
	Short: "NFSv4.2 shares: export directories, mount remote shares",
}

var nfsExportCmd = &cobra.Command{Use: "export", Short: "Directories this host shares"}

var nfsExportAddCmd = &cobra.Command{
	Use:     "add <path>",
	Short:   "Share a directory with client networks (installs the NFS server on first use)",
	Example: `  ziroctl nfs export add /srv/media --clients 10.0.0.0/24 --ro`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadNFSConfig()
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		e := NFSExport{Path: args[0], Clients: nfsClients, ReadOnly: nfsRO}
		kept := c.Exports[:0]
		for _, x := range c.Exports {
			if x.Path != e.Path {
				kept = append(kept, x)
			}
		}
		c.Exports = append(kept, e)
		if _, err := renderExports(c.Exports); err != nil {
			return err
		}
		if err := publishExports(nfsExportsFile, c.Exports); err != nil {
			return err
		}
		if err := syncNFSFirewall(c.Exports); err != nil {
			return err
		}
		if err := saveNFSConfig(c); err != nil {
			return err
		}
		fmt.Printf("✅ Exported %s to %s (NFSv4.2, %s). Clients: ziroctl nfs mount <this-host>:%s <dir>\n",
			e.Path, strings.Join(e.Clients, ", "), map[bool]string{true: "read-only", false: "read-write"}[e.ReadOnly], e.Path)
		return nil
	},
}

var nfsExportRmCmd = &cobra.Command{
	Use:   "remove <path>",
	Short: "Stop sharing a directory (its files stay)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadNFSConfig()
		if err != nil {
			return err
		}
		kept := c.Exports[:0]
		for _, x := range c.Exports {
			if x.Path != args[0] {
				kept = append(kept, x)
			}
		}
		if len(kept) == len(c.Exports) {
			return fmt.Errorf("%s is not exported", args[0])
		}
		c.Exports = kept
		if err := publishExports(nfsExportsFile, c.Exports); err != nil {
			return err
		}
		if err := syncNFSFirewall(c.Exports); err != nil {
			return err
		}
		return saveNFSConfig(c)
	},
}

var nfsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List exports and mounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _ := loadNFSConfig()
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(c)
		}
		fmt.Println("EXPORTS")
		for _, e := range c.Exports {
			fmt.Printf("  %-30s %-4s %s\n", e.Path, map[bool]string{true: "ro", false: "rw"}[e.ReadOnly], strings.Join(e.Clients, ","))
		}
		fmt.Println("MOUNTS")
		for _, m := range c.Mounts {
			src, fs := mountEntry(m.Target)
			state := "not mounted"
			if strings.HasPrefix(fs, "nfs") {
				state = "mounted from " + src
			}
			fmt.Printf("  %-30s %s:%s (%s)\n", m.Target, m.Server, m.Path, state)
		}
		return nil
	},
}

var nfsMountCmd = &cobra.Command{
	Use:     "mount <server>:<path> <target>",
	Short:   "Mount a remote NFSv4 share (persistent across reboots)",
	Example: `  ziroctl nfs mount 10.0.0.5:/srv/media /mnt/media --ro`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, path, ok := strings.Cut(args[0], ":")
		if !ok {
			return errors.New("source must be <server-ip>:<path>")
		}
		if err := validateMountPoint(args[1]); err != nil {
			return err
		}
		m := NFSMount{Server: server, Path: path, Target: args[1], ReadOnly: nfsRO}
		if err := mountNFS(m); err != nil {
			return err
		}
		c, err := loadNFSConfig()
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		kept := c.Mounts[:0]
		for _, x := range c.Mounts {
			if x.Target != m.Target {
				kept = append(kept, x)
			}
		}
		c.Mounts = append(kept, m)
		if err := saveNFSConfig(c); err != nil {
			return err
		}
		fmt.Printf("✅ %s mounted at %s\n", args[0], args[1])
		return nil
	},
}

var nfsUmountCmd = &cobra.Command{
	Use:   "umount <target>",
	Short: "Unmount a share and forget it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := umountNFS(args[0]); err != nil {
			return err
		}
		c, err := loadNFSConfig()
		if err != nil {
			return err
		}
		kept := c.Mounts[:0]
		for _, x := range c.Mounts {
			if x.Target != args[0] {
				kept = append(kept, x)
			}
		}
		c.Mounts = kept
		return saveNFSConfig(c)
	},
}

func init() {
	nfsExportAddCmd.Flags().StringSliceVar(&nfsClients, "clients", nil, "Client IPv4 addresses or CIDRs (required)")
	nfsExportAddCmd.Flags().BoolVar(&nfsRO, "ro", false, "Read-only export")
	nfsMountCmd.Flags().BoolVar(&nfsRO, "ro", false, "Mount read-only")
	nfsExportCmd.AddCommand(nfsExportAddCmd, nfsExportRmCmd)
	nfsCmd.AddCommand(nfsExportCmd, nfsListCmd, nfsMountCmd, nfsUmountCmd)
	rootCmd.AddCommand(nfsCmd)
}

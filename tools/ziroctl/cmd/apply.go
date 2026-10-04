package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// `ziroctl apply -f host.yaml`: provision a whole host from one declarative file (hostname, SSH
// keys, firewall, packages, plugins, stacks, updates, network, cluster membership, and on a
// master the router). It plans
// first and changes only what differs, so applying the same file twice is a no-op. Each section
// calls the same operation as its CLI command. The file can arrive as cloud user-data starting
// with "#ziro-config", from the installer (ziro.config=https://...), or over the API.

type HostConfig = schema.HostConfig

var (
	appliedHostConfig = "/etc/ziro/applied.yaml" // the last file applied (0600)
	applyTag          = "ziro:apply"             // authorized_keys lines this file manages
)

// HostChange is one planned change; Action is create, update, unchanged or check (decided
// while applying, e.g. keys fetched from GitHub).
type HostChange struct {
	Section string `json:"section"`
	Item    string `json:"item"`
	Action  string `json:"action"`
}

type hostPlanner struct {
	c    schema.HostSpec
	dir  string // the host file's directory (stacks resolve here)
	plan []HostChange
	todo []func() error // applied in plan order
}

func (p *hostPlanner) add(section, item string, changed bool, apply func() error) {
	action := "unchanged"
	if changed {
		action = "update"
		p.todo = append(p.todo, func() error {
			if err := apply(); err != nil {
				return fmt.Errorf("%s %s: %w", section, item, err)
			}
			return nil
		})
	}
	p.plan = append(p.plan, HostChange{section, item, action})
}

func planHost(cfg HostConfig, dir string, confirm time.Duration) (*hostPlanner, error) {
	p := &hostPlanner{c: cfg.Host, dir: dir}
	h := cfg.Host
	if h.Hostname != "" {
		cur, _ := os.ReadFile(hostnamePath) // the persisted name (what boots next)
		p.add("hostname", h.Hostname, strings.TrimSpace(string(cur)) != h.Hostname, func() error { return setHostname(h.Hostname) })
	}
	if h.Network != nil {
		var nc NetConfig
		dec := json.NewDecoder(bytes.NewReader(h.Network))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&nc); err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		cur, _ := loadNetConfig(netConfigPath)
		a, _ := json.Marshal(cur)
		b, _ := json.Marshal(&nc)
		p.add("network", fmt.Sprintf("%d interface(s)", len(nc.Interfaces)), !bytes.Equal(a, b), func() error {
			if err := saveNetConfig(netConfigPath, &nc); err != nil {
				return err
			}
			return startNetApply(confirm)
		})
	}
	if s := h.SSH; s != nil {
		if len(s.Keys) > 0 {
			keys, rejected := acceptKeys([]byte(joinLines(s.Keys)), applyTag)
			if len(rejected) > 0 {
				return nil, fmt.Errorf("ssh keys: %v", rejected)
			}
			cur, _ := os.ReadFile(sshAuthorizedKeysPath)
			out, added, removed := mergeAuthorizedKeys(cur, keys, applyTag, true) // keys dropped from the file go
			p.add("ssh", fmt.Sprintf("%d key(s)", len(keys)), added+removed > 0, func() error { return writeAuthorizedKeys(out) })
		}
		for _, src := range s.Import {
			p.plan = append(p.plan, HostChange{"ssh", "import " + src, "check"})
			p.todo = append(p.todo, func() error { _, _, _, err := importKeys(src, false); return err })
		}
	}
	if f := h.Firewall; f != nil {
		fw := loadFirewallConfig()
		for _, port := range f.Allow {
			pn, proto := parsePortProto(port)
			open := false
			for _, r := range fw.AllowedPorts {
				open = open || (r.Port == pn && r.Protocol == proto && r.Source == "")
			}
			p.add("firewall", "allow "+port, !open, func() error { _, err := firewallAllow(port, "ziroctl apply"); return err })
		}
		for _, t := range f.Block {
			_, ip, err := canonicalBlockTarget(t)
			if err != nil {
				return nil, fmt.Errorf("firewall: %w", err)
			}
			blocked := false
			for _, b := range fw.BlockedIPs {
				_, saved, err := canonicalBlockTarget(b.IP)
				blocked = blocked || (err == nil && saved == ip)
			}
			p.add("firewall", "block "+ip, !blocked, func() error { _, err := firewallBlock(ip, "ziroctl apply"); return err })
		}
	}
	for _, pkg := range h.Packages {
		p.add("packages", pkg, !apkInstalled(pkg), func() error {
			if err := apkAdd([]string{pkg}); err != nil {
				return err
			}
			return recordExtraPackages([]string{pkg}, nil)
		})
	}
	if len(h.Plugins) > 0 {
		all, err := loadManifests()
		if err != nil {
			return nil, err
		}
		enabled := enabledModules()
		for _, pl := range h.Plugins {
			m, ok := installedManifest(all, pl.Name)
			if !ok {
				return nil, fmt.Errorf("plugins: unknown plugin %q (see: ziroctl plugin search)", pl.Name)
			}
			st := enabled[pl.Name]
			switch {
			case st == nil || st.Status != "enabled":
				p.add("plugins", pl.Name, true, func() error { return enableModule(pl.Name, moduleOpts{Set: pl.Set}) })
			default:
				changed := false
				for k, v := range pl.Set {
					changed = changed || st.Settings[k] != v
				}
				p.add("plugins", pl.Name, changed, func() error { return reinstallModule(m, st, moduleOpts{Auto: st.Auto, Set: pl.Set}) })
			}
		}
	}
	for _, sf := range h.Stacks {
		path := filepath.Join(dir, filepath.Clean(sf))
		if rel, err := filepath.Rel(dir, path); err != nil || rel == ".." || filepath.IsAbs(rel) || len(rel) > 2 && rel[:3] == "../" {
			return nil, fmt.Errorf("stacks: %s is outside the host file's directory", sf)
		}
		s, apps, err := loadStackFile(path)
		if err != nil {
			return nil, err
		}
		prev, err := loadStackState(s.Stack)
		var nf errNotFound
		if err != nil && !errors.As(err, &nf) {
			return nil, err
		}
		plan, err := planStack(s, apps, prev)
		if err != nil {
			return nil, err
		}
		changed := false
		for _, c := range plan {
			changed = changed || c.Action != "unchanged"
		}
		p.add("stacks", s.Stack, changed, func() error { return applyStack(s, apps, plan, prev) })
	}
	if u := h.Update; u != nil {
		var cur updateConf
		if b, err := os.ReadFile(updateConfFile); err == nil {
			_ = json.Unmarshal(b, &cur)
		}
		p.add("update", fmt.Sprintf("auto=%v", u.Auto), cur.Auto != u.Auto, func() error {
			b, _ := json.Marshal(updateConf{Auto: u.Auto})
			return writeFileAtomic(updateConfFile, append(b, '\n'), 0644)
		})
	}
	if c := h.Cluster; c != nil && c.Join != nil {
		cfg, err := loadClusterConfig()
		member := err == nil && cfg.Role != ""
		p.add("cluster", "join "+c.Join.Address, !member, func() error {
			// The join command's own implementation, with the file's values for its flags.
			joinTokenFile, joinCAHashFlag, joinControlPlane, joinTokenFlag = c.Join.TokenFile, c.Join.CAHash, c.Join.ControlPlane, ""
			return clusterJoinCmd.RunE(clusterJoinCmd, []string{c.Join.Address})
		})
	}
	if h.Router != nil {
		if err := planRouter(p, h.Router); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func joinLines(ls []string) string {
	var b bytes.Buffer
	for _, l := range ls {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// applyHostFile plans and (unless dryRun) applies a host file; it records the file applied.
func applyHostFile(data []byte, dir string, dryRun bool, confirm time.Duration) ([]HostChange, error) {
	cfg, err := schema.ParseHostConfig(data)
	if err != nil {
		return nil, err
	}
	p, err := planHost(cfg, dir, confirm)
	if err != nil || dryRun {
		return planOrNil(p), err
	}
	for _, f := range p.todo {
		if err := f(); err != nil {
			return p.plan, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(appliedHostConfig), 0700); err != nil {
		return p.plan, err
	}
	return p.plan, writeFileAtomic(appliedHostConfig, data, 0600)
}

func planOrNil(p *hostPlanner) []HostChange {
	if p == nil {
		return nil
	}
	return p.plan
}

var (
	hostFile    string
	hostDryRun  bool
	hostConfirm time.Duration
)

var applyCmd = &cobra.Command{
	Use:   "apply -f <host.yaml>",
	Short: "Make this host match a YAML or JSON config file",
	Example: `  ziroctl apply -f host.yaml --dry-run
  ziroctl apply -f host.yaml --confirm-timeout 2m`,
	Long: `Provisions the whole host from one file:

  host:
    version: 1
    hostname: web-1
    ssh: { keys: ["ssh-ed25519 AAAA... ops"], import: [gh:alice] }
    firewall: { allow: [80/tcp, 443/tcp] }
    packages: [htop]
    plugins: [ { name: clamav, set: { onaccess: /srv } } ]
    stacks: [ ./shop.yaml ]
    update: { auto: true }
    network: { interfaces: [ { name: eth0, mode: dhcp } ] }
    cluster: { join: { address: 10.0.0.1:7443, token_file: /run/secrets/join } }

SSH keys listed here are managed by the file: removing one from it removes it from the host
(other keys are never touched). Network changes take --confirm-timeout like 'network apply'.
Cloud user-data starting with "#ziro-config" is applied at first boot.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(hostFile)
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(hostFile)
		if err != nil {
			return err
		}
		plan, err := applyHostFile(data, filepath.Dir(abs), hostDryRun, hostConfirm)
		perr := printResult(map[string]any{"plan": plan, "applied": err == nil && !hostDryRun}, func() {
			sym := map[string]string{"update": "~", "unchanged": "=", "check": "?"}
			for _, c := range plan {
				fmt.Printf("  %s %-9s %s\n", sym[c.Action], c.Section, c.Item)
			}
			if err == nil && !hostDryRun {
				fmt.Println("✓ host matches", hostFile)
			}
		})
		if err != nil {
			return err
		}
		return perr
	},
}

func init() {
	applyCmd.Flags().StringVarP(&hostFile, "file", "f", "", "Host config (YAML or JSON)")
	_ = applyCmd.MarkFlagRequired("file")
	applyCmd.Flags().BoolVar(&hostDryRun, "dry-run", false, "Only show the plan")
	applyCmd.Flags().DurationVar(&hostConfirm, "confirm-timeout", 0, "Network changes roll back unless confirmed within this time (ziroctl network confirm)")
	rootCmd.AddCommand(applyCmd)
}

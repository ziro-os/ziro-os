package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// HostConfig describes a whole host declaratively; `ziroctl apply -f host.yaml` makes the host
// match it and is a no-op when it already does:
//
//	host:
//	  version: 1
//	  hostname: web-1
//	  ssh: { keys: ["ssh-ed25519 AAAA... ops"], import: [gh:alice] }
//	  firewall: { allow: [80/tcp, 443/tcp] }
//	  packages: [htop]
//	  plugins: [ { name: clamav, set: { onaccess: /srv } } ]
//	  stacks: [ ./shop.yaml ]
//	  update: { auto: true }
//	  network: { interfaces: [ { name: eth0, mode: dhcp } ] }        # ziroctl network schema
//	  cluster: { join: { address: 10.0.0.1:7443, token_file: /run/secrets/join, ca_hash: "sha256:..." } }
type HostConfig struct {
	Host HostSpec `json:"host"`
}

type HostSpec struct {
	Version  int             `json:"version"`
	Hostname string          `json:"hostname,omitempty"`
	SSH      *HostSSH        `json:"ssh,omitempty"`
	Firewall *HostFirewall   `json:"firewall,omitempty"`
	Packages []string        `json:"packages,omitempty"`
	Plugins  []HostPlugin    `json:"plugins,omitempty"`
	Stacks   []string        `json:"stacks,omitempty"` // stack files next to the host file
	Update   *HostUpdate     `json:"update,omitempty"`
	Network  json.RawMessage `json:"network,omitempty"` // validated by ziroctl's network rules
	Cluster  *HostCluster    `json:"cluster,omitempty"`
}

type HostSSH struct {
	Keys   []string `json:"keys,omitempty"`   // authorized_keys lines
	Import []string `json:"import,omitempty"` // gh:<user>, gl:<user>
}

type HostFirewall struct {
	Allow []string `json:"allow,omitempty"` // 443, 443/tcp, 51820/udp
	Block []string `json:"block,omitempty"` // IP or CIDR
}

type HostPlugin struct {
	Name string            `json:"name"`
	Set  map[string]string `json:"set,omitempty"`
}

type HostUpdate struct {
	Auto bool `json:"auto"`
}

type HostCluster struct {
	Join *HostClusterJoin `json:"join,omitempty"`
}

type HostClusterJoin struct {
	Address      string `json:"address"`    // master host:port
	TokenFile    string `json:"token_file"` // never the token itself: files are not world-readable
	CAHash       string `json:"ca_hash,omitempty"`
	ControlPlane bool   `json:"control_plane,omitempty"`
}

var (
	sshKeyRe      = regexp.MustCompile(`^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/=]{40,}( [^\x00-\x1f]{0,200})?$`)
	keySourceRe   = regexp.MustCompile(`^(gh|gl):[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	portSpecRe    = regexp.MustCompile(`^[0-9]{1,5}(/(tcp|udp))?$`)
	PackageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,99}$`)
	hostPortRe    = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,253}:[0-9]{1,5}$`)
)

// ParseHostConfig decodes a host config (YAML or JSON) strictly and validates it.
func ParseHostConfig(b []byte) (HostConfig, error) {
	var c HostConfig
	if err := DecodeStrict(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func (c HostConfig) Validate() error {
	h := c.Host
	if h.Version != 1 {
		return fmt.Errorf("unsupported host config version %d (want 1)", h.Version)
	}
	if h.Hostname != "" && (len(h.Hostname) > 63 || !HostRe.MatchString(h.Hostname) || strings.Contains(h.Hostname, ".")) {
		return fmt.Errorf("bad hostname %q (one DNS label)", h.Hostname)
	}
	if h.SSH != nil {
		for _, k := range h.SSH.Keys {
			if !sshKeyRe.MatchString(strings.TrimSpace(k)) {
				return fmt.Errorf("ssh: not a public key line: %.40q", k)
			}
		}
		for _, s := range h.SSH.Import {
			if !keySourceRe.MatchString(s) {
				return fmt.Errorf("ssh: bad import source %q (gh:<user> or gl:<user>)", s)
			}
		}
	}
	if h.Firewall != nil {
		for _, p := range h.Firewall.Allow {
			if !portSpecRe.MatchString(p) {
				return fmt.Errorf("firewall: bad port %q (443, 443/tcp, 51820/udp)", p)
			}
		}
		for _, b := range h.Firewall.Block {
			if strings.ContainsAny(b, " \t\r\n") || b == "" {
				return fmt.Errorf("firewall: bad block target %q", b)
			}
		}
	}
	for _, p := range h.Packages {
		if !PackageNameRe.MatchString(p) {
			return fmt.Errorf("bad package name %q", p)
		}
	}
	seen := map[string]bool{}
	for _, p := range h.Plugins {
		if err := ValidName(p.Name); err != nil || seen[p.Name] {
			return fmt.Errorf("plugins: bad or duplicate name %q", p.Name)
		}
		seen[p.Name] = true
		for k, v := range p.Set {
			if !SettingNameRe.MatchString(k) || strings.ContainsAny(v, "\x00\r\n") {
				return fmt.Errorf("plugin %s: bad setting %q", p.Name, k)
			}
		}
	}
	for _, s := range h.Stacks {
		if !IsLocalRef(s) || strings.Contains(s, "/../") || !(strings.HasSuffix(s, ".yaml") || strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".json")) {
			return fmt.Errorf("stacks: %q must be a ./file.yaml next to the host config", s)
		}
	}
	if len(h.Network) > 0 && h.Network[0] != '{' {
		return fmt.Errorf("network must be an object (the ziroctl network schema)")
	}
	if j := h.Cluster; j != nil && j.Join != nil {
		if !hostPortRe.MatchString(j.Join.Address) {
			return fmt.Errorf("cluster.join.address must be host:port")
		}
		if !strings.HasPrefix(j.Join.TokenFile, "/") {
			return fmt.Errorf("cluster.join.token_file must be an absolute path")
		}
		if j.Join.CAHash != "" && !strings.HasPrefix(j.Join.CAHash, "sha256:") {
			return fmt.Errorf("cluster.join.ca_hash must be sha256:<hex>")
		}
	}
	return nil
}

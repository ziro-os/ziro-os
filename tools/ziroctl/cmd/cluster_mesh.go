package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Cluster mesh: every node runs WireGuard interface ziro0 with a /32 per peer, so apps
// reach each other on <app>.cluster.ziro over an encrypted, key-authenticated overlay.
// The master distributes keys/endpoints in heartbeat replies; no wg-quick, no /dev/stdin.
const (
	meshIface  = "ziro0"
	meshPort   = 51821
	meshDomain = "cluster.ziro"
	hostsFile  = "/etc/hosts"
	hostsBegin = "# BEGIN ziro-cluster (managed by ziroctl; do not edit)"
	hostsEnd   = "# END ziro-cluster"
)

func meshKeyPath() string { return filepath.Join(clusterDir, "wg.key") }

// meshKeypair loads this node's mesh key, creating it (0600) on first use.
func meshKeypair() (privPath, pub string, err error) {
	p := meshKeyPath()
	if b, err := os.ReadFile(p); err == nil {
		pub, err := wgPublicKey(strings.TrimSpace(string(b)))
		return p, pub, err
	}
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return "", "", err
	}
	priv, pub := generateWgKeypair()
	if err := os.WriteFile(p, []byte(priv+"\n"), 0600); err != nil {
		return "", "", err
	}
	return p, pub, nil
}

func validWGKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32
}

func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// meshApplied is the configuration applyMesh last converged ziro0 to. The master sends the same
// view every heartbeat; re-running wg and ip for every peer each time cost N+4 forks per node per
// tick (N² across the cluster) for nothing. It is re-applied when it changes, when the interface
// is gone, and every meshReapplyEvery in case something else changed the interface.
var meshApplied struct {
	key string
	at  time.Time
}

const meshReapplyEvery = 5 * time.Minute

// Seams for tests: the real work and the interface check.
var (
	meshApplyNow = applyMeshNow
	meshLinkUp   = linkExists
)

func meshKey(meshIP string, prefix int, peers []MeshPeer) string {
	b, _ := json.Marshal(struct {
		IP     string
		Prefix int
		Peers  []MeshPeer
	}{meshIP, prefix, peers})
	return string(b)
}

// applyMesh converges ziro0 to the master's view: own address, listen port, peer set.
func applyMesh(meshIP string, prefix int, peers []MeshPeer) error {
	if meshIP == "" || prefix == 0 {
		return nil
	}
	key := meshKey(meshIP, prefix, peers)
	if key == meshApplied.key && time.Since(meshApplied.at) < meshReapplyEvery && meshLinkUp(meshIface) {
		return nil
	}
	if err := meshApplyNow(meshIP, prefix, peers); err != nil {
		meshApplied.key = "" // try in full next time
		return err
	}
	meshApplied.key, meshApplied.at = key, time.Now()
	return nil
}

func applyMeshNow(meshIP string, prefix int, peers []MeshPeer) error {
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("wireguard-tools not installed: %w", err)
	}
	keyPath, selfPub, err := meshKeypair()
	if err != nil {
		return err
	}
	if !linkExists(meshIface) {
		if err := run("ip", "link", "add", "dev", meshIface, "type", "wireguard"); err != nil {
			return err
		}
	}
	if err := run("wg", "set", meshIface, "private-key", keyPath, "listen-port", strconv.Itoa(meshPort)); err != nil {
		return err
	}
	if err := run("ip", "address", "replace", meshIP+"/"+strconv.Itoa(prefix), "dev", meshIface); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "up", "dev", meshIface); err != nil {
		return err
	}

	want := map[string]bool{}
	for _, p := range peers {
		if p.PubKey == selfPub || !validWGKey(p.PubKey) {
			continue
		}
		allowed := []string{p.MeshIP + "/32"}
		for _, r := range p.Routes {
			allowed = append(allowed, r+"/32")
		}
		if p.PodCIDR != "" {
			allowed = append(allowed, p.PodCIDR)
		}
		for _, a := range allowed {
			if _, err := netip.ParsePrefix(a); err != nil {
				return fmt.Errorf("invalid mesh address %q", a)
			}
		}
		want[p.PubKey] = true
		args := []string{"set", meshIface, "peer", p.PubKey, "allowed-ips", strings.Join(allowed, ",")}
		if p.Endpoint != "" {
			if _, err := netip.ParseAddrPort(p.Endpoint); err != nil {
				return fmt.Errorf("invalid peer endpoint %q", p.Endpoint)
			}
			args = append(args, "endpoint", p.Endpoint, "persistent-keepalive", "25")
		}
		if err := run("wg", args...); err != nil {
			return err
		}
	}
	out, err := exec.Command("wg", "show", meshIface, "peers").Output()
	if err != nil {
		return err
	}
	for _, k := range strings.Fields(string(out)) {
		if !want[k] {
			_ = run("wg", "set", meshIface, "peer", k, "remove")
		}
	}
	return nil
}

func teardownMesh() {
	if linkExists(meshIface) {
		_ = run("ip", "link", "del", "dev", meshIface)
	}
	removeClusterPolicy()
	teardownPodNetwork()
	_ = writeHostsBlock(hostsFile, nil)
	_ = os.Remove(meshKeyPath())
	for _, p := range []string{meshDiscoKeyPath(), nodeKeyPath(), nodeCertPath()} {
		_ = os.Remove(p)
	}
}

// renderHostsBlock replaces (or appends) the managed block; everything else is kept as is.
func renderHostsBlock(current string, eps map[string][]string) string {
	var keep []string
	in := false
	for _, l := range strings.Split(strings.TrimRight(current, "\n"), "\n") {
		switch {
		case l == hostsBegin:
			in = true
		case l == hostsEnd:
			in = false
		case !in:
			keep = append(keep, l)
		}
	}
	out := strings.Join(keep, "\n") + "\n"
	if len(eps) == 0 {
		return out
	}
	names := make([]string, 0, len(eps))
	for n := range eps {
		names = append(names, n)
	}
	sort.Strings(names)
	out += hostsBegin + "\n"
	for _, n := range names {
		for _, ip := range eps[n] {
			out += ip + "\t" + n + "." + meshDomain + "\n"
		}
	}
	return out + hostsEnd + "\n"
}

func writeHostsBlock(path string, eps map[string][]string) error {
	cur, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	next := renderHostsBlock(string(cur), eps)
	if next == string(cur) {
		return nil
	}
	return writeFileAtomic(path, []byte(next), 0644)
}

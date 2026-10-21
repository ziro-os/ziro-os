package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Sandboxes on a cluster. Sandboxes stay node-local (they are ephemeral: a lost node means
// lost sandboxes, marked gone, never migrated); the cluster adds placement and routing:
//
//   - The master keeps a small directory in the Raft state: sandbox id -> node (and owner).
//     A create through the master's API picks a runner node (ready, not cordoned, the sandbox
//     module enabled, the fewest sandboxes, then the most memory) and forwards to it.
//   - Every node with the sandbox module serves its sandbox API on its mesh address
//     (sandboxMeshPort), authenticated by a cluster token. The master's API forwards each
//     request for a sandbox to the node that owns it, with the caller's identity, exactly like
//     the local socket.
//   - The SSH gateway on any node routes a token to the owning node: tokens carry their sandbox
//     id, the owner checks the token over the mesh, and the session is relayed to the owner's
//     own gateway. Users keep one address: ssh -p 22998 zsbx_...@gateway.
//   - Preview URLs are gateway routes (cluster route store) to the owning node's preview proxy
//     on its mesh address.
//
// Heartbeats carry what each side needs: nodes report the sandboxes they hold (the master
// prunes its directory), and get the mesh token, the gateway domain and where every sandbox
// lives (for the SSH edge), which the agent writes to sandboxMeshFile for ziro-sandboxd.

const (
	capSandbox    = "sandbox"
	sandboxSecret = "ziro-sandboxes"
)

var sandboxMeshPort = 7446 // every node's sandbox API on its mesh address

var sandboxMeshFile = "/etc/ziro/sandbox-mesh.json"

// SandboxPlacement is where a sandbox runs (cluster state).
type SandboxPlacement struct {
	Node  string    `json:"node"`
	Owner string    `json:"owner"`
	Since time.Time `json:"since"`
}

// sandboxMeshConfig is what a node's ziro-sandboxd needs to take part in the cluster.
type sandboxMeshConfig struct {
	Listen string            `json:"listen"`           // this node's mesh address:port
	Token  string            `json:"token"`            // cluster token for node-to-node sandbox calls
	Domain string            `json:"domain,omitempty"` // the gateway domain (preview URLs)
	Where  map[string]string `json:"where,omitempty"`  // sandbox id -> owner's mesh address (SSH edge)
	// The SSH gateways' shared host key (PEM): one address, one key, whichever node answers.
	HostKey string   `json:"host_key,omitempty"`
	Nodes   []string `json:"nodes,omitempty"` // every sandbox node's mesh address (SSH edge, before Where knows a new sandbox)
}

// withSandboxCap adds the sandbox capability when ziro-sandboxd runs on this node.
func withSandboxCap(caps []string) []string {
	if _, err := os.Stat(sandboxSocket); err == nil {
		return append(append([]string{}, caps...), capSandbox)
	}
	return caps
}

// localSandboxIDs are the sandboxes this node holds (reported in heartbeats).
func localSandboxIDs() []string {
	ids := []string{}
	ents, _ := os.ReadDir(sandboxRoot)
	for _, e := range ents {
		if sandboxIDRe.MatchString(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids
}

// sandboxMeshFor builds a node's sandbox mesh config (master, in the heartbeat). The caller
// holds the state for writing.
func sandboxMeshFor(st *ClusterState, n *ClusterNode) *sandboxMeshConfig {
	if !hasCap(n, capSandbox) || n.MeshIP == "" {
		return nil
	}
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]string{}
	}
	sec := st.Secrets[sandboxSecret]
	if sec == nil {
		sec = map[string]string{}
		st.Secrets[sandboxSecret] = sec
	}
	if sec["TOKEN"] == "" {
		sec["TOKEN"] = randomHex(32)
	}
	if sec["SSH_HOST_KEY"] == "" {
		if _, priv, err := ed25519.GenerateKey(rand.Reader); err == nil {
			if blk, err := ssh.MarshalPrivateKey(priv, "ziro sandbox gateways"); err == nil {
				sec["SSH_HOST_KEY"] = string(pem.EncodeToMemory(blk))
			}
		}
	}
	c := &sandboxMeshConfig{Listen: net.JoinHostPort(n.MeshIP, strconv.Itoa(sandboxMeshPort)),
		Token: sec["TOKEN"], HostKey: sec["SSH_HOST_KEY"], Domain: st.GatewayDomain.Name, Where: map[string]string{}}
	for _, o := range st.Nodes {
		if hasCap(&o, capSandbox) && o.MeshIP != "" {
			c.Nodes = append(c.Nodes, o.MeshIP)
		}
	}
	sort.Strings(c.Nodes)
	for id, p := range st.Sandboxes {
		if o := st.node(p.Node); o != nil && o.MeshIP != "" {
			c.Where[id] = o.MeshIP
		}
	}
	return c
}

func hasCapList(caps []string, c string) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// dropClusterPreviewRoutes removes a sandbox's preview routes from the cluster's gateway
// (the caller holds the state for writing).
func dropClusterPreviewRoutes(st *ClusterState, id string) {
	kept := st.Routes[:0]
	for _, r := range st.Routes {
		if !strings.HasPrefix(r.Name, "sbx-"+id+"-") {
			kept = append(kept, r)
		}
	}
	st.Routes = kept
}

// pruneSandboxes drops the directory entries of a node's sandboxes it no longer reports (its
// reaper deleted them, or it restarted). Entries younger than a minute are kept: a create may
// not have reached a heartbeat yet. It returns the ids it dropped.
func pruneSandboxes(st *ClusterState, node string, held []string, now time.Time) []string {
	have := map[string]bool{}
	for _, id := range held {
		have[id] = true
	}
	var gone []string
	for id, p := range st.Sandboxes {
		if p.Node == node && !have[id] && now.Sub(p.Since) > time.Minute {
			delete(st.Sandboxes, id)
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	return gone
}

// pickSandboxNode chooses where a new sandbox runs: ready, schedulable runner nodes with the
// sandbox module; the fewest sandboxes first, then the most memory. only, when set, limits the
// choice (a snapshot exists on those nodes only).
func pickSandboxNode(st *ClusterState, only map[string]bool) *ClusterNode {
	count := map[string]int{}
	for _, p := range st.Sandboxes {
		count[p.Node]++
	}
	var best *ClusterNode
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if n.Status != "Ready" || n.Cordoned || n.MeshIP == "" || n.Labels["runner"] == "false" || !hasCap(n, capSandbox) {
			continue
		}
		if only != nil && !only[n.ID] {
			continue
		}
		if best == nil || count[n.ID] < count[best.ID] || (count[n.ID] == count[best.ID] && n.MemTotal > best.MemTotal) {
			best = n
		}
	}
	return best
}

// writeSandboxMesh saves the config for ziro-sandboxd when it changed (agent).
func writeSandboxMesh(c *sandboxMeshConfig) {
	if c == nil {
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		return
	}
	if cur, err := os.ReadFile(sandboxMeshFile); err == nil && string(cur) == string(b) {
		return
	}
	_ = writeFileAtomic(sandboxMeshFile, b, 0600)
}

func loadSandboxMesh() *sandboxMeshConfig {
	b, err := os.ReadFile(sandboxMeshFile)
	if err != nil {
		return nil
	}
	var c sandboxMeshConfig
	if json.Unmarshal(b, &c) != nil || c.Listen == "" || len(c.Token) < 32 {
		return nil
	}
	return &c
}

// sandboxPolicyRules open a sandbox node's mesh ports (deny-mode policy) to the other nodes: the
// sandbox API (masters forward, edges check tokens), the SSH gateway (relays) and the preview
// proxy (gateways). Each is still authenticated: the cluster token, or a preview token.
// Known limitation: the default ports; a node with other ssh_port/preview_port needs them opened too.
func sandboxPolicyRules(st *ClusterState, nodeID string) []MeshRule {
	n := st.node(nodeID)
	if n == nil || !hasCap(n, capSandbox) {
		return nil
	}
	var src []string
	for _, o := range st.Nodes {
		if o.ID != nodeID && o.MeshIP != "" {
			src = append(src, o.MeshIP)
		}
	}
	if len(src) == 0 {
		return nil
	}
	sort.Strings(src)
	var rules []MeshRule
	for _, port := range []int{sandboxMeshPort, 22998, 22997} {
		rules = append(rules, MeshRule{App: "sandboxes", Port: port, Proto: "tcp", Sources: src})
	}
	return rules
}

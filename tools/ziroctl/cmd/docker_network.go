package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/libcni"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// `docker network connect` and `disconnect`, which nerdctl does not have (it is in nerdctl's list of
// unimplemented Docker commands). Coolify needs both: it joins its proxy (Traefik) to each service's
// network and a service's containers to its destination network.
//
// nerdctl keeps a container's networks in the "nerdctl/networks" label and the same annotation of its
// OCI spec; its createRuntime hook attaches each of them (interface eth<i> for the i-th) when the task
// starts, and its postStop hook detaches them. So:
//   - a container that is not running only needs the label and annotation changed: the hook attaches
//     the network when it starts;
//   - a running one is also attached now, with the same CNI call the hook makes (libcni ADD into the
//     task's network namespace, interface eth<len(networks)>), and added to nerdctl's hosts store so
//     the containers on that network resolve its name.
//
// The hook that runs when this task stops knows only the networks it started with, so the address a
// running connect takes is released by disconnect, by the next start of the container (the hook
// removes every listed network before it attaches them), or by the lease collector in
// `ziroctl container health serve` once the container is gone.
//
// Known limitation: --ip, --ip6, --link and --driver-opt are not supported, and an --alias other than
// the container's name or hostname does not resolve (nerdctl's hosts store has no aliases).

var (
	cniCacheDir        = "/var/lib/cni"
	defaultCNIConfDir  = "/etc/cni/net.d"
	defaultCNIBinDir   = "/usr/libexec/cni"
	nerdctlNetworksKey = "nerdctl/networks"
)

// dockerNetOp is one connect or disconnect.
type dockerNetOp struct {
	Network   string
	Container string
	Aliases   []string
	Force     bool // disconnect: no error when the container is not on the network
}

func containerdNamespace() string {
	if ns := os.Getenv("CONTAINERD_NAMESPACE"); ns != "" {
		return ns
	}
	return "default"
}

// findNerdctlContainer finds a container by full ID, unique ID prefix or nerdctl name.
func findNerdctlContainer(ctx context.Context, c *ctrdClient, ref string) (ctrdContainer, error) {
	if !dockerIDRe.MatchString(ref) {
		return ctrdContainer{}, fmt.Errorf("no such container: %s", ref)
	}
	if ct, err := c.Container(ctx, ref); err == nil {
		return ct, nil
	} else if !isCtrdNotFound(err) {
		return ctrdContainer{}, err
	}
	if byName, err := c.Containers(ctx, ctrdLabelFilter("nerdctl/name", ref)); err == nil && len(byName) == 1 {
		return byName[0], nil
	}
	list, err := c.Containers(ctx)
	if err != nil {
		return ctrdContainer{}, err
	}
	var byPrefix []ctrdContainer
	for _, ct := range list {
		if ct.Labels["nerdctl/name"] == ref {
			return ct, nil
		}
		if strings.HasPrefix(ct.ID, ref) {
			byPrefix = append(byPrefix, ct)
		}
	}
	switch len(byPrefix) {
	case 1:
		return byPrefix[0], nil
	case 0:
		return ctrdContainer{}, fmt.Errorf("no such container: %s", ref)
	}
	return ctrdContainer{}, fmt.Errorf("multiple containers match %q: use more of the ID", ref)
}

// cniNetwork is one network's CNI configuration file.
type cniNetwork struct {
	Name    string
	ID      string // nerdctl's network ID
	Path    string
	Bytes   []byte
	Subnets []*net.IPNet
}

// cniNetworks reads the network configurations in dir (nerdctl writes one .conflist per network).
func cniNetworks(dir string) []cniNetwork {
	files, _ := filepath.Glob(filepath.Join(dir, "*.conflist"))
	slices.Sort(files)
	var out []cniNetwork
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var c struct {
			Name      string `json:"name"`
			NerdctlID string `json:"nerdctlID"`
			Plugins   []struct {
				IPAM struct {
					Subnet string `json:"subnet"`
					Ranges [][]struct {
						Subnet string `json:"subnet"`
					} `json:"ranges"`
				} `json:"ipam"`
			} `json:"plugins"`
		}
		if json.Unmarshal(b, &c) != nil || c.Name == "" {
			continue
		}
		n := cniNetwork{Name: c.Name, ID: c.NerdctlID, Path: f, Bytes: b}
		for _, p := range c.Plugins {
			subnets := []string{p.IPAM.Subnet}
			for _, r := range p.IPAM.Ranges {
				for _, x := range r {
					subnets = append(subnets, x.Subnet)
				}
			}
			for _, s := range subnets {
				if _, ipn, err := net.ParseCIDR(s); err == nil {
					n.Subnets = append(n.Subnets, ipn)
				}
			}
		}
		out = append(out, n)
	}
	return out
}

func findCNINetwork(nets []cniNetwork, ref string) (cniNetwork, bool) {
	for _, n := range nets {
		if n.Name == ref || (n.ID != "" && (n.ID == ref || (len(ref) >= 12 && strings.HasPrefix(n.ID, ref)))) {
			return n, true
		}
	}
	return cniNetwork{}, false
}

// hookPaths reads the CNI plugin dir, the CNI config dir and nerdctl's data store from the arguments
// nerdctl gave its OCI hook in the container's spec, so connect uses what the container was created with.
func hookPaths(spec *specs.Spec, labels map[string]string) (cniBin, cniConf, dataStore string) {
	cniBin, cniConf = defaultCNIBinDir, defaultCNIConfDir
	if spec != nil && spec.Hooks != nil {
		for _, h := range append(append([]specs.Hook(nil), spec.Hooks.CreateRuntime...), spec.Hooks.Poststop...) {
			for _, a := range h.Args {
				switch {
				case strings.HasPrefix(a, "--cni-path="):
					cniBin = strings.TrimPrefix(a, "--cni-path=")
				case strings.HasPrefix(a, "--cni-netconfpath="):
					cniConf = strings.TrimPrefix(a, "--cni-netconfpath=")
				}
			}
		}
	}
	// The state dir is <data store>/containers/<namespace>/<id>.
	if sd := labels["nerdctl/state-dir"]; sd != "" {
		dataStore = filepath.Dir(filepath.Dir(filepath.Dir(sd)))
	}
	return cniBin, cniConf, dataStore
}

// nextIfName is the interface for a new network: eth<len(networks)>, the name the hook gives that
// network on the next start, or the first free one after it.
func nextIfName(inUse map[string]bool, networks int) string {
	for i := networks; ; i++ {
		if n := fmt.Sprintf("eth%d", i); !inUse[n] {
			return n
		}
	}
}

// netnsInterfaces lists the interfaces of the network namespace of pid (from /proc/<pid>/net/dev).
func netnsInterfaces(pid uint32) map[string]bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", pid))
	out := map[string]bool{}
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && !strings.Contains(name, "|") {
			out[strings.TrimSpace(name)] = true
		}
	}
	return out
}

// cachedIfName finds the interface a network was attached as, from libcni's result cache
// (<cache>/results/<network>-<container>-<ifname>).
func cachedIfName(cacheDir, network, fullID string) string {
	prefix := network + "-" + fullID + "-"
	files, _ := filepath.Glob(filepath.Join(cacheDir, "results", prefix+"*"))
	for _, f := range files {
		if ifn := strings.TrimPrefix(filepath.Base(f), prefix); strings.HasPrefix(ifn, "eth") {
			return ifn
		}
	}
	return ""
}

// lockContainerNetworks serializes network changes of one container.
func lockContainerNetworks(stateDir string) (func(), error) {
	if stateDir == "" {
		return func() {}, nil
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "ziro-network.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// setContainerNetworks writes the networks list to the container's label and spec annotation, which
// is what nerdctl's hooks and inspect read.
func setContainerNetworks(ctx context.Context, c *ctrdClient, st *containerNetState, networks []string) error {
	if len(networks) == 0 {
		networks = []string{"none"}
	}
	b, _ := json.Marshal(networks)
	var spec map[string]any // the whole spec, so fields this code does not know are kept
	if err := json.Unmarshal(st.ct.Spec, &spec); err != nil || spec == nil {
		return fmt.Errorf("the container's spec: %v", err)
	}
	ann, _ := spec["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
	}
	ann[nerdctlNetworksKey] = string(b)
	spec["annotations"] = ann
	raw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return c.UpdateLabelAndSpec(ctx, st.ct.ID, nerdctlNetworksKey, string(b), st.ct.SpecType, raw)
}

// containerNetState is what connect and disconnect need to know about a container.
type containerNetState struct {
	ct       ctrdContainer
	spec     *specs.Spec
	networks []string
	pid      uint32 // 0 when not running
	ns       string
}

func loadContainerNetState(ctx context.Context, c *ctrdClient, ref string) (*containerNetState, error) {
	ct, err := findNerdctlContainer(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	st := &containerNetState{ct: ct, spec: &specs.Spec{}, ns: c.namespace}
	_ = json.Unmarshal(ct.Spec, st.spec)
	_ = json.Unmarshal([]byte(ct.Labels[nerdctlNetworksKey]), &st.networks)
	if t, err := c.Task(ctx, ct.ID); err == nil && t.Status == ctrdTaskRunning && t.Pid != 0 {
		st.pid = t.Pid
	} else if err != nil && !isCtrdNotFound(err) {
		return nil, err
	}
	return st, nil
}

func (st *containerNetState) fullID() string { return st.ns + "-" + st.ct.ID }

func (st *containerNetState) cniNetworking() error {
	for _, n := range st.networks {
		if n == "host" || n == "none" || strings.HasPrefix(n, "container:") || strings.HasPrefix(n, "ns:") {
			if n == "none" && len(st.networks) == 1 {
				return nil // a network can be added to a container that has none
			}
			return fmt.Errorf("container %s uses the %s network mode: it cannot join other networks", st.ct.Labels["nerdctl/name"], n)
		}
	}
	return nil
}

func cniRuntimeConf(st *containerNetState, ifName string) *libcni.RuntimeConf {
	nsPath := ""
	if st.pid != 0 {
		nsPath = fmt.Sprintf("/proc/%d/ns/net", st.pid)
	}
	return &libcni.RuntimeConf{
		ContainerID: st.fullID(), NetNS: nsPath, IfName: ifName,
		Args: [][2]string{{"IgnoreUnknown", "1"}, {"NERDCTL_CNI_DHCP_HOSTNAME", st.ct.Labels["nerdctl/hostname"]}},
	}
}

// dockerNetworkConnect attaches a container to a network (`docker network connect`).
func dockerNetworkConnect(ctx context.Context, op dockerNetOp) error {
	c := newCtrdClient(containerdSocket, containerdNamespace())
	st, err := loadContainerNetState(ctx, c, op.Container)
	if err != nil {
		return err
	}
	unlock, err := lockContainerNetworks(st.ct.Labels["nerdctl/state-dir"])
	if err != nil {
		return err
	}
	defer unlock()
	return connectContainer(ctx, c, st, op, cniOps{})
}

// cniOps are the CNI calls, replaced in tests.
type cniOps struct {
	add func(ctx context.Context, conf []byte, rt *libcni.RuntimeConf, bin string) (*types100.Result, error)
	del func(ctx context.Context, conf []byte, rt *libcni.RuntimeConf, bin string) error
}

func (o cniOps) withDefaults() cniOps {
	if o.add == nil {
		o.add = func(ctx context.Context, conf []byte, rt *libcni.RuntimeConf, bin string) (*types100.Result, error) {
			list, err := libcni.ConfListFromBytes(conf)
			if err != nil {
				return nil, err
			}
			res, err := libcni.NewCNIConfigWithCacheDir([]string{bin}, cniCacheDir, nil).AddNetworkList(ctx, list, rt)
			if err != nil {
				return nil, err
			}
			return types100.NewResultFromResult(res)
		}
	}
	if o.del == nil {
		o.del = func(ctx context.Context, conf []byte, rt *libcni.RuntimeConf, bin string) error {
			list, err := libcni.ConfListFromBytes(conf)
			if err != nil {
				return err
			}
			return libcni.NewCNIConfigWithCacheDir([]string{bin}, cniCacheDir, nil).DelNetworkList(ctx, list, rt)
		}
	}
	return o
}

func connectContainer(ctx context.Context, c *ctrdClient, st *containerNetState, op dockerNetOp, ops cniOps) error {
	ops = ops.withDefaults()
	cniBin, cniConf, dataStore := hookPaths(st.spec, st.ct.Labels)
	if err := st.cniNetworking(); err != nil {
		return err
	}
	network, ok := findCNINetwork(cniNetworks(cniConf), op.Network)
	if !ok {
		return fmt.Errorf("network %s not found", op.Network)
	}
	name := st.ct.Labels["nerdctl/name"]
	if slices.Contains(st.networks, network.Name) {
		return fmt.Errorf("endpoint with name %s already exists in network %s", name, network.Name)
	}
	for _, a := range op.Aliases {
		if a != name && a != st.ct.Labels["nerdctl/hostname"] {
			fmt.Fprintf(os.Stderr, "docker: note: alias %q does not resolve: only the container's name and hostname do on Ziro OS\n", a)
		}
	}
	networks := slices.DeleteFunc(slices.Clone(st.networks), func(n string) bool { return n == "none" })
	if st.pid == 0 {
		return setContainerNetworks(ctx, c, st, append(networks, network.Name))
	}

	// Running: attach now, as the hook would.
	rt := cniRuntimeConf(st, nextIfName(netnsInterfaces(st.pid), len(networks)))
	res, err := ops.add(ctx, network.Bytes, rt, cniBin)
	if err != nil {
		return fmt.Errorf("attaching %s to %s: %v", name, network.Name, err)
	}
	undo := func() { _ = ops.del(ctx, network.Bytes, rt, cniBin) }
	if dataStore != "" {
		hs, err := newNerdctlHostsStore(dataStore, st.ns)
		if err == nil {
			err = hs.update(st.ct.ID, func(m *nerdctlHostsMeta) {
				if m.Name == "" {
					m.Name, m.Hostname = name, st.ct.Labels["nerdctl/hostname"]
				}
				if m.Networks == nil {
					m.Networks = map[string]*types100.Result{}
				}
				m.Networks[network.Name] = res
			})
		}
		if err != nil {
			undo()
			return fmt.Errorf("hosts store: %v", err)
		}
	}
	if err := setContainerNetworks(ctx, c, st, append(networks, network.Name)); err != nil {
		undo()
		return err
	}
	return nil
}

// dockerNetworkDisconnect detaches a container from a network (`docker network disconnect`).
func dockerNetworkDisconnect(ctx context.Context, op dockerNetOp) error {
	c := newCtrdClient(containerdSocket, containerdNamespace())
	st, err := loadContainerNetState(ctx, c, op.Container)
	if err != nil {
		if op.Force {
			return nil
		}
		return err
	}
	unlock, err := lockContainerNetworks(st.ct.Labels["nerdctl/state-dir"])
	if err != nil {
		return err
	}
	defer unlock()
	return disconnectContainer(ctx, c, st, op, cniOps{})
}

func disconnectContainer(ctx context.Context, c *ctrdClient, st *containerNetState, op dockerNetOp, ops cniOps) error {
	ops = ops.withDefaults()
	cniBin, cniConf, dataStore := hookPaths(st.spec, st.ct.Labels)
	network, ok := findCNINetwork(cniNetworks(cniConf), op.Network)
	name := op.Network
	if ok {
		name = network.Name
	}
	if !slices.Contains(st.networks, name) {
		if op.Force {
			return nil
		}
		return fmt.Errorf("container %s is not connected to network %s", st.ct.Labels["nerdctl/name"], op.Network)
	}
	if st.pid != 0 && ok {
		if ifName := cachedIfName(cniCacheDir, name, st.fullID()); ifName != "" {
			if err := ops.del(ctx, network.Bytes, cniRuntimeConf(st, ifName), cniBin); err != nil && !op.Force {
				return fmt.Errorf("detaching from %s: %v", name, err)
			}
		}
		if dataStore != "" {
			if hs, err := newNerdctlHostsStore(dataStore, st.ns); err == nil {
				_ = hs.update(st.ct.ID, func(m *nerdctlHostsMeta) { delete(m.Networks, name) })
			}
		}
	}
	return setContainerNetworks(ctx, c, st, slices.DeleteFunc(slices.Clone(st.networks), func(n string) bool { return n == name }))
}

// parseNetworkConnect reads `network connect [--alias A]... NETWORK CONTAINER` and
// `network disconnect [-f] NETWORK CONTAINER` (args start after "connect"/"disconnect").
func parseNetworkConnect(args []string) (dockerNetOp, error) {
	var op dockerNetOp
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		flag, val, hasVal := strings.Cut(a, "=")
		switch {
		case flag == "--alias":
			if !hasVal {
				if i+1 >= len(args) {
					return op, fmt.Errorf("flag needs an argument: --alias")
				}
				val = args[i+1]
				i++
			}
			op.Aliases = append(op.Aliases, val)
		case a == "-f" || a == "--force":
			op.Force = true
		case flag == "--ip" || flag == "--ip6" || flag == "--link" || flag == "--link-local-ip" || flag == "--driver-opt":
			return op, fmt.Errorf("%s is not supported by docker network connect on Ziro OS", flag)
		case strings.HasPrefix(a, "-"):
			return op, fmt.Errorf("unknown flag: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 2 {
		return op, fmt.Errorf("requires exactly 2 arguments: NETWORK CONTAINER")
	}
	op.Network, op.Container = pos[0], pos[1]
	return op, nil
}

// releaseStaleCNILeases removes host-local address leases and CNI result caches held by nerdctl
// containers in ns that have no running task: what a running `network connect` leaves behind when the
// container is stopped and removed (see the comment at the top). running lists the IDs of running
// containers; libcni's dataDir is <cache>/networks/<network>/<ip>, holding "<namespace>-<id>\n<ifname>".
func releaseStaleCNILeases(cacheDir, ns string, running map[string]bool, exists map[string]bool) (released []string) {
	files, _ := filepath.Glob(filepath.Join(cacheDir, "networks", "*", "*"))
	for _, f := range files {
		base := filepath.Base(f)
		if net.ParseIP(base) == nil {
			continue // last_reserved_ip.0, lock
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		owner, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
		id, ok := strings.CutPrefix(strings.TrimSpace(owner), ns+"-")
		if !ok || running[id] || exists[id] {
			continue // another namespace, or a container that may start again (its hook releases it)
		}
		if os.Remove(f) == nil {
			released = append(released, filepath.Base(filepath.Dir(f))+"/"+base)
		}
	}
	results, _ := filepath.Glob(filepath.Join(cacheDir, "results", "*-"+ns+"-*"))
	for _, f := range results {
		rest := filepath.Base(f)
		_, after, ok := strings.Cut(rest, "-"+ns+"-")
		if !ok {
			continue
		}
		id, _, _ := strings.Cut(after, "-")
		if id != "" && !running[id] && !exists[id] {
			_ = os.Remove(f)
		}
	}
	return released
}

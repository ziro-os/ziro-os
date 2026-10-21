package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Sandboxes: disposable, strongly isolated containers for untrusted code (AI agents, code
// interpreters). The `sandbox` module runs ziro-sandboxd, which owns them; the CLI and the REST
// API (/api/v1/sandboxes) are its clients. Design: docs/design/rfcs/0004-sandboxes.md.
//
// Isolation is decided here, never by the caller:
//   - gVisor (runsc, systrap platform): the workload's syscalls go to gVisor's user-space kernel,
//     not the host's. runc only when the host config allows it and an operator asks.
//   - every capability dropped but a short list (which, under gVisor, apply to its kernel),
//     no-new-privileges, memory/cpu/pids limits, no host mounts, no devices, no privileged mode.
//   - no network unless the spec asks for one; then egress is default-deny with an allowlist
//     or the public internet only, never the host, the LAN or other sandboxes (sandbox_net.go).
//   - a per-sandbox /workspace directory and a size-limited /tmp; the image's rootfs is the
//     container's own copy-on-write layer.
//   - a lifetime (default 1h, max 24h) and an optional idle timeout; the reaper deletes
//     sandboxes that are over either.
//
// Ownership: a sandbox belongs to the API token that created it ("root" from the host CLI);
// deployers see only their own, operators and admins see all.

var (
	sandboxSocket     = "/run/ziro/sandboxd.sock"
	sandboxRoot       = "/var/lib/ziro/sandbox"
	sandboxConfigFile = "/etc/ziro/sandbox.json"
	sandboxRunsc      = "/var/lib/ziro/plugins/sandbox/runsc-ziro"     // runsc with Ziro's flags (modules/sandbox.json)
	sandboxRunscKVM   = "/var/lib/ziro/plugins/sandbox/runsc-ziro-kvm" // the same on gVisor's KVM platform
	// kvmReady makes /dev/kvm available (loading the KVM module on x86_64) and reports whether it is.
	kvmReady = func() bool {
		if fileExists("/dev/kvm") {
			return true
		}
		for _, mod := range []string{"kvm_intel", "kvm_amd"} {
			if exec.Command("modprobe", mod).Run() == nil && fileExists("/dev/kvm") {
				return true
			}
		}
		return false
	}
	sandboxNerdctl = func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "nerdctl", args...).CombinedOutput()
	}
)

const sandboxLabel = "ziro.sandbox"

// sandboxCaps are the capabilities a sandbox keeps (Docker's default set minus NET_RAW, MKNOD,
// AUDIT_WRITE, SETFCAP and SYS_CHROOT): enough to install packages as root inside it.
var sandboxCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID"}

var sandboxIDRe = regexp.MustCompile(`^[a-z2-7]{12}$`)

// sandboxConfig is the host's policy for sandboxes (/etc/ziro/sandbox.json, all optional).
type sandboxConfig struct {
	MaxSandboxes   int              `json:"max_sandboxes"`
	MaxPerOwner    int              `json:"max_per_owner"`
	MaxMemory      string           `json:"max_memory,omitempty"` // all sandboxes together (default: no cap beyond the count)
	Defaults       schema.Resources `json:"defaults"`
	Limits         schema.Resources `json:"limits"`
	DefaultTimeout string           `json:"default_timeout"`
	MaxTimeout     string           `json:"max_timeout"`
	AllowRunc      bool             `json:"allow_runc,omitempty"` // let operators pick the runc runtime (weaker isolation)
	DefaultRuntime string           `json:"default_runtime"`      // gvisor or gvisor-kvm
	Pools          map[string]int   `json:"pools,omitempty"`      // template -> paused sandboxes kept ready
	Subnet         string           `json:"subnet"`               // the sandbox network
	SSHPort        int              `json:"ssh_port"`             // the SSH gateway (0: off)
	SSHHost        string           `json:"ssh_host,omitempty"`   // the name clients reach the gateway by (default: the API's host name)
	PreviewPort    int              `json:"preview_port"`         // the loopback port the gateway's preview routes use (0: previews off)
	SecretPort     int              `json:"secret_proxy_port"`    // the egress proxy for credential injection (0: secrets off)
	ImagePolicy    ImagePolicy      `json:"image_policy,omitempty"`
}

func defaultSandboxConfig() sandboxConfig {
	return sandboxConfig{
		MaxSandboxes:   32,
		MaxPerOwner:    8,
		Defaults:       schema.Resources{Memory: "1Gi", CPUs: 1, PIDs: 512},
		Limits:         schema.Resources{Memory: "8Gi", CPUs: 4, PIDs: 4096},
		DefaultTimeout: "1h",
		MaxTimeout:     "24h",
		Subnet:         sandboxDefSubnet,
		DefaultRuntime: schema.SandboxGVisor,
		SSHPort:        22998,
		PreviewPort:    22997,
		SecretPort:     22996,
	}
}

func loadSandboxConfig() (sandboxConfig, error) {
	c := defaultSandboxConfig()
	b, err := os.ReadFile(sandboxConfigFile)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", sandboxConfigFile, err)
	}
	for _, r := range []*schema.Resources{&c.Defaults, &c.Limits} {
		if err := r.Validate(); err != nil {
			return c, fmt.Errorf("%s: %w", sandboxConfigFile, err)
		}
	}
	for _, d := range []string{c.DefaultTimeout, c.MaxTimeout} {
		if _, err := time.ParseDuration(d); err != nil {
			return c, fmt.Errorf("%s: bad timeout %q", sandboxConfigFile, d)
		}
	}
	if c.PreviewPort < 0 || c.PreviewPort > 65535 || (c.PreviewPort != 0 && c.PreviewPort == c.SSHPort) {
		return c, fmt.Errorf("%s: bad preview_port %d", sandboxConfigFile, c.PreviewPort)
	}
	if c.SecretPort < 0 || c.SecretPort > 65535 || (c.SecretPort != 0 && (c.SecretPort == c.SSHPort || c.SecretPort == c.PreviewPort)) {
		return c, fmt.Errorf("%s: bad secret_proxy_port %d", sandboxConfigFile, c.SecretPort)
	}
	if err := validatePools(c.Pools, c.MaxPerOwner); err != nil {
		return c, fmt.Errorf("%s: %w", sandboxConfigFile, err)
	}
	if c.DefaultRuntime != schema.SandboxGVisor && c.DefaultRuntime != schema.SandboxGVisorKVM {
		return c, fmt.Errorf("%s: default_runtime must be gvisor or gvisor-kvm", sandboxConfigFile)
	}
	if c.SSHPort < 0 || c.SSHPort > 65535 {
		return c, fmt.Errorf("%s: bad ssh_port %d", sandboxConfigFile, c.SSHPort)
	}
	if c.SSHHost != "" && !validDomain(c.SSHHost) {
		if _, err := netip.ParseAddr(c.SSHHost); err != nil {
			return c, fmt.Errorf("%s: ssh_host must be a host name or an address", sandboxConfigFile)
		}
	}
	if err := validateSandboxSubnet(c.Subnet); err != nil {
		return c, fmt.Errorf("%s: %w", sandboxConfigFile, err)
	}
	if c.MaxMemory != "" {
		if _, err := schema.ParseSize(c.MaxMemory); err != nil {
			return c, fmt.Errorf("%s: max_memory: %w", sandboxConfigFile, err)
		}
	}
	return c, nil
}

// sandboxCaller is who asks: the token name and role the API passed on, or root (the host CLI).
type sandboxCaller struct{ Owner, Role string }

func (c sandboxCaller) seesAll() bool { return apiRoleRank[c.Role] >= apiRoleRank["operator"] }

// resolveSandboxSpec fills in the host defaults and checks the spec against the host limits.
// It returns the lifetime.
func resolveSandboxSpec(s *schema.SandboxSpec, cfg sandboxConfig, caller sandboxCaller) (time.Duration, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	if s.Runtime == "" {
		s.Runtime = cfg.DefaultRuntime
	}
	if s.Runtime == schema.SandboxGVisorKVM && !kvmReady() {
		return 0, errors.New("the gvisor-kvm runtime needs /dev/kvm, which this host doesn't have (a VM without nested virtualization?); use gvisor")
	}
	if s.Runtime == schema.SandboxRunc {
		if !cfg.AllowRunc {
			return 0, errors.New("the runc runtime is disabled on this host (allow_runc in " + sandboxConfigFile + ")")
		}
		if !caller.seesAll() {
			return 0, errors.New("the runc runtime needs the operator role")
		}
	}
	if s.Workdir == "" {
		s.Workdir = "/workspace"
	}
	if e := privilegedAllow(s.Network); e != "" && !caller.seesAll() {
		return 0, fmt.Errorf("network: allowing %s (a private or reserved range) needs the operator role", e)
	}
	r := schema.Resources{}
	if s.Resources != nil {
		r = *s.Resources
	}
	if r.Memory == "" {
		r.Memory = cfg.Defaults.Memory
	}
	if r.CPUs == 0 {
		r.CPUs = cfg.Defaults.CPUs
	}
	if r.PIDs == 0 {
		r.PIDs = cfg.Defaults.PIDs
	}
	if lim := cfg.Limits.MemoryBytes(); lim > 0 && r.MemoryBytes() > lim {
		return 0, fmt.Errorf("memory %s is over this host's limit of %s", r.Memory, cfg.Limits.Memory)
	}
	if cfg.Limits.CPUs > 0 && r.CPUs > cfg.Limits.CPUs {
		return 0, fmt.Errorf("cpus %v is over this host's limit of %v", r.CPUs, cfg.Limits.CPUs)
	}
	if cfg.Limits.PIDs > 0 && r.PIDs > cfg.Limits.PIDs {
		return 0, fmt.Errorf("pids %d is over this host's limit of %d", r.PIDs, cfg.Limits.PIDs)
	}
	s.Resources = &r
	if s.Timeout == "" {
		s.Timeout = cfg.DefaultTimeout
	}
	ttl, _ := time.ParseDuration(s.Timeout)
	if maxTTL, _ := time.ParseDuration(cfg.MaxTimeout); ttl > maxTTL {
		return 0, fmt.Errorf("timeout %s is over this host's maximum of %s", s.Timeout, cfg.MaxTimeout)
	}
	return ttl, nil
}

func newSandboxID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.EncodeToString(b))[:12]
}

func sandboxContainer(id string) string { return "ziro-sbx-" + id }
func sandboxDir(id string) string       { return filepath.Join(sandboxRoot, id) }

// sandboxRunArgs is the nerdctl command line that starts a sandbox. Nothing in the spec can add
// a mount, a device or a capability; its network is the sandbox network, policed by the host.
func sandboxRunArgs(sb *sdkapi.Sandbox, image, gateway string, secretEnv map[string]string) []string {
	s := sb.Spec
	args := []string{"run", "-d", "--name", sandboxContainer(sb.ID), "--hostname", "sandbox",
		"--label", sandboxLabel + "=" + sb.ID, "--restart", "no"}
	switch s.Runtime {
	case schema.SandboxGVisorKVM:
		args = append(args, "--runtime", sandboxRunscKVM)
	case schema.SandboxRunc:
	default:
		args = append(args, "--runtime", sandboxRunsc)
	}
	args = append(args, "--security-opt", "no-new-privileges", "--cap-drop", "ALL")
	for _, c := range sandboxCaps {
		args = append(args, "--cap-add", c)
	}
	args = append(args, containerResourceArgs(s.Resources)...)
	if sb.IP != "" {
		args = append(args, "--network", sandboxNetName, "--ip", sb.IP, "--dns", gateway)
	} else {
		args = append(args, "--network", "none")
	}
	args = append(args, "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
		"-v", filepath.Join(sandboxDir(sb.ID), "workspace")+":/workspace",
		"-w", s.Workdir)
	if s.User != "" {
		args = append(args, "-u", s.User)
	}
	if len(secretEnv) > 0 { // the sandbox's CA, read-only (credential injection)
		for _, mnt := range secretMounts(sb.ID) {
			args = append(args, "-v", mnt)
		}
	}
	env := map[string]string{}
	for k, v := range s.Env {
		env[k] = v
	}
	for k, v := range secretEnv {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+env[k])
	}
	if len(s.Command) == 0 {
		// Keep the sandbox up for exec and SSH, whatever the image would run.
		return append(args, "--entrypoint", "sleep", "--", image, "infinity")
	}
	return append(append(args, "--", image), s.Command...)
}

// ---- the store: one JSON record per sandbox, next to its workspace ----

type sandboxStore struct {
	mu      sync.Mutex
	all     map[string]*sdkapi.Sandbox
	touched map[string]time.Time // when each record's LastActive was last saved (touch)
}

func loadSandboxStore() *sandboxStore {
	st := &sandboxStore{all: map[string]*sdkapi.Sandbox{}}
	ents, _ := os.ReadDir(sandboxRoot)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(sandboxRoot, e.Name(), "sandbox.json"))
		if err != nil {
			continue
		}
		var sb sdkapi.Sandbox
		if json.Unmarshal(b, &sb) == nil && sb.ID == e.Name() {
			st.all[sb.ID] = &sb
		}
	}
	return st
}

// save writes a record; the caller holds mu.
func (st *sandboxStore) save(sb *sdkapi.Sandbox) error {
	b, err := json.MarshalIndent(sb, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(sandboxDir(sb.ID), "sandbox.json"), b, 0600)
}

// get returns a copy of a sandbox the caller may see; anyone else's is "not found", so ids
// can't be probed.
func (st *sandboxStore) get(id string, c sandboxCaller) (sdkapi.Sandbox, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	sb, ok := st.all[id]
	if !ok || (!c.seesAll() && sb.Owner != c.Owner) {
		return sdkapi.Sandbox{}, errNotFound("no sandbox " + id)
	}
	return *sb, nil
}

func (st *sandboxStore) list(c sandboxCaller) []sdkapi.Sandbox {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []sdkapi.Sandbox{}
	for _, sb := range st.all {
		if c.seesAll() || sb.Owner == c.Owner {
			out = append(out, *sb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// update changes a sandbox under the lock and saves it.
func (st *sandboxStore) update(id string, f func(sb *sdkapi.Sandbox)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	sb, ok := st.all[id]
	if !ok {
		return errNotFound("no sandbox " + id)
	}
	f(sb)
	return st.save(sb)
}

// ---- lifecycle ----

type sandboxManager struct {
	st     *sandboxStore
	net    *sandboxNet
	access *accessStore
	ssh    *sshGateway // nil when ssh_port is 0
	mesh   *meshState  // the node's cluster view (sandbox_mesh.go)
	now    func() time.Time

	previewKey  []byte // nil when preview_port is 0
	previewPort int
	egress      *egressProxy // nil when secret_proxy_port is 0
}

// applyNet converges the sandbox network to the records.
func (m *sandboxManager) applyNet() error {
	return m.net.apply(m.st.list(sandboxCaller{Owner: "root", Role: "admin"}))
}

func (m *sandboxManager) create(ctx context.Context, spec schema.SandboxSpec, c sandboxCaller) (sdkapi.Sandbox, error) {
	cfg, err := loadSandboxConfig()
	if err != nil {
		return sdkapi.Sandbox{}, err
	}
	if !strings.HasPrefix(c.Owner, poolOwnerPrefix) {
		if sb, ok := m.claim(ctx, spec, c, cfg); ok { // a warm one
			return sb, nil
		}
	}
	if spec, err = applyTemplate(spec); err != nil {
		return sdkapi.Sandbox{}, err
	}
	ttl, err := resolveSandboxSpec(&spec, cfg, c)
	if err != nil {
		return sdkapi.Sandbox{}, err
	}
	image := spec.Image
	snap, err := snapshotAllowed(image, c)
	if err != nil {
		return sdkapi.Sandbox{}, err
	}
	if snap { // snapshots come from this host; anything else meets the image policy
		if image, err = findSnapshot(ctx, image); err != nil {
			return sdkapi.Sandbox{}, err
		}
	} else if image, err = enforceImagePolicy(cfg.ImagePolicy, spec.Image); err != nil {
		return sdkapi.Sandbox{}, err
	}
	secrets := spec.Secrets // values go to secrets.json only
	if len(secrets) > 0 {
		if m.egress == nil {
			return sdkapi.Sandbox{}, errors.New("secrets need the egress proxy (secret_proxy_port in " + sandboxConfigFile + ")")
		}
		spec.Secrets = withoutValues(secrets)
	}
	now := m.now().UTC()
	sb := &sdkapi.Sandbox{ID: newSandboxID(), Owner: c.Owner, State: "pending", Spec: spec,
		Created: now, Expires: now.Add(ttl), LastActive: now}

	m.st.mu.Lock()
	if err := checkSandboxQuota(m.st.all, cfg, c.Owner, spec.Resources.MemoryBytes()); err != nil {
		m.st.mu.Unlock()
		return sdkapi.Sandbox{}, err
	}
	if networked(spec) {
		sb.IP, err = allocSandboxIP(m.net.subnet, m.st.all)
	}
	if err == nil {
		err = os.MkdirAll(filepath.Join(sandboxDir(sb.ID), "workspace"), 0755)
	}
	if err == nil {
		err = m.st.save(sb)
	}
	if err == nil {
		m.st.all[sb.ID] = sb
	}
	m.st.mu.Unlock()
	if err != nil {
		_ = os.RemoveAll(sandboxDir(sb.ID))
		return sdkapi.Sandbox{}, err
	}
	if spec.User != "" {
		uid, gid := sandboxUIDGID(spec.User)
		_ = os.Chown(filepath.Join(sandboxDir(sb.ID), "workspace"), uid, gid)
	}

	var out []byte
	var runErr error
	if snap {
		if runErr = restoreWorkspace(image, sb.ID); runErr != nil {
			runErr = fmt.Errorf("snapshot workspace: %w", runErr)
		}
	}
	var secretEnv map[string]string
	if runErr == nil {
		if secretEnv, runErr = prepareSecrets(sb.ID, secrets, sb.Expires); runErr != nil {
			runErr = fmt.Errorf("secrets: %w", runErr)
		}
	}
	if sb.IP != "" && runErr == nil {
		// The rules for its address go in before the container exists: fail closed.
		if runErr = m.applyNet(); runErr != nil {
			runErr = fmt.Errorf("network policy: %w", runErr)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute) // the first run pulls the image
	defer cancel()
	if runErr == nil {
		out, runErr = sandboxNerdctl(ctx, sandboxRunArgs(sb, image, sandboxGateway(m.net.subnet), secretEnv)...)
	}
	var view sdkapi.Sandbox
	uerr := m.st.update(sb.ID, func(x *sdkapi.Sandbox) {
		if runErr != nil {
			x.State, x.Error = "failed", cmdError(out, runErr)
		} else {
			x.State = "running"
		}
		view = *x
	})
	if uerr != nil { // deleted while it was starting
		_, _ = sandboxNerdctl(context.Background(), "rm", "-f", sandboxContainer(sb.ID))
		return sdkapi.Sandbox{}, errors.New("the sandbox was deleted while it was starting")
	}
	if runErr != nil {
		return view, fmt.Errorf("start sandbox: %s", view.Error)
	}
	return view, nil
}

// checkSandboxQuota applies the host's count and memory caps; the caller holds the store lock.
func checkSandboxQuota(all map[string]*sdkapi.Sandbox, cfg sandboxConfig, owner string, mem int64) error {
	n, mine, used := 0, 0, int64(0)
	for _, sb := range all {
		n++
		if sb.Owner == owner {
			mine++
		}
		used += sb.Spec.Resources.MemoryBytes()
	}
	if cfg.MaxSandboxes > 0 && n >= cfg.MaxSandboxes {
		return fmt.Errorf("this host runs its maximum of %d sandboxes", cfg.MaxSandboxes)
	}
	if cfg.MaxPerOwner > 0 && mine >= cfg.MaxPerOwner {
		return fmt.Errorf("%s already has its maximum of %d sandboxes", owner, cfg.MaxPerOwner)
	}
	if cfg.MaxMemory != "" {
		if lim, _ := schema.ParseSize(cfg.MaxMemory); used+mem > lim {
			return fmt.Errorf("not enough sandbox memory left on this host (max_memory %s)", cfg.MaxMemory)
		}
	}
	return nil
}

func sandboxUIDGID(user string) (int, int) {
	u, g, _ := strings.Cut(user, ":")
	uid, _ := strconv.Atoi(u)
	gid := uid
	if g != "" {
		gid, _ = strconv.Atoi(g)
	}
	return uid, gid
}

// cmdError is the last line of a failed command's output, or its error.
func cmdError(out []byte, err error) string {
	msg := strings.TrimSpace(string(out))
	if i := strings.LastIndex(msg, "\n"); i >= 0 {
		msg = msg[i+1:]
	}
	if msg == "" {
		return err.Error()
	}
	return msg
}

func (m *sandboxManager) remove(id string, c sandboxCaller) error {
	sb, err := m.st.get(id, c)
	if err != nil {
		return err
	}
	dropPreviews(sb)
	m.st.mu.Lock()
	delete(m.st.all, id)
	delete(m.st.touched, id)
	m.st.mu.Unlock()
	m.access.drop(id)
	if m.egress != nil {
		m.egress.forget(id)
	}
	err = m.destroy(id)
	if nerr := m.applyNet(); nerr != nil {
		fmt.Printf("[sandboxd] network after deleting %s: %v\n", id, nerr)
	}
	return err
}

// destroy removes a sandbox's container and files (its record is already gone from the store).
// nerdctl rm -f of a gVisor container can report success after a kill error and leave it
// exited, so it is checked and removed again.
func (m *sandboxManager) destroy(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := sandboxContainer(id)
	for attempt := 0; ; attempt++ {
		out, err := sandboxNerdctl(ctx, "rm", "-f", name)
		if err != nil && !strings.Contains(string(out), "no such container") {
			return fmt.Errorf("remove sandbox %s: %s", id, cmdError(out, err))
		}
		ps, err := sandboxNerdctl(ctx, "ps", "-a", "--format", "{{.Names}}")
		if err != nil || !slices.Contains(strings.Fields(string(ps)), name) {
			break
		}
		if attempt == 2 {
			return fmt.Errorf("remove sandbox %s: the container is still there (the reaper retries)", id)
		}
		time.Sleep(time.Second)
	}
	return os.RemoveAll(sandboxDir(id))
}

// setPaused freezes (pause) or thaws (resume) a sandbox's processes.
func (m *sandboxManager) setPaused(ctx context.Context, id string, c sandboxCaller, pause bool) (sdkapi.Sandbox, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sb, err
	}
	from, to, verb := "running", "paused", "pause"
	if !pause {
		from, to, verb = "paused", "running", "unpause"
	}
	if sb.State != from {
		return sb, fmt.Errorf("sandbox %s is %s, not %s", id, sb.State, from)
	}
	if out, err := sandboxNerdctl(ctx, verb, sandboxContainer(id)); err != nil {
		return sb, fmt.Errorf("%s sandbox %s: %s", verb, id, cmdError(out, err))
	}
	err = m.st.update(id, func(x *sdkapi.Sandbox) { x.State, x.LastActive = to, m.now().UTC(); sb = *x })
	return sb, err
}

// renew moves the expiry to now + ttl ("" = the sandbox's own timeout), within the host maximum.
func (m *sandboxManager) renew(id string, c sandboxCaller, ttl string) (sdkapi.Sandbox, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sb, err
	}
	if ttl == "" {
		ttl = sb.Spec.Timeout
	}
	cfg, err := loadSandboxConfig()
	if err != nil {
		return sb, err
	}
	d, err := time.ParseDuration(ttl)
	maxTTL, _ := time.ParseDuration(cfg.MaxTimeout)
	if err != nil || d < time.Minute || d > maxTTL {
		return sb, fmt.Errorf("timeout must be between 1m and %s", cfg.MaxTimeout)
	}
	err = m.st.update(id, func(x *sdkapi.Sandbox) { x.Expires = m.now().UTC().Add(d); sb = *x })
	return sb, err
}

func (m *sandboxManager) setMetadata(id string, c sandboxCaller, md map[string]string) (sdkapi.Sandbox, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sb, err
	}
	if err := schema.ValidateSandboxMetadata(md); err != nil {
		return sb, err
	}
	err = m.st.update(id, func(x *sdkapi.Sandbox) { x.Spec.Metadata = md; sb = *x })
	return sb, err
}

// setNetwork replaces a sandbox's network policy and applies it now. A sandbox created without
// a network can't get one (it has no interface). If the rules can't be applied, the sandbox is
// paused and marked failed: it never keeps running under a policy other than the one asked for.
func (m *sandboxManager) setNetwork(ctx context.Context, id string, c sandboxCaller, n schema.SandboxNetwork) (sdkapi.Sandbox, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sb, err
	}
	if err := n.Validate(); err != nil {
		return sb, err
	}
	if e := privilegedAllow(&n); e != "" && !c.seesAll() {
		return sb, fmt.Errorf("network: allowing %s (a private or reserved range) needs the operator role", e)
	}
	if n.Mode == "" {
		n.Mode = schema.SandboxNetNone
	}
	if sb.IP == "" && n.Mode != schema.SandboxNetNone {
		return sb, errors.New("this sandbox was created without a network; create a new one with a network mode")
	}
	if sb.State != "running" && sb.State != "paused" {
		return sb, fmt.Errorf("sandbox %s is %s", id, sb.State)
	}
	if err := m.st.update(id, func(x *sdkapi.Sandbox) { x.Spec.Network = &n; sb = *x }); err != nil {
		return sb, err
	}
	if sb.IP == "" {
		return sb, nil
	}
	if err := m.applyNet(); err != nil {
		_, _ = sandboxNerdctl(ctx, "pause", sandboxContainer(id))
		msg := "network policy could not be applied, sandbox paused: " + err.Error()
		_ = m.st.update(id, func(x *sdkapi.Sandbox) { x.State, x.Error = "failed", msg; sb = *x })
		return sb, errors.New(msg)
	}
	return sb, nil
}

// sandboxTouchSave is how stale a saved LastActive may get: activity is kept in memory at once
// (the idle reaper reads that), and written out at most this often, not on every exec.
const sandboxTouchSave = 30 * time.Second

func (m *sandboxManager) touch(id string) {
	now := m.now().UTC()
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	sb, ok := m.st.all[id]
	if !ok {
		return
	}
	sb.LastActive = now
	if m.st.touched == nil {
		m.st.touched = map[string]time.Time{}
	}
	if now.Sub(m.st.touched[id]) >= sandboxTouchSave {
		m.st.touched[id] = now
		_ = m.st.save(sb)
	}
}

// ---- the reaper ----

const sandboxStoppedMsg = "the sandbox stopped (its command exited, it ran out of memory, or the host restarted)"

// reconcile is the reaper's pass: one container listing, then markExited and reap on it.
func (m *sandboxManager) reconcile(ctx context.Context) {
	// -a: without it nerdctl lists only containers that are "Up", and a paused one looks gone.
	out, err := sandboxNerdctl(ctx, "ps", "-a", "--filter", "label="+sandboxLabel, "--format", "{{.Names}}\t{{.Status}}")
	if err != nil {
		fmt.Printf("[sandboxd] list containers: %s\n", cmdError(out, err))
		return
	}
	status := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if name, st, ok := strings.Cut(l, "\t"); ok {
			status[name] = strings.ToLower(st)
		}
	}
	m.markExited(status)
	m.reap(ctx, status)
}

// containerState is the sandbox state a container status means: running, paused, or "" (gone or
// exited).
func containerState(status string) string {
	switch {
	case strings.HasPrefix(status, "up"):
		return "running"
	case strings.HasPrefix(status, "paused"):
		return "paused"
	}
	return ""
}

// markExited flags running and paused sandboxes whose container stopped (the command exited,
// OOM, a host restart). A sandbox it flagged whose container is alive after all (a listing that
// missed it) gets its state back.
func (m *sandboxManager) markExited(status map[string]string) {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	for id, sb := range m.st.all {
		live := containerState(status[sandboxContainer(id)])
		switch {
		case (sb.State == "running" || sb.State == "paused") && live == "":
			sb.State, sb.Error = "failed", sandboxStoppedMsg
		case sb.State == "failed" && sb.Error == sandboxStoppedMsg && live != "":
			sb.State, sb.Error = live, ""
		default:
			continue
		}
		_ = m.st.save(sb)
	}
}

// reap deletes sandboxes past their lifetime or idle timeout and removes sandbox containers
// nobody owns (a crash between starting a container and saving its record). status is the
// container listing (name -> lowercased status); reap takes its sandboxes out of it.
func (m *sandboxManager) reap(ctx context.Context, status map[string]string) {
	now := m.now().UTC()
	var expired []string
	m.st.mu.Lock()
	for id, sb := range m.st.all {
		delete(status, sandboxContainer(id))
		idle, _ := time.ParseDuration(sb.Spec.IdleTimeout)
		switch {
		case now.After(sb.Expires):
			expired = append(expired, id+" (lifetime over)")
		case idle > 0 && sb.State == "running" && now.Sub(sb.LastActive) > idle:
			expired = append(expired, id+" (idle)")
		}
	}
	var gone []sdkapi.Sandbox
	for _, e := range expired {
		id := strings.Fields(e)[0]
		gone = append(gone, *m.st.all[id])
		delete(m.st.all, id)
		delete(m.st.touched, id)
	}
	m.st.mu.Unlock()
	for _, sb := range gone {
		dropPreviews(sb)
	}
	for _, e := range expired {
		id := strings.Fields(e)[0]
		m.access.drop(id)
		if m.egress != nil {
			m.egress.forget(id)
		}
		err := m.destroy(id)
		_ = auditLog("ziro-sandboxd", "local", "sandbox expire", e, err)
	}
	if len(expired) > 0 {
		if err := m.applyNet(); err != nil {
			fmt.Printf("[sandboxd] network after expiry: %v\n", err)
		}
	}
	for name := range status { // containers without a record
		if strings.HasPrefix(name, "ziro-sbx-") {
			_, _ = sandboxNerdctl(ctx, "rm", "-f", name)
		}
	}
}

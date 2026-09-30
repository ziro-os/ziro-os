package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Declarative networking. /etc/ziro/network.json is the source of truth: when it exists, ziro-init
// runs `ziroctl network apply --boot` instead of DHCP on every interface, so static addresses,
// VLANs, bonds, MTUs and routes survive reboots. Changes go through `network apply`, which diffs
// against what was applied last and can roll itself back unless confirmed (remote-safe).

var (
	netConfigPath      = "/etc/ziro/network.json"
	netAppliedPath     = "/etc/ziro/network.applied.json"
	netRollbackPath    = "/etc/ziro/network.rollback.json"
	resolvPath         = "/etc/resolv.conf"
	resolvPinned       = "/etc/udhcpc/udhcpc.conf" // read by Alpine's udhcpc default.script
	hostnamePath       = "/etc/hostname"
	hostsPath          = "/etc/hosts"
	kernelHostnamePath = "/proc/sys/kernel/hostname"
	ipBin              = "/sbin/ip" // iproute2: busybox ip mishandles vlan/bond/veth options
	dhcpScript         = "/usr/share/udhcpc/default.script"
)

type NetIface struct {
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`                // dhcp (default), static, manual (up, no address), off
	Addresses []string `json:"addresses,omitempty"` // CIDRs, IPv4 and/or IPv6
	Gateway   string   `json:"gateway,omitempty"`
	Gateway6  string   `json:"gateway6,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"` // auto (SLAAC, default), static, off
	MTU       int      `json:"mtu,omitempty"`
	Parent    string   `json:"parent,omitempty"`    // VLAN: parent interface
	VLANID    int      `json:"vlan_id,omitempty"`   // VLAN: 802.1Q id
	BondMode  string   `json:"bond_mode,omitempty"` // bond: active-backup, 802.3ad, balance-alb, ...
	Slaves    []string `json:"slaves,omitempty"`    // bond members
}

type NetRoute struct {
	To     string `json:"to"`
	Via    string `json:"via,omitempty"`
	Dev    string `json:"dev,omitempty"`
	Metric int    `json:"metric,omitempty"`
}

type NetConfig struct {
	Interfaces []NetIface `json:"interfaces"`
	Routes     []NetRoute `json:"routes,omitempty"`
}

var bondModes = map[string]bool{"balance-rr": true, "active-backup": true, "balance-xor": true, "broadcast": true,
	"802.3ad": true, "balance-tlb": true, "balance-alb": true}

func (c NetConfig) iface(name string) *NetIface {
	for i := range c.Interfaces {
		if c.Interfaces[i].Name == name {
			return &c.Interfaces[i]
		}
	}
	return nil
}

func (c NetConfig) validate() error {
	names := map[string]bool{}
	slaveOf := map[string]string{}
	for _, i := range c.Interfaces {
		if !ifaceNameRe.MatchString(i.Name) || i.Name == "lo" {
			return fmt.Errorf("invalid interface name %q", i.Name)
		}
		if names[i.Name] {
			return fmt.Errorf("interface %s listed twice", i.Name)
		}
		names[i.Name] = true
		switch i.Mode {
		case "", "dhcp", "manual", "off":
			if len(i.Addresses) > 0 && i.Mode != "" && i.Mode != "dhcp" {
				return fmt.Errorf("%s: addresses need mode static (or dhcp for IPv6 extras)", i.Name)
			}
		case "static":
			if len(i.Addresses) == 0 {
				return fmt.Errorf("%s: static mode needs at least one address", i.Name)
			}
		default:
			return fmt.Errorf("%s: mode must be dhcp, static, manual or off", i.Name)
		}
		switch i.IPv6 {
		case "", "auto", "static", "off":
		default:
			return fmt.Errorf("%s: ipv6 must be auto, static or off", i.Name)
		}
		has6 := false
		for _, a := range i.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
				return fmt.Errorf("%s: invalid address %q (want CIDR, e.g. 10.0.0.5/24)", i.Name, a)
			}
			has6 = has6 || p.Addr().Is6()
		}
		if has6 && i.IPv6 == "off" {
			return fmt.Errorf("%s: IPv6 addresses with ipv6 off", i.Name)
		}
		for _, g := range []struct {
			v  string
			v4 bool
		}{{i.Gateway, true}, {i.Gateway6, false}} {
			if g.v == "" {
				continue
			}
			a, err := netip.ParseAddr(g.v)
			if err != nil || a.Is4() != g.v4 {
				return fmt.Errorf("%s: invalid gateway %q", i.Name, g.v)
			}
		}
		if i.MTU != 0 && (i.MTU < 576 || i.MTU > 9216) {
			return fmt.Errorf("%s: mtu must be 576..9216", i.Name)
		}
		if (i.Parent == "") != (i.VLANID == 0) {
			return fmt.Errorf("%s: a VLAN needs both parent and vlan_id", i.Name)
		}
		if i.VLANID != 0 && (i.VLANID < 1 || i.VLANID > 4094 || !ifaceNameRe.MatchString(i.Parent)) {
			return fmt.Errorf("%s: vlan_id must be 1..4094 on a valid parent", i.Name)
		}
		if i.BondMode != "" && !bondModes[i.BondMode] {
			return fmt.Errorf("%s: unknown bond mode %q", i.Name, i.BondMode)
		}
		if (i.BondMode == "") != (len(i.Slaves) == 0) {
			return fmt.Errorf("%s: a bond needs bond_mode and slaves", i.Name)
		}
		for _, s := range i.Slaves {
			if !ifaceNameRe.MatchString(s) || s == i.Name {
				return fmt.Errorf("%s: invalid slave %q", i.Name, s)
			}
			if o, dup := slaveOf[s]; dup {
				return fmt.Errorf("%s is a slave of both %s and %s", s, o, i.Name)
			}
			slaveOf[s] = i.Name
		}
	}
	for s, b := range slaveOf {
		if i := c.iface(s); i != nil && i.Mode != "manual" {
			return fmt.Errorf("%s is a slave of %s: set its mode to manual (or leave it out)", s, b)
		}
	}
	for _, r := range c.Routes {
		p, err := netip.ParsePrefix(r.To)
		if err != nil {
			return fmt.Errorf("invalid route destination %q", r.To)
		}
		if r.Via == "" && r.Dev == "" {
			return fmt.Errorf("route %s needs via and/or dev", r.To)
		}
		if r.Via != "" {
			a, err := netip.ParseAddr(r.Via)
			if err != nil || a.Is4() != p.Addr().Is4() {
				return fmt.Errorf("route %s: invalid gateway %q", r.To, r.Via)
			}
		}
		if r.Dev != "" && !ifaceNameRe.MatchString(r.Dev) {
			return fmt.Errorf("route %s: invalid dev %q", r.To, r.Dev)
		}
		if r.Metric < 0 || r.Metric > 65535 {
			return fmt.Errorf("route %s: metric out of range", r.To)
		}
	}
	return nil
}

func loadNetConfig(path string) (*NetConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c NetConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.validate()
}

func saveNetConfig(path string, c *NetConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0644)
}

// defaultNetConfig is what ziro-init does without a config: DHCP on every Ethernet interface.
func defaultNetConfig() *NetConfig {
	c := &NetConfig{}
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		t, _ := os.ReadFile(filepath.Join("/sys/class/net", e.Name(), "type"))
		if e.Name() != "lo" && strings.TrimSpace(string(t)) == "1" && ifaceNameRe.MatchString(e.Name()) {
			if _, err := os.Stat(filepath.Join("/sys/class/net", e.Name(), "device")); err == nil {
				c.Interfaces = append(c.Interfaces, NetIface{Name: e.Name(), Mode: "dhcp"})
			}
		}
	}
	return c
}

// ---- plan ----

// netStep is one action: an ip(8) command, a sysctl file write, or starting/stopping DHCP.
type netStep struct {
	IP      []string `json:"ip,omitempty"`
	File    string   `json:"file,omitempty"`
	Value   string   `json:"value,omitempty"`
	DHCP    string   `json:"dhcp,omitempty"`    // start DHCP on this interface
	NoDHCP  string   `json:"no_dhcp,omitempty"` // stop DHCP on this interface
	Soft    bool     `json:"soft,omitempty"`    // failure is fine (e.g. deleting something already gone)
	Comment string   `json:"comment,omitempty"`
}

func (s netStep) String() string {
	switch {
	case s.IP != nil:
		return "ip " + strings.Join(s.IP, " ")
	case s.File != "":
		return s.File + " = " + s.Value
	case s.DHCP != "":
		return "start DHCP on " + s.DHCP
	default:
		return "stop DHCP on " + s.NoDHCP
	}
}

func ipv6Sysctl(name, key, val string) netStep {
	return netStep{File: "/proc/sys/net/ipv6/conf/" + name + "/" + key, Value: val, Soft: true}
}

func routeArgs(r NetRoute) []string {
	args := []string{"route", "replace", r.To}
	if p, _ := netip.ParsePrefix(r.To); p.Addr().Is6() {
		args = append([]string{"-6"}, args...)
	}
	if r.Via != "" {
		args = append(args, "via", r.Via)
	}
	if r.Dev != "" {
		args = append(args, "dev", r.Dev)
	}
	if r.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(r.Metric))
	}
	return args
}

// netPlan turns prev -> next into ordered steps: remove what went away, create bonds and VLANs,
// configure each interface, then routes.
func netPlan(prev, next *NetConfig) []netStep {
	var steps []netStep
	if prev == nil {
		prev = &NetConfig{}
	}
	nextRoutes := map[string]bool{}
	for _, r := range next.Routes {
		nextRoutes[strings.Join(routeArgs(r), " ")] = true
	}
	for _, r := range prev.Routes {
		if !nextRoutes[strings.Join(routeArgs(r), " ")] {
			args := routeArgs(r)
			for i, a := range args {
				if a == "replace" {
					args[i] = "del"
				}
			}
			steps = append(steps, netStep{IP: args, Soft: true, Comment: "route removed"})
		}
	}
	for _, p := range prev.Interfaces {
		if (p.VLANID != 0 || p.BondMode != "") && next.iface(p.Name) == nil {
			steps = append(steps, netStep{NoDHCP: p.Name}, netStep{IP: []string{"link", "del", p.Name}, Soft: true, Comment: "removed"})
		}
	}
	// Bonds first (slaves must be down to enslave), then VLANs (their parent may be a bond).
	for _, i := range next.Interfaces {
		if i.BondMode == "" {
			continue
		}
		steps = append(steps, netStep{IP: []string{"link", "add", i.Name, "type", "bond", "mode", i.BondMode, "miimon", "100"}, Soft: true})
		for _, s := range i.Slaves {
			steps = append(steps, netStep{NoDHCP: s},
				netStep{IP: []string{"link", "set", s, "down"}},
				netStep{IP: []string{"link", "set", s, "master", i.Name}, Soft: true},
				netStep{IP: []string{"link", "set", s, "up"}})
		}
	}
	for _, i := range next.Interfaces {
		if i.VLANID != 0 {
			steps = append(steps, netStep{IP: []string{"link", "add", "link", i.Parent, "name", i.Name, "type", "vlan", "id", strconv.Itoa(i.VLANID)}, Soft: true})
		}
	}
	for _, i := range next.Interfaces {
		name := i.Name
		if i.Mode == "off" {
			steps = append(steps, netStep{NoDHCP: name}, netStep{IP: []string{"link", "set", name, "down"}})
			continue
		}
		if i.MTU > 0 {
			steps = append(steps, netStep{IP: []string{"link", "set", name, "mtu", strconv.Itoa(i.MTU)}})
		}
		switch i.IPv6 {
		case "off":
			steps = append(steps, ipv6Sysctl(name, "disable_ipv6", "1"))
		case "static":
			steps = append(steps, ipv6Sysctl(name, "disable_ipv6", "0"), ipv6Sysctl(name, "accept_ra", "0"), ipv6Sysctl(name, "autoconf", "0"))
		default: // SLAAC; accept_ra=2 because the host forwards (containers)
			steps = append(steps, ipv6Sysctl(name, "disable_ipv6", "0"), ipv6Sysctl(name, "accept_ra", "2"), ipv6Sysctl(name, "autoconf", "1"))
		}
		steps = append(steps, netStep{IP: []string{"link", "set", name, "up"}})
		switch i.Mode {
		case "static":
			steps = append(steps, netStep{NoDHCP: name},
				netStep{IP: []string{"-4", "addr", "flush", "dev", name, "scope", "global"}})
			if i.IPv6 == "static" {
				steps = append(steps, netStep{IP: []string{"-6", "addr", "flush", "dev", name, "scope", "global"}})
			}
		case "manual":
			steps = append(steps, netStep{NoDHCP: name})
		default:
			steps = append(steps, netStep{DHCP: name})
		}
		for _, a := range i.Addresses {
			steps = append(steps, netStep{IP: []string{"addr", "replace", a, "dev", name}})
		}
		if i.Gateway != "" {
			steps = append(steps, netStep{IP: []string{"-4", "route", "replace", "default", "via", i.Gateway, "dev", name}})
		}
		if i.Gateway6 != "" {
			steps = append(steps, netStep{IP: []string{"-6", "route", "replace", "default", "via", i.Gateway6, "dev", name}})
		}
	}
	for _, r := range next.Routes {
		steps = append(steps, netStep{IP: routeArgs(r)})
	}
	return steps
}

// ---- apply ----

func dhcpPidfile(name string) string { return "/run/udhcpc." + name + ".pid" }

func stopDHCP(name string) {
	if b, err := os.ReadFile(dhcpPidfile(name)); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		_ = os.Remove(dhcpPidfile(name))
	}
	_ = exec.Command("pkill", "-f", "udhcpc .*-i "+name+"( |$)").Run()
}

var runNetStep = func(s netStep) error {
	switch {
	case s.IP != nil:
		if out, err := exec.Command(ipBin, s.IP...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(s.IP, " "), err, strings.TrimSpace(string(out)))
		}
	case s.File != "":
		return os.WriteFile(s.File, []byte(s.Value+"\n"), 0644)
	case s.DHCP != "":
		stopDHCP(s.DHCP)
		c := exec.Command("udhcpc", "-b", "-i", s.DHCP, "-s", dhcpScript, "-p", dhcpPidfile(s.DHCP))
		if log, err := os.OpenFile("/var/log/udhcpc."+s.DHCP+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			c.Stdout, c.Stderr = log, log
			defer log.Close()
		}
		return c.Run() // -b: forks into the background once started
	case s.NoDHCP != "":
		stopDHCP(s.NoDHCP)
	}
	return nil
}

func executeNetPlan(steps []netStep, verbose bool) error {
	var errs []string
	for _, s := range steps {
		if verbose {
			fmt.Println("  " + s.String())
		}
		if err := runNetStep(s); err != nil && !s.Soft {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// applyNetConfig applies next (diffing against what was applied last) and records it.
func applyNetConfig(next *NetConfig, verbose bool) error {
	prev, _ := loadNetConfig(netAppliedPath)
	err := executeNetPlan(netPlan(prev, next), verbose)
	if serr := saveNetConfig(netAppliedPath, next); serr != nil && err == nil {
		err = serr
	}
	return err
}

type netRollback struct {
	Token    string     `json:"token"`
	Deadline time.Time  `json:"deadline"`
	Prev     *NetConfig `json:"prev"`      // nil: there was no network.json (DHCP everywhere)
	PrevFile bool       `json:"prev_file"` // whether network.json existed before
}

func newToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// startNetApply applies the pending network.json. With a confirm timeout it arms an automatic
// rollback that a detached watcher executes unless `network confirm` runs first.
func startNetApply(confirm time.Duration) error {
	next, err := loadNetConfig(netConfigPath)
	if err != nil {
		return fmt.Errorf("no valid %s: %w", netConfigPath, err)
	}
	if confirm > 0 {
		if _, err := os.Stat(netRollbackPath); err == nil {
			return errors.New("a previous change is still waiting for `ziroctl network confirm` (or its rollback)")
		}
		prev, perr := loadNetConfig(netAppliedPath)
		rb := netRollback{Token: newToken(), Deadline: time.Now().Add(confirm), Prev: prev, PrevFile: perr == nil}
		b, _ := json.Marshal(rb)
		if err := writeFileAtomic(netRollbackPath, b, 0600); err != nil {
			return err
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		w := exec.Command(self, "network", "rollback-watch", rb.Token)
		w.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survives the SSH session that ran apply
		if err := w.Start(); err != nil {
			return err
		}
		_ = w.Process.Release()
	}
	fmt.Println("Applying network configuration:")
	err = applyNetConfig(next, true)
	if confirm > 0 {
		fmt.Printf("\n⚠ Run `ziroctl network confirm` within %s to keep this configuration; otherwise it is rolled back.\n", confirm)
	}
	return err
}

// rollbackNet restores the configuration recorded before an unconfirmed apply.
func rollbackNet(rb netRollback) error {
	prev := rb.Prev
	if prev == nil {
		prev = defaultNetConfig()
	}
	cur, _ := loadNetConfig(netAppliedPath)
	err := executeNetPlan(netPlan(cur, prev), false)
	_ = saveNetConfig(netAppliedPath, prev)
	if rb.PrevFile {
		_ = saveNetConfig(netConfigPath, prev)
	} else {
		_ = os.Remove(netConfigPath)
	}
	_ = os.Remove(netRollbackPath)
	_ = auditLog("network", "rollback", "network rollback", "unconfirmed change reverted", err)
	alertf("high", "network", "Network change rolled back (not confirmed in time)", map[string]any{"error": fmt.Sprint(err)})
	return err
}

// ---- hostname and resolvers ----

var hostnameLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validHostname(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return fmt.Errorf("hostname must be 1-253 characters")
	}
	for _, l := range strings.Split(h, ".") {
		if !hostnameLabelRe.MatchString(l) {
			return fmt.Errorf("invalid hostname %q (RFC 1123: lowercase letters, digits and hyphens per label)", h)
		}
	}
	return nil
}

// rewriteHosts points the 127.0.1.1 entry at name (adding it if missing); other lines are kept.
func rewriteHosts(hosts, name string) string {
	short, _, _ := strings.Cut(name, ".")
	entry := "127.0.1.1\t" + name
	if short != name {
		entry += " " + short
	}
	var out []string
	done := false
	for _, l := range strings.Split(strings.TrimRight(hosts, "\n"), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "127.0.1.1" {
			if !done {
				out = append(out, entry)
				done = true
			}
			continue
		}
		out = append(out, l)
	}
	if !done {
		out = append(out, entry)
	}
	return strings.Join(out, "\n") + "\n"
}

func setHostname(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := validHostname(name); err != nil {
		return err
	}
	if err := writeFileAtomic(hostnamePath, []byte(name+"\n"), 0644); err != nil {
		return err
	}
	hosts, _ := os.ReadFile(hostsPath)
	if err := writeFileAtomic(hostsPath, []byte(rewriteHosts(string(hosts), name)), 0644); err != nil {
		return err
	}
	// Same as sethostname(2); via /proc so this builds on every platform the tests run on.
	return os.WriteFile(kernelHostnamePath, []byte(name), 0644)
}

func renderResolv(servers, search []string) (string, error) {
	if len(servers) == 0 || len(servers) > 3 {
		return "", errors.New("give 1 to 3 nameservers (the resolver ignores more)")
	}
	var b strings.Builder
	b.WriteString("# Managed by `ziroctl network dns` (pinned: DHCP leaves it alone)\n")
	if len(search) > 0 {
		for _, s := range search {
			if err := validHostname(strings.ToLower(s)); err != nil {
				return "", fmt.Errorf("invalid search domain %q", s)
			}
		}
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	for _, s := range servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", fmt.Errorf("invalid nameserver %q", s)
		}
		b.WriteString("nameserver " + a.String() + "\n")
	}
	b.WriteString("options timeout:2 attempts:2 rotate\n")
	return b.String(), nil
}

const resolvPinMarker = "# Managed by `ziroctl network dns`: resolvers are pinned"

// setResolvers pins the resolvers (DHCP stops rewriting resolv.conf), or with nil returns to DHCP.
func setResolvers(servers, search []string) error {
	if servers == nil {
		b, err := os.ReadFile(resolvPinned)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), resolvPinMarker) {
			return fmt.Errorf("%s was not written by ziroctl; edit it by hand", resolvPinned)
		}
		return os.Remove(resolvPinned)
	}
	content, err := renderResolv(servers, search)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(resolvPinned), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(resolvPinned, []byte(resolvPinMarker+"\nRESOLV_CONF=no\n"), 0644); err != nil {
		return err
	}
	return writeFileAtomic(resolvPath, []byte(content), 0644)
}

// ---- CLI ----

var (
	netConfirmTimeout time.Duration
	netBoot           bool
	netDNSSearch      []string
	netSetMode        string
	netSetAddrs       []string
	netSetGateway     string
	netSetGateway6    string
	netSetIPv6        string
	netSetMTU         int
	netRouteVia       string
	netRouteDev       string
	netRouteMetric    int
	netBondMode       string
)

// editNetConfig loads the pending config (or the running default), edits, validates and saves it.
func editNetConfig(edit func(*NetConfig) error) error {
	c, err := loadNetConfig(netConfigPath)
	if err != nil {
		if !os.IsNotExist(errors.Unwrap(err)) && !os.IsNotExist(err) {
			return err
		}
		if c, err = loadNetConfig(netAppliedPath); err != nil {
			c = defaultNetConfig()
		}
	}
	if err := edit(c); err != nil {
		return err
	}
	if err := saveNetConfig(netConfigPath, c); err != nil {
		return err
	}
	fmt.Printf("Saved %s. Apply with: ziroctl network apply --confirm-timeout 120s\n", netConfigPath)
	return nil
}

var networkApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply /etc/ziro/network.json (use --confirm-timeout for remote changes)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if netBoot {
			return netApplyBoot()
		}
		if netConfirmTimeout == 0 && os.Getenv("SSH_CONNECTION") != "" {
			fmt.Println("⚠ Applying over SSH without --confirm-timeout: a mistake can cut this session off.")
		}
		return startNetApply(netConfirmTimeout)
	},
}

// netApplyBoot runs from ziro-init. An unconfirmed change that was pending when the host rebooted is
// rolled back first: the admin never confirmed it worked.
func netApplyBoot() error {
	if b, err := os.ReadFile(netRollbackPath); err == nil {
		var rb netRollback
		if json.Unmarshal(b, &rb) == nil {
			_ = os.Remove(netAppliedPath) // nothing is configured yet at boot
			return rollbackNet(rb)
		}
	}
	_ = os.Remove(netAppliedPath)
	c, err := loadNetConfig(netConfigPath)
	if err != nil {
		fmt.Printf("[network] %v; falling back to DHCP on every interface\n", err)
		c = defaultNetConfig()
	}
	return applyNetConfig(c, true)
}

var networkConfirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Keep the configuration applied with --confirm-timeout (cancels the rollback)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := os.Remove(netRollbackPath); err != nil {
			return errors.New("nothing to confirm")
		}
		fmt.Println("✅ Network configuration confirmed.")
		return nil
	},
}

var networkRollbackWatchCmd = &cobra.Command{
	Use:    "rollback-watch <token>",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for {
			b, err := os.ReadFile(netRollbackPath)
			if err != nil {
				return nil // confirmed (file removed)
			}
			var rb netRollback
			if json.Unmarshal(b, &rb) != nil || rb.Token != args[0] {
				return nil // superseded
			}
			if time.Now().After(rb.Deadline) {
				return rollbackNet(rb)
			}
			time.Sleep(time.Second)
		}
	},
}

var networkShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the pending network configuration (and what differs from the running one)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadNetConfig(netConfigPath)
		if err != nil {
			return fmt.Errorf("no %s yet (the host uses DHCP on every interface): %w", netConfigPath, err)
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(c)
		}
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
		prev, _ := loadNetConfig(netAppliedPath)
		steps := netPlan(prev, c)
		fmt.Printf("\n%d step(s) to apply:\n", len(steps))
		for _, s := range steps {
			fmt.Println("  " + s.String())
		}
		return nil
	},
}

var networkSetCmd = &cobra.Command{
	Use:   "set <iface>",
	Short: "Configure an interface in the pending config (then: network apply)",
	Example: `  ziroctl network set eth0 --mode static --address 10.0.0.5/24 --gateway 10.0.0.1
  ziroctl network set eth0 --mode dhcp --mtu 9000 --ipv6 auto
  ziroctl network set eth1 --mode off`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editNetConfig(func(c *NetConfig) error {
			i := c.iface(args[0])
			if i == nil {
				c.Interfaces = append(c.Interfaces, NetIface{Name: args[0], Mode: "dhcp"})
				i = &c.Interfaces[len(c.Interfaces)-1]
			}
			f := cmd.Flags()
			if f.Changed("mode") {
				i.Mode = netSetMode
				if netSetMode != "static" && !f.Changed("address") {
					i.Addresses, i.Gateway = nil, ""
				}
			}
			if f.Changed("address") {
				i.Addresses = netSetAddrs
			}
			if f.Changed("gateway") {
				i.Gateway = netSetGateway
			}
			if f.Changed("gateway6") {
				i.Gateway6 = netSetGateway6
			}
			if f.Changed("ipv6") {
				i.IPv6 = netSetIPv6
			}
			if f.Changed("mtu") {
				i.MTU = netSetMTU
			}
			return nil
		})
	},
}

var networkRouteCmd = &cobra.Command{Use: "route", Short: "Static routes (pending config)"}

var networkRouteAddCmd = &cobra.Command{
	Use:     "add <cidr>",
	Short:   "Add a static route",
	Example: `  ziroctl network route add 10.20.0.0/16 --via 10.0.0.254`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editNetConfig(func(c *NetConfig) error {
			c.Routes = append(c.Routes, NetRoute{To: args[0], Via: netRouteVia, Dev: netRouteDev, Metric: netRouteMetric})
			return nil
		})
	},
}

var networkRouteDelCmd = &cobra.Command{
	Use:   "del <cidr>",
	Short: "Remove a static route",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editNetConfig(func(c *NetConfig) error {
			kept := c.Routes[:0]
			for _, r := range c.Routes {
				if r.To != args[0] {
					kept = append(kept, r)
				}
			}
			if len(kept) == len(c.Routes) {
				return fmt.Errorf("no route to %s", args[0])
			}
			c.Routes = kept
			return nil
		})
	},
}

var networkVLANCmd = &cobra.Command{Use: "vlan", Short: "802.1Q VLAN interfaces (pending config)"}

var networkVLANAddCmd = &cobra.Command{
	Use:     "add <parent> <id>",
	Short:   "Add VLAN <parent>.<id> (configure it with network set)",
	Example: `  ziroctl network vlan add eth0 100 && ziroctl network set eth0.100 --mode static --address 172.16.100.5/24`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid VLAN id %q", args[1])
		}
		return editNetConfig(func(c *NetConfig) error {
			name := fmt.Sprintf("%s.%d", args[0], id)
			if c.iface(name) != nil {
				return fmt.Errorf("%s already exists", name)
			}
			c.Interfaces = append(c.Interfaces, NetIface{Name: name, Mode: "dhcp", Parent: args[0], VLANID: id})
			return nil
		})
	},
}

var networkBondCmd = &cobra.Command{Use: "bond", Short: "Bonded interfaces (pending config)"}

var networkBondAddCmd = &cobra.Command{
	Use:     "add <name> <slave>...",
	Short:   "Bond slaves into <name> (slaves become manual)",
	Example: `  ziroctl network bond add bond0 eth1 eth2 --mode active-backup`,
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editNetConfig(func(c *NetConfig) error {
			if c.iface(args[0]) != nil {
				return fmt.Errorf("%s already exists", args[0])
			}
			for _, s := range args[1:] {
				if i := c.iface(s); i != nil {
					i.Mode, i.Addresses, i.Gateway = "manual", nil, ""
				} else {
					c.Interfaces = append(c.Interfaces, NetIface{Name: s, Mode: "manual"})
				}
			}
			c.Interfaces = append(c.Interfaces, NetIface{Name: args[0], Mode: "dhcp", BondMode: netBondMode, Slaves: args[1:]})
			return nil
		})
	},
}

var networkIfaceDelCmd = &cobra.Command{
	Use:   "remove <iface>",
	Short: "Remove an interface (VLAN, bond or physical) from the pending config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return editNetConfig(func(c *NetConfig) error {
			kept := c.Interfaces[:0]
			for _, i := range c.Interfaces {
				if i.Name != args[0] {
					kept = append(kept, i)
				}
			}
			if len(kept) == len(c.Interfaces) {
				return fmt.Errorf("no interface %s in the config", args[0])
			}
			c.Interfaces = kept
			return nil
		})
	},
}

var networkHostnameCmd = &cobra.Command{
	Use:   "hostname [new-name]",
	Short: "Show or set the hostname (applied immediately and persisted)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			h, err := os.Hostname()
			fmt.Println(h)
			return err
		}
		if err := setHostname(args[0]); err != nil {
			return err
		}
		fmt.Printf("✅ Hostname set to %s\n", strings.ToLower(args[0]))
		return nil
	},
}

var networkDNSCmd = &cobra.Command{
	Use:   "dns [auto | <nameserver>...]",
	Short: "Show or set DNS resolvers (auto = from DHCP)",
	Example: `  ziroctl network dns 1.1.1.1 9.9.9.9 --search corp.example
  ziroctl network dns auto`,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case len(args) == 0:
			b, err := os.ReadFile(resolvPath)
			if err != nil {
				return err
			}
			mode := "from DHCP"
			if fileExists(resolvPinned) {
				mode = "pinned"
			}
			fmt.Printf("# %s\n%s", mode, b)
			return nil
		case len(args) == 1 && args[0] == "auto":
			if err := setResolvers(nil, nil); err != nil && !os.IsNotExist(err) {
				return err
			}
			fmt.Println("✅ Resolvers follow DHCP again (on the next lease renewal; `ziroctl network restart` to refresh now)")
			return nil
		}
		if err := setResolvers(args, netDNSSearch); err != nil {
			return err
		}
		fmt.Printf("✅ Resolvers pinned: %s\n", strings.Join(args, ", "))
		return nil
	},
}

func sortedIfaceNames(c *NetConfig) []string {
	var n []string
	for _, i := range c.Interfaces {
		n = append(n, i.Name)
	}
	sort.Strings(n)
	return n
}

func init() {
	networkApplyCmd.Flags().DurationVar(&netConfirmTimeout, "confirm-timeout", 0, "Roll back unless `network confirm` runs within this time (e.g. 120s)")
	networkApplyCmd.Flags().BoolVar(&netBoot, "boot", false, "Apply at boot (ziro-init)")
	_ = networkApplyCmd.Flags().MarkHidden("boot")
	networkDNSCmd.Flags().StringSliceVar(&netDNSSearch, "search", nil, "Search domains")
	f := networkSetCmd.Flags()
	f.StringVar(&netSetMode, "mode", "", "dhcp, static, manual or off")
	f.StringSliceVar(&netSetAddrs, "address", nil, "Address in CIDR form (repeatable; IPv4 and IPv6)")
	f.StringVar(&netSetGateway, "gateway", "", "IPv4 default gateway")
	f.StringVar(&netSetGateway6, "gateway6", "", "IPv6 default gateway")
	f.StringVar(&netSetIPv6, "ipv6", "", "auto (SLAAC), static or off")
	f.IntVar(&netSetMTU, "mtu", 0, "MTU (576-9216)")
	networkRouteAddCmd.Flags().StringVar(&netRouteVia, "via", "", "Gateway")
	networkRouteAddCmd.Flags().StringVar(&netRouteDev, "dev", "", "Interface")
	networkRouteAddCmd.Flags().IntVar(&netRouteMetric, "metric", 0, "Metric")
	networkBondAddCmd.Flags().StringVar(&netBondMode, "mode", "active-backup", "Bond mode (active-backup, 802.3ad, balance-alb, ...)")
	networkRouteCmd.AddCommand(networkRouteAddCmd, networkRouteDelCmd)
	networkVLANCmd.AddCommand(networkVLANAddCmd)
	networkBondCmd.AddCommand(networkBondAddCmd)
	networkCmd.AddCommand(networkApplyCmd, networkConfirmCmd, networkRollbackWatchCmd, networkShowCmd, networkSetCmd,
		networkRouteCmd, networkVLANCmd, networkBondCmd, networkIfaceDelCmd, networkHostnameCmd, networkDNSCmd)
}

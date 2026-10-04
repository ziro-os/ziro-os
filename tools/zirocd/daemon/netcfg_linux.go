package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const ifaceName = "zr0"

func DefaultStateDir() string { return "/var/lib/zirocd" }
func ControlPath() string     { return "/run/zirocd.sock" }

func secureDir(dir string) error { return os.MkdirAll(dir, 0700) }

// configureInterface gives the tunnel its addresses with the network prefix length, so the
// kernel routes the whole network into it.
func configureInterface(name string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		fam := "-4"
		if a.Addr().Is6() {
			fam = "-6"
		}
		if err := run("ip", fam, "address", "replace", a.String(), "dev", name); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", "dev", name, "up")
}

func addRoute(name string, p netip.Prefix) error {
	fam := "-4"
	if p.Addr().Is6() {
		fam = "-6"
	}
	return run("ip", fam, "route", "replace", p.String(), "dev", name)
}

func delRoute(name string, p netip.Prefix) error {
	fam := "-4"
	if p.Addr().Is6() {
		fam = "-6"
	}
	return run("ip", fam, "route", "del", p.String(), "dev", name)
}

// setDNS routes only the network's domain to the tunnel's resolver: through systemd-resolved,
// or on Ziro OS through a forward rule of Ziro DNS (which reloads it within 2s).
func setDNS(name, domain string, ns netip.Addr) error {
	if !domainRe.MatchString(domain) {
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err == nil {
		if err := run("resolvectl", "dns", name, ns.String()); err != nil {
			return err
		}
		return run("resolvectl", "domain", name, "~"+domain)
	}
	if _, err := exec.LookPath("ziroctl"); err == nil {
		return run("ziroctl", "dns", "forward", "add", domain, ns.String())
	}
	return nil
}

func clearDNS(name, domain string) {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		_ = run("resolvectl", "revert", name)
	} else if _, err := exec.LookPath("ziroctl"); err == nil && domainRe.MatchString(domain) {
		_ = run("ziroctl", "dns", "forward", "remove", domain)
	}
}

// setSubnetRouter makes this host route the network into the subnets it advertises: IP
// forwarding on, and traffic from the network masqueraded on its way out (LAN hosts need no
// route back). Idempotent; off removes the NAT rules.
func setSubnetRouter(name string, networks []netip.Prefix, on bool) error {
	if on {
		for _, f := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if b, err := os.ReadFile(f); err == nil && strings.TrimSpace(string(b)) == "1" {
				continue // already on (containers often mount /proc/sys read-only)
			}
			if err := os.WriteFile(f, []byte("1"), 0644); err != nil {
				return err
			}
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		_ = run("nft", "delete", "table", "inet", "zirocd")
		if !on {
			return nil
		}
		rules := "table inet zirocd {\n chain postrouting {\n  type nat hook postrouting priority srcnat; policy accept;\n"
		for _, n := range networks {
			fam := "ip"
			if n.Addr().Is6() {
				fam = "ip6"
			}
			rules += "  " + fam + " saddr " + n.String() + " oifname != \"" + name + "\" masquerade\n"
		}
		rules += " }\n}\n"
		c := exec.Command("nft", "-f", "-")
		c.Stdin = strings.NewReader(rules)
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("nft: %v: %s", err, out)
		}
		return nil
	}
	for _, n := range networks { // iptables fallback
		tool := "iptables"
		if n.Addr().Is6() {
			tool = "ip6tables"
		}
		rule := func(op string) []string {
			return []string{"-t", "nat", op, "POSTROUTING", "-s", n.String(), "!", "-o", name, "-j", "MASQUERADE"}
		}
		exists := exec.Command(tool, rule("-C")...).Run() == nil
		switch {
		case on && !exists:
			if err := run(tool, rule("-A")...); err != nil {
				return err
			}
		case !on && exists:
			_ = run(tool, rule("-D")...)
		}
	}
	return nil
}

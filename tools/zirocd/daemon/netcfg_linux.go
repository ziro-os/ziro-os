package daemon

import (
	"net/netip"
	"os"
	"os/exec"
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

// setDNS routes only the network's domain to the tunnel's resolver (systemd-resolved).
// ponytail: hosts without resolvectl (Ziro OS uses its own DNS responder) skip split DNS; R4 wires it.
func setDNS(name, domain string, ns netip.Addr) error {
	if _, err := exec.LookPath("resolvectl"); err != nil || !domainRe.MatchString(domain) {
		return nil
	}
	if err := run("resolvectl", "dns", name, ns.String()); err != nil {
		return err
	}
	return run("resolvectl", "domain", name, "~"+domain)
}

func clearDNS(name, domain string) {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		_ = run("resolvectl", "revert", name)
	}
}

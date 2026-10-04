package daemon

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const ifaceName = "utun" // the kernel picks utunN

func DefaultStateDir() string { return "/Library/Application Support/zirocd" }
func ControlPath() string     { return "/var/run/zirocd.sock" }

func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

// configureInterface: utun is point-to-point, so each address is its own peer address; the
// network prefixes are routed into it explicitly.
func configureInterface(name string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		if a.Addr().Is4() {
			if err := run("/sbin/ifconfig", name, "inet", a.Addr().String(), a.Addr().String(), "netmask", "255.255.255.255", "up"); err != nil {
				return err
			}
		} else if err := run("/sbin/ifconfig", name, "inet6", a.Addr().String(), "prefixlen", "128", "alias"); err != nil {
			return err
		}
		if err := addRoute(name, a.Masked()); err != nil {
			return err
		}
	}
	return nil
}

func addRoute(name string, p netip.Prefix) error {
	fam := "-inet"
	if p.Addr().Is6() {
		fam = "-inet6"
	}
	_ = run("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", name)
	return run("/sbin/route", "-q", "-n", "add", fam, p.String(), "-interface", name)
}

func delRoute(name string, p netip.Prefix) error {
	fam := "-inet"
	if p.Addr().Is6() {
		fam = "-inet6"
	}
	return run("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", name)
}

// setDNS: /etc/resolver/<domain> sends only that domain to the tunnel resolver.
func setDNS(name, domain string, ns netip.Addr) error {
	if !domainRe.MatchString(domain) {
		return nil
	}
	if err := os.MkdirAll("/etc/resolver", 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("/etc/resolver", domain), []byte("# managed by zirocd\nnameserver "+ns.String()+"\n"), 0644)
}

func clearDNS(name, domain string) {
	if domainRe.MatchString(domain) {
		_ = os.Remove(filepath.Join("/etc/resolver", domain))
	}
}

// setSubnetRouter: routing a LAN into the network needs a Linux host.
func setSubnetRouter(name string, networks []netip.Prefix, on bool) error {
	if on {
		return errors.New("subnet routing is supported on Linux hosts only")
	}
	return nil
}

// defaultGateway asks the routing table for the IPv4 default route.
func defaultGateway() (netip.Addr, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "gateway:"); ok {
			return netip.ParseAddr(strings.TrimSpace(v))
		}
	}
	return netip.Addr{}, errors.New("no default route")
}

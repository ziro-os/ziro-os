package daemon

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ifaceName = "Ziro"

func DefaultStateDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "zirocd")
}

func ControlPath() string { return `\\.\pipe\zirocd` }

// secureDir creates dir readable only by SYSTEM and Administrators (ProgramData lets every user
// read by default), and resets the ACL of an existing one.
func secureDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func maskOf(bits int) string {
	var b [4]byte
	for i := 0; i < bits && i < 32; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom4(b).String()
}

func configureInterface(name string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		if a.Addr().Is4() {
			if err := run("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static",
				"address="+a.Addr().String(), "mask="+maskOf(a.Bits())); err != nil {
				return err
			}
		} else if err := run("netsh", "interface", "ipv6", "add", "address", "interface="+name, "address="+a.String(), "store=active"); err != nil {
			return err
		}
	}
	return nil
}

func addRoute(name string, p netip.Prefix) error {
	fam := "ipv4"
	if p.Addr().Is6() {
		fam = "ipv6"
	}
	_ = delRoute(name, p)
	return run("netsh", "interface", fam, "add", "route", "prefix="+p.String(), "interface="+name, "store=active", "metric="+strconv.Itoa(5))
}

func delRoute(name string, p netip.Prefix) error {
	fam := "ipv4"
	if p.Addr().Is6() {
		fam = "ipv6"
	}
	return run("netsh", "interface", fam, "delete", "route", "prefix="+p.String(), "interface="+name, "store=active")
}

// setDNS adds an NRPT rule: only <domain> goes to the tunnel resolver.
func setDNS(name, domain string, ns netip.Addr) error {
	if !domainRe.MatchString(domain) {
		return nil
	}
	clearDNS(name, domain)
	return run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Add-DnsClientNrptRule -Namespace '."+domain+"' -NameServers '"+ns.String()+"' -Comment 'zirocd'")
}

func clearDNS(name, domain string) {
	_ = run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientNrptRule | Where-Object Comment -eq 'zirocd' | Remove-DnsClientNrptRule -Force")
}

// setSubnetRouter: routing a LAN into the network needs a Linux host.
func setSubnetRouter(name string, networks []netip.Prefix, on bool) error {
	if on {
		return errors.New("subnet routing is supported on Linux hosts only")
	}
	return nil
}

// defaultGateway asks Windows for the IPv4 default route with the lowest metric.
func defaultGateway() (netip.Addr, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(string(out)))
}

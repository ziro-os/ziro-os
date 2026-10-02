package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Host facts read straight from /proc, /sys and statfs: no subprocesses, cheap enough for the
// login banner, `system top` and the metrics endpoint. One reader for each source.

var procRoot = "/proc"

// readMeminfo returns /proc/meminfo in bytes (MemTotal, MemAvailable, SwapTotal, ...).
func readMeminfo() map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v <<= 10
		}
		out[k] = v
	}
	return out
}

// readPressure returns the "some" and "full" 10-second averages of /proc/pressure/<resource>
// (memory, cpu, io), in percent. ok is false without PSI.
func readPressure(resource string) (some, full float64, ok bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, "pressure", resource))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		for _, f := range strings.Fields(rest) {
			if v, found := strings.CutPrefix(f, "avg10="); found {
				x, _ := strconv.ParseFloat(v, 64)
				if kind == "some" {
					some = x
				} else if kind == "full" {
					full = x
				}
			}
		}
	}
	return some, full, true
}

func readLoadavg() (l1, l5, l15 float64) {
	if b, err := os.ReadFile(filepath.Join(procRoot, "loadavg")); err == nil {
		fmt.Sscanf(string(b), "%f %f %f", &l1, &l5, &l15)
	}
	return
}

// diskUsage returns used and total bytes of the filesystem holding path.
func diskUsage(path string) (used, total uint64, ok bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil || st.Blocks == 0 {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)
	total = uint64(st.Blocks) * bs
	return total - uint64(st.Bavail)*bs, total, true
}

// sameFilesystem reports whether a and b are on the same mounted filesystem.
func sameFilesystem(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return true
	}
	sa, ok1 := fa.Sys().(*syscall.Stat_t)
	sb, ok2 := fb.Sys().(*syscall.Stat_t)
	return !ok1 || !ok2 || sa.Dev == sb.Dev
}

// HostAddress is an IPv4 address worth showing: the primary (default route) first, then the
// cluster mesh and pod gateway, then other NICs. Container veths and bridges are left out.
type HostAddress struct {
	IP    string `json:"ip"`
	Iface string `json:"iface"`
	Role  string `json:"role"` // primary, mesh, pods, nic
}

// ifaceRole classifies an interface; "" means not shown (container plumbing).
func ifaceRole(name, primary string) string {
	switch {
	case name == primary:
		return "primary"
	case name == meshIface:
		return "mesh"
	case name == podDNSIface:
		return "pods"
	}
	for _, p := range []string{"veth", "cni", "nerdctl", "docker", "br-", "flannel", "virbr", "lo"} {
		if strings.HasPrefix(name, p) {
			return ""
		}
	}
	return "nic"
}

// hostAddresses lists each address once, in role order.
func hostAddresses() []HostAddress {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	primary := defaultRouteIface()
	seen := map[string]bool{}
	var out []HostAddress
	for _, ifc := range ifaces {
		role := ifaceRole(ifc.Name, primary)
		if role == "" || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || seen[ipn.IP.String()] {
				continue
			}
			seen[ipn.IP.String()] = true
			out = append(out, HostAddress{IP: ipn.IP.String(), Iface: ifc.Name, Role: role})
		}
	}
	order := map[string]int{"primary": 0, "nic": 1, "mesh": 2, "pods": 3}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].Role] < order[out[j].Role] })
	return out
}

// cgroupOOMKills sums oom_kill events per service under ziro/<class>/*/memory.events.
func cgroupOOMKills() map[string]int {
	out := map[string]int{}
	for _, class := range []string{"system", "workloads"} {
		dirs, _ := filepath.Glob(filepath.Join(cgroupRoot, "ziro", class, "*", "memory.events"))
		for _, p := range dirs {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, line := range bytes.Split(b, []byte("\n")) {
				if v, ok := bytes.CutPrefix(line, []byte("oom_kill ")); ok {
					if n, _ := strconv.Atoi(string(v)); n > 0 {
						out[filepath.Base(filepath.Dir(p))] = n
					}
				}
			}
		}
	}
	return out
}

package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var motdConsole bool

var motdCmd = &cobra.Command{
	Use:   "motd",
	Short: "Print the host summary shown at login (resources, addresses, workloads, what needs attention)",
	Run: func(cmd *cobra.Command, args []string) {
		s := collectHostSummary(!motdConsole)
		if jsonOutput {
			_ = printResult(s, nil)
			return
		}
		renderMOTD(cmd.OutOrStdout(), s, os.Getenv("NO_COLOR") == "")
	},
}

// HostSummary is what an operator needs at a glance; Attention lists only what is wrong.
type HostSummary struct {
	Version     string        `json:"version"`
	Hostname    string        `json:"hostname"`
	Mode        string        `json:"mode"` // installed, live
	Platform    string        `json:"platform"`
	Arch        string        `json:"arch"`
	Kernel      string        `json:"kernel"`
	CPUs        int           `json:"cpus"`
	Load1       float64       `json:"load1"`
	MemTotal    uint64        `json:"mem_total"`
	MemUsed     uint64        `json:"mem_used"`
	Disks       []DiskUse     `json:"disks"`
	Addresses   []HostAddress `json:"addresses"`
	Containers  int           `json:"containers"`
	ClusterRole string        `json:"cluster_role,omitempty"` // master, worker
	ClusterInfo string        `json:"cluster_info,omitempty"`
	API         bool          `json:"api"`
	Attention   []string      `json:"attention,omitempty"`
}

type DiskUse struct {
	Path  string `json:"path"`
	Used  uint64 `json:"used"`
	Total uint64 `json:"total"`
}

func (d DiskUse) Percent() int { return int(d.Used * 100 / max(d.Total, 1)) }

// oneShotServices run to completion at boot; stopped is their normal state.
var oneShotServices = map[string]bool{"firewall": true, "cloud-init": true, "wireguard": true}

// collectHostSummary gathers the summary. slow allows probes that spawn processes (container
// count); the boot console skips them.
func collectHostSummary(slow bool) HostSummary {
	s := HostSummary{Version: Version, Mode: "live", Arch: hostArch(), CPUs: runtime.NumCPU(), Addresses: hostAddresses()}
	s.Hostname, _ = os.Hostname()
	if fileExists("/etc/ziro-installed") {
		s.Mode = "installed"
	}
	s.Platform, _ = detectCloudPlatform()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	s.Load1, _, _ = readLoadavg()
	mi := readMeminfo()
	s.MemTotal, s.MemUsed = mi["MemTotal"], mi["MemTotal"]-min(mi["MemAvailable"], mi["MemTotal"])
	for _, p := range []string{"/", "/var/lib/containerd"} {
		if used, total, ok := diskUsage(p); ok && (p == "/" || !sameFilesystem(p, "/")) {
			s.Disks = append(s.Disks, DiskUse{p, used, total})
		}
	}
	s.API = isAPIServerRunning()
	if slow {
		if out, err := exec.Command("nerdctl", "ps", "-q").Output(); err == nil {
			s.Containers = len(strings.Fields(string(out)))
		}
	}
	if cfg, err := loadClusterConfig(); err == nil && cfg.Role != "" {
		s.ClusterRole = cfg.Role
		if cfg.Role == "master" {
			if st, err := readState(); err == nil {
				ready := 0
				for _, n := range st.Nodes {
					if n.Status == "Ready" {
						ready++
					}
				}
				s.ClusterInfo = fmt.Sprintf("%d/%d nodes ready", ready, len(st.Nodes))
				if ready < len(st.Nodes) {
					s.Attention = append(s.Attention, fmt.Sprintf("%d cluster node(s) not ready", len(st.Nodes)-ready))
				}
			}
		}
	}
	s.Attention = append(s.Attention, hostAttention(mi, s.Disks)...)
	return s
}

// hostAttention lists conditions an operator should act on.
func hostAttention(mi map[string]uint64, disks []DiskUse) []string {
	var out []string
	if some, _, ok := readPressure("memory"); ok && some >= 10 {
		out = append(out, fmt.Sprintf("memory pressure %.0f%%", some))
	} else if mi["MemTotal"] > 0 && mi["MemAvailable"]*10 < mi["MemTotal"] {
		out = append(out, fmt.Sprintf("memory low (%s available)", humanBytes(mi["MemAvailable"])))
	}
	for _, d := range disks {
		if d.Percent() >= 85 {
			out = append(out, fmt.Sprintf("disk %s %d%% full", d.Path, d.Percent()))
		}
	}
	kills := cgroupOOMKills()
	names := make([]string, 0, len(kills))
	for n := range kills {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, fmt.Sprintf("%s killed %dx for memory", n, kills[n]))
	}
	for _, svc := range listAllServices() {
		if svc.Enabled && svc.Status != "RUNNING" && !oneShotServices[svc.Name] {
			out = append(out, "service "+svc.Name+" not running")
		}
	}
	if !loadFirewallConfig().Enabled {
		out = append(out, "firewall disabled")
	}
	if u := readUpdateCheck(); u.Available() {
		out = append(out, "ziroctl "+u.Latest+" available (ziroctl update)")
	}
	return out
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%d MiB", b>>20)
	}
	return fmt.Sprintf("%d KiB", b>>10)
}

func renderMOTD(out io.Writer, s HostSummary, color bool) {
	label, bold, warn, reset := "", "", "", ""
	if color {
		label, bold, warn, reset = "\033[2m", "\033[1m", "\033[1;33m", "\033[0m"
	}
	row := func(name, value string) { fmt.Fprintf(out, " %s%-10s%s %s\n", label, name, reset, value) }

	head := []string{bold + "Ziro OS " + s.Version + reset, s.Hostname, s.Mode}
	if s.Platform != "" {
		head = append(head, s.Platform)
	}
	fmt.Fprintf(out, "\n %s\n", strings.Join(append(head, s.Arch, "kernel "+s.Kernel), "  "))

	res := []string{fmt.Sprintf("%d vCPU", s.CPUs), fmt.Sprintf("load %.2f", s.Load1)}
	if s.MemTotal > 0 {
		res = append(res, fmt.Sprintf("memory %s/%s (%d%%)", humanBytes(s.MemUsed), humanBytes(s.MemTotal), s.MemUsed*100/s.MemTotal))
	}
	for _, d := range s.Disks {
		res = append(res, fmt.Sprintf("disk %s %d%%", d.Path, d.Percent()))
	}
	row("Resources", strings.Join(res, "  "))

	var addrs []string
	for _, a := range s.Addresses {
		switch a.Role {
		case "primary", "nic":
			addrs = append(addrs, fmt.Sprintf("%s (%s)", a.IP, a.Iface))
		default:
			addrs = append(addrs, a.Role+" "+a.IP)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"no address yet (DHCP)"}
	}
	row("Network", strings.Join(addrs, "  "))

	work := []string{fmt.Sprintf("%d containers", s.Containers)}
	if s.ClusterRole != "" {
		work = append(work, strings.TrimSpace("cluster "+s.ClusterRole+" "+s.ClusterInfo))
	}
	if s.API {
		work = append(work, "api on")
	} else {
		work = append(work, "api off")
	}
	row("Workloads", strings.Join(work, "  "))
	if len(s.Attention) > 0 {
		row("Attention", warn+strings.Join(s.Attention, "  ·  ")+reset)
	}
	fmt.Fprintln(out)
}

func init() {
	motdCmd.Flags().BoolVar(&motdConsole, "console", false, "Fast summary for the boot console (no subprocess probes)")
	rootCmd.AddCommand(motdCmd)
}

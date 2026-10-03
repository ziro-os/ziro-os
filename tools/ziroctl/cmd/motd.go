package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var motdConsole bool

var motdCmd = &cobra.Command{
	Use:   "motd",
	Short: "Show the host summary printed at login",
	Long: `Show the summary printed at every login and on the boot console: version, resources,
addresses, workloads, and anything that needs attention with the command that fixes it.`,
	Example: `  ziroctl motd
  ziroctl motd --json | jq .attention`,
	Run: func(cmd *cobra.Command, args []string) {
		s := collectHostSummary()
		if jsonOutput {
			_ = printResult(s, nil)
			return
		}
		renderMOTD(cmd.OutOrStdout(), s, detectStyle(os.Stdout))
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
	Uptime      uint64        `json:"uptime_seconds"`
	Load5       float64       `json:"load5"`
	Load15      float64       `json:"load15"`
	Attention   []Attention   `json:"attention,omitempty"`
}

// Attention is one thing that needs the operator, with the command that deals with it.
type Attention struct {
	Text string `json:"text"`
	Fix  string `json:"fix,omitempty"`
}

type DiskUse struct {
	Path  string `json:"path"`
	Used  uint64 `json:"used"`
	Total uint64 `json:"total"`
}

func (d DiskUse) Percent() int { return int(d.Used * 100 / max(d.Total, 1)) }

// collectHostSummary gathers the summary from /proc, /sys and local state only (no
// subprocesses), so it is cheap enough for every login and the boot console.
func collectHostSummary() HostSummary {
	s := HostSummary{Version: Version, Mode: "live", Arch: hostArch(), CPUs: runtime.NumCPU(), Addresses: hostAddresses()}
	s.Hostname, _ = os.Hostname()
	if fileExists("/etc/ziro-installed") {
		s.Mode = "installed"
	}
	s.Platform, _ = detectCloudPlatform()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(procRoot, "uptime")); err == nil {
		var up float64
		fmt.Sscanf(string(b), "%f", &up)
		s.Uptime = uint64(up)
	}
	s.Load1, s.Load5, s.Load15 = readLoadavg()
	mi := readMeminfo()
	s.MemTotal, s.MemUsed = mi["MemTotal"], mi["MemTotal"]-min(mi["MemAvailable"], mi["MemTotal"])
	for _, p := range []string{"/", "/var/lib/containerd"} {
		if used, total, ok := diskUsage(p); ok && (p == "/" || !sameFilesystem(p, "/")) {
			s.Disks = append(s.Disks, DiskUse{p, used, total})
		}
	}
	s.API = isAPIServerRunning()
	s.Containers = len(containerCgroups()) // a running container is a cgroup; no nerdctl spawn
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
					s.Attention = append(s.Attention, Attention{fmt.Sprintf("%d cluster node(s) not ready", len(st.Nodes)-ready), "ziroctl cluster nodes"})
				}
			}
		}
	}
	s.Attention = append(s.Attention, hostAttention(mi, s.Disks)...)
	return s
}

// hostAttention lists conditions an operator should act on.
func hostAttention(mi map[string]uint64, disks []DiskUse) []Attention {
	var out []Attention
	if some, _, ok := readPressure("memory"); ok && some >= 10 {
		out = append(out, Attention{fmt.Sprintf("memory pressure %.0f%%", some), "ziroctl system top"})
	} else if mi["MemTotal"] > 0 && mi["MemAvailable"]*10 < mi["MemTotal"] {
		out = append(out, Attention{fmt.Sprintf("memory low (%s available)", humanBytes(mi["MemAvailable"])), "ziroctl system top"})
	}
	for _, d := range disks {
		if d.Percent() >= 85 {
			out = append(out, Attention{fmt.Sprintf("disk %s %d%% full", d.Path, d.Percent()), "ziroctl system df"})
		}
	}
	kills := cgroupOOMKills()
	names := make([]string, 0, len(kills))
	for n := range kills {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, Attention{fmt.Sprintf("%s killed %dx for memory", n, kills[n]), "ziroctl service status " + n})
	}
	for _, svc := range listAllServices() {
		if svc.Enabled && svc.Status != "RUNNING" && !oneShotServices[svc.Name] {
			out = append(out, Attention{"service " + svc.Name + " not running", "ziroctl doctor --fix"})
		}
	}
	if !loadFirewallConfig().Enabled {
		out = append(out, Attention{"firewall disabled", "ziroctl firewall enable"})
	}
	if u := readUpdateCheck(); u.Available() {
		out = append(out, Attention{"ziroctl " + u.Latest + " available", "ziroctl update"})
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

// The wordmark, in half blocks: "Ziro" (brand blue) and "OS" (cyan), two rows tall.
var motdLogo = [2][2]string{{"▀▀█ █ █▀█ █▀█", "█▀█ █▀▀"}, {"█▄▄ █ █▀▄ █▄█", "█▄█ ▄▄█"}}

func renderMOTD(out io.Writer, s HostSummary, st termStyle) {
	var head []string
	for _, h := range []string{s.Hostname, s.Platform, s.Arch, s.Kernel} {
		if h != "" {
			head = append(head, h)
		}
	}
	if s.Uptime > 0 {
		head = append(head, "up "+humanDuration(s.Uptime))
	}
	version := st.bold(s.Version)
	if s.Mode == "live" {
		version += "  " + st.warn("LIVE")
	}
	if st.unicode {
		fmt.Fprintf(out, "\n  %s  %s   %s\n", st.blue(motdLogo[0][0]), st.cyan(motdLogo[0][1]), version)
		fmt.Fprintf(out, "  %s  %s   %s\n\n", st.blue(motdLogo[1][0]), st.cyan(motdLogo[1][1]), st.dim(strings.Join(head, " · ")))
	} else {
		fmt.Fprintf(out, "\n  %s %s %s\n  %s\n\n", st.blue("Ziro"), st.cyan("OS"), version, strings.Join(head, " - "))
	}
	row := func(name, value string) { fmt.Fprintf(out, "  %s %s\n", st.dim(fmt.Sprintf("%-9s", name)), value) }
	sep := st.sep()

	row("CPU", fmt.Sprintf("%d vCPU  load %.2f %.2f %.2f", s.CPUs, s.Load1, s.Load5, s.Load15))
	if s.MemTotal > 0 {
		pct := float64(s.MemUsed) * 100 / float64(s.MemTotal)
		row("Memory", fmt.Sprintf("%s  %-20s %3.0f%%", st.meter(pct, 14), humanBytes(s.MemUsed)+" / "+humanBytes(s.MemTotal), pct))
	}
	for _, d := range s.Disks {
		row("Disk "+d.Path, fmt.Sprintf("%s  %-20s %3d%%", st.meter(float64(d.Percent()), 14), humanBytes(d.Used)+" / "+humanBytes(d.Total), d.Percent()))
	}

	var addrs []string
	for _, a := range s.Addresses {
		switch a.Role {
		case "primary", "nic":
			addrs = append(addrs, a.IP+" "+st.dim(a.Iface))
		default:
			addrs = append(addrs, st.dim(a.Role)+" "+a.IP)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"no address yet (DHCP)"}
	}
	row("Network", strings.Join(addrs, sep))

	work := []string{fmt.Sprintf("%d containers", s.Containers)}
	if s.ClusterRole != "" {
		work = append(work, strings.TrimSpace("cluster "+s.ClusterRole+" "+s.ClusterInfo))
	}
	work = append(work, map[bool]string{true: "api on", false: "api off"}[s.API])
	row("Workload", strings.Join(work, sep))

	att := s.Attention
	if s.Mode == "live" {
		att = append([]Attention{{"running from live media: changes are lost at reboot", "ziroctl install"}}, att...)
	}
	if len(att) > 0 {
		w := 0
		for _, a := range att {
			w = max(w, len(a.Text))
		}
		fmt.Fprintln(out)
		for _, a := range att {
			fmt.Fprintf(out, "  %s %-*s  %s\n", st.warn("!"), w, a.Text, st.dim(a.Fix))
		}
	}
	fmt.Fprintln(out)
}

// humanDuration renders seconds as "3d 4h", "4h 12m" or "12m".
func humanDuration(sec uint64) string {
	d, h, m := sec/86400, sec/3600%24, sec/60%60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func init() {
	motdCmd.Flags().BoolVar(&motdConsole, "console", false, "")
	_ = motdCmd.Flags().MarkHidden("console") // passed by ziro-init; the summary no longer spawns anything
	rootCmd.AddCommand(motdCmd)
}

// termStyle is what the terminal can show: color depth (0 none, 16, 256, 24-bit) and whether
// block glyphs render. Shared by the login summary and `system top`.
type termStyle struct {
	depth   int
	unicode bool
}

// detectStyle picks the richest style f's terminal supports: no color when NO_COLOR is set,
// TERM is dumb or f is not a terminal; ASCII on serial-style terminals or non-UTF-8 locales.
func detectStyle(f *os.File) termStyle {
	t := os.Getenv("TERM")
	st := termStyle{unicode: true}
	switch t {
	case "", "dumb", "vt100", "vt102", "vt220":
		st.unicode = false
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			st.unicode = strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
			break
		}
	}
	if os.Getenv("NO_COLOR") != "" || t == "dumb" || !term.IsTerminal(int(f.Fd())) {
		return st
	}
	switch ct := os.Getenv("COLORTERM"); {
	case ct == "truecolor" || ct == "24bit":
		st.depth = 24
	case strings.Contains(t, "256color"):
		st.depth = 256
	default:
		st.depth = 16
	}
	return st
}

func (st termStyle) paint(s, c16, c256, c24 string) string {
	switch {
	case st.depth == 0 || s == "":
		return s
	case st.depth == 24:
		return "\033[" + c24 + "m" + s + "\033[0m"
	case st.depth == 256:
		return "\033[" + c256 + "m" + s + "\033[0m"
	}
	return "\033[" + c16 + "m" + s + "\033[0m"
}

// Brand colors: blue #4F6BFF, cyan #22D3EE.
func (st termStyle) blue(s string) string {
	return st.paint(s, "1;94", "1;38;5;69", "1;38;2;79;107;255")
}
func (st termStyle) cyan(s string) string {
	return st.paint(s, "1;96", "1;38;5;45", "1;38;2;34;211;238")
}
func (st termStyle) bold(s string) string { return st.paint(s, "1", "1", "1") }
func (st termStyle) dim(s string) string  { return st.paint(s, "2", "38;5;246", "38;2;148;163;184") }
func (st termStyle) warn(s string) string {
	return st.paint(s, "1;33", "1;38;5;220", "1;38;2;250;204;21")
}

// level colors a value by how full it is: green, yellow from 70%, red from 90%.
func (st termStyle) level(s string, pct float64) string {
	switch {
	case pct >= 90:
		return st.paint(s, "31", "38;5;203", "38;2;248;113;113")
	case pct >= 70:
		return st.paint(s, "33", "38;5;220", "38;2;250;204;21")
	}
	return st.paint(s, "32", "38;5;78", "38;2;52;211;153")
}

// meter is a usage bar of width cells, colored by level.
func (st termStyle) meter(pct float64, width int) string {
	n := max(0, min(int(pct/100*float64(width)+0.5), width))
	full, empty := "█", "░"
	if !st.unicode {
		full, empty = "#", "-"
	}
	return st.level(strings.Repeat(full, n), pct) + st.dim(strings.Repeat(empty, width-n))
}

func (st termStyle) sep() string {
	if st.unicode {
		return st.dim(" · ")
	}
	return "  "
}

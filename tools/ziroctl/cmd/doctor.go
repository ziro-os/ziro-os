package cmd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// doctorCheck is one diagnostic result. Critical checks gate `ziroctl upgrade`. A check that
// can repair itself carries fix, run by `doctor --fix`.
type doctorCheck struct {
	Name     string       `json:"name"`
	Passed   bool         `json:"passed"`
	Details  string       `json:"details"`
	Critical bool         `json:"critical"`
	Fix      string       `json:"fix,omitempty"`   // what --fix does, or the command to run
	Fixed    bool         `json:"fixed,omitempty"` // failed, then passed after --fix
	fix      func() error // nil: advice only
}

var (
	doctorFix    bool
	doctorSettle = 2 * time.Second
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the host for problems",
	Long: `Check the host: kernel and storage, containerd, networking, every enabled service, the
cluster connection and disk space. --fix repairs what it safely can (starts services that
are down, restarts the cluster agent, prunes logs and temp files) and checks again.`,
	Example: `  ziroctl doctor
  ziroctl doctor --fix
  ziroctl doctor --json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		checks := append(runDoctor(), hostChecks()...)
		if doctorFix {
			checks = applyDoctorFixes(checks, func() []doctorCheck { return append(runDoctor(), hostChecks()...) })
		}
		if err := printResult(checks, func() { printDoctor(checks) }); err != nil {
			return err
		}
		// Non-zero exit when a critical check fails, so automation can gate on it.
		for _, c := range checks {
			if c.Critical && !c.Passed {
				return fmt.Errorf("critical check failed: %s", c.Name)
			}
		}
		return nil
	},
}

// applyDoctorFixes runs the fix of every failed check, then checks again and marks what the
// fixes repaired.
func applyDoctorFixes(checks []doctorCheck, recheck func() []doctorCheck) []doctorCheck {
	failed := map[string]bool{}
	ran := false
	for _, c := range checks {
		if !c.Passed && c.fix != nil {
			failed[c.Name] = true
			if err := c.fix(); err != nil {
				fmt.Fprintf(os.Stderr, "fix %s: %v\n", c.Name, err)
			}
			ran = true
		}
	}
	if !ran {
		return checks
	}
	time.Sleep(doctorSettle) // let restarted daemons settle
	after := recheck()
	seen := map[string]bool{}
	for i := range after {
		seen[after[i].Name] = true
		after[i].Fixed = after[i].Passed && failed[after[i].Name]
	}
	// A repaired row can fold into a summary ("Services: all running"): still say what was fixed.
	for _, c := range checks {
		if failed[c.Name] && !seen[c.Name] {
			after = append(after, doctorCheck{Name: c.Name, Passed: true, Fixed: true, Details: c.Fix})
		}
	}
	return after
}

// hostChecks are the reliability checks: services (sshd and containerd included), the cluster
// link, disk space, the firewall.
func hostChecks() []doctorCheck {
	var out []doctorCheck
	down := 0
	svcs := listAllServices()
	for _, svc := range svcs {
		if !svc.Enabled || svc.Status == "RUNNING" || oneShotServices[svc.Name] {
			continue
		}
		down++
		name := svc.Name
		out = append(out, doctorCheck{Name: "Service " + name, Details: "not running; " + lastLogLine(svc.LogFile),
			Fix: "start " + name, fix: func() error { return restartDown(name) }})
	}
	if down == 0 {
		out = append(out, doctorCheck{Name: "Services", Passed: true, Details: fmt.Sprintf("%d enabled, all running", countEnabled(svcs))})
	}

	if cfg, err := loadClusterConfig(); err == nil && cfg.Role != "" {
		switch cfg.Role {
		case "worker":
			c := doctorCheck{Name: "Cluster master reachable", Details: cfg.MasterAddr, Fix: "restart cluster-agent",
				fix: func() error { return restartService("cluster-agent") }}
			if conn, err := net.DialTimeout("tcp", cfg.MasterAddr, 3*time.Second); err == nil {
				conn.Close()
				c.Passed = true
			} else {
				c.Details = err.Error()
			}
			out = append(out, c)
		case "master":
			if st, err := readState(); err == nil {
				out = append(out, clusterDoctorChecks(cfg, st, time.Now())...)
			}
		}
		if c, ok := agentDoctorCheck(time.Now()); ok {
			out = append(out, c)
		}
	}

	for _, p := range []string{"/", "/var"} {
		if used, total, ok := diskUsage(p); ok && (p == "/" || !sameFilesystem(p, "/")) {
			pct := int(used * 100 / max(total, 1))
			out = append(out, doctorCheck{Name: "Disk " + p, Passed: pct < 85, Details: fmt.Sprintf("%d%% used", pct),
				Fix: "prune logs, temp files and caches", fix: func() error {
					_, errs := applyPrune(planPrune(map[string]bool{"logs": true, "tmp": true, "cache": true}, time.Now()))
					return errors.Join(errs...)
				}})
		}
	}

	if c, ok := dnsDoctorCheck(time.Now()); ok {
		out = append(out, c)
	}
	if c, ok := dnsCertDoctorCheck(time.Now()); ok {
		out = append(out, c)
	}

	fw := loadFirewallConfig().Enabled
	out = append(out, doctorCheck{Name: "Firewall", Passed: fw, Details: map[bool]string{true: "enabled", false: "disabled"}[fw],
		Fix: "ziroctl firewall enable"})
	return out
}

func countEnabled(svcs []ServiceStatusInfo) int {
	n := 0
	for _, s := range svcs {
		if s.Enabled && !oneShotServices[s.Name] {
			n++
		}
	}
	return n
}

// lastLogLine is the last non-empty line of a service log, for a hint on why it is down.
func lastLogLine(path string) string {
	b := readTail(path, 4<<10)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if l := strings.TrimSpace(lines[len(lines)-1]); l != "" {
		return "log: " + l
	}
	return "see " + path
}

func readTail(path string, n int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > n {
		_, _ = f.Seek(-n, io.SeekEnd)
	}
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return b
}

func runDoctor() []doctorCheck {
	var checks []doctorCheck
	check := func(name string, passed bool, details string, critical bool) {
		checks = append(checks, doctorCheck{Name: name, Passed: passed, Details: details, Critical: critical})
	}

	// 1. Kernel & Architecture
	check("Linux", runtime.GOOS == "linux", runtime.GOARCH, true)

	// 2. Storage Drivers
	drivers := []string{"virtio_blk", "sd_mod", "nvme", "ahci"}
	loadedDrivers := []string{}
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		content := string(data)
		for _, drv := range drivers {
			if strings.Contains(content, drv) {
				loadedDrivers = append(loadedDrivers, drv)
			}
		}
	}
	if len(loadedDrivers) > 0 {
		check("Storage drivers", true, strings.Join(loadedDrivers, ", "), false)
	} else if _, err := os.Stat("/sys/block"); err == nil {
		// Built into the kernel
		check("Storage drivers", true, "built into the kernel", false)
	} else {
		check("Storage drivers", false, "none detected", false)
	}

	// 3. Storage Disks
	disks, _ := os.ReadDir("/sys/block")
	diskCount := 0
	for _, d := range disks {
		name := d.Name()
		if !strings.HasPrefix(name, "loop") && !strings.HasPrefix(name, "ram") && !strings.HasPrefix(name, "sr") {
			diskCount++
		}
	}
	check("Disks", diskCount > 0, fmt.Sprintf("%d disk(s) found", diskCount), false)

	// 4. cgroups v2
	_, cgErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	check("cgroup v2", cgErr == nil, "/sys/fs/cgroup", false)

	// 5. containerd answers on its socket
	c := doctorCheck{Name: "containerd responds", Fix: "start containerd", fix: func() error { return restartDown("containerd") }}
	if err := containerdResponds(); err == nil {
		c.Passed, c.Details = true, containerdSocket
	} else {
		c.Details = err.Error()
	}
	checks = append(checks, c)

	// 6. OCI runc binary
	_, runcErr1 := exec.LookPath("runc")
	_, runcErr2 := os.Stat("/usr/bin/runc")
	check("runc", runcErr1 == nil || runcErr2 == nil, "/usr/bin/runc", false)

	// 7. CNI Plugins
	cniPlugins, _ := os.ReadDir("/opt/cni/bin")
	check("CNI plugins", len(cniPlugins) > 0, fmt.Sprintf("%d plugins in /opt/cni/bin", len(cniPlugins)), false)

	// 8. Network Interfaces
	ifaces, _ := net.Interfaces()
	upCount := 0
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Name != "lo" {
			upCount++
		}
	}
	check("Network interface up", upCount > 0, fmt.Sprintf("%d active interface(s)", upCount), false)

	// 9. Outbound reachability (needed to fetch upgrades)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://1.1.1.1")
	if resp != nil {
		resp.Body.Close()
	}
	check("Internet reachable", err == nil, "https://1.1.1.1", true)

	return checks
}

const containerdSocket = "/run/containerd/containerd.sock"

// containerdResponds dials containerd's socket (the node agent's health probe too).
func containerdResponds() error {
	conn, err := net.DialTimeout("unix", containerdSocket, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func printDoctor(checks []doctorCheck) {
	st := detectStyle(os.Stdout)
	w := 0
	for _, c := range checks {
		w = max(w, len(c.Name))
	}
	failing := 0
	for _, c := range checks {
		status := st.level("ok  ", 0)
		switch {
		case c.Fixed:
			status = st.cyan("fixed")
		case !c.Passed && c.Critical:
			status = st.level("fail", 100)
			failing++
		case !c.Passed:
			status = st.warn("warn")
			failing++
		}
		hint := ""
		if !c.Passed && c.Fix != "" {
			hint = st.dim("  → " + c.Fix)
		}
		fmt.Printf("  %-5s %-*s  %s%s\n", status, w, c.Name, c.Details, hint)
	}
	if failing > 0 && !doctorFix {
		fmt.Printf("\n  %d to look at. %s repairs services, the cluster agent and disk space.\n", failing, st.bold("ziroctl doctor --fix"))
	}
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Repair what can be repaired safely, then check again")
	rootCmd.AddCommand(doctorCmd)
}

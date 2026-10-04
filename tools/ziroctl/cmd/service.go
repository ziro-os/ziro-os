package cmd

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type ServiceStatusInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"` // RUNNING, STOPPED, FAILED
	PID         int    `json:"pid"`
	Enabled     bool   `json:"enabled"`
	Uptime      string `json:"uptime"`
	LogFile     string `json:"logfile"`
}

var servicesDir = "/etc/ziro/services"

const (
	enabledDir = "/etc/ziro/services/enabled"
	logsDir    = "/var/log"
	runDir     = "/run"
)

var defaultServices = []ServiceDef{
	{
		Name:        "containerd",
		Description: "Containerd OCI Runtime Daemon",
		Exec:        "/usr/bin/containerd",
		Args:        "--config /etc/containerd/config.toml",
		PIDFile:     "/run/containerd/containerd.pid",
		LogFile:     "/var/log/containerd.log",
		Autostart:   true,
	},
	{
		Name:        "sshd",
		Description: "OpenSSH Secure Shell Daemon",
		Exec:        "/usr/sbin/sshd",
		Args:        "-D -e",
		PIDFile:     "/run/sshd.pid",
		LogFile:     "/var/log/sshd.log",
		Check:       "-t",
		Autostart:   true,
	},
	{
		Name:        "crond",
		Description: "Periodic Cronjob Scheduler Daemon",
		Exec:        "/usr/sbin/crond",
		Args:        "-f -d 5 -c /etc/crontabs", // -d: log to stderr (no syslogd); crontabs live in /etc
		PIDFile:     "/run/crond.pid",
		LogFile:     "/var/log/crond.log",
		Autostart:   true,
	},
	{
		Name:        "firewall",
		Description: "Ziro-OS nftables Cloud Firewall",
		Exec:        "/usr/bin/ziroctl",
		Args:        "firewall apply",
		PIDFile:     "/run/ziro-firewall.pid",
		LogFile:     "/var/log/firewall.log",
		Autostart:   true,
	},
	{
		Name:        "wireguard",
		Description: "WireGuard Cloud Mesh VPN Service",
		Exec:        "/usr/bin/ziroctl",
		Args:        "wireguard up",
		PIDFile:     "/run/ziro-wireguard.pid",
		LogFile:     "/var/log/wireguard.log",
		Autostart:   false,
	},
	{
		Name:        "sentinel",
		Description: "Ziro Sentinel Security & Threat Protection",
		Exec:        "/usr/bin/ziroctl",
		Args:        "security monitor",
		PIDFile:     "/run/ziro-sentinel.pid",
		LogFile:     "/var/log/sentinel.log",
		Autostart:   true,
	},
	{
		Name:        "cloud-init",
		Description: "Cloud metadata SSH keys & user-data bootstrap (once per instance)",
		Exec:        "/usr/bin/ziroctl",
		Args:        "cloud userdata --wait 60",
		PIDFile:     "/run/ziro-cloud-init.pid",
		LogFile:     "/var/log/cloud-init.log",
		Autostart:   true,
	},
	{
		Name:        "cluster-master",
		Description: "Ziro cluster control plane (join, heartbeat, scheduling)",
		Exec:        "/usr/bin/ziroctl",
		Args:        "cluster serve",
		PIDFile:     "/run/ziro-cluster-master.pid",
		LogFile:     "/var/log/cluster-master.log",
		Autostart:   false,
	},
	{
		Name:        "cluster-agent",
		Description: "Ziro cluster node agent (heartbeat & container reconcile)",
		Exec:        "/usr/bin/ziroctl",
		Args:        "cluster agent",
		PIDFile:     "/run/ziro-cluster-agent.pid",
		LogFile:     "/var/log/cluster-agent.log",
		Autostart:   false,
	},
	{
		Name:        "gateway",
		Description: "zirogate cluster ingress (TLS, routing, rate limits)",
		Exec:        "/usr/bin/ziroctl",
		Args:        "gateway serve",
		PIDFile:     "/run/ziro-gateway.pid",
		LogFile:     "/var/log/gateway.log",
		Autostart:   false,
	},
	{
		Name:        "router-relay",
		Description: "Ziro router relay (TLS packet relay + STUN for zirocd devices)",
		Exec:        "/usr/bin/ziroctl",
		Args:        "router relay serve",
		PIDFile:     "/run/ziro-router-relay.pid",
		LogFile:     "/var/log/router-relay.log",
		Autostart:   false,
	},
	{
		Name:        "zirocd",
		Description: "Ziro router client (joins this host to router networks)",
		Exec:        "/usr/bin/zirocd",
		Args:        "daemon",
		PIDFile:     "/run/zirocd.pid",
		LogFile:     "/var/log/zirocd.log",
		Autostart:   false,
	},
	{
		Name:        "ziro-api",
		Description: "Ziro Control Plane REST API Server",
		Exec:        "/usr/bin/ziroctl",
		Args:        "api start",
		PIDFile:     "/run/ziro-api.pid",
		LogFile:     "/var/log/ziro-api.log",
		Autostart:   false,
	},
}

var serviceCmd = &cobra.Command{
	Use:     "service",
	Aliases: []string{"systemctl", "svc"},
	Short:   "Manage system services",
	Example: `  ziroctl service list
  ziroctl service restart sshd
  ziroctl service logs containerd`,
}

var serviceListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List services and their state",
	Example: `  ziroctl service list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		services := listAllServices()
		if jsonOutput {
			return printResult(services, nil)
		}
		fmt.Printf("%-16s %-10s %-8s %-10s %s\n", "SERVICE", "STATUS", "PID", "ENABLED", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 75))
		for _, s := range services {
			pidStr := "-"
			if s.PID > 0 {
				pidStr = fmt.Sprintf("%d", s.PID)
			}
			enStr := "no"
			if s.Enabled {
				enStr = "yes"
			}
			fmt.Printf("%-16s %-10s %-8s %-10s %s\n", s.Name, s.Status, pidStr, enStr, s.Description)
		}
		return nil
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:     "status <service>",
	Short:   "Show a service's state and recent log",
	Example: `  ziroctl service status containerd`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		s, err := getServiceStatus(name)
		if err != nil {
			return fmt.Errorf("service '%s' not found", name)
		}
		if jsonOutput {
			return printResult(s, nil)
		}
		fmt.Printf("● %s - %s\n", s.Name, s.Description)
		fmt.Printf("   Loaded:  %s (/etc/ziro/services/%s.conf; enabled: %v)\n", s.Name, s.Name, s.Enabled)
		fmt.Printf("   Active:  %s", s.Status)
		if s.PID > 0 {
			fmt.Printf(" (PID: %d, Uptime: %s)", s.PID, s.Uptime)
		}
		fmt.Println()
		if s.LogFile != "" {
			fmt.Printf("   Log:     %s\n", s.LogFile)
			printRecentLogs(s.LogFile, 5)
		}
		return nil
	},
}

var serviceStartCmd = &cobra.Command{
	Use:     "start <service>",
	Short:   "Start a service",
	Example: `  ziroctl service start ziro-api`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := startService(name); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
		fmt.Printf("Started service: %s\n", name)
		return nil
	},
}

var serviceStopCmd = &cobra.Command{
	Use:     "stop <service>",
	Short:   "Stop a service",
	Example: `  ziroctl service stop ziro-api`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := stopService(name); err != nil {
			return fmt.Errorf("stop %s: %w", name, err)
		}
		fmt.Printf("Stopped service: %s\n", name)
		return nil
	},
}

var serviceRestartCmd = &cobra.Command{
	Use:     "restart <service>",
	Short:   "Restart a service",
	Example: `  ziroctl service restart sshd`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := restartService(name); err != nil {
			return fmt.Errorf("restart %s: %w", name, err)
		}
		fmt.Printf("Restarted service: %s\n", name)
		return nil
	},
}

var serviceEnableCmd = &cobra.Command{
	Use:     "enable <service>",
	Short:   "Start a service at boot",
	Example: `  ziroctl service enable ziro-api`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := enableService(name); err != nil {
			return fmt.Errorf("enable %s: %w", name, err)
		}
		fmt.Printf("Enabled service '%s' for boot autostart.\n", name)
		return nil
	},
}

var serviceDisableCmd = &cobra.Command{
	Use:     "disable <service>",
	Short:   "Stop a service from starting at boot",
	Example: `  ziroctl service disable ziro-api`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := disableService(name); err != nil {
			return fmt.Errorf("disable %s: %w", name, err)
		}
		fmt.Printf("Disabled service '%s' from boot autostart.\n", name)
		return nil
	},
}

var serviceLogsCmd = &cobra.Command{
	Use:     "logs <service>",
	Short:   "Show a service's recent log",
	Example: `  ziroctl service logs sshd`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		s, err := getServiceStatus(name)
		if err != nil {
			return fmt.Errorf("service '%s' not found", name)
		}
		if s.LogFile == "" || !fileExists(s.LogFile) {
			fmt.Printf("No log file found for service %s.\n", name)
			return nil
		}
		printRecentLogs(s.LogFile, 50)
		return nil
	},
}

// initManaged daemons are supervised (and restarted) by ziro-init itself. To stop one, ziroctl
// drops a marker in stopMarkerDir, which makes init hold the restart until it is removed.
var initManaged = map[string]bool{"containerd": true, "sshd": true}

var stopMarkerDir = "/run/ziro/stopped"

var serviceBootCmd = &cobra.Command{
	Use:    "boot",
	Short:  "Start all enabled services (invoked by ziro-init at boot)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Housekeeping that touches the network or disks (an apk reinstall, an NFS mount) runs beside
		// the service starts and is bounded: a stalled mirror or share must never keep a worker's
		// agent and sentinel from starting. Services that need what it repairs fail their first start;
		// the pass below and ziro-init's heal tick (service heal) bring them up.
		housekeeping := make(chan struct{})
		go func() {
			defer close(housekeeping)
			_ = expandAll(false, true) // a disk resized while the host was off
			reconcileModules()         // packages vanish after an OS upgrade; /run is empty every boot
			nfsBoot()                  // standalone NFS mounts (the network is up)
		}()
		// In parallel: init waits for this, and each start watches its daemon for up to 1s.
		var wg sync.WaitGroup
		for _, s := range listAllServices() {
			if !s.Enabled || initManaged[s.Name] || s.Status == "RUNNING" {
				continue
			}
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				// deepcode ignore CommandInjection: names come from root-owned definitions in /etc/ziro/services; startService re-validates the definition and its executable
				if err := startService(name); err != nil {
					fmt.Printf("[boot] %s: %v\n", name, err)
					return
				}
				fmt.Printf("[boot] started %s\n", name)
			}(s.Name)
		}
		wg.Wait()
		select {
		case <-housekeeping:
		case <-time.After(bootHousekeepingWait):
			fmt.Printf("[boot] housekeeping still running after %s; continuing\n", bootHousekeepingWait)
		}
		printHeal(healServices(true)) // whatever housekeeping repaired or the first pass missed
		moduleBootHooks()
		return nil
	},
}

// bootHousekeepingWait bounds how long boot waits for package/mount repairs before moving on.
const bootHousekeepingWait = 60 * time.Second

func printHeal(fixes []ServiceFix) {
	for _, f := range fixes {
		if f.Error != "" {
			fmt.Printf("[heal] %s: %s\n", f.Name, f.Error)
		} else {
			fmt.Printf("[heal] started %s\n", f.Name)
		}
	}
}

// serviceHealCmd is ziro-init's retry tick: it starts every enabled daemon that is down, so a
// start that failed before any process existed (init never sees an exit) is retried, and a dead
// sentinel (the other healer) comes back.
var serviceHealCmd = &cobra.Command{
	Use:    "heal",
	Short:  "Start enabled services that are down (invoked by ziro-init)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		printHeal(healServices(true))
		return nil
	},
}

const maxLogSize = 10 << 20

// rotateLog keeps one previous generation once a log exceeds maxLogSize.
// Copy+truncate (not rename) so daemons holding the file with O_APPEND keep working.
// logGenerations is how many compressed rotations are kept (path.1.gz newest).
const logGenerations = 3

// rotateLog compresses a log over maxLogSize into path.1.gz, shifting older generations, then
// truncates it in place (daemons keep their open descriptor, O_APPEND writes continue at 0).
func rotateLog(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < maxLogSize {
		return
	}
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()
	tmp := path + ".1.gz.tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	zw := gzip.NewWriter(dst)
	_, err = io.Copy(zw, src)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return
	}
	for i := logGenerations - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d.gz", path, i), fmt.Sprintf("%s.%d.gz", path, i+1))
	}
	_ = os.Remove(path + ".1") // the old uncompressed generation
	if os.Rename(tmp, path+".1.gz") == nil {
		_ = os.Truncate(path, 0)
	}
}

var serviceRotateLogsCmd = &cobra.Command{
	Use:    "rotate-logs",
	Short:  "Rotate /var/log/*.log files larger than 10MB, keeping 3 compressed generations (run hourly by crond)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		logs, _ := filepath.Glob(filepath.Join(logsDir, "*.log"))
		for _, l := range logs {
			rotateLog(l)
		}
		return nil
	},
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// rootOwnedFile: a regular file owned by root and not writable by group or others.
func rootOwnedFile(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().IsRegular() && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

// trustedExecutable: an absolute, clean path to a root-owned executable nobody else can write.
func trustedExecutable(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("service exec %q must be an absolute path", p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !rootOwnedFile(fi) || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("service exec %s must be an executable owned by root, not group- or world-writable", p)
	}
	return nil
}

func loadServiceDef(name string) (*ServiceDef, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	// First check /etc/ziro/services/<name>.conf, opened through os.Root: the name can only
	// select a file inside servicesDir, never follow ".." or a symlink out of it.
	confPath := filepath.Join(servicesDir, name+".conf")
	if root, err := os.OpenRoot(servicesDir); err == nil {
		defer root.Close()
		def := &ServiceDef{Name: name}
		f, err := root.Open(name + ".conf")
		if err == nil {
			defer f.Close()
			// A service definition decides what runs as root: trust only root-owned files that
			// nobody else can write.
			if fi, err := f.Stat(); err != nil || !rootOwnedFile(fi) {
				return nil, fmt.Errorf("service definition %s must be a regular file owned by root, not group- or world-writable", confPath)
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					switch k {
					case "description":
						def.Description = v
					case "exec":
						def.Exec = v
					case "args":
						def.Args = v
					case "pidfile":
						def.PIDFile = v
					case "logfile":
						def.LogFile = v
					case "check":
						def.Check = v
					case "user":
						def.User = v
					case "env_file":
						def.EnvFile = v
					case "memory", "cpus", "pids":
						if def.Resources == nil {
							def.Resources = &Resources{}
						}
						switch k {
						case "memory":
							def.Resources.Memory = v
						case "cpus": // unparseable -> -1, rejected by Validate below
							if def.Resources.CPUs, err = strconv.ParseFloat(v, 64); err != nil {
								def.Resources.CPUs = -1
							}
						case "pids":
							if def.Resources.PIDs, err = strconv.Atoi(v); err != nil {
								def.Resources.PIDs = -1
							}
						}
					case "restart":
						def.Restart = v
					case "autostart":
						def.Autostart = (v == "true" || v == "1" || v == "yes")
					}
				}
			}
			if err := checkServicePaths(def); err != nil {
				return nil, fmt.Errorf("%s: %w", confPath, err)
			}
			if err := def.Resources.Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", confPath, err)
			}
			return def, nil
		}
	}

	// Fallback to built-in default services
	for _, s := range defaultServices {
		if s.Name == name {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("unknown service: %s", name)
}

func listAllServices() []ServiceStatusInfo {
	seen := make(map[string]bool)
	var list []ServiceStatusInfo

	// Check files in servicesDir
	if entries, err := os.ReadDir(servicesDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				name := strings.TrimSuffix(e.Name(), ".conf")
				seen[name] = true
				if st, err := getServiceStatus(name); err == nil {
					list = append(list, *st)
				}
			}
		}
	}

	// Add built-ins not already loaded
	for _, s := range defaultServices {
		if !seen[s.Name] {
			if st, err := getServiceStatus(s.Name); err == nil {
				list = append(list, *st)
			}
		}
	}

	return list
}

// getServicePID returns the PID only if that process really is this service
// (argv matches exec+args). Several services share /usr/bin/ziroctl, and pidfiles
// go stale, so a bare name or pidfile match could signal an unrelated process.
func getServicePID(def *ServiceDef) int {
	if def.PIDFile != "" {
		if data, err := os.ReadFile(def.PIDFile); err == nil {
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 && (pidMatches(def, pid) || retitled(def, pid)) {
				return pid
			}
		}
	}

	// Fallback for daemons started without a pidfile (e.g. containerd/sshd by init)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err == nil && pid > 1 && pidMatches(def, pid) {
			return pid
		}
	}
	return 0
}

func pidMatches(def *ServiceDef, pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return false
	}
	argv := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	want := strings.Fields(def.Args)
	if filepath.Base(argv[0]) != filepath.Base(def.Exec) || len(argv)-1 != len(want) {
		return false
	}
	for i, a := range want {
		if argv[i+1] != a {
			return false
		}
	}
	return true
}

// retitled reports whether the pidfile's process is def.Exec after it rewrote its argv into
// one title (sshd: "sshd: /usr/sbin/sshd -D -e [listener] ..."). Only trusted for a pidfile
// PID, and only when the running binary is def.Exec, so a recycled PID never matches.
func retitled(def *ServiceDef, pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	title := strings.TrimRight(string(data), "\x00")
	if err != nil || strings.Contains(title, "\x00") || !strings.HasPrefix(title, filepath.Base(def.Exec)) {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	want, werr := filepath.EvalSymlinks(def.Exec)
	return err == nil && werr == nil && exe == want
}

func isPIDRunning(pid int) bool {
	procPath := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(procPath); err == nil {
		return true
	}
	// Fallback to signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func getServiceStatus(name string) (*ServiceStatusInfo, error) {
	def, err := loadServiceDef(name)
	if err != nil {
		return nil, err
	}

	pid := getServicePID(def)
	status := "STOPPED"
	uptime := "-"
	if pid > 0 {
		status = "RUNNING"
		uptime = getPIDUptime(pid)
	}

	// An explicit enable/disable marker overrides the conf's autostart default.
	enabled := def.Autostart
	if data, err := os.ReadFile(filepath.Join(enabledDir, name)); err == nil {
		enabled = strings.TrimSpace(string(data)) == "enabled"
	}

	return &ServiceStatusInfo{
		Name:        def.Name,
		Description: def.Description,
		Status:      status,
		PID:         pid,
		Enabled:     enabled,
		Uptime:      uptime,
		LogFile:     def.LogFile,
	}, nil
}

// getPIDUptime is how long the process has run: its start time (field 22 of /proc/<pid>/stat,
// in clock ticks since boot) against the system uptime.
func getPIDUptime(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	up, uerr := os.ReadFile("/proc/uptime")
	i := bytes.LastIndexByte(b, ')')
	if err != nil || uerr != nil || i < 0 {
		return "unknown"
	}
	f := strings.Fields(string(b[i+1:]))
	var sysUp float64
	fmt.Sscanf(string(up), "%f", &sysUp)
	if len(f) < 20 {
		return "unknown"
	}
	start, _ := strconv.ParseFloat(f[19], 64) // field 22 overall; fields after ")" start at 3
	return (time.Duration((sysUp - start/100) * float64(time.Second))).Round(time.Second).String()
}

// oneShotServices run to completion at boot; stopped is their normal state.
var oneShotServices = map[string]bool{"firewall": true, "cloud-init": true, "wireguard": true}

// ServiceFix is one service healServices found down and what it did about it.
type ServiceFix struct {
	Name  string `json:"name"`
	Error string `json:"error,omitempty"` // empty: restarted
}

const healCooldown = 5 * time.Minute

var (
	healMu   sync.Mutex
	healLast = map[string]time.Time{}
)

// healServices starts every enabled long-running service that is down. ziro-init restarts a
// crashed daemon by itself; this is the second line (a daemon that never started, or one
// stopped outside its supervision). force skips the per-service cooldown (doctor --fix).
func healServices(force bool) []ServiceFix {
	healMu.Lock()
	defer healMu.Unlock()
	var out []ServiceFix
	for _, svc := range listAllServices() {
		if !svc.Enabled || svc.Status == "RUNNING" || oneShotServices[svc.Name] {
			continue
		}
		if fileExists(filepath.Join(stopMarkerDir, svc.Name)) { // stopped on purpose
			continue
		}
		if !force && time.Since(healLast[svc.Name]) < healCooldown {
			continue
		}
		healLast[svc.Name] = time.Now()
		fix := ServiceFix{Name: svc.Name}
		if err := restartDown(svc.Name); err != nil {
			fix.Error = err.Error()
		}
		out = append(out, fix)
	}
	return out
}

func startService(name string) error {
	def, err := loadServiceDef(name)
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(stopMarkerDir, name)) // an explicit start ends a deliberate stop
	pid := getServicePID(def)
	if pid > 0 {
		return fmt.Errorf("service '%s' is already running (PID %d)", name, pid)
	}
	if initManaged[name] {
		return releaseToInit(def)
	}
	if def.Restart == "" { // one-shot (firewall, cloud-init): run it here and report its exit
		return runForeground(def)
	}
	return spawnSupervised(def)
}

// restartDown starts a daemon that should be running and isn't: an init-managed one (released
// to ziro-init) or a supervised one (through the spawn helper). It never runs a one-shot
// service, so the long-running callers (the sentinel's self-heal, doctor --fix) never execute a
// service definition's command themselves.
func restartDown(name string) error {
	def, err := loadServiceDef(name)
	if err != nil {
		return err
	}
	if getServicePID(def) > 0 {
		return nil
	}
	// A deliberate (re)start: restartSupervised's stop dropped a marker that would otherwise hold
	// later restarts. The heal pass never gets here for a service stopped on purpose.
	_ = os.Remove(filepath.Join(stopMarkerDir, name))
	if initManaged[name] {
		return releaseToInit(def)
	}
	if def.Restart == "" {
		return fmt.Errorf("%s is a one-shot service: run ziroctl service start %s", name, name)
	}
	return spawnSupervised(def)
}

// restartSupervised restarts a running daemon the same way (stop, then restartDown): for the
// sentinel's memory watchdog, which restarts plugin services by their cgroup name.
func restartSupervised(name string) error {
	if err := stopService(name); err != nil {
		return err
	}
	return restartDown(name)
}

// spawnSupervised starts a supervised daemon through the spawn helper and checks it survives
// its first second.
func spawnSupervised(def *ServiceDef) error {
	// A supervised daemon must be a child of PID 1, never of this process: whoever reaps a
	// daemon is the only one that sees it exit, and only ziro-init restarts it. So it is started
	// by a short-lived helper ("service spawn") that exits at once, and the daemon is re-parented
	// to init. Started directly, a daemon that died under a long-lived parent (service boot,
	// sentinel, ziro-api, cluster-agent) was reaped there and never restarted.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The helper reads the service name from stdin: nothing from a definition reaches argv.
	spawn := exec.Command(self, "service", "spawn")
	spawn.Stdin = strings.NewReader(def.Name)
	out, err := spawn.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("spawn %s: unexpected output %q", def.Name, out)
	}
	// Report a daemon that dies on startup (bad config, port in use) instead of claiming
	// success; init has already scheduled its restart.
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if !processAlive(pid) {
			return fmt.Errorf("exited during startup; see %s (ziro-init retries it)", def.LogFile)
		}
	}
	return nil
}

// processAlive is false for a process that is gone or a zombie waiting for its parent.
func processAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) {
		return b[i+2] != 'Z' && b[i+2] != 'X'
	}
	return true
}

// spawnDaemon starts def's process in its cgroup, identity and log, writes the pidfile and
// returns without waiting for it.
func spawnDaemon(def *ServiceDef) (*exec.Cmd, *os.File, error) {
	if err := trustedExecutable(def.Exec); err != nil {
		return nil, nil, err
	}
	_ = os.MkdirAll(filepath.Dir(def.PIDFile), 0755)
	_ = os.MkdirAll(filepath.Dir(def.LogFile), 0755)

	args := strings.Fields(def.Args)
	// deepcode ignore CommandInjection: def.Exec comes from a root-owned, non-group/world-writable definition and passed trustedExecutable (absolute, root-owned, not writable by others); args are argv, no shell
	cmd := exec.Command(def.Exec, args...)

	rotateLog(def.LogFile)
	logF, err := os.OpenFile(def.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		cmd.Stdout = logF
		cmd.Stderr = logF
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := applyServiceIdentity(cmd, def); err != nil {
		if logF != nil {
			logF.Close()
		}
		return nil, nil, err
	}
	closeCg := func() {}
	if cg, err := serviceCgroup(def); err == nil {
		closeCg = startInCgroup(cmd.SysProcAttr, cg)
	} else if !errors.Is(err, errNoCgroup) {
		fmt.Fprintf(os.Stderr, "warning: %s: cgroup: %v\n", def.Name, err)
	}
	err = cmd.Start()
	closeCg()
	if err != nil {
		if logF != nil {
			logF.Close()
		}
		return nil, nil, fmt.Errorf("failed to start process: %w", err)
	}
	setOOMScoreAdj(cmd.Process.Pid, serviceClass(def.Name))
	if def.PIDFile != "" {
		_ = os.WriteFile(def.PIDFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	}
	return cmd, logF, nil
}

// runForeground runs a one-shot service and reports how it ended within a second; a
// longer-running one keeps going in the background.
func runForeground(def *ServiceDef) error {
	cmd, logF, err := spawnDaemon(def)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if logF != nil {
			logF.Close()
		}
		if def.PIDFile != "" {
			_ = os.Remove(def.PIDFile)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("exited during startup (%v); see %s", err, def.LogFile)
		}
	case <-time.After(time.Second):
	}
	return nil
}

var serviceSpawnCmd = &cobra.Command{
	Use:    "spawn",
	Short:  "Start a supervised daemon (name on stdin) and exit, leaving it to ziro-init",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if err != nil {
			return err
		}
		def, err := loadServiceDef(strings.TrimSpace(string(b))) // validates the name
		if err != nil {
			return err
		}
		c, _, err := spawnDaemon(def)
		if err != nil {
			return err
		}
		fmt.Println(c.Process.Pid) // exiting now re-parents the daemon to PID 1
		return nil
	},
}

// releaseToInit starts an init-supervised daemon: remove the stop marker and wait for
// ziro-init to spawn it (init resets its backoff for a held daemon).
func releaseToInit(def *ServiceDef) error {
	if err := os.Remove(filepath.Join(stopMarkerDir, def.Name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := 0; i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		if getServicePID(def) > 0 {
			return nil
		}
	}
	return fmt.Errorf("ziro-init did not start it within 10s; see %s", def.LogFile)
}

// restartService validates the config first (a broken sshd_config must not take down the
// running sshd and lock everyone out), then stops and starts.
func restartService(name string) error {
	def, err := loadServiceDef(name)
	if err != nil {
		return err
	}
	if def.Check != "" {
		if err := trustedExecutable(def.Exec); err != nil {
			return err
		}
		// deepcode ignore CommandInjection: same trusted, root-owned definition and executable as startService; argv, no shell
		if out, err := exec.Command(def.Exec, strings.Fields(def.Check)...).CombinedOutput(); err != nil {
			return fmt.Errorf("config check failed, service left running: %s", strings.TrimSpace(string(out)))
		}
	}
	if err := stopService(name); err != nil {
		return err
	}
	return startService(name)
}

func stopService(name string) error {
	def, err := loadServiceDef(name)
	if err != nil {
		return err
	}
	pid := getServicePID(def)
	if pid <= 0 {
		return nil // already stopped
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	// The marker holds ziro-init's restart (init-managed) and the heal tick (all others) until the
	// next explicit start; /run is empty after a reboot, so a stopped service still boots.
	if err := os.MkdirAll(stopMarkerDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stopMarkerDir, name), nil, 0644); err != nil {
		return err
	}
	// Remove the pidfile first: ziro-init restarts restart=always services whose pidfile
	// still names the exited process, and a deliberate stop must not look like a crash.
	if def.PIDFile != "" {
		_ = os.Remove(def.PIDFile)
	}

	_ = proc.Signal(syscall.SIGTERM)
	if !waitGone(pid, 3*time.Second) {
		_ = proc.Signal(syscall.SIGKILL)
		if !waitGone(pid, 2*time.Second) {
			return fmt.Errorf("PID %d did not exit", pid)
		}
	}
	if def.PIDFile != "" {
		_ = os.Remove(def.PIDFile)
	}
	if initManaged[name] {
		// Let ziro-init's supervisor loop (250ms) see the marker before a restart removes it.
		time.Sleep(400 * time.Millisecond)
	}
	return nil
}

// waitGone waits until pid is gone from /proc (exited and reaped).
func waitGone(pid int, d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		if !processAlive(pid) { // a zombie is gone: ziro-init reaps it
			return true
		}
	}
	return false
}

func enableService(name string) error {
	if _, err := loadServiceDef(name); err != nil {
		return err
	}
	return writeServiceState(name, "enabled\n")
}

func disableService(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	return writeServiceState(name, "disabled\n")
}

// writeServiceState records a service's enabled state through os.Root: the name (validated by the
// callers) can only ever select a file inside enabledDir, never follow ".." or a symlink out of it.
func writeServiceState(name, state string) error {
	if err := os.MkdirAll(enabledDir, 0755); err != nil {
		return err
	}
	root, err := os.OpenRoot(enabledDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFile(name, []byte(state), 0644)
}

func printRecentLogs(path string, maxLines int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	start := 0
	if len(lines) > maxLines {
		start = len(lines) - maxLines
	}
	for _, l := range lines[start:] {
		fmt.Printf("     %s\n", l)
	}
}

func init() {
	serviceCmd.AddCommand(serviceListCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceRestartCmd)
	serviceCmd.AddCommand(serviceSpawnCmd)
	serviceCmd.AddCommand(serviceEnableCmd)
	serviceCmd.AddCommand(serviceDisableCmd)
	serviceCmd.AddCommand(serviceLogsCmd)
	serviceCmd.AddCommand(serviceBootCmd, serviceHealCmd)
	serviceCmd.AddCommand(serviceRotateLogsCmd)
	rootCmd.AddCommand(serviceCmd)
}

// applyServiceIdentity drops the daemon to def.User and adds def.EnvFile to its environment.
// Env files hold secrets (a plugin's generated tokens), so only a root-owned file that others
// can't read or write is accepted.
func applyServiceIdentity(cmd *exec.Cmd, def *ServiceDef) error {
	if def.EnvFile != "" {
		env, err := readEnvFile(def.EnvFile)
		if err != nil {
			return err
		}
		cmd.Env = append(os.Environ(), env...)
	}
	if def.User == "" || def.User == "root" {
		return nil
	}
	u, err := user.Lookup(def.User)
	if err != nil {
		return fmt.Errorf("service %s: user %q: %w", def.Name, def.User, err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
	return nil
}

func readEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !rootOwnedFile(fi) || fi.Mode().Perm()&0o004 != 0 {
		return nil, fmt.Errorf("env file %s must be a root-owned regular file, not world-readable or group/world-writable", path)
	}
	var env []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, _, ok := strings.Cut(l, "="); !ok || k == "" {
			return nil, fmt.Errorf("env file %s: bad line (want KEY=VALUE)", path)
		}
		env = append(env, l)
	}
	return env, sc.Err()
}

// supervisedConf renders a definition as /etc/ziro/services/<name>.conf, supervised by ziro-init
// (restart=always).
func supervisedConf(d ServiceDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name=%s\ndescription=%s\nexec=%s\nargs=%s\npidfile=%s\nlogfile=%s\n", d.Name, d.Description, d.Exec, d.Args, d.PIDFile, d.LogFile)
	if d.User != "" {
		fmt.Fprintf(&b, "user=%s\n", d.User)
	}
	if d.EnvFile != "" {
		fmt.Fprintf(&b, "env_file=%s\n", d.EnvFile)
	}
	if r := d.Resources; r != nil {
		if r.Memory != "" {
			fmt.Fprintf(&b, "memory=%s\n", r.Memory)
		}
		if r.CPUs > 0 {
			fmt.Fprintf(&b, "cpus=%g\n", r.CPUs)
		}
		if r.PIDs > 0 {
			fmt.Fprintf(&b, "pids=%d\n", r.PIDs)
		}
	}
	b.WriteString("autostart=true\nrestart=always\n")
	return b.String()
}

package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type ServiceDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Exec        string `json:"exec"`
	Args        string `json:"args"`
	PIDFile     string `json:"pidfile"`
	LogFile     string `json:"logfile"`
	Check       string `json:"check,omitempty"` // args that make exec validate its config (sshd: -t)
	Autostart   bool   `json:"autostart"`
}

type ServiceStatusInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"` // RUNNING, STOPPED, FAILED
	PID         int    `json:"pid"`
	Enabled     bool   `json:"enabled"`
	Uptime      string `json:"uptime"`
	LogFile     string `json:"logfile"`
}

const (
	servicesDir = "/etc/ziro/services"
	enabledDir  = "/etc/ziro/services/enabled"
	logsDir     = "/var/log"
	runDir      = "/run"
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
	Short:   "Manage Ziro-OS system services and background daemons",
}

var serviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all system services, state, and enabled status",
	RunE: func(cmd *cobra.Command, args []string) error {
		services := listAllServices()
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
	Use:   "status <service>",
	Short: "Show detailed status and recent logs for a service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		s, err := getServiceStatus(name)
		if err != nil {
			return fmt.Errorf("service '%s' not found", name)
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
	Use:   "start <service>",
	Short: "Start a system service",
	Args:  cobra.ExactArgs(1),
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
	Use:   "stop <service>",
	Short: "Stop a running system service",
	Args:  cobra.ExactArgs(1),
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
	Use:   "restart <service>",
	Short: "Restart a system service",
	Args:  cobra.ExactArgs(1),
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
	Use:   "enable <service>",
	Short: "Enable a system service to start automatically on boot",
	Args:  cobra.ExactArgs(1),
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
	Use:   "disable <service>",
	Short: "Disable a system service from starting on boot",
	Args:  cobra.ExactArgs(1),
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
	Use:   "logs <service>",
	Short: "View recent log output from a system service",
	Args:  cobra.ExactArgs(1),
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

const stopMarkerDir = "/run/ziro/stopped"

var serviceBootCmd = &cobra.Command{
	Use:    "boot",
	Short:  "Start all enabled services (invoked by ziro-init at boot)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
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
		return nil
	},
}

const maxLogSize = 10 << 20

// rotateLog keeps one previous generation once a log exceeds maxLogSize.
// Copy+truncate (not rename) so daemons holding the file with O_APPEND keep working.
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
	dst, err := os.OpenFile(path+".1", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err == nil {
		_ = os.Truncate(path, 0)
	}
}

var serviceRotateLogsCmd = &cobra.Command{
	Use:    "rotate-logs",
	Short:  "Rotate /var/log/*.log files larger than 10MB (run hourly by crond)",
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

// validName guards every user-supplied identifier that ends up in a file path.
var validNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func validName(name string) error {
	if !validNameRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid name %q (allowed: a-z 0-9 _ . -)", name)
	}
	return nil
}

// rootOwnedFile: a regular file owned by root and not writable by group or others.
func rootOwnedFile(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().IsRegular() && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

// checkServicePaths keeps a definition's pid and log files where ziroctl and ziro-init expect
// them (both delete or truncate these paths as root).
func checkServicePaths(def *ServiceDef) error {
	for _, c := range []struct{ path, dir string }{{def.PIDFile, "/run/"}, {def.LogFile, "/var/log/"}} {
		if c.path != "" && (!strings.HasPrefix(c.path, c.dir) || strings.Contains(c.path, "..")) {
			return fmt.Errorf("%q must be under %s", c.path, c.dir)
		}
	}
	return nil
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
					case "autostart":
						def.Autostart = (v == "true" || v == "1" || v == "yes")
					}
				}
			}
			if err := checkServicePaths(def); err != nil {
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

func getPIDUptime(pid int) string {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if fi, err := os.Stat(statPath); err == nil {
		dur := time.Since(fi.ModTime()).Round(time.Second)
		return dur.String()
	}
	return "unknown"
}

func startService(name string) error {
	def, err := loadServiceDef(name)
	if err != nil {
		return err
	}
	pid := getServicePID(def)
	if pid > 0 {
		return fmt.Errorf("service '%s' is already running (PID %d)", name, pid)
	}
	if initManaged[name] {
		return releaseToInit(def)
	}

	if err := trustedExecutable(def.Exec); err != nil {
		return err
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

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		if logF != nil {
			logF.Close()
		}
		return fmt.Errorf("failed to start process: %w", err)
	}

	newPID := cmd.Process.Pid
	if def.PIDFile != "" {
		_ = os.WriteFile(def.PIDFile, []byte(strconv.Itoa(newPID)), 0644)
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

	// Report a daemon that dies on startup (bad config, port in use) instead of claiming
	// success. A clean exit is fine: firewall/cloud-init are one-shot.
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("exited during startup (%v); see %s", err, def.LogFile)
		}
	case <-time.After(time.Second):
	}
	return nil
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
	if initManaged[name] {
		if err := os.MkdirAll(stopMarkerDir, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stopMarkerDir, name), nil, 0644); err != nil {
			return err
		}
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
		if !isPIDRunning(pid) {
			return true
		}
	}
	return false
}

func enableService(name string) error {
	if _, err := loadServiceDef(name); err != nil {
		return err
	}
	_ = os.MkdirAll(enabledDir, 0755)
	target := filepath.Join(enabledDir, name)
	return os.WriteFile(target, []byte("enabled\n"), 0644)
}

func disableService(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	_ = os.MkdirAll(enabledDir, 0755)
	return os.WriteFile(filepath.Join(enabledDir, name), []byte("disabled\n"), 0644)
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
	serviceCmd.AddCommand(serviceEnableCmd)
	serviceCmd.AddCommand(serviceDisableCmd)
	serviceCmd.AddCommand(serviceLogsCmd)
	serviceCmd.AddCommand(serviceBootCmd)
	serviceCmd.AddCommand(serviceRotateLogsCmd)
	rootCmd.AddCommand(serviceCmd)
}

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	canaryDir   = "/var/canary"
	canaryFile  = "/var/canary/sentinel.token"
	canaryMagic = "ZIRO-OS-IMMUTABLE-CANARY-HEURISTIC-SHIELD-TOKEN-2026"
	fimDBPath   = "/etc/ziro/fim.db"
)

type ThreatDetection struct {
	Type        string `json:"type"`     // "REVERSE_SHELL", "CRYPTO_MINER", "RANSOMWARE", "ESCAPE_ATTEMPT"
	Severity    string `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM"
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Details     string `json:"details"`
}

type SecurityScanReport struct {
	Timestamp      string            `json:"timestamp"`
	IntegrityOK    bool              `json:"integrity_ok"`
	CanaryOK       bool              `json:"canary_ok"`
	ThreatsCount   int               `json:"threats_count"`
	Threats        []ThreatDetection `json:"threats"`
	FIMIssues      []string          `json:"fim_issues"`
	HardeningScore int               `json:"hardening_score"`
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security audit, malware/ransomware detection, and cloud hardening controls",
}

var securityAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Score the host against CIS-mapped hardening checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		checks := hostAudit("")
		score := auditScore(checks)
		if jsonOutput {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"score": score, "checks": checks})
		}
		out := cmd.OutOrStdout()
		fmt.Fprintln(out, "=== Ziro-OS Security & Hardening Audit ===")
		for _, c := range checks {
			printCheck(out, fmt.Sprintf("%-10s %s", c.Control, c.Title), c.Pass)
			if !c.Pass && c.Detail != "" {
				fmt.Fprintf(out, "            -> %s\n", c.Detail)
			}
		}
		fmt.Fprintf(out, "\nScore: %d/100 (%d of %d checks pass)\n", score, countPass(checks), len(checks))
		return nil
	},
}

// AuditCheck is one hardening control. Control names the CIS Benchmark section it maps to
// (docs/compliance.md has the table).
type AuditCheck struct {
	ID      string `json:"id"`
	Control string `json:"control"`
	Title   string `json:"title"`
	Pass    bool   `json:"pass"`
	Detail  string `json:"detail,omitempty"`
}

// auditSysctls: key -> minimum value (all of these are "higher is stricter" or exact booleans).
// absentOK: the sysctl only exists when its feature is built in, so its absence is the strictest
// possible state (e.g. no perf events or kexec at all on the custom kernel).
var auditSysctls = []struct {
	key, control string
	min          int
	exact        bool
	absentOK     bool
}{
	{"kernel.randomize_va_space", "CIS 1.5.1", 2, true, false},
	{"fs.suid_dumpable", "CIS 1.5.2", 0, true, false},
	{"kernel.kptr_restrict", "CIS 1.5.3", 2, true, false},
	{"kernel.dmesg_restrict", "CIS 1.5.3", 1, true, false},
	{"kernel.yama.ptrace_scope", "CIS 1.5.4", 1, false, false},
	{"kernel.unprivileged_bpf_disabled", "CIS 1.5.3", 1, false, true},
	{"net.core.bpf_jit_harden", "CIS 1.5.3", 2, true, true},
	{"kernel.kexec_load_disabled", "CIS 1.5.3", 1, true, true},
	{"kernel.perf_event_paranoid", "CIS 1.5.3", 2, false, true},
	{"fs.protected_hardlinks", "CIS 1.5.3", 1, true, false},
	{"fs.protected_symlinks", "CIS 1.5.3", 1, true, false},
	{"net.ipv4.tcp_syncookies", "CIS 3.3.8", 1, true, false},
	{"net.ipv4.conf.all.accept_redirects", "CIS 3.3.2", 0, true, false},
	{"net.ipv4.conf.all.secure_redirects", "CIS 3.3.3", 0, true, false},
	{"net.ipv4.conf.all.send_redirects", "CIS 3.3.1", 0, true, false},
	{"net.ipv4.conf.all.accept_source_route", "CIS 3.3.1", 0, true, false},
	{"net.ipv4.conf.all.rp_filter", "CIS 3.3.7", 1, false, false},
	{"net.ipv4.conf.all.log_martians", "CIS 3.3.4", 1, true, false},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "CIS 3.3.5", 1, true, false},
	{"net.ipv6.conf.all.accept_redirects", "CIS 3.3.2", 0, true, false},
}

// hostAudit runs every check; root prefixes all paths (tests use a fake tree).
func hostAudit(root string) []AuditCheck {
	var checks []AuditCheck
	add := func(id, control, title string, pass bool, detail string) {
		checks = append(checks, AuditCheck{ID: id, Control: control, Title: title, Pass: pass, Detail: detail})
	}
	for _, s := range auditSysctls {
		raw, err := os.ReadFile(filepath.Join(root, "/proc/sys", strings.ReplaceAll(s.key, ".", "/")))
		if os.IsNotExist(err) && s.absentOK {
			add("sysctl:"+s.key, s.control, s.key+" (feature not built into this kernel)", true, "")
			continue
		}
		v, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
		pass := err == nil && perr == nil && (v == s.min || (!s.exact && v > s.min))
		want := fmt.Sprintf("want %d", s.min)
		if !s.exact {
			want = fmt.Sprintf("want >= %d", s.min)
		}
		add("sysctl:"+s.key, s.control, s.key, pass, fmt.Sprintf("is %s, %s", strings.TrimSpace(string(raw)), want))
	}

	status, _ := os.ReadFile(filepath.Join(root, "/proc/self/status"))
	add("seccomp", "CIS 1.6", "Kernel seccomp support", strings.Contains(string(status), "Seccomp:"), "")
	_, err := os.Stat(filepath.Join(root, "/sys/fs/cgroup/cgroup.controllers"))
	add("cgroupv2", "CIS 1.6", "Unified cgroups v2 hierarchy", err == nil, "")

	sshd, _ := os.ReadFile(filepath.Join(root, "/etc/ssh/sshd_config"))
	add("ssh:keyonly", "CIS 5.2.8", "SSH key-only authentication (passwords disabled)", sshKeyOnlyConfig(sshd), "set PasswordAuthentication no")

	fw := loadFirewallConfig()
	add("fw:enabled", "CIS 3.5.1", "Host firewall enabled with default-drop input", fw.Enabled && !strings.EqualFold(fw.DefaultInput, "ACCEPT"), "ziroctl firewall enable")
	add("fw:guard", "CIS 3.5.1", "Ziro Guard flood/scan/brute-force protection active",
		fw.Enabled && !fw.Guard.Disabled && (root != "" || guardActive()), "ziroctl security protect status")

	for _, f := range []struct {
		path string
		max  os.FileMode
		ctl  string
	}{{"/etc/shadow", 0640, "CIS 6.1.5"}, {"/etc/passwd", 0644, "CIS 6.1.2"}, {"/root/.ssh", 0700, "CIS 5.2.x"}} {
		fi, err := os.Stat(filepath.Join(root, f.path))
		pass := err == nil && fi.Mode().Perm()&^f.max == 0
		detail := "missing"
		if err == nil {
			detail = fmt.Sprintf("mode %o, want %o or stricter", fi.Mode().Perm(), f.max)
		}
		add("perm:"+f.path, f.ctl, f.path+" permissions", pass, detail)
	}
	fi, err := os.Stat(filepath.Join(root, "/tmp"))
	add("tmp:sticky", "CIS 1.1.x", "/tmp sticky bit", err == nil && fi.Mode()&os.ModeSticky != 0, "")

	if root == "" {
		_, _, verr := verifyAudit(auditFiles())
		add("audit:chain", "CIS 4.1.x", "Tamper-evident audit log chain intact", verr == nil || len(auditFiles()) == 0, fmt.Sprint(verr))
	}
	return checks
}

func countPass(checks []AuditCheck) int {
	n := 0
	for _, c := range checks {
		if c.Pass {
			n++
		}
	}
	return n
}

func auditScore(checks []AuditCheck) int {
	if len(checks) == 0 {
		return 0
	}
	return countPass(checks) * 100 / len(checks)
}

var (
	scanAV    bool
	scanQuiet bool
)

var securityScanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Perform AI heuristic malware, ransomware, and reverse shell detection (--av: antivirus scan)",
	Example: `  ziroctl security scan                 # Sentinel heuristics (processes, canary, file integrity)
  ziroctl security scan --av            # ClamAV scan of /root /home /tmp /var/tmp and volumes
  ziroctl security scan --av /srv/data  # ClamAV scan of specific paths`,
	Run: func(cmd *cobra.Command, args []string) {
		if scanAV {
			found, err := runAVScan(args, scanQuiet)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(2)
			}
			if jsonOutput {
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"detections": found})
			}
			if len(found) > 0 {
				os.Exit(1)
			}
			return
		}
		if !jsonOutput {
			fmt.Println("🛡️  Starting Ziro-OS Sentinel Security & Threat Scan...")
		}
		rep := runSecurityScan()

		if jsonOutput {
			data, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println("================================================================")
		fmt.Printf(" 🔍 Threat Scan Report (%s)\n", rep.Timestamp)
		fmt.Println("================================================================")

		// FIM
		if rep.IntegrityOK {
			fmt.Println(" ✓ File Integrity Monitoring: PASS (Critical system binaries intact)")
		} else {
			fmt.Printf(" ❌ File Integrity Monitoring: ALERT (%d modified binaries detected)\n", len(rep.FIMIssues))
			for _, iss := range rep.FIMIssues {
				fmt.Printf("    • %s\n", iss)
			}
		}

		// Ransomware canary
		if rep.CanaryOK {
			fmt.Println(" ✓ Ransomware Canary Shield:   PASS (No mass file encryption detected)")
		} else {
			fmt.Println(" ❌ Ransomware Canary Shield:   ALERT! Honeypot canary token corrupted or deleted!")
		}

		// AI Heuristic Process Threats
		fmt.Printf(" ✓ Heuristic Process Analysis: %d active threat(s) detected\n", rep.ThreatsCount)
		for _, t := range rep.Threats {
			fmt.Printf("    🚨 [%s] %s (PID %d: %s) -> %s\n", t.Severity, t.Type, t.PID, t.ProcessName, t.Details)
		}

		fmt.Printf("\n 🛡️  Hardening & Protection Score: %d / 100\n", rep.HardeningScore)
		fmt.Println("================================================================")
	},
}

var sentinelEnforce bool

var securityMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start continuous Sentinel background threat monitoring daemon",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🛡️  Ziro Sentinel Continuous Protection Monitor started.")
		ensureCanary()
		go runGuardWatcher()
		go runResourceWatchdog()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		lastAlert := ""
		for {
			rep := runSecurityScan()
			// Log only when the alert set changes, so a persistent finding cannot fill the disk.
			sig := fmt.Sprint(rep.CanaryOK, rep.IntegrityOK, rep.FIMIssues)
			for _, t := range rep.Threats {
				sig += fmt.Sprintf("|%s:%d", t.Type, t.PID)
			}
			changed := sig != lastAlert
			lastAlert = sig
			if changed {
				raiseScanAlerts(rep)
			}
			flushAlerts() // retry anything still queued
			if changed && (rep.ThreatsCount > 0 || !rep.CanaryOK || !rep.IntegrityOK) {
				fmt.Printf("[%s] 🚨 ALERT: %d threats detected! Canary: %v, FIM: %v\n",
					time.Now().Format("15:04:05"), rep.ThreatsCount, rep.CanaryOK, rep.IntegrityOK)
				for _, t := range rep.Threats {
					fmt.Printf("    [%s] %s PID %d (%s): %s\n", t.Severity, t.Type, t.PID, t.ProcessName, t.Details)
				}
			}
			// Auto-kill only when explicitly enforced: heuristics can false-positive on real workloads.
			for _, t := range rep.Threats {
				if sentinelEnforce && t.Severity == "CRITICAL" && t.PID > 1 {
					fmt.Printf("    ⚡ Auto-mitigating CRITICAL threat: terminating PID %d (%s)...\n", t.PID, t.ProcessName)
					_ = exec.Command("kill", "-9", strconv.Itoa(t.PID)).Run()
				}
			}
			<-ticker.C
		}
	},
}

var securityHardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply cloud security hardening (sysctl, SSH, and file permissions)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("==================================================")
		fmt.Println(" 🛡️  Applying Ziro-OS Cloud Security Hardening")
		fmt.Println("==================================================")

		// 1. Kernel sysctl parameters
		sysctls := map[string]string{
			"/proc/sys/net/ipv4/conf/all/rp_filter":           "2",
			"/proc/sys/net/ipv4/conf/default/rp_filter":       "2",
			"/proc/sys/net/ipv4/tcp_syncookies":               "1",
			"/proc/sys/net/ipv4/conf/all/accept_source_route": "0",
			"/proc/sys/net/ipv4/conf/all/send_redirects":      "0",
			"/proc/sys/net/ipv4/conf/all/accept_redirects":    "0",
			"/proc/sys/kernel/dmesg_restrict":                 "1",
			"/proc/sys/kernel/kptr_restrict":                  "2",
			"/proc/sys/fs/protected_hardlinks":                "1",
			"/proc/sys/fs/protected_symlinks":                 "1",
		}

		for param, val := range sysctls {
			if err := os.WriteFile(param, []byte(val+"\n"), 0644); err == nil {
				fmt.Printf("  ✓ Configured %s = %s\n", param, val)
			}
		}

		// Write persistent sysctl config
		_ = os.MkdirAll("/etc/sysctl.d", 0755)
		hardenedConf := `# Ziro-OS Hardened Cloud Security Configuration
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
`
		_ = os.WriteFile("/etc/sysctl.d/99-hardened.conf", []byte(hardenedConf), 0644)
		fmt.Println("  ✓ Saved persistent rules to /etc/sysctl.d/99-hardened.conf")

		// 2. SSH Hardening
		sshdConfigPath := "/etc/ssh/sshd_config"
		if err := hardenSSHFile(sshdConfigPath); err != nil {
			return fmt.Errorf("SSH hardening failed: %w", err)
		}
		if err := exec.Command("pkill", "-HUP", "sshd").Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				return fmt.Errorf("SSH reload failed: %w", err)
			}
		}
		fmt.Println("  ✓ Validated and hardened OpenSSH server configuration (/etc/ssh/sshd_config)")

		// 3. File Permissions
		_ = os.Chmod("/etc/shadow", 0600)
		_ = os.Chmod("/etc/passwd", 0644)
		_ = os.Chmod("/root", 0700)
		_ = os.Chmod("/root/.ssh", 0700)
		_ = os.Chmod("/root/.ssh/authorized_keys", 0600)
		fmt.Println("  ✓ Restricted permissions on /etc/shadow, /etc/passwd, and /root/.ssh")

		_ = os.Remove(fimDBPath)
		checkFIM()
		fmt.Printf("  ✓ Recorded file integrity baseline at %s\n", fimDBPath)

		ensureCanary()
		fmt.Println("  ✓ Armed Ransomware Canary honeypot at /var/canary/sentinel.token")

		fmt.Println("\n✅ Security hardening successfully applied!")
		fmt.Println("==================================================")
		return nil
	},
}

func ensureCanary() {
	_ = os.MkdirAll(canaryDir, 0700)
	if !fileExists(canaryFile) {
		_ = os.WriteFile(canaryFile, []byte(canaryMagic), 0600)
	}
}

func runSecurityScan() SecurityScanReport {
	ensureCanary()
	rep := SecurityScanReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		IntegrityOK:    true,
		CanaryOK:       true,
		HardeningScore: 100,
	}

	// 1. Canary check
	data, err := os.ReadFile(canaryFile)
	if err != nil || string(data) != canaryMagic {
		rep.CanaryOK = false
		rep.HardeningScore -= 30
		rep.Threats = append(rep.Threats, ThreatDetection{
			Type:        "RANSOMWARE_OR_TAMPER",
			Severity:    "CRITICAL",
			ProcessName: "Canary Sentinel",
			Details:     "Canary file was altered, encrypted, or removed by an unauthorized process",
		})
	}

	// 2. FIM check against the recorded baseline
	rep.IntegrityOK, rep.FIMIssues = checkFIM()
	if !rep.IntegrityOK {
		rep.HardeningScore -= 30
	}

	// 3. AI Heuristic threat inspection of /proc
	threats := scanProcThreats()
	rep.Threats = append(rep.Threats, threats...)
	rep.ThreatsCount = len(rep.Threats)
	if rep.ThreatsCount > 0 {
		rep.HardeningScore -= (rep.ThreatsCount * 25)
		if rep.HardeningScore < 0 {
			rep.HardeningScore = 0
		}
	}

	return rep
}

// raiseScanAlerts turns a Sentinel scan into alerts (deduplicated by alertf per title).
func raiseScanAlerts(rep SecurityScanReport) {
	for _, t := range rep.Threats {
		sev := strings.ToLower(t.Severity)
		if _, ok := alertSeverities[sev]; !ok {
			sev = "high"
		}
		alertf(sev, "threat", fmt.Sprintf("%s: %s (PID %d)", t.Type, t.ProcessName, t.PID),
			map[string]any{"pid": t.PID, "process": t.ProcessName, "type": t.Type, "details": t.Details})
	}
	if !rep.CanaryOK {
		alertf("critical", "canary", "Ransomware canary file was modified or removed",
			map[string]any{"path": "/var/canary/sentinel.token"})
	}
	if !rep.IntegrityOK {
		alertf("high", "fim", "Critical system files changed", map[string]any{"files": rep.FIMIssues})
	}
}

var fimCriticalFiles = []string{
	"/bin/busybox",
	"/sbin/init",
	"/usr/bin/containerd",
	"/usr/bin/ziroctl",
	"/usr/sbin/sshd",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/ssh/sshd_config",
}

// checkFIM compares critical files with the baseline in fimDBPath, creating the
// baseline on first run. Re-baseline after legitimate updates with 'security harden'.
func checkFIM() (bool, []string) {
	current := map[string]string{}
	for _, f := range fimCriticalFiles {
		if h, err := computeFileSHA256(f); err == nil {
			current[f] = h
		}
	}

	var baseline map[string]string
	data, err := os.ReadFile(fimDBPath)
	if err != nil || json.Unmarshal(data, &baseline) != nil {
		_ = os.MkdirAll(filepath.Dir(fimDBPath), 0700)
		if out, err := json.MarshalIndent(current, "", "  "); err == nil {
			_ = os.WriteFile(fimDBPath, out, 0600)
		}
		return true, nil
	}

	var issues []string
	for _, f := range fimCriticalFiles {
		want, had := baseline[f]
		got, has := current[f]
		switch {
		case had && !has:
			issues = append(issues, f+": missing or unreadable")
		case had && want != got:
			issues = append(issues, f+": modified since baseline")
		}
	}
	return len(issues) == 0, issues
}

var (
	minerPatterns  = []string{"xmrig", "stratum+tcp", "stratum+ssl", "cryptonight", "minerd", "ethminer", "nanominer"}
	escapePatterns = []string{"/sys/fs/cgroup/release_agent", "devices.allow", "core_pattern"}
	shells         = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true}
	netcats        = map[string]bool{"nc": true, "ncat": true, "netcat": true}
)

// classifyProcess matches argv tokens, not raw substrings, so e.g. 'ssh -i key.pem'
// is never mistaken for 'sh -i'. It returns the threat type, severity and matched signature.
func classifyProcess(argv []string, stdinIsSocket bool) (string, string, string) {
	if len(argv) == 0 {
		return "", "", ""
	}
	base := filepath.Base(argv[0])
	joined := strings.Join(argv, " ")
	lower := strings.ToLower(joined)

	if strings.Contains(joined, "/dev/tcp/") || strings.Contains(joined, "/dev/udp/") {
		return "REVERSE_SHELL", "CRITICAL", "/dev/tcp redirection"
	}
	if shells[base] && stdinIsSocket {
		return "REVERSE_SHELL", "CRITICAL", "shell with network socket on stdin"
	}
	if netcats[base] {
		for _, a := range argv[1:] {
			if a == "-e" || a == "-c" || a == "--exec" || a == "--sh-exec" {
				return "REVERSE_SHELL", "CRITICAL", base + " " + a
			}
		}
	}
	if strings.Contains(joined, "pty.spawn") {
		return "REVERSE_SHELL", "HIGH", "pty.spawn"
	}
	for _, pat := range minerPatterns {
		if strings.Contains(lower, pat) {
			return "CRYPTO_MINER", "CRITICAL", pat
		}
	}
	for _, pat := range escapePatterns {
		if strings.Contains(joined, pat) {
			return "ESCAPE_ATTEMPT", "HIGH", pat
		}
	}
	if base == "nsenter" && strings.Contains(joined, "-t 1") {
		return "ESCAPE_ATTEMPT", "HIGH", "nsenter into PID 1"
	}
	return "", "", ""
}

func scanProcThreats() []ThreatDetection {
	var detections []ThreatDetection
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return detections
	}
	self := os.Getpid()

	for _, entry := range procEntries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		cmdBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(cmdBytes) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdBytes), "\x00"), "\x00")
		fd0, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", "0"))

		typ, sev, sig := classifyProcess(argv, strings.HasPrefix(fd0, "socket:"))
		if typ == "" {
			continue
		}
		commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		// Details carry only the signature, never the full cmdline (it may contain secrets).
		detections = append(detections, ThreatDetection{
			Type:        typ,
			Severity:    sev,
			PID:         pid,
			ProcessName: strings.TrimSpace(string(commBytes)),
			Details:     "matched signature: " + sig,
		})
	}
	return detections
}

func printCheck(out io.Writer, name string, passed bool) {
	if passed {
		fmt.Fprintf(out, " [PASS] %s\n", name)
	} else {
		fmt.Fprintf(out, " [WARN] %s\n", name)
	}
}

func init() {
	securityCmd.AddCommand(securityAuditCmd)
	securityScanCmd.Flags().BoolVar(&scanAV, "av", false, "Antivirus scan with ClamAV (module clamav)")
	securityScanCmd.Flags().BoolVar(&scanQuiet, "quiet", false, "Only alert; no output (cron)")
	securityCmd.AddCommand(securityScanCmd)
	securityMonitorCmd.Flags().BoolVar(&sentinelEnforce, "enforce", false, "SIGKILL processes flagged CRITICAL (default: alert only)")
	securityCmd.AddCommand(securityMonitorCmd)
	securityCmd.AddCommand(securityHardenCmd)
	rootCmd.AddCommand(securityCmd)
}

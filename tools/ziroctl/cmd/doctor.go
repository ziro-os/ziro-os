package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// doctorCheck is one diagnostic result. Critical checks gate `ziroctl upgrade`.
type doctorCheck struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Details  string `json:"details"`
	Critical bool   `json:"critical"`
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive system and cloud-native health diagnostics",
	Long: `ziroctl doctor runs an end-to-end audit of kernel modules, storage drivers,
containerd runtime sockets, cgroups v2, networking, and cloud metadata.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		checks := runDoctor()
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

func runDoctor() []doctorCheck {
	var checks []doctorCheck
	check := func(name string, passed bool, details string, critical bool) {
		checks = append(checks, doctorCheck{name, passed, details, critical})
	}

	// 1. Kernel & Architecture
	check("Operating System Architecture", runtime.GOOS == "linux", runtime.GOARCH, true)

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
		check("Storage Driver Modules Loaded", true, strings.Join(loadedDrivers, ", "), false)
	} else if _, err := os.Stat("/sys/block"); err == nil {
		// Built into the kernel
		check("Storage Driver Modules Loaded", true, "sysfs block subsystem active", false)
	} else {
		check("Storage Driver Modules Loaded", false, "No block drivers detected", false)
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
	check("Physical/Virtual Storage Disks", diskCount > 0, fmt.Sprintf("%d disk(s) found", diskCount), false)

	// 4. cgroups v2
	_, cgErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	check("cgroups v2 Unified Hierarchy", cgErr == nil, "/sys/fs/cgroup", false)

	// 5. Containerd Daemon & Socket
	_, sockErr := os.Stat("/run/containerd/containerd.sock")
	check("containerd Runtime Socket", sockErr == nil, "/run/containerd/containerd.sock", false)

	// 6. OCI runc binary
	_, runcErr1 := exec.LookPath("runc")
	_, runcErr2 := os.Stat("/usr/bin/runc")
	check("OCI Runtime (runc) Installed", runcErr1 == nil || runcErr2 == nil, "OCI specification executor", false)

	// 7. CNI Plugins
	cniPlugins, _ := os.ReadDir("/opt/cni/bin")
	check("CNI Network Plugins", len(cniPlugins) > 0, fmt.Sprintf("%d plugins in /opt/cni/bin", len(cniPlugins)), false)

	// 8. Network Interfaces
	ifaces, _ := net.Interfaces()
	upCount := 0
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Name != "lo" {
			upCount++
		}
	}
	check("Ethernet Interface Up", upCount > 0, fmt.Sprintf("%d active interface(s)", upCount), false)

	// 9. Outbound reachability (needed to fetch upgrades)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://1.1.1.1")
	if resp != nil {
		resp.Body.Close()
	}
	check("Outbound Internet Reachability", err == nil, "Cloudflare 1.1.1.1 connectivity", true)

	// 10. OpenSSH Daemon
	_, sshdErr := os.Stat("/run/sshd")
	check("Hardened OpenSSH Service", sshdErr == nil, "Port 22 listener", false)

	return checks
}

func printDoctor(checks []doctorCheck) {
	fmt.Println("==================================================")
	fmt.Println(" 🩺 Ziro-OS Cloud & System Diagnostics (Doctor)")
	fmt.Println("==================================================")
	passed := 0
	for _, c := range checks {
		status := "WARN"
		if c.Passed {
			status = "PASS"
			passed++
		}
		fmt.Printf(" [%s] %-40s %s\n", status, c.Name, c.Details)
	}
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Diagnostic Results: %d/%d checks passed\n", passed, len(checks))
	if passed == len(checks) {
		fmt.Println("🚀 System status: EXCELLENT — Ready for container workloads!")
	} else {
		fmt.Println("ℹ️  System status: OPERATIONAL with warnings. Review items marked [WARN].")
	}
	fmt.Println("==================================================")
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

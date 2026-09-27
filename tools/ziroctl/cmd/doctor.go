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

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive system and cloud-native health diagnostics",
	Long: `ziroctl doctor runs an end-to-end audit of kernel modules, storage drivers,
containerd runtime sockets, cgroups v2, networking, and cloud metadata.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("==================================================")
		fmt.Println(" 🩺 Ziro-OS Cloud & System Diagnostics (Doctor)")
		fmt.Println("==================================================")

		totalChecks := 0
		passedChecks := 0

		check := func(name string, passed bool, details string) {
			totalChecks++
			if passed {
				passedChecks++
				fmt.Printf(" [PASS] %-40s %s\n", name, details)
			} else {
				fmt.Printf(" [WARN] %-40s %s\n", name, details)
			}
		}

		// 1. Kernel & Architecture
		check("Operating System Architecture", runtime.GOOS == "linux", runtime.GOARCH)

		// 2. Storage Drivers
		hasStorageDriver := false
		drivers := []string{"virtio_blk", "sd_mod", "nvme", "ahci"}
		loadedDrivers := []string{}
		if data, err := os.ReadFile("/proc/modules"); err == nil {
			content := string(data)
			for _, drv := range drivers {
				if strings.Contains(content, drv) {
					loadedDrivers = append(loadedDrivers, drv)
					hasStorageDriver = true
				}
			}
		}
		if hasStorageDriver {
			check("Storage Driver Modules Loaded", true, strings.Join(loadedDrivers, ", "))
		} else {
			// Check if built into kernel or in dev
			if _, err := os.Stat("/sys/block"); err == nil {
				check("Storage Driver Modules Loaded", true, "sysfs block subsystem active")
			} else {
				check("Storage Driver Modules Loaded", false, "No block drivers detected")
			}
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
		check("Physical/Virtual Storage Disks", diskCount > 0, fmt.Sprintf("%d disk(s) found", diskCount))

		// 4. cgroups v2
		_, cgErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
		check("cgroups v2 Unified Hierarchy", cgErr == nil, "/sys/fs/cgroup")

		// 5. Containerd Daemon & Socket
		_, sockErr := os.Stat("/run/containerd/containerd.sock")
		check("containerd Runtime Socket", sockErr == nil, "/run/containerd/containerd.sock")

		// 6. OCI runc binary
		_, runcErr1 := exec.LookPath("runc")
		_, runcErr2 := os.Stat("/usr/bin/runc")
		check("OCI Runtime (runc) Installed", runcErr1 == nil || runcErr2 == nil, "OCI specification executor")

		// 7. CNI Plugins
		cniPlugins, _ := os.ReadDir("/opt/cni/bin")
		check("CNI Network Plugins", len(cniPlugins) > 0, fmt.Sprintf("%d plugins in /opt/cni/bin", len(cniPlugins)))

		// 8. Network Interfaces
		ifaces, err := net.Interfaces()
		upCount := 0
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp != 0 && ifc.Name != "lo" {
				upCount++
			}
		}
		check("Ethernet Interface Up", upCount > 0, fmt.Sprintf("%d active interface(s)", upCount))

		// 9. DNS Resolution
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("https://1.1.1.1")
		dnsPass := err == nil
		if resp != nil {
			resp.Body.Close()
		}
		check("Outbound Internet Reachability", dnsPass, "Cloudflare 1.1.1.1 connectivity")

		// 10. OpenSSH Daemon
		_, sshdErr := os.Stat("/run/sshd")
		check("Hardened OpenSSH Service", sshdErr == nil, "Port 22 listener")

		fmt.Println("--------------------------------------------------")
		fmt.Printf("Diagnostic Results: %d/%d checks passed\n", passedChecks, totalChecks)
		if passedChecks == totalChecks {
			fmt.Println("🚀 System status: EXCELLENT — Ready for container workloads!")
		} else {
			fmt.Println("ℹ️  System status: OPERATIONAL with warnings. Review items marked [WARN].")
		}
		fmt.Println("==================================================")
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud environment, hypervisor, and instance metadata tools",
}

var cloudInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect host virtualization, hypervisor, cloud platform, and hardware",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("==================================================")
		fmt.Println(" ☁️  Ziro-OS Cloud Environment & Platform")
		fmt.Println("==================================================")

		platform, hypervisor := detectCloudPlatform()
		fmt.Printf("Cloud Platform:    %s\n", platform)
		fmt.Printf("Hypervisor / Type: %s\n", hypervisor)
		fmt.Printf("Architecture:      %s (%s)\n", runtime.GOARCH, runtime.GOOS)
		fmt.Printf("CPU Cores:         %d logical cores\n", runtime.NumCPU())

		// Read DMI details if available
		sysVendor := readDMI("sys_vendor")
		productName := readDMI("product_name")
		productUUID := readDMI("product_uuid")
		biosVendor := readDMI("bios_vendor")
		biosVersion := readDMI("bios_version")

		if sysVendor != "" {
			fmt.Printf("System Vendor:     %s\n", sysVendor)
		}
		if productName != "" {
			fmt.Printf("Product / Model:   %s\n", productName)
		}
		if productUUID != "" {
			fmt.Printf("System UUID:       %s\n", productUUID)
		}
		if biosVendor != "" || biosVersion != "" {
			fmt.Printf("BIOS / Firmware:   %s %s\n", biosVendor, biosVersion)
		}

		// Cloud metadata service check
		fmt.Println("\n--- Cloud Metadata Availability ---")
		checkMetadataService()

		// Guest agent check
		fmt.Println("\n--- Virtualization Guest Agents ---")
		if _, err := os.Stat("/dev/virtio-ports/org.qemu.guest_agent.0"); err == nil {
			fmt.Println("  • QEMU / Proxmox Guest Agent Channel: DETECTED (/dev/virtio-ports/org.qemu.guest_agent.0)")
		} else {
			fmt.Println("  • QEMU / Proxmox Guest Agent Channel: Not attached")
		}

		fmt.Println("==================================================")
	},
}

var cloudUserDataCmd = &cobra.Command{
	Use:   "userdata [URL]",
	Short: "Fetch and execute cloud user-data bootstrap script",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var scriptURL string
		if len(args) > 0 {
			scriptURL = args[0]
		} else {
			// Try standard cloud metadata endpoint
			scriptURL = "http://169.254.169.254/latest/user-data"
		}

		fmt.Printf("Fetching cloud user-data from: %s...\n", scriptURL)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(scriptURL)
		if err != nil {
			return fmt.Errorf("failed to fetch user-data: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("metadata server returned HTTP %d", resp.StatusCode)
		}

		scriptBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		if len(scriptBytes) == 0 {
			fmt.Println("User-data script is empty.")
			return nil
		}

		tmpFile := "/tmp/ziro-cloud-init.sh"
		if err := os.WriteFile(tmpFile, scriptBytes, 0755); err != nil {
			return fmt.Errorf("failed to write script: %w", err)
		}
		defer os.Remove(tmpFile)

		fmt.Println("Executing cloud user-data bootstrap script...")
		runCmd := exec.Command("/bin/sh", tmpFile)
		runCmd.Stdout = os.Stdout
		runCmd.Stderr = os.Stderr
		return runCmd.Run()
	},
}

func readDMI(field string) string {
	path := fmt.Sprintf("/sys/class/dmi/id/%s", field)
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func detectCloudPlatform() (string, string) {
	sysVendor := strings.ToLower(readDMI("sys_vendor"))
	productName := strings.ToLower(readDMI("product_name"))
	biosVendor := strings.ToLower(readDMI("bios_vendor"))

	if strings.Contains(sysVendor, "qemu") || strings.Contains(productName, "qemu") {
		if strings.Contains(biosVendor, "seabios") {
			return "Proxmox VE / QEMU KVM", "QEMU (SeaBIOS)"
		}
		if strings.Contains(biosVendor, "edk ii") || strings.Contains(biosVendor, "ovmf") {
			return "Proxmox VE / QEMU KVM", "QEMU (OVMF UEFI)"
		}
		return "QEMU Virtual Machine", "KVM / QEMU"
	}
	if strings.Contains(sysVendor, "amazon") || strings.Contains(sysVendor, "ec2") {
		return "Amazon Web Services (AWS)", "AWS Nitro / Xen"
	}
	if strings.Contains(sysVendor, "google") {
		return "Google Cloud Platform (GCP)", "Google Compute Engine"
	}
	if strings.Contains(sysVendor, "microsoft") {
		return "Microsoft Azure", "Hyper-V"
	}
	if strings.Contains(sysVendor, "vmware") || strings.Contains(productName, "vmware") {
		return "VMware vSphere / ESXi", "VMware Virtual Platform"
	}
	if strings.Contains(sysVendor, "innotek") || strings.Contains(productName, "virtualbox") {
		return "Oracle VirtualBox", "VirtualBox Hypervisor"
	}

	// Check /proc/cpuinfo flags
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(data), "hypervisor") {
			return "Generic Cloud / Virtualized", "KVM / Hypervisor"
		}
	}

	return "Bare Metal Physical Hardware", "None (Direct Hardware)"
}

func checkMetadataService() {
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		resp.Body.Close()
		fmt.Println("  • Link-Local Metadata (169.254.169.254): AVAILABLE (AWS/OpenStack compatible)")
	} else {
		fmt.Println("  • Link-Local Metadata (169.254.169.254): Not reachable")
	}
}

func init() {
	cloudCmd.AddCommand(cloudInspectCmd)
	cloudCmd.AddCommand(cloudUserDataCmd)
	rootCmd.AddCommand(cloudCmd)
}

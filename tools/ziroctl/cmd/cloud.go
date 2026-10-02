package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

const (
	imdsBase           = "http://169.254.169.254/latest"
	cloudInitMarker    = "/var/lib/ziro/cloud-init.instance"
	rootAuthorizedKeys = "/root/.ssh/authorized_keys"
)

const cloudInitForce = "/etc/ziro/cloud-init.force"

var cloudWait int

func cloudMetadataTrusted() bool {
	if fileExists(cloudInitForce) {
		return true
	}
	dmi := strings.ToLower(readDMI("sys_vendor") + " " + readDMI("product_name") + " " + readDMI("bios_vendor"))
	for _, v := range []string{"amazon", "ec2", "openstack", "alibaba"} {
		if strings.Contains(dmi, v) {
			return true
		}
	}
	return false
}

// imdsGet fetches an EC2-compatible metadata path, using an IMDSv2 session
// token when available (required on hardened AWS instances), else IMDSv1.
func imdsGet(path string) ([]byte, int, error) {
	client := metadataClient(3 * time.Second)
	token := ""
	if req, err := http.NewRequest(http.MethodPut, imdsBase+"/api/token", nil); err == nil {
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
		if resp, err := client.Do(req); err == nil {
			if resp.StatusCode == http.StatusOK {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				token = strings.TrimSpace(string(b))
			}
			resp.Body.Close()
		}
	}
	req, err := http.NewRequest(http.MethodGet, imdsBase+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return body, resp.StatusCode, err
}

// Metadata is link-local: never send tokens through a proxy or a redirect.
func metadataClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("metadata redirects are not permitted")
		}}
}

func validateUserDataURL(u *url.URL) error {
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("user-data URLs must use https without credentials")
	}
	return nil
}

func userDataClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many user-data redirects")
		}
		return validateUserDataURL(req.URL)
	}}
}

// installMetadataSSHKeys appends instance public keys to root's authorized_keys (idempotent).
func installMetadataSSHKeys() int {
	list, code, err := imdsGet("/meta-data/public-keys/")
	if err != nil || code != http.StatusOK {
		return 0
	}
	_ = os.MkdirAll(filepath.Dir(rootAuthorizedKeys), 0700)
	existing, _ := os.ReadFile(rootAuthorizedKeys)
	added := 0
	for _, line := range strings.Split(string(list), "\n") {
		idx := strings.SplitN(strings.TrimSpace(line), "=", 2)[0]
		if idx == "" {
			continue
		}
		key, code, err := imdsGet("/meta-data/public-keys/" + idx + "/openssh-key")
		k := strings.TrimSpace(string(key))
		if err != nil || code != http.StatusOK || !(strings.HasPrefix(k, "ssh-") || strings.HasPrefix(k, "ecdsa-")) {
			continue
		}
		if strings.Contains(string(existing), k) {
			continue
		}
		if err := appendLine(rootAuthorizedKeys, k); err == nil {
			existing = append(existing, []byte(k+"\n")...)
			added++
		}
	}
	return added
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// runUserDataScript executes a shell user-data payload from a private temp file.
func runUserDataScript(script []byte) error {
	if len(bytes.TrimSpace(script)) == 0 {
		fmt.Println("User-data is empty.")
		return nil
	}
	if bytes.HasPrefix(script, []byte("#cloud-config")) {
		fmt.Println("User-data is #cloud-config (not supported): use #ziro-config (a ziroctl host file) or a shell script.")
		return nil
	}
	if bytes.HasPrefix(script, []byte("#ziro-config")) {
		fmt.Println("Applying the #ziro-config host configuration...")
		return applyProvisioning(script)
	}
	f, err := os.CreateTemp("", "ziro-userdata-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(script); err != nil {
		f.Close()
		return err
	}
	f.Close()

	fmt.Println("Executing cloud user-data bootstrap script...")
	runCmd := exec.Command("/bin/sh", f.Name())
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr
	return runCmd.Run()
}

// provisionFile is a host config staged by the installer (user-data starting with #ziro-config);
// the first boot applies it once.
var (
	provisionFile    = "/etc/ziro/provision.yaml"
	provisionApplied = "/var/lib/ziro/provision.applied"
)

// applyProvisioning applies a host config received at boot. Stack files it names resolve in
// /etc/ziro/provision.d.
func applyProvisioning(data []byte) error {
	plan, err := applyHostFile(data, "/etc/ziro/provision.d", false, 0)
	for _, c := range plan {
		fmt.Printf("  %-9s %-30s %s\n", c.Section, c.Item, c.Action)
	}
	return err
}

// applyStagedProvisioning applies the installer-staged host config once.
func applyStagedProvisioning() error {
	data, err := os.ReadFile(provisionFile)
	if err != nil || fileExists(provisionApplied) {
		return nil
	}
	if err := applyProvisioning(data); err != nil {
		return fmt.Errorf("provisioning %s: %w", provisionFile, err)
	}
	_ = os.MkdirAll(filepath.Dir(provisionApplied), 0700)
	return os.WriteFile(provisionApplied, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600)
}

var cloudUserDataCmd = &cobra.Command{
	Use:   "userdata [URL]",
	Short: "Install metadata SSH keys and run the cloud user-data script (once per instance)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// Explicit URL: code is executed as root, so it must be authenticated by TLS.
			u, err := url.Parse(args[0])
			if err != nil || validateUserDataURL(u) != nil {
				return fmt.Errorf("refusing %q: user-data URLs must use https", args[0])
			}
			client := userDataClient()
			resp, err := client.Get(u.String())
			if err != nil {
				return fmt.Errorf("failed to fetch user-data: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			if err != nil {
				return err
			}
			return runUserDataScript(body)
		}

		if err := applyStagedProvisioning(); err != nil {
			fmt.Println("⚠", err)
		}
		// 169.254.169.254 is only trustworthy on a real cloud: on a LAN anyone can
		// answer it and would get root via SSH keys/user-data.
		if !cloudMetadataTrusted() {
			fmt.Println("Not an EC2-compatible cloud (DMI); skipping metadata. Override: touch " + cloudInitForce)
			return nil
		}

		// Metadata service: wait for DHCP/IMDS at boot.
		var instanceID []byte
		var code int
		var err error
		for i := 0; ; i++ {
			instanceID, code, err = imdsGet("/meta-data/instance-id")
			if (err == nil && code == http.StatusOK) || i >= cloudWait {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || code != http.StatusOK {
			fmt.Println("No EC2-compatible metadata service found; nothing to do.")
			return nil
		}
		id := strings.TrimSpace(string(instanceID))

		if n := installMetadataSSHKeys(); n > 0 {
			fmt.Printf("✓ Installed %d SSH public key(s) from instance metadata\n", n)
		}

		if prev, _ := os.ReadFile(cloudInitMarker); strings.TrimSpace(string(prev)) == id {
			fmt.Printf("User-data already executed for instance %s; skipping.\n", id)
			return nil
		}
		body, code, err := imdsGet("/user-data")
		if err != nil {
			return fmt.Errorf("failed to fetch user-data: %w", err)
		}
		if code == http.StatusOK {
			if err := runUserDataScript(body); err != nil {
				return err
			}
		} else if code != http.StatusNotFound {
			return fmt.Errorf("metadata server returned HTTP %d", code)
		}
		_ = os.MkdirAll(filepath.Dir(cloudInitMarker), 0700)
		return os.WriteFile(cloudInitMarker, []byte(id+"\n"), 0600)
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

	// arm64 guests have no DMI: QEMU's virt machine shows in the device tree.
	if dt, err := os.ReadFile("/proc/device-tree/compatible"); err == nil && strings.Contains(string(dt), "linux,dummy-virt") {
		return "QEMU Virtual Machine", "KVM / QEMU"
	}
	// Check /proc/cpuinfo flags
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(data), "hypervisor") {
			return "Generic Cloud / Virtualized", "KVM / Hypervisor"
		}
	}

	return "Bare metal", "None (Direct Hardware)"
}

func checkMetadataService() {
	client := metadataClient(time.Second)
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
	cloudUserDataCmd.Flags().IntVar(&cloudWait, "wait", 0, "Seconds to wait for the metadata service")
	cloudCmd.AddCommand(cloudUserDataCmd)
	rootCmd.AddCommand(cloudCmd)
}

package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var motdCmd = &cobra.Command{
	Use:   "motd",
	Short: "Print dynamic cloud status and MOTD banner",
	Run: func(cmd *cobra.Command, args []string) {
		printDynamicMOTD(cmd.OutOrStdout())
	},
}

func printDynamicMOTD(out io.Writer) {
	cyan := "\033[1;36m"
	green := "\033[1;32m"
	yellow := "\033[1;33m"
	white := "\033[1;37m"
	reset := "\033[0m"

	fmt.Fprintf(out, "%s", cyan)
	fmt.Fprint(out, `
  _____  _               ___  ____  
 |__  / (_) _ __  ___   / _ \/ ___| 
   / /  | || '__/ _ \ | | | \___ \ 
  / /_  | || |  | (_) || |_| |___) |
 |____| |_||_|   \___/  \___/|____/ 
`)
	fmt.Fprintf(out, "%s\n", reset)

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "ziro-host"
	}

	kernel := "unknown"
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		kernel = strings.TrimSpace(string(out))
	}

	platform, _ := detectCloudPlatform()

	mode := fmt.Sprintf("%s[LIVE BOOT MEDIA]%s", cyan, reset)
	if _, err := os.Stat("/etc/ziro-installed"); err == nil {
		mode = fmt.Sprintf("%s[INSTALLED HOST]%s", green, reset)
	}

	// Memory info
	sys := inspectSystem()
	memStr := ""
	if sys.TotalMemMB > 0 {
		memStr = fmt.Sprintf("%d MB used / %d MB total", sys.TotalMemMB-sys.FreeMemMB, sys.TotalMemMB)
	} else {
		memStr = "Available"
	}

	// Active IP addresses
	var ips []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							ips = append(ips, ipnet.IP.String())
						}
					}
				}
			}
		}
	}
	ipStr := strings.Join(ips, ", ")
	if ipStr == "" {
		ipStr = "Configuring / DHCP"
	}

	// Containerd status & running containers
	containerdStatus := fmt.Sprintf("%sACTIVE%s", green, reset)
	if !sys.ContainerdOK {
		containerdStatus = fmt.Sprintf("%sSTOPPED%s", yellow, reset)
	}

	containerCount := "0"
	if out, err := exec.Command("nerdctl", "ps", "-q").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			containerCount = "0"
		} else {
			containerCount = fmt.Sprintf("%d", len(lines))
		}
	}

	// Cluster Role
	clusterRole := "Standalone Node"
	if isClusterMaster() {
		clusterRole = fmt.Sprintf("%sMaster (Mesh Coordinator)%s", green, reset)
	} else if isClusterWorker() {
		clusterRole = fmt.Sprintf("%sWorker (Connected)%s", cyan, reset)
	}

	// Security Shield
	shieldStatus := fmt.Sprintf("%sACTIVE%s (AI Threat Monitor & Canary Guard)", green, reset)

	// API Status
	apiStatus := fmt.Sprintf("%sSTANDBY%s (Enable via 'ziroctl service start ziro-api')", yellow, reset)
	if isAPIServerRunning() {
		apiStatus = fmt.Sprintf("%sACTIVE%s (Control Plane Port 8443)", green, reset)
	}

	fmt.Fprintf(out, " %sSystem:%s        Ziro-OS v%s (Cloud-Native Container Host) %s\n", white, reset, Version, mode)
	fmt.Fprintf(out, " %sEnvironment:%s   %s%s%s (%s)\n", white, reset, green, platform, reset, runtime.GOARCH)
	fmt.Fprintf(out, " %sNode & Kernel:%s %s (Kernel %s, %d CPUs, %s)\n", white, reset, hostname, kernel, runtime.NumCPU(), memStr)
	fmt.Fprintf(out, " %sIPv4 Address:%s  %s%s%s\n", white, reset, cyan, ipStr, reset)
	fmt.Fprintf(out, " %sOCI Runtime:%s   containerd (%s, %s active containers)\n", white, reset, containerdStatus, containerCount)
	fmt.Fprintf(out, " %sCluster Mesh:%s  %s\n", white, reset, clusterRole)
	fmt.Fprintf(out, " %sSecurity:%s      %s\n", white, reset, shieldStatus)
	fmt.Fprintf(out, " %sREST API:%s      %s\n", white, reset, apiStatus)
	fmt.Fprintln(out)
	fmt.Fprintf(out, " Quick start: '%sziroctl help%s' | '%sziroctl service list%s' | '%sziroctl cluster status%s'\n", cyan, reset, cyan, reset, cyan, reset)
	fmt.Fprintln(out)
}

func init() {
	rootCmd.AddCommand(motdCmd)
}

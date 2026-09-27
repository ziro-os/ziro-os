package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Network and CNI management",
}

var networkListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active network interfaces and CNI plugins",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("=== Network Interfaces ===")
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Error querying interfaces: %v\n", err)
		} else {
			for _, iface := range ifaces {
				addrs, _ := iface.Addrs()
				addrList := ""
				for _, a := range addrs {
					addrList += a.String() + " "
				}
				fmt.Printf("• %-12s Flags: %-20v IP: %s\n", iface.Name, iface.Flags, addrList)
			}
		}

		fmt.Println("\n=== CNI Configurations (/etc/cni/net.d) ===")
		configs, err := filepath.Glob("/etc/cni/net.d/*")
		if err != nil || len(configs) == 0 {
			fmt.Println("  (No CNI network configurations found)")
		} else {
			for _, cfg := range configs {
				fmt.Printf("• %s\n", filepath.Base(cfg))
			}
		}

		fmt.Println("\n=== CNI Plugin Binaries (/opt/cni/bin) ===")
		plugins, err := os.ReadDir("/opt/cni/bin")
		if err != nil || len(plugins) == 0 {
			fmt.Println("  (No CNI plugin binaries installed)")
		} else {
			for _, p := range plugins {
				fmt.Printf("• %s\n", p.Name())
			}
		}
	},
}

func init() {
	networkCmd.AddCommand(networkListCmd)
	rootCmd.AddCommand(networkCmd)
}

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("ziroctl - Ziro-OS management CLI")
		fmt.Println("Usage: ziroctl <command> [args...]")
		fmt.Println("Commands:")
		fmt.Println("  container - Container operations")
		fmt.Println("  module    - Module management")
		fmt.Println("  config    - Configuration management")
		fmt.Println("  version   - Show version")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "version":
		fmt.Println("ziroctl v0.1.0")
	case "container":
		handleContainer(os.Args[2:])
	case "module":
		handleModule(os.Args[2:])
	case "config":
		handleConfig(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func handleContainer(args []string) {
	if len(args) == 0 {
		fmt.Println("Container operations:")
		fmt.Println("  run <image>  - Run a container")
		fmt.Println("  list         - List containers")
		fmt.Println("  stop <id>    - Stop container")
		return
	}
	
	// Placeholder - would integrate with containerd
	fmt.Printf("Container command: %v\n", args)
}

func handleModule(args []string) {
	fmt.Printf("Module command: %v\n", args)
}

func handleConfig(args []string) {
	fmt.Printf("Config command: %v\n", args)
}
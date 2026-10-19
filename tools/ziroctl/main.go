package main

import (
	"os"
	"path/filepath"

	"github.com/ziro-os/ziroctl/cmd"
)

func main() {
	// One binary, several names: run as ziroctld (a symlink) it is the deploy daemon, as
	// ziro-sandboxd the sandbox daemon.
	switch filepath.Base(os.Args[0]) {
	case "ziroctld":
		os.Args = append([]string{os.Args[0], "deploy", "serve"}, os.Args[1:]...)
	case "ziro-sandboxd":
		os.Args = append([]string{os.Args[0], "sandbox", "serve"}, os.Args[1:]...)
	}
	cmd.Execute()
}

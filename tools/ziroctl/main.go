package main

import (
	"os"
	"path/filepath"

	"github.com/ziro-os/ziroctl/cmd"
)

func main() {
	// One binary, two names: run as ziroctld (a symlink), it is the deploy daemon.
	if filepath.Base(os.Args[0]) == "ziroctld" {
		os.Args = append([]string{os.Args[0], "deploy", "serve"}, os.Args[1:]...)
	}
	cmd.Execute()
}

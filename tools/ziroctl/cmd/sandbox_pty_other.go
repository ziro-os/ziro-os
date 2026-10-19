//go:build !linux

package cmd

import (
	"errors"
	"os"
	"os/exec"
)

func startPTY(cmd *exec.Cmd, cols, rows uint32) (*os.File, error) {
	return nil, errors.New("terminals need Linux")
}

func setWinsize(f *os.File, cols, rows uint32) error { return nil }

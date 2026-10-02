//go:build !linux

package cmd

import "syscall"

func startInCgroup(*syscall.SysProcAttr, string) func() { return func() {} }

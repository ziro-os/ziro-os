//go:build !linux

package cmd

import "errors"

var resizeFS = func(string, uint64) error { return errors.New("online resize needs Linux") }

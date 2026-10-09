//go:build !linux

package cmd

import "errors"

func execWithCaps(string, []string, []string, uint32, uint32, []int) error {
	return errors.New("service capabilities need Linux")
}

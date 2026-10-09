package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Capabilities for services (RFC 0003). A service with "caps" runs as its unprivileged "user"
// with exactly those Linux capabilities (and nothing else: the rest of the bounding set is
// dropped), and with no_new_privs set, so neither a setuid binary nor a file capability can
// add to them. Services without "caps" are started as before.
//
// The daemon is started through "ziroctl service exec <name>", which does the privilege change
// itself: Go's SysProcAttr can raise ambient capabilities but can neither drop the bounding
// set nor set no_new_privs.

// capNumbers maps a service definition's capability names to Linux capability numbers.
func capNumbers(names []string) ([]int, error) {
	out := make([]int, 0, len(names))
	for _, n := range names {
		c, ok := schema.ServiceCaps[n]
		if !ok {
			return nil, fmt.Errorf("capability %q is not available to services", n)
		}
		out = append(out, c)
	}
	return out, nil
}

// capMask packs capability numbers into the two 32-bit words of a capset(2) data array.
func capMask(caps []int) (lo, hi uint32) {
	for _, c := range caps {
		if c < 32 {
			lo |= 1 << uint(c)
		} else {
			hi |= 1 << uint(c-32)
		}
	}
	return lo, hi
}

// parseCapList reads the "caps=a,b" value of a service definition.
func parseCapList(v string) []string {
	var out []string
	for _, c := range strings.Split(v, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// serviceCommand is the process spawnDaemon starts for def: the daemon itself, or for a
// service with caps the launcher that drops privileges and then becomes the daemon.
func serviceCommand(def *ServiceDef) (*exec.Cmd, error) {
	if len(def.Caps) == 0 {
		return exec.Command(def.Exec, strings.Fields(def.Args)...), nil
	}
	if err := def.ValidateCaps(); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Only the (validated) service name is on the command line; the launcher loads the rest of
	// the definition itself, as spawn does.
	return exec.Command(self, "service", "exec", def.Name), nil
}

var serviceExecCmd = &cobra.Command{
	Use:    "exec <name>",
	Short:  "Start a service with only its capabilities (used by service start)",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		def, err := loadServiceDef(args[0]) // validates the name and the definition
		if err != nil {
			return err
		}
		if len(def.Caps) == 0 {
			return fmt.Errorf("service %s has no caps: nothing to drop", def.Name)
		}
		if err := def.ValidateCaps(); err != nil {
			return err
		}
		if err := trustedExecutable(def.Exec); err != nil {
			return err
		}
		caps, err := capNumbers(def.Caps)
		if err != nil {
			return err
		}
		u, err := user.Lookup(def.User)
		if err != nil {
			return fmt.Errorf("service %s: user %q: %w", def.Name, def.User, err)
		}
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		if uid == 0 {
			return fmt.Errorf("service %s: user %q is root", def.Name, def.User)
		}
		env := os.Environ()
		if def.EnvFile != "" { // read as root, before the privileges are dropped
			extra, err := readEnvFile(def.EnvFile)
			if err != nil {
				return err
			}
			env = append(env, extra...)
		}
		argv := append([]string{def.Exec}, strings.Fields(def.Args)...)
		return execWithCaps(def.Exec, argv, env, uint32(uid), uint32(gid), caps) // returns only on error
	},
}

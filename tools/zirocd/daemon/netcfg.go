package daemon

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// OS network configuration goes through the platform's own tools (ip, ifconfig/route, netsh),
// always with argument vectors built from parsed addresses: no shell, nothing from the wire
// reaches a command line unvalidated.

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.ziro$`)

func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

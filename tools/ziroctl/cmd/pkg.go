package cmd

import (
	"fmt"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"os"
	"slices"
	"strings"
)

// Packages installed on top of the image (pkg install, dev run's QEMU) are recorded so the boot
// reconcile reinstalls them after an OS upgrade replaced /usr.
var (
	extraPackagesFile = "/etc/ziro/packages"
	packageNameRe     = schema.PackageNameRe
)

func extraPackages() []string {
	b, err := os.ReadFile(extraPackagesFile)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Fields(string(b)) {
		if packageNameRe.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

func recordExtraPackages(add, remove []string) error {
	cur := extraPackages()
	for _, a := range add {
		if !slices.Contains(cur, a) {
			cur = append(cur, a)
		}
	}
	cur = slices.DeleteFunc(cur, func(p string) bool { return slices.Contains(remove, p) })
	slices.Sort(cur)
	data := strings.Join(cur, "\n")
	if data != "" {
		data += "\n"
	}
	return writeFileAtomic(extraPackagesFile, []byte(data), 0644)
}

// reconcileExtraPackages reinstalls recorded packages that are missing (after an OS upgrade).
func reconcileExtraPackages() {
	var missing []string
	for _, p := range extraPackages() {
		if !apkInstalled(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("[packages] reinstalling %s\n", strings.Join(missing, " "))
	if err := apkAdd(missing); err != nil {
		fmt.Printf("[packages] %v\n", err)
	}
}

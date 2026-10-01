package cmd

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/spf13/cobra"
)

// The kernel kit (kernel-devel-<arch>.tar.gz, built by kernel/build-kernel.sh and published with
// each release): out-of-tree kernel modules and CO-RE eBPF programs for the Ziro kernel, built in
// a container from the image the kit's own host tools were built in.

var (
	devKit      string
	devSignKey  string
	devSignCert string

	kitBuilderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_@-]{0,200}$`)
	bpfSourceRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]+\.c$`)
)

// devKitPath is --kit, or the release's kit for the arch (downloaded and verified).
func devKitPath(arch string) (string, error) {
	if devKit != "" {
		return filepath.Abs(devKit)
	}
	p, err := devReleaseFiles("kernel-devel-" + arch + ".tar.gz")
	if err != nil {
		return "", err
	}
	return p[0], nil
}

// kitBuilder reads the builder image recorded in the kit.
func kitBuilder(kit string) (string, error) {
	f, err := os.Open(kit)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return "", fmt.Errorf("%s: not a Ziro kernel kit (no builder): %w", kit, err)
		}
		if filepath.Clean(h.Name) == "builder" {
			b, err := io.ReadAll(io.LimitReader(tr, 256))
			if err != nil {
				return "", err
			}
			img := string(b)
			if len(img) > 0 && img[len(img)-1] == '\n' {
				img = img[:len(img)-1]
			}
			if !kitBuilderRe.MatchString(img) {
				return "", fmt.Errorf("%s: invalid builder image %q", kit, img)
			}
			return img, nil
		}
	}
}

// kitDocker runs script in the kit's builder image for the kit's arch, with the kit at /kit.tar.gz,
// dir at /src (read-write) and extra read-only mounts. Results are chowned to the caller.
func kitDocker(arch, kit, dir string, mounts []string, env []string, script string) error {
	img, err := kitBuilder(kit)
	if err != nil {
		return err
	}
	platform := map[string]string{"x86_64": "linux/amd64", "arm64": "linux/arm64"}[arch]
	if platform == "" {
		return fmt.Errorf("unsupported arch %q (x86_64 or arm64)", arch)
	}
	args := []string{"run", "--rm", "--platform", platform, "-v", kit + ":/kit.tar.gz:ro", "-v", dir + ":/src",
		"-e", "HOST_UID=" + strconv.Itoa(os.Getuid()), "-e", "HOST_GID=" + strconv.Itoa(os.Getgid())}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	c := exec.Command("docker", append(args, img, "sh", "-euc", script)...)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}
	return nil
}

var devKmodCmd = &cobra.Command{Use: "kmod", Short: "Out-of-tree kernel modules for the Ziro kernel"}

var devKmodBuildCmd = &cobra.Command{
	Use:   "build <dir>",
	Short: "Build (and sign) the kernel module(s) in <dir> against the Ziro kernel kit",
	Long: `Builds the Kbuild module(s) in <dir> (obj-m in its Makefile/Kbuild) against the kernel kit and
writes the .ko files to <dir>.

The Ziro kernel only loads signed modules (MODULE_SIG_FORCE). The official kernel trusts the Ziro
key only: official modules are signed in Ziro CI. Sign your own with --sign-key and boot a kernel
built to trust your certificate (ZIRO_EXTRA_TRUSTED_CERT, see docs/sdk.md).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		if !fileExists(filepath.Join(dir, "Makefile")) && !fileExists(filepath.Join(dir, "Kbuild")) {
			return fmt.Errorf("%s has no Makefile or Kbuild", dir)
		}
		arch := devArchName()
		kit, err := devKitPath(arch)
		if err != nil {
			return err
		}
		var mounts []string
		sign := "0"
		if devSignKey != "" {
			cert := devSignCert
			if cert == "" {
				cert = devSignKey // one PEM with the private key and the certificate
			}
			key, err1 := filepath.Abs(devSignKey)
			cert, err2 := filepath.Abs(cert)
			if err := errors.Join(err1, err2); err != nil {
				return err
			}
			mounts, sign = []string{key + ":/keys/key.pem:ro", cert + ":/keys/cert.pem:ro"}, "1"
		}
		// The source is built in a copy, so the container never writes root-owned objects to <dir>.
		return kitDocker(arch, kit, dir, mounts, []string{"SIGN=" + sign}, `
			apk add --no-cache build-base pahole bash libelf >/dev/null
			mkdir -p /tmp/kit /tmp/src && tar -xzf /kit.tar.gz -C /tmp/kit && cp -a /src/. /tmp/src/
			make -s -C /tmp/kit/kdev M=/tmp/src modules
			n=0
			for ko in $(find /tmp/src -name "*.ko"); do
				if [ "$SIGN" = 1 ]; then
					/tmp/kit/kdev/scripts/sign-file sha512 /keys/key.pem /keys/cert.pem "$ko"
				fi
				install -o "$HOST_UID" -g "$HOST_GID" -m 0644 "$ko" "/src/${ko#/tmp/src/}"
				echo "✓ ${ko#/tmp/src/} for $(cat /tmp/kit/kernel.release)$([ "$SIGN" = 1 ] && echo ", signed" || echo ", unsigned")"
				n=$((n+1))
			done
			[ "$n" -gt 0 ] || { echo "no .ko built" >&2; exit 1; }`)
	},
}

var devBpfCmd = &cobra.Command{Use: "bpf", Short: "CO-RE eBPF programs for the Ziro kernel"}

var devBpfBuildCmd = &cobra.Command{
	Use:   "build <prog.bpf.c>",
	Short: "Compile a CO-RE eBPF program against the Ziro kernel's BTF (vmlinux.h from the kit)",
	Long: `Compiles <prog.bpf.c> with clang -target bpf, with vmlinux.h (all kernel types, from the
kernel's BTF) and the libbpf headers on the include path. Writes <prog.bpf.o> next to it. The
object is CO-RE: libbpf relocates it to the running kernel when it's loaded.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		src, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		if !bpfSourceRe.MatchString(filepath.Base(src)) || !fileExists(src) {
			return fmt.Errorf("%s: want an existing .c file (letters, digits, . _ -)", args[0])
		}
		arch := devArchName()
		kit, err := devKitPath(arch)
		if err != nil {
			return err
		}
		target := map[string]string{"x86_64": "x86", "arm64": "arm64"}[arch]
		return kitDocker(arch, kit, filepath.Dir(src), nil, []string{"F=" + filepath.Base(src), "TARGET=" + target}, `
			apk add --no-cache clang libbpf-dev >/dev/null
			mkdir -p /tmp/kit && tar -xzf /kit.tar.gz -C /tmp/kit ./vmlinux.h
			out="${F%.c}.o"
			clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$TARGET -isystem /tmp/kit -I/src -c "/src/$F" -o "/tmp/$out"
			install -o "$HOST_UID" -g "$HOST_GID" -m 0644 "/tmp/$out" "/src/$out"
			echo "✓ $out"`)
	},
}

func init() {
	for _, c := range []*cobra.Command{devKmodBuildCmd, devBpfBuildCmd} {
		c.Flags().StringVar(&devKit, "kit", "", "Kernel kit (kernel-devel-<arch>.tar.gz; default: the release's)")
		c.Flags().StringVar(&devArch, "arch", "", "Target architecture: x86_64 or arm64 (default: the host's)")
		devReleaseFlag(c)
	}
	devKmodBuildCmd.Flags().StringVar(&devSignKey, "sign-key", "", "Sign with this private key (PEM; may also hold the certificate)")
	devKmodBuildCmd.Flags().StringVar(&devSignCert, "sign-cert", "", "Signing certificate (PEM; default: in --sign-key)")
	devKmodCmd.AddCommand(devKmodBuildCmd)
	devBpfCmd.AddCommand(devBpfBuildCmd)
	devCmd.AddCommand(devKmodCmd, devBpfCmd)
}

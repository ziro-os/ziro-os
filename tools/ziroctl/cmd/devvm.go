package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// `ziroctl dev run`: boot a throwaway Ziro VM (QEMU, live mode, nothing persists) from a verified
// release, install a plugin or deploy an app from a local definition, then run checks or attach.

const devBootMarker = "Live initialization complete" // printed by init when live mode is ready

var (
	devRelease  string
	devImageDir string
	devArch     string
	devMem      int
	devForwards []string
	devChecks   []string
	devSets     []string
	devCopies   []string
	devBootWait time.Duration
)

var (
	devForwardRe = regexp.MustCompile(`^([0-9]{1,5}):([0-9]{1,5})$`)
	devGuestPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	ansiRe       = regexp.MustCompile(`\x1b(\[[0-9;?]*[A-Za-z]|[78])`) // progress bars' cursor/erase codes
)

// devImage returns the kernel and initramfs to boot: from --image-dir (a local `make rootfs`
// build), or from a release, downloaded once into the cache and verified against SHA256SUMS.
func devImage(arch string) (kernel, initrd string, err error) {
	kname, iname := "vmlinuz-"+arch+"-custom", imageAssetName(arch, "custom")
	if devImageDir != "" {
		// The default (custom kernel) flavor, else the alpine flavor's names.
		for _, n := range [][2]string{{kname, iname}, {"vmlinuz-" + arch, imageAssetName(arch, "alpine")}} {
			kernel, initrd = filepath.Join(devImageDir, n[0]), filepath.Join(devImageDir, n[1])
			if fileExists(kernel) && fileExists(initrd) {
				return kernel, initrd, nil
			}
		}
		return "", "", fmt.Errorf("no %s image in %s (run 'make rootfs TARGET_ARCH=%s')", arch, devImageDir, arch)
	}
	p, err := devReleaseFiles(kname, iname)
	if err != nil {
		return "", "", err
	}
	return p[0], p[1], nil
}

// devReleaseFiles downloads release assets (--release) into the user cache once, verified against
// the release's SHA256SUMS, and returns their paths. Cached files are re-verified on every use.
func devReleaseFiles(names ...string) ([]string, error) {
	rel, err := fetchRelease(context.Background(), strings.TrimPrefix(devRelease, "latest"))
	if err != nil {
		return nil, err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cache, "ziro", "dev", rel.TagName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	sa := rel.asset("SHA256SUMS")
	if sa == nil {
		return nil, fmt.Errorf("release %s has no SHA256SUMS", rel.TagName)
	}
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if _, err := download(sa.URL, sumsPath, 1<<20); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(sumsPath)
	if err != nil {
		return nil, err
	}
	sums := parseSums(data)
	var out []string
	for _, name := range names {
		want := sums[name]
		a := rel.asset(name)
		if want == "" || a == nil {
			return nil, fmt.Errorf("release %s has no verified %s", rel.TagName, name)
		}
		p := filepath.Join(dir, name)
		out = append(out, p)
		if got, err := computeFileSHA256(p); err == nil && got == want {
			continue // cached and intact
		}
		fmt.Fprintf(os.Stderr, "downloading %s %s...\n", rel.TagName, name)
		got, err := download(a.URL, p, 1<<30)
		if err != nil {
			return nil, err
		}
		if got != want {
			os.Remove(p)
			return nil, fmt.Errorf("%s: SHA-256 mismatch (got %s, want %s)", name, got, want)
		}
	}
	return out, nil
}

// devQemuArgs mirrors tests/qemu/boot-smoke.py: live mode, serial console on stdio, user networking.
func devQemuArgs(arch, kernel, initrd string, mem int, forwards []string) (bin string, args []string, err error) {
	native := arch == map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	accel := "tcg"
	if native && runtime.GOOS == "linux" && unixAccess("/dev/kvm") {
		accel = "kvm"
	} else if native && runtime.GOOS == "darwin" {
		accel = "hvf"
	}
	cpu := "max"
	if accel != "tcg" {
		cpu = "host"
	}
	netdev := "user,id=n0"
	for _, f := range forwards {
		m := devForwardRe.FindStringSubmatch(f)
		if m == nil {
			return "", nil, fmt.Errorf("--forward %q: want host-port:guest-port", f)
		}
		netdev += ",hostfwd=tcp:127.0.0.1:" + m[1] + "-:" + m[2] // host side on loopback only
	}
	args = []string{"-cpu", cpu, "-m", strconv.Itoa(mem), "-smp", "2", "-nographic", "-no-reboot", "-accel", accel,
		"-kernel", kernel, "-initrd", initrd, "-netdev", netdev, "-device", "virtio-net-pci,netdev=n0"}
	switch arch {
	case "x86_64":
		return "qemu-system-x86_64", append(args, "-append", "console=ttyS0 rdinit=/init panic=-1"), nil
	case "arm64":
		return "qemu-system-aarch64", append([]string{"-machine", "virt"}, append(args, "-append", "console=ttyAMA0 rdinit=/init panic=-1")...), nil
	}
	return "", nil, fmt.Errorf("unsupported arch %q (x86_64 or arm64)", arch)
}

// devArchName is --arch, or the host's architecture in Ziro's naming (x86_64, arm64).
func devArchName() string {
	if devArch != "" {
		return devArch
	}
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

func devReleaseFlag(c *cobra.Command) {
	c.Flags().StringVar(&devRelease, "release", "latest", "Ziro release to use (vX.Y.Z or latest)")
}

func unixAccess(p string) bool {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// vmConsole drives the guest's serial console (a port of boot-smoke.py's Console).
type vmConsole struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	mu    sync.Mutex
	buf   bytes.Buffer
	tee   io.Writer // console output also goes here (log file, or the terminal when attached)
	done  chan struct{}
	seq   int
}

func startConsole(bin string, args []string, log io.Writer) (*vmConsole, error) {
	c := &vmConsole{cmd: exec.Command(bin, args...), tee: log, done: make(chan struct{})}
	var err error
	if c.stdin, err = c.cmd.StdinPipe(); err != nil {
		return nil, err
	}
	out, err := c.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	c.cmd.Stderr = c.cmd.Stdout
	if err := c.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s (is QEMU installed?): %w", bin, err)
	}
	go func() {
		defer close(c.done)
		b := make([]byte, 4096)
		for {
			n, err := out.Read(b)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(b[:n])
				tee := c.tee
				c.mu.Unlock()
				tee.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return c, nil
}

func (c *vmConsole) mark() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}

// waitFor polls the output since start for re; nil on timeout. QEMU exiting is an error.
func (c *vmConsole) waitFor(re *regexp.Regexp, start int, timeout time.Duration) ([][]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		m := re.FindSubmatch(c.buf.Bytes()[start:])
		c.mu.Unlock()
		if m != nil {
			return m, nil
		}
		select {
		case <-c.done:
			return nil, errors.New("QEMU exited")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, nil
}

// run runs a shell command on the guest and returns its exit code and output.
func (c *vmConsole) run(cmd string, timeout time.Duration) (int, string, error) {
	c.seq++
	tag := fmt.Sprintf("__ZD%d__", c.seq)
	start := c.mark()
	// The markers are split in the typed text, so the terminal echo never matches the output pattern.
	if _, err := fmt.Fprintf(c.stdin, "echo %sB''EGIN; %s; echo %sE''ND rc=$?\n", tag, cmd, tag); err != nil {
		return 0, "", err
	}
	m, err := c.waitFor(regexp.MustCompile(`(?s)`+tag+`BEGIN\r?\n(.*?)`+tag+`END rc=(\d+)`), start, timeout)
	if err != nil {
		return 0, "", err
	}
	if m == nil {
		return 0, "", fmt.Errorf("timed out after %s: %s", timeout, cmd)
	}
	rc, _ := strconv.Atoi(string(m[2]))
	return rc, ansiRe.ReplaceAllString(strings.ReplaceAll(string(m[1]), "\r", ""), ""), nil
}

func (c *vmConsole) stop() {
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
}

// shQuote quotes s for the guest's POSIX shell.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// copyIn writes data to path on the guest through the console, in base64 chunks.
func (c *vmConsole) copyIn(data []byte, path string) error {
	enc := base64.StdEncoding.EncodeToString(data)
	if _, _, err := c.run("rm -f /tmp/.devcopy", 10*time.Second); err != nil {
		return err
	}
	for len(enc) > 0 {
		n := min(len(enc), 3000) // well under the tty's 4095-byte line limit
		if _, _, err := c.run("printf %s "+enc[:n]+" >>/tmp/.devcopy", 10*time.Second); err != nil {
			return err
		}
		enc = enc[n:]
	}
	rc, out, err := c.run("base64 -d /tmp/.devcopy >"+shQuote(path)+" && rm /tmp/.devcopy", 10*time.Second)
	if err == nil && rc != 0 {
		err = fmt.Errorf("copy to the VM failed: %s", out)
	}
	return err
}

var devRunCmd = &cobra.Command{
	Use:   "run [manifest.json|app.json]",
	Short: "Boot a throwaway Ziro VM, install a plugin or deploy an app, then run --check commands or attach",
	Long: `Boots a verified Ziro release (or a local build, --image-dir) in QEMU in live mode: nothing
persists. The plugin is installed with 'plugin install -f', the app deployed with 'apps deploy -f'.

With --check, each command runs in the VM and dev run exits non-zero if any fails (CI). Without it,
you're attached to the VM's root console: Ctrl-C stops the VM. Without a definition, it just boots
(--copy puts files in the VM first, e.g. a kernel module to test).

QEMU uses KVM on Linux and HVF on macOS when the VM's arch matches the host, otherwise emulation.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var def []byte
		if len(args) == 1 {
			var err error
			if def, err = os.ReadFile(args[0]); err != nil {
				return err
			}
			if f := lintDefinition(args[0], def); len(f) > 0 && f[0].Level == "error" {
				return errors.New(f[0].Message)
			}
		}
		copies := map[string][]byte{}
		for _, c := range devCopies {
			src, dst, ok := strings.Cut(c, ":")
			if !ok || !devGuestPath.MatchString(dst) || strings.Contains(dst, "..") {
				return fmt.Errorf("--copy %q: want local-file:/absolute/guest/path", c)
			}
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			copies[dst] = b
		}
		for _, s := range devSets {
			if !strings.Contains(s, "=") {
				return fmt.Errorf("--set %q: want name=value", s)
			}
		}
		arch := devArchName()
		kernel, initrd, err := devImage(arch)
		if err != nil {
			return err
		}
		bin, qargs, err := devQemuArgs(arch, kernel, initrd, devMem, devForwards)
		if err != nil {
			return err
		}
		logf, err := os.CreateTemp("", "ziro-dev-*.log")
		if err != nil {
			return err
		}
		defer logf.Close()
		fmt.Fprintf(os.Stderr, "booting %s (console log: %s)...\n", filepath.Base(initrd), logf.Name())
		con, err := startConsole(bin, qargs, logf)
		if err != nil {
			return err
		}
		defer con.stop()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		defer signal.Stop(sig)
		go func() { <-sig; con.stop() }()

		t0 := time.Now()
		m, err := con.waitFor(regexp.MustCompile(regexp.QuoteMeta(devBootMarker)+"|Kernel panic"), 0, devBootWait)
		if err != nil || m == nil || strings.Contains(string(m[0]), "panic") {
			return fmt.Errorf("VM didn't boot (see %s)", logf.Name())
		}
		fmt.Fprintf(os.Stderr, "✓ booted in %s\n", time.Since(t0).Round(time.Second))
		time.Sleep(3 * time.Second)
		if _, err := io.WriteString(con.stdin, "\n"); err != nil {
			return err
		}
		if _, _, err := con.run("stty -echo", 30*time.Second); err != nil {
			return err
		}

		// QEMU forwards to the VM's NIC: open the guest ports (the VM is throwaway and only
		// reachable through the host's loopback forwards).
		for _, f := range devForwards {
			guest := devForwardRe.FindStringSubmatch(f)[2]
			if _, _, err := con.run("ziroctl firewall allow "+guest+"/tcp >/dev/null", time.Minute); err != nil {
				return err
			}
		}
		for dst, b := range copies {
			if err := con.copyIn(b, dst); err != nil {
				return err
			}
		}
		if def != nil {
			install := "ziroctl plugin install -f /tmp/dev.json"
			if definitionKind(def) == "app" {
				install = "ziroctl apps deploy -f /tmp/dev.json --local"
				if len(devForwards) > 0 {
					install += " --bind 0.0.0.0" // reachable by --forward
				}
			}
			for _, s := range devSets {
				install += " --set " + shQuote(s)
			}
			if err := con.copyIn(def, "/tmp/dev.json"); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "$ %s\n", install)
			rc, out, err := con.run(install+" 2>&1", 15*time.Minute)
			if err != nil {
				return err
			}
			fmt.Print(out)
			if rc != 0 {
				return fmt.Errorf("install failed (exit %d)", rc)
			}
		}

		if len(devChecks) > 0 {
			failed := 0
			for _, c := range devChecks {
				rc, out, err := con.run(c+" 2>&1", 5*time.Minute)
				if err != nil {
					return err
				}
				mark := "✓"
				if rc != 0 {
					mark, failed = "✗", failed+1
				}
				fmt.Printf("%s %s (exit %d)\n%s", mark, c, rc, out)
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d checks failed", failed, len(devChecks))
			}
			return nil
		}

		// Attach: the guest console to the terminal (line-buffered; the guest doesn't echo).
		fmt.Fprintln(os.Stderr, "attached to the VM's root console; Ctrl-C stops it")
		con.mu.Lock()
		con.tee = io.MultiWriter(logf, os.Stdout)
		con.mu.Unlock()
		go func() { _, _ = io.Copy(con.stdin, os.Stdin); con.stop() }()
		_, _ = io.WriteString(con.stdin, "\n")
		<-con.done
		return nil
	},
}

func init() {
	f := devRunCmd.Flags()
	devReleaseFlag(devRunCmd)
	f.StringVar(&devImageDir, "image-dir", "", "Boot a local build instead (a make rootfs build/ directory)")
	f.StringVar(&devArch, "arch", "", "VM architecture: x86_64 or arm64 (default: the host's)")
	f.IntVar(&devMem, "mem", 2048, "VM memory in MiB")
	f.StringArrayVar(&devForwards, "forward", nil, "Forward 127.0.0.1:<host-port> to the VM (host-port:guest-port); apps then publish on the VM's NIC")
	f.StringArrayVar(&devChecks, "check", nil, "Command to run in the VM after install; any failure fails dev run (repeatable)")
	f.StringArrayVar(&devSets, "set", nil, "Plugin or app setting (name=value)")
	f.StringArrayVar(&devCopies, "copy", nil, "Copy a local file into the VM before install (file:/guest/path; repeatable)")
	f.DurationVar(&devBootWait, "boot-timeout", 5*time.Minute, "How long to wait for the VM to boot")
	devCmd.AddCommand(devRunCmd)
}

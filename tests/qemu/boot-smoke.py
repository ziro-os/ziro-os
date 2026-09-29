#!/usr/bin/env python3
"""Boot the built Ziro-OS kernel + initramfs in QEMU and verify the container host works.

Drives the live-mode serial console (stdlib only, no pexpect) and checks:
kernel/modules match, module loading, containerd, boot-time services (firewall,
Sentinel), DHCP networking, and running a real container.

With --installed it also installs to a virtual disk from the live system, then boots that
disk through the tiny boot initramfs (root=LABEL=ZIRO_ROOT) and checks the missing-disk path
fails closed (no shell, reboot).

usage: tests/qemu/boot-smoke.py [--arch x86_64|arm64] [--build-dir build] [--no-pull] [--installed]
"""
import argparse
import os
import platform
import re
import subprocess
import sys
import threading
import time

BOOT_MARKER = "Live initialization complete"
INSTALLED_MARKER = "Enterprise Container Host Status"


def qemu_command(arch, build_dir, flavor, initrd=None, append="rdinit=/init", disk=None):
    sfx = "" if flavor == "alpine" else f"-{flavor}"
    kernel = os.path.join(build_dir, f"vmlinuz-{arch}{sfx}")
    initrd = initrd or os.path.join(build_dir, f"ziro-initramfs-{arch}{sfx}.cpio.gz")
    for f in (kernel, initrd):
        if not os.path.exists(f):
            sys.exit(f"missing {f}; run 'make rootfs TARGET_ARCH={arch} KERNEL_FLAVOR={flavor}' first")

    host = platform.machine().lower()
    native = (arch == "x86_64" and host in ("x86_64", "amd64")) or (arch == "arm64" and host in ("arm64", "aarch64"))
    accel = "tcg"
    if native and sys.platform == "linux" and os.access("/dev/kvm", os.R_OK | os.W_OK):
        accel = "kvm"
    elif native and sys.platform == "darwin":
        accel = "hvf"

    common = ["-m", "2048", "-smp", "2", "-nographic", "-no-reboot", "-accel", accel,
              "-kernel", kernel, "-initrd", initrd,
              "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"]
    if disk:
        common += ["-drive", f"file={disk},if=none,id=d0,format=raw", "-device", "virtio-blk-pci,drive=d0"]
    cpu = "host" if accel in ("kvm", "hvf") else "max"
    if arch == "x86_64":
        return ["qemu-system-x86_64", "-cpu", cpu, *common,
                "-append", f"console=ttyS0 {append} panic=-1"], accel
    return ["qemu-system-aarch64", "-machine", "virt", "-cpu", cpu, *common,
            "-append", f"console=ttyAMA0 {append} panic=-1"], accel


class Console:
    def __init__(self, cmd, log_path):
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.buf = ""
        self.lock = threading.Lock()
        self.log = open(log_path, "w", encoding="utf-8", errors="replace")
        self.seq = 0
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while True:
            chunk = self.proc.stdout.read1(4096)
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace")
            with self.lock:
                self.buf += text
            self.log.write(text)
            self.log.flush()

    def wait_for(self, pattern, timeout, start=0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                m = re.search(pattern, self.buf[start:], re.S)
            if m:
                return m
            if self.proc.poll() is not None:
                raise RuntimeError(f"QEMU exited with code {self.proc.returncode}")
            time.sleep(0.2)
        return None

    def run(self, cmd, timeout=60):
        """Run a shell command on the guest console; return (rc, output) or (None, '') on timeout."""
        self.seq += 1
        tag = f"__Z{self.seq}__"
        with self.lock:
            start = len(self.buf)
        # Markers are split in the typed text so the terminal echo never matches the output pattern.
        line = f"echo {tag}B''EGIN; {cmd}; echo {tag}E''ND rc=$?\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()
        m = self.wait_for(rf"{tag}BEGIN\r?\n(.*?){tag}END rc=(\d+)", timeout, start)
        if not m:
            return None, ""
        return int(m.group(2)), m.group(1).replace("\r", "")

    def close(self):
        self.proc.kill()
        self.proc.wait()
        self.log.close()


def retry(console, cmd, ok, timeout, every=3):
    deadline = time.time() + timeout
    rc, out = None, ""
    while time.time() < deadline:
        rc, out = console.run(cmd, timeout=min(60, max(5, deadline - time.time())))
        if rc is not None and ok(rc, out):
            return True, out
        time.sleep(every)
    return False, out


def installed_checks(args, disk, check):
    """Boot the installed disk through the tiny initramfs, then prove a missing disk fails closed."""
    sfx = "" if args.flavor == "alpine" else f"-{args.flavor}"
    tiny = os.path.join(args.build_dir, f"rootfs-full-{args.arch}{sfx}", "boot", "initramfs-boot.cpio.gz")
    root = "root=LABEL=ZIRO_ROOT rootwait=30"
    cmd, _ = qemu_command(args.arch, args.build_dir, args.flavor, initrd=tiny, append=root, disk=disk)
    con = Console(cmd, os.path.join(args.build_dir, f"qemu-installed-{args.arch}-{args.flavor}.log"))
    try:
        t0 = time.time()
        m = con.wait_for(re.escape(INSTALLED_MARKER) + "|FATAL|Kernel panic", args.boot_timeout)
        ok = bool(m) and INSTALLED_MARKER in m.group(0)
        check(f"installed disk boots via tiny initramfs ({time.time() - t0:.0f}s)", ok, m.group(0) if m else "timeout")
        if ok:
            con.proc.stdin.write(b"\n")
            con.proc.stdin.flush()
            check("installed console requires login", bool(con.wait_for(r"login:", 60)), "no login prompt")
    finally:
        con.close()

    cmd, _ = qemu_command(args.arch, args.build_dir, args.flavor, initrd=tiny, append="root=LABEL=ZIRO_ROOT rootwait=3")
    con = Console(cmd, os.path.join(args.build_dir, f"qemu-nodisk-{args.arch}-{args.flavor}.log"))
    try:
        m = con.wait_for(r"FATAL: root device not found.*rebooting in", 120)
        with con.lock:
            leaked = "emergency shell" in con.buf or "live environment" in con.buf
        check("missing root disk fails closed (no live fallback, no shell)", bool(m) and not leaked,
              con.buf[-400:] if not m else "")
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "alpine"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    ap.add_argument("--no-pull", action="store_true", help="skip the container run check (no internet)")
    ap.add_argument("--installed", action="store_true", help="also install to a disk and boot it (tiny initramfs)")
    args = ap.parse_args()

    disk = None
    if args.installed:
        disk = os.path.join(args.build_dir, f"install-test-{args.arch}-{args.flavor}.img")
        with open(disk, "wb") as f:
            f.truncate(4 << 30)   # sparse 4 GiB
    cmd, accel = qemu_command(args.arch, args.build_dir, args.flavor, disk=disk)
    log_path = os.path.join(args.build_dir, f"qemu-boot-{args.arch}-{args.flavor}.log")
    print(f"booting {args.arch}/{args.flavor} kernel ({accel}); serial log: {log_path}")
    con = Console(cmd, log_path)

    results = []

    def check(name, passed, detail=""):
        results.append(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[:200]}" if detail and not passed else ""))

    try:
        t0 = time.time()
        booted = con.wait_for(re.escape(BOOT_MARKER) + "|Kernel panic", args.boot_timeout)
        if not booted or "panic" in booted.group(0):
            check("boot to live init", False, booted.group(0) if booted else "timeout")
            return 1
        check(f"boot to live init ({time.time() - t0:.0f}s)", True)
        time.sleep(3)
        con.proc.stdin.write(b"\n")
        con.proc.stdin.flush()

        rc, out = con.run("uname -r; ls /lib/modules")
        check("console shell responds", rc == 0, out)
        rc, out = con.run('[ -d "/lib/modules/$(uname -r)" ] && echo KMATCH')
        check("kernel matches shipped modules", "KMATCH" in out, out)
        rc, out = con.run("modprobe nf_tables && modprobe wireguard && modprobe overlay && echo MODOK")
        check("modprobe nf_tables/wireguard/overlay", "MODOK" in out, out)
        rc, out = con.run("test -e /dev/fd/0 && test -e /dev/stdin && bash -c 'cat <(echo PSUB)'")
        check("/dev/fd + bash process substitution", "PSUB" in out, out)
        rc, out = con.run("ziroctl wg init >/dev/null && ziroctl wg up && ziroctl wg up && "
                          "wg show wg0 listen-port && ziroctl wg down && echo WGOK")
        check("wireguard init/up/up(idempotent)/down", "WGOK" in out, out)

        if args.flavor == "custom":
            rc, out = con.run("cat /sys/module/module/parameters/sig_enforce")
            check("module signature enforcement active (custom kernel)", "Y" in out, out)
            rc, out = con.run("cat /sys/kernel/security/lockdown /sys/kernel/security/lsm; echo; ls /sys/kernel/btf/vmlinux")
            check("lockdown=integrity, landlock+bpf LSMs, BTF (custom kernel)",
                  "[integrity]" in out and "landlock" in out and "bpf" in out and "/sys/kernel/btf/vmlinux" in out, out)
        rc, out = con.run("sysctl -n kernel.io_uring_disabled; test -s /boot/initramfs-boot.cpio.gz && echo TINYOK")
        check("io_uring restricted + tiny boot initramfs shipped", out.split()[:1] == ["1"] and "TINYOK" in out, out)

        ok, out = retry(con, "test -S /run/containerd/containerd.sock && echo CTRDOK", lambda rc, o: "CTRDOK" in o, 60)
        check("containerd socket ready", ok, out)

        ok, out = retry(con, "ziroctl service status sentinel", lambda rc, o: "RUNNING" in o, 60)
        check("Sentinel started at boot (service boot)", ok, out)
        ok, out = retry(con, "nft list table inet ziro", lambda rc, o: rc == 0 and "policy drop" in o, 60)
        check("firewall table 'inet ziro' applied at boot", ok, out)

        ok, out = retry(con, "ip -4 addr show | grep 'inet 10.0.2.'", lambda rc, o: rc == 0, 90)
        check("DHCP network configured", ok, out)

        if args.no_pull:
            print("  [SKIP] container run (--no-pull)")
        else:
            ok, out = retry(con, "nerdctl run --rm docker.io/library/busybox:latest echo CONTAINER_OK",
                            lambda rc, o: "CONTAINER_OK" in o, 300, every=10)
            check("nerdctl run busybox", ok, out)
        if args.installed:
            rc, out = con.run("ziro-install --disk /dev/vda --yes --hostname ziro-itest --password Ziro-Test-9 "
                              "</dev/null >/tmp/install.log 2>&1; echo INSTALL_RC=$?; tail -15 /tmp/install.log", timeout=600)
            check("installer to /dev/vda (GRUB + tiny initramfs)", "INSTALL_RC=0" in out, out[-1500:])
            con.run("sync")
    finally:
        con.close()

    if args.installed and all(results):
        installed_checks(args, disk, check)

    if not all(results):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            tail = f.read().splitlines()[-60:]
        print("---- last serial console lines ----\n" + "\n".join(tail))
        return 1
    print(f"all {len(results)} boot checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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


def qemu_command(arch, build_dir, flavor, initrd=None, append="rdinit=/init", disk=None, data_disk=None, qmp=None):
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
    if data_disk:
        common += ["-drive", f"file={data_disk},if=none,id=d1,format=raw", "-device", "virtio-blk-pci,drive=d1"]
    if qmp:
        common += ["-qmp", f"unix:{qmp},server=on,wait=off"]
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


def qmp_resize(sock_path, device, size):
    """Grow a virtual disk while the guest runs (like resizing a cloud volume)."""
    import json, socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    f = s.makefile("rw")
    f.readline()  # greeting
    for cmd in ({"execute": "qmp_capabilities"},
                {"execute": "block_resize", "arguments": {"device": device, "size": size}}):
        f.write(json.dumps(cmd) + "\n")
        f.flush()
        while True:  # skip async events until the command's reply
            reply = json.loads(f.readline())
            if "return" in reply or "error" in reply:
                break
        if "error" in reply:
            raise RuntimeError(reply["error"])
    s.close()


def console_login(con, password="Ziro-Test-9"):
    with con.lock:
        start = len(con.buf)
    con.proc.stdin.write(b"root\n")
    con.proc.stdin.flush()
    if not con.wait_for(r"[Pp]assword:", 30, start):
        return False
    con.proc.stdin.write(password.encode() + b"\n")
    con.proc.stdin.flush()
    time.sleep(3)
    rc, out = con.run("stty -echo 2>/dev/null; echo LOGGED_IN", timeout=30)
    return "LOGGED_IN" in out


def installed_checks(args, disk, check):
    """Boot the installed disk through the tiny initramfs, then prove a missing disk fails closed."""
    sfx = "" if args.flavor == "alpine" else f"-{args.flavor}"
    tiny = os.path.join(args.build_dir, f"rootfs-full-{args.arch}{sfx}", "boot", "initramfs-boot.cpio.gz")
    root = "root=LABEL=ZIRO_ROOT rootwait=30"
    # The cloud volume was resized while the host was off: the root must fill it at boot.
    with open(disk, "r+b") as f:
        f.truncate(6 << 30)
    data = os.path.join(args.build_dir, f"data-test-{args.arch}-{args.flavor}.img")
    with open(data, "wb") as f:
        f.truncate(1 << 30)
    qmp = os.path.join(args.build_dir, f"qmp-{args.arch}.sock")
    if os.path.exists(qmp):
        os.remove(qmp)
    cmd, _ = qemu_command(args.arch, args.build_dir, args.flavor, initrd=tiny, append=root, disk=disk,
                          data_disk=data, qmp=qmp)
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
            if console_login(con):
                disk_checks(con, check, qmp)
            else:
                check("console login (installer password)", False, "login failed")
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


def disk_checks(con, check, qmp):
    gib = lambda out: int(out.split()[-1]) / (1 << 20) if out.split() and out.split()[-1].isdigit() else 0
    ok, out = retry(con, "df -k / | awk 'NR==2{print $2}'", lambda rc, o: gib(o) > 5.3, 90, every=10)
    check("root filesystem grown at boot to fill the resized disk (6 GiB)", ok, out)
    qmp_resize(qmp, "d0", 8 << 30)
    rc, out = con.run("sleep 2; ziroctl disk expand; df -k / | awk 'NR==2{print $2}'", timeout=180)
    check("disk grown live (QMP block_resize) -> disk expand grows the mounted root", gib(out) > 7.3, out)
    rc, out = con.run("ziroctl disk add /dev/vda --mount /x 2>&1; ziroctl disk add /dev/vdb --mount /etc 2>&1", timeout=60)
    check("disk add refuses the boot disk and system mount points", "root filesystem" in out and "system path" in out, out)
    rc, out = con.run("ziroctl disk add /dev/vdb --mount /data && echo hello > /data/t && umount /data && "
                      "ziroctl disk boot && cat /data/t && awk '$2==\"/data\"{print $4}' /proc/mounts", timeout=180)
    check("disk add formats and mounts a data disk; disk boot re-mounts it (nodev,nosuid)",
          "hello" in out and "nosuid" in out and "nodev" in out, out)


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
        rc, out = con.run("ziroctl service status crond")
        check("crond started at boot", "RUNNING" in out, out)
        # Ziro Guard: an "attacker" in its own network namespace (veth, so traffic isn't loopback).
        # Sysctls present on every kernel (perf/kexec may be compiled out of the custom flavor).
        rc, out = con.run("sysctl -n net.ipv4.conf.all.log_martians net.ipv4.tcp_rfc1337 dev.tty.ldisc_autoload; "
                          "ziroctl security audit --json | grep -o '\"score\":[0-9]*'; ziroctl security audit | grep -A1 WARN")
        check("hardening sysctls applied, audit score 100", out.split()[:3] == ["1", "1", "0"] and '"score":100' in out, out)
        rc, out = con.run("unshare -n sleep 900 & echo $! > /tmp/atk.pid; sleep 1; A=$(cat /tmp/atk.pid); "
                          # iproute2 (/sbin/ip): busybox ip ignores "peer name".
                          "/sbin/ip link add atk0 type veth peer name atk1 && /sbin/ip link set atk1 netns $A && "
                          "/sbin/ip addr add 10.99.0.1/24 dev atk0 && /sbin/ip link set atk0 up && "
                          "nsenter -t $A -n sh -c '/sbin/ip addr add 10.99.0.2/24 dev atk1; /sbin/ip link set atk1 up; /sbin/ip link set lo up' && "
                          # Capture-only receiver: busybox nc drops the request when it also sends a response,
                          # so it answers nothing (ziroctl times out and keeps the alert queued for retry).
                          "(sleep 120 | nc -l -p 9999 > /tmp/hook.txt &) && "
                          "ziroctl security alerting add local --url http://127.0.0.1:9999/hook --events ban >/dev/null && echo ATKOK")
        check("attacker namespace and local webhook receiver", "ATKOK" in out, out)
        con.run("A=$(cat /tmp/atk.pid); for i in 1 2 3 4 5 6; do nsenter -t $A -n ssh -o BatchMode=yes "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 attacker@10.99.0.1 true; done 2>/dev/null",
                timeout=90)
        ok, out = retry(con, "nft list set inet ziro_guard ban4", lambda rc, o: "10.99.0.2" in o, 20)
        check("SSH brute force banned in the kernel (6 failed logins)", ok, out)
        rc, out = con.run("A=$(cat /tmp/atk.pid); nsenter -t $A -n nc -w 3 10.99.0.1 22 </dev/null | head -c 7; echo; "
                          "ziroctl security bans unban 10.99.0.2", timeout=30)
        # While banned nc gets no banner (dropped). After the unban the banner comes back once
        # sshd's own PerSourcePenalties (a few seconds per failure) have expired too.
        ok, out2 = retry(con, "nsenter -t $(cat /tmp/atk.pid) -n nc -w 3 10.99.0.1 22 </dev/null | head -c 7",
                         lambda rc, o: o.startswith("SSH-2.0"), 90, every=5)
        check("ban blocks SSH, unban restores it", not out.lstrip().startswith("SSH-") and "Unbanned 10.99.0.2" in out and ok, out + out2)
        ok, out = retry(con, "grep -c 'X-Ziro-Signature: sha256=' /tmp/hook.txt && grep -o 'SSH brute force from 10.99.0.2 banned' /tmp/hook.txt",
                        lambda rc, o: rc == 0, 45)  # slow TCG runners
        check("signed ban alert delivered to the webhook", ok, out)
        if not ok:
            _, diag = con.run("echo '--- hook.txt'; head -c 600 /tmp/hook.txt; echo; echo '--- spool'; ls -la /var/lib/ziro/alerts; "
                              "cat /var/lib/ziro/alerts/.recent; echo; cat /etc/ziro/alerting.json | grep -v secret; "
                              "echo '--- sentinel'; tail -15 /var/log/sentinel.log; ps | grep '[n]c -l'; netstat -tan | grep 9999")
            print("    diagnostics:\n" + "\n".join("      " + l for l in diag.splitlines()), flush=True)
        con.run("A=$(cat /tmp/atk.pid); for p in $(seq 1000 1030); do nsenter -t $A -n nc -w 1 10.99.0.1 $p </dev/null; done 2>/dev/null",
                timeout=120)
        rc, out = con.run("ziroctl security bans list")
        check("port scan banned by the kernel (no userspace)", "10.99.0.2" in out, out)
        con.run("ziroctl security bans unban 10.99.0.2; kill $(cat /tmp/atk.pid); /sbin/ip link del atk0; ziroctl security alerting remove local")
        ok, out = retry(con, "nft list table inet ziro", lambda rc, o: rc == 0 and "policy drop" in o, 60)
        check("firewall table 'inet ziro' applied at boot", ok, out)

        ok, out = retry(con, "ip -4 addr show | grep 'inet 10.0.2.'", lambda rc, o: rc == 0, 90)
        check("DHCP network configured", ok, out)

        # Networking day-2: hostname, pinned resolvers, declarative config with automatic rollback.
        rc, out = con.run("ziroctl network hostname smoke-node >/dev/null && hostname && grep -c '^127.0.1.1.*smoke-node' /etc/hosts")
        check("network hostname: set live and persisted", out.split()[:2] == ["smoke-node", "1"], out)
        rc, out = con.run("ziroctl network dns 9.9.9.9 --search smoke.example >/dev/null && kill -USR1 $(cat /run/udhcpc.eth0.pid) && "
                          "sleep 4 && cat /etc/resolv.conf")
        check("pinned resolvers survive a DHCP renewal", "nameserver 9.9.9.9" in out and "udhcpc" not in out, out)
        con.run("ziroctl network dns auto >/dev/null; kill -USR1 $(cat /run/udhcpc.eth0.pid); sleep 3")
        rc, out = con.run("ziroctl network set eth0 --mode static --address 10.0.2.15/24 --gateway 10.0.2.2 >/dev/null && "
                          "ziroctl network vlan add eth0 100 >/dev/null && "
                          "ziroctl network set eth0.100 --mode static --address 172.16.100.5/24 >/dev/null && "
                          "ziroctl network apply --confirm-timeout 15s >/dev/null && "
                          "ip -4 addr show eth0.100 | grep -c 172.16.100.5; ip route | grep -c 'default via 10.0.2.2'", timeout=60)
        check("network apply: static address, VLAN and gateway applied", out.split()[-2:] == ["1", "1"], out)
        ok, out = retry(con, "ip link show eth0.100 >/dev/null 2>&1 && echo VLAN_UP || echo VLAN_GONE; "
                        "test -e /etc/ziro/network.json && echo CFG || echo NOCFG; pgrep -f 'udhcpc.*eth0' >/dev/null && echo DHCP",
                        lambda rc, o: "VLAN_GONE" in o and "NOCFG" in o and "DHCP" in o, 60, every=5)
        check("unconfirmed network change rolled back by itself (VLAN removed, DHCP restored)", ok, out)
        rc, out = con.run("printf '{\"interfaces\":[{\"name\":\"eth0\",\"mode\":\"dhcp\"},"
                          "{\"name\":\"eth0.200\",\"mode\":\"static\",\"parent\":\"eth0\",\"vlan_id\":200,"
                          "\"addresses\":[\"172.16.200.5/24\"]}]}' > /etc/ziro/network.json && "
                          "ziroctl network apply --boot >/dev/null && echo VLAN200=$(ip -4 addr show eth0.200 | grep -c 172.16.200.5); "
                          "rm -f /etc/ziro/network.json /etc/ziro/network.applied.json; ip link del eth0.200", timeout=60)
        check("boot-time apply of /etc/ziro/network.json (what ziro-init runs)", "VLAN200=1" in out, out)
        rc, out = con.run("ziroctl ssh key import gh:torvalds 2>&1; grep -c 'ziro-import:gh:torvalds' /root/.ssh/authorized_keys", timeout=60)
        if "key(s) added" in out:
            check("ssh key import gh:<user> (tagged, deduplicated)", out.split()[-1] != "0", out)
            con.run("ziroctl ssh key remove --source gh:torvalds")
        else:
            print(f"  [SKIP] ssh key import from GitHub (unreachable or no published keys): {out.strip()[:120]}")

        if args.no_pull:
            print("  [SKIP] container run (--no-pull)")
        else:
            ok, out = retry(con, "nerdctl run --rm docker.io/library/busybox:latest echo CONTAINER_OK",
                            lambda rc, o: "CONTAINER_OK" in o, 300, every=10)
            check("nerdctl run busybox", ok, out)

        # Service lifecycle for init-supervised daemons. sshd rewrites its process title and
        # ziro-init respawns both, so status/stop/restart must go through init, not around it.
        rc, out = con.run("stat -c '%U %a' /root/.ssh /var/empty")
        check("sshd private dirs root-owned 0700", out.split() == ["root", "700", "root", "700"], out)
        ok, out = retry(con, "P=$(cat /run/crond.pid) && kill $P && sleep 4 && N=$(cat /run/crond.pid) && "
                        "[ \"$N\" != \"$P\" ] && kill -0 $N && echo RESPAWNED", lambda rc, o: "RESPAWNED" in o, 30)
        check("init respawns a killed restart=always service (crond)", ok, out)
        rc, out = con.run("ziroctl service status sshd")
        check("service status finds sshd (retitled process)", "RUNNING" in out, out)
        con.run("cp /etc/ssh/sshd_config /tmp/sshd_config.bak && printf 'Port 22\\nPort 2222\\n' >> /etc/ssh/sshd_config")
        rc, out = con.run("ziroctl service restart sshd && netstat -ltn | grep -c ':2222 ' && ps -o args | grep -c '[l]istener'")
        check("service restart sshd applies new config (one listener)", rc == 0 and out.split()[-2:] == ["2", "1"], out)
        con.run("echo 'NoSuchOption yes' >> /etc/ssh/sshd_config")
        rc, out = con.run("P=$(cat /run/sshd.pid); ziroctl service restart sshd; [ \"$(cat /run/sshd.pid)\" = \"$P\" ] && echo KEPT")
        check("broken sshd_config: restart refused, sshd kept", "config check failed" in out and "KEPT" in out, out)
        con.run("cp /tmp/sshd_config.bak /etc/ssh/sshd_config")
        rc, out = con.run("ziroctl service stop sshd && sleep 3 && ziroctl service status sshd; ps -o args | grep -c '[l]istener'")
        check("service stop sshd stays stopped (init holds restart)", "STOPPED" in out and out.split()[-1] == "0", out)
        rc, out = con.run("ziroctl service start sshd && ziroctl service status sshd && { netstat -ltn | grep -c ':2222 ' || true; }")
        check("service start sshd (released to init, old config back)", rc == 0 and "RUNNING" in out and out.split()[-1] == "0", out)
        rc, out = con.run("P=$(cat /run/containerd/containerd.pid); ziroctl service restart containerd && "
                          "[ \"$(cat /run/containerd/containerd.pid)\" != \"$P\" ] && sleep 2 && "
                          "nerdctl info >/dev/null && echo CRESTART")
        check("service restart containerd (no race with init)", "CRESTART" in out, out)
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

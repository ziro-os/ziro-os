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
import base64
import os
import platform
import re
import subprocess
import sys
import threading
import time

BOOT_MARKER = "Live initialization complete"
INSTALLED_MARKER = "Ziro OS ready (installed)"


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

    common = ["-m", os.environ.get("ZIRO_SMOKE_MEM", "2048"), "-smp", "2", "-nographic", "-no-reboot", "-accel", accel,
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


def apps_checks(con, check):
    """Official signed catalogs end to end: plugins (s3-ziro + rclone backups) and apps."""
    rc, out = con.run("ziroctl plugin update", timeout=120)
    check("plugin update: both official catalogs verify", rc == 0 and out.count("✓") == 2, out)
    rc, out = con.run("ziroctl plugin enable s3-ziro --set capacity=1G 2>&1 | tail -1; ziroctl plugin enable rclone-ziro 2>&1 | tail -1; "
                      "ziroctl backup create --remote ziro_s3:ziro-backups 2>&1 | tail -1", timeout=600)
    check("s3-ziro + rclone-ziro: backup uploaded to local S3", "Uploaded to ziro_s3:ziro-backups" in out, out)
    rc, out = con.run("ziroctl apps deploy postgres 2>&1 | tail -2; U=$(ziroctl apps credentials postgres | awk '/^url:/{print $2}'); "
                      "nerdctl exec ziro-app-postgres psql \"$U\" -tAc 'select 40+2'", timeout=900)
    check("apps deploy postgres: ready, credentials work", out.strip().endswith("42"), out)
    rc, out = con.run("ps -o args | grep -c '[p]assword'; ziroctl apps rm postgres | tail -1; ls /etc/ziro/apps/postgres.secrets "
                      "/var/lib/ziro/apps/postgres/0 >/dev/null && echo KEPT", timeout=120)
    check("apps rm keeps data and credentials; no password in argv", out.split()[0] == "0" and "KEPT" in out, out)
    rc, out = con.run("ziroctl apps deploy valkey 2>&1 | tail -1; P=$(ziroctl apps credentials valkey | awk '/^password:/{print $2}'); "
                      "nerdctl exec -e VALKEYCLI_AUTH=$P ziro-app-valkey valkey-cli set k v; "
                      "nerdctl exec ziro-app-valkey sh -c 'for p in /proc/[0-9]*; do grep -q valkey-server $p/cmdline 2>/dev/null && "
                      "awk \"/^Uid/{print \\$2}\" $p/status; done'", timeout=600)
    check("apps deploy valkey: auth works, server not root", "OK" in out and out.split()[-1] != "0", out)
    rc, out = con.run("ziroctl apps rm valkey --purge | tail -1; ziroctl apps rm postgres --purge >/dev/null 2>&1; "
                      "ziroctl cluster init --advertise 10.0.2.15 >/dev/null 2>&1; ziroctl apps deploy mysql-cluster 2>&1 | tail -1", timeout=300)
    check("apps deploy mysql-cluster on a one-node cluster", "deployed" in out, out)
    q = ("R=$(ziroctl apps credentials mysql-cluster | awk '/^root_password:/{print $2}'); "
         "C=$(nerdctl ps --format '{{.Names}}' | grep zc-mysql-cluster-0); "
         "nerdctl exec $C mysql -uroot -p$R -N -e \"SELECT MEMBER_STATE FROM performance_schema.replication_group_members\" 2>/dev/null")
    ok, out = retry(con, q, lambda rc, o: o.count("ONLINE") == 3, 900, every=15)
    check("mysql-cluster: 3 members ONLINE (group replication over pod DNS)", ok, out)


def docker_api_checks(con, check):
    """The opt-in Docker Engine API socket (RFC 0006), and the docker commands Coolify's validation runs."""
    sock = "curl -s --unix-socket /var/run/docker.sock"
    rc, out = con.run("ziroctl docker-api enable 2>&1 | tail -1; sleep 2; ziroctl docker-api status; ls -lL /var/run/docker.sock", timeout=120)
    check("docker-api enable: the socket answers, root-only", "running on" in out and "srw-rw----" in out, out)
    rc, out = con.run(f"{sock} -i http://d/_ping", timeout=30)
    check("docker-api _ping: OK with Api-Version", "OK" in out and "Api-Version" in out, out)
    rc, out = con.run(f"{sock} http://d/v1.43/version; echo; {sock} http://d/info", timeout=60)
    check("docker-api version and info", '"ApiVersion"' in out and '"OSType":"linux"' in out, out)
    rc, out = con.run("nerdctl run -d --name dk-web -l traefik.enable=true -p 8099:80 alpine sleep 3600 2>&1 | tail -1", timeout=300)
    check("container for the docker-api checks", rc == 0, out)
    rc, out = con.run(f"{sock} 'http://d/containers/json'", timeout=60)
    check("docker-api containers/json lists the running container with labels and ports",
          '"/dk-web"' in out and '"Status":"Up"' in out and "traefik.enable" in out and "PublicPort" in out, out, limit=-600)
    rc, out = con.run(f"{sock} http://d/containers/dk-web/json | head -c 300", timeout=60)
    check("docker-api containers/{name}/json is the runtime's inspect document", '"Id"' in out, out)
    rc, out = con.run(f"{sock} http://d/networks | head -c 300", timeout=60)
    check("docker-api networks", out.lstrip().startswith("[") and '"Name"' in out, out)
    # curl -N: without it curl buffers a file's output until it exits and the stream looks empty.
    rc, out = con.run(f"({sock} -N --max-time 25 http://d/events > /tmp/ev.json &); sleep 3; "
                      "nerdctl run -d --name dk-ev alpine sleep 60 >/dev/null 2>&1; sleep 8; "
                      "nerdctl rm -f dk-ev 2>&1 | tail -1; sleep 8; cat /tmp/ev.json; echo ---; nerdctl ps -a --format '{{.Names}} {{.Status}}'; "
                      "tail -5 /var/log/dockerd.log", timeout=120)
    check("docker-api events: start and die/destroy of a container", '"Action":"start"' in out and '"Action":"destroy"' in out, out, limit=-900)
    rc, out = con.run(f"{sock} -o /dev/null -w '%{{http_code}}' -X POST http://d/containers/dk-web/stop?t=1; echo; "
                      "nerdctl ps -q | wc -l", timeout=60)
    check("docker-api stop: 204 and the container is stopped", out.split()[0] == "204" and out.split()[-1] == "0", out)
    rc, out = con.run(f"{sock} -o /dev/null -w '%{{http_code}}' -X DELETE http://d/containers/dk-web; echo; "
                      f"{sock} -o /dev/null -w '%{{http_code}}' -X POST http://d/containers/dk-web/exec; echo; "
                      "grep -c 'POST /containers/dk-web/stop' /var/log/ziro/audit.log", timeout=60)
    check("docker-api remove 204, exec 501, mutations audited", out.split() == ["204", "501", "1"], out)
    # Phase 2: what a deploy tool does through the API: pull, create, start, read logs and inspect, volumes, networks.
    js = "-H 'Content-Type: application/json'"
    rc, out = con.run(f"{sock} -X POST 'http://d/images/create?fromImage=docker.io/library/busybox&tag=1.36' | tail -2", timeout=600)
    check("docker-api image pull streams progress", "Downloaded newer image" in out, out)
    rc, out = con.run(f"{sock} http://d/images/json | head -c 600; echo; {sock} http://d/images/docker.io/library/busybox:1.36/json | head -c 200", timeout=120)
    check("docker-api images list and inspect (name with slashes)", "busybox" in out and '"Id"' in out, out)
    body = ('{"Image":"docker.io/library/busybox:1.36","Cmd":["sh","-c","echo hello-from-api; sleep 3600"],"Env":["FOO=bar"],'
            '"Labels":{"via":"api"},"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"8098"}]},"RestartPolicy":{"Name":"no"}}}')
    rc, out = con.run(f"{sock} -X POST {js} -d '{body}' 'http://d/containers/create?name=dk-api'; echo; "
                      f"{sock} -o /dev/null -w '%{{http_code}}' -X POST http://d/containers/dk-api/start; echo; sleep 3", timeout=120)
    check("docker-api container create (env, labels, port) and start", '"Id"' in out and "204" in out, out)
    rc, out = con.run(f"{sock} 'http://d/containers/dk-api/logs?stdout=1&stderr=1' | grep -a -c hello-from-api; "
                      f"{sock} http://d/containers/dk-api/json | grep -a -c 'FOO=bar'; "
                      f"{sock} 'http://d/containers/json' | grep -a -c '\"via\":\"api\"'", timeout=120)
    check("docker-api logs (multiplexed), inspect env, list labels", out.split() == ["1", "1", "1"], out)
    rc, out = con.run(f"{sock} -X POST {js} -d '{{\"Name\":\"dk-vol\"}}' -o /dev/null -w '%{{http_code}}' http://d/volumes/create; echo; "
                      f"{sock} http://d/volumes | grep -a -c dk-vol; {sock} -o /dev/null -w '%{{http_code}}' -X DELETE http://d/volumes/dk-vol", timeout=120)
    check("docker-api volume create, list, remove", out.split() == ["201", "1", "204"], out)
    rc, out = con.run(f"{sock} -X POST {js} -d '{{\"Name\":\"dk-net\",\"Driver\":\"bridge\"}}' -o /dev/null -w '%{{http_code}}' http://d/networks/create; echo; "
                      f"nerdctl network ls | grep -c dk-net; {sock} -o /dev/null -w '%{{http_code}}' -X DELETE http://d/networks/dk-net; echo; "
                      "nerdctl network ls | grep -c dk-net", timeout=120)
    check("docker-api network create and remove", out.split() == ["201", "1", "204", "0"], out)
    con.run("nerdctl rm -f dk-api >/dev/null 2>&1", timeout=60)
    # What Coolify's Validate Server runs over SSH (non-interactive: a plain sh with its default PATH).
    for cmd in ("docker --version", "docker version", "docker info --format '{{.ServerVersion}}'",
                "docker network ls", "docker compose version", "command -v docker git jq bash curl"):
        rc, out = con.run(f"sh -c \"{cmd}\" 2>/dev/null | head -5", timeout=120)  # stdout: nerdctl warns about buildctl on stderr
        check(f"coolify validation: {cmd}", rc == 0 and out.strip() != "", out)
    con.run("ziroctl docker-api disable >/dev/null 2>&1; nerdctl rm -f dk-web dk-ev >/dev/null 2>&1", timeout=60)


def backup_checks(con, check):
    """Backup and restore end to end, starting from a host that has no /var/backups/ziro (a fresh install)."""
    rc, out = con.run("rm -rf /var/backups/ziro /etc/ziro/backup.key; "
                      "ziroctl backup create --output /var/backups/ziro/ziro-backup-preupgrade-1.0.0-smoke.tar.gz 2>&1 | tail -4; "
                      "ls /var/backups/ziro; ls -l /etc/ziro/backup.key | cut -c1-10", timeout=300)
    check("backup into a missing /var/backups/ziro (the fresh-install upgrade path), key made 0600",
          "preupgrade-1.0.0-smoke.tar.gz.enc" in out and ".sha256" in out and "-rw-------" in out, out)
    con.run("mkdir -p /var/lib/ziro/gateway/certs /var/lib/ziro/volumes /var/lib/ziro/upgrade /var/lib/ziro/apps/db/0 /var/lib/ziro/sandbox/s1 /var/lib/ziro/tailscale; "
            "echo APP > /var/lib/ziro/apps/db/0/data; echo SBX > /var/lib/ziro/sandbox/s1/f; echo TSKEY > /var/lib/ziro/tailscale/node.key; echo CERT-A > /var/lib/ziro/gateway/certs/t.pem; "
            "echo VOL > /var/lib/ziro/volumes/v; echo IMG > /var/lib/ziro/upgrade/i; echo '{\"k\":1}' > /etc/ziro/zz-backup-test.json", timeout=60)
    rc, out = con.run("ziroctl backup create 2>&1 | tail -3; ziroctl backup list", timeout=300)
    name = re.search(r"(ziro-backup-\d{8}-\d{6}\.tar\.gz\.enc)", out)
    check("backup create: encrypted archive with checksum, listed", name is not None and "true" in out, out)
    if not name:
        return
    arc = name.group(1)
    rc, out = con.run(f"ziroctl backup verify {arc} 2>&1 | tail -2", timeout=300)
    check("backup verify: checksum, allowlist and every tag", "every checksum and tag verified" in out, out)
    con.run("head -c32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > /tmp/wrong.key; echo >> /tmp/wrong.key", timeout=30)
    rc, out = con.run(f"grep -c CERT-A /var/backups/ziro/{arc}; ziroctl backup verify {arc} --key-file /tmp/wrong.key 2>&1 | tail -1", timeout=120)
    check("an encrypted archive shows no contents, and a wrong key is refused", out.split()[0] == "0" and "key is wrong" in out, out)
    con.run("echo CERT-B > /var/lib/ziro/gateway/certs/t.pem; rm -f /etc/ziro/zz-backup-test.json; echo NEW > /etc/ziro/zz-new.json", timeout=60)
    rc, out = con.run(f"ziroctl backup restore {arc} --dry-run > /tmp/dry.txt 2>&1; grep -c 'gateway/certs/t.pem' /tmp/dry.txt; "
                      "grep -c 'zz-backup-test.json' /tmp/dry.txt; grep -cE 'lib/ziro/(volumes|apps|sandbox|upgrade|tailscale)|backup.key' /tmp/dry.txt; "
                      "cat /var/lib/ziro/gateway/certs/t.pem", timeout=300)
    check("restore --dry-run lists state, lists none of volumes, app data, sandboxes, upgrade staging, node or backup keys; changes nothing",
          out.split()[:3] == ["1", "1", "0"] and "CERT-B" in out, out)
    rc, out = con.run(f"cp /var/backups/ziro/{arc}.sha256 /tmp/sum.bak; echo 0000 > /var/backups/ziro/{arc}.sha256; "
                      f"ziroctl backup restore {arc} >/dev/null 2>&1; echo RC=$?; cp /tmp/sum.bak /var/backups/ziro/{arc}.sha256; "
                      "cat /var/lib/ziro/gateway/certs/t.pem", timeout=300)
    check("a checksum mismatch makes restore fail (exit 1) and change nothing", "RC=1" in out and "CERT-B" in out, out)
    rc, out = con.run(f"ziroctl backup restore {arc} 2>&1 | tail -4; echo RC=$?; cat /var/lib/ziro/gateway/certs/t.pem; cat /etc/ziro/zz-backup-test.json; "
                      "ls /etc/ziro/zz-new.json 2>&1 | tail -1; ls /var/backups/ziro | grep -c prerestore; ls /var/lib/ziro/volumes /var/lib/ziro/upgrade", timeout=600)
    check("restore: files back as saved, snapshot of the state before it, bulk dirs untouched",
          "RC=0" in out and "CERT-A" in out and '"k":1' in out and "zz-new.json" in out and re.search(r"^[1-9]\s*$", out, re.M) is not None, out)
    rc, out = con.run("ls /var/log/ziro/audit.log >/dev/null && ziroctl audit verify 2>&1 | tail -1", timeout=60)
    check("the audit log survives a restore and still verifies", rc == 0, out)
    rc, out = con.run("for i in 1 2 3; do ziroctl backup create --auto --no-secrets >/dev/null 2>&1; sleep 1; done; "
                      "ziroctl backup prune --keep 1 --keep-safety 1 | tail -1; ls /var/backups/ziro | grep -v sha256 | wc -l", timeout=300)
    check("backup prune --keep 1 --keep-safety 1 leaves one regular and one safety archive per kind", out.split()[-1].isdigit() and int(out.split()[-1]) <= 3, out)
    con.run("rm -f /etc/ziro/zz-backup-test.json /etc/ziro/zz-new.json; rm -rf /var/lib/ziro/gateway/certs/t.pem /var/lib/ziro/volumes /var/lib/ziro/upgrade /var/lib/ziro/apps/db /var/lib/ziro/sandbox/s1 /var/lib/ziro/tailscale", timeout=60)


def nft_accel_checks(con, check):
    """The SYN proxy and the flow offload table, against the kernel: real handshakes and forwarded flows."""
    setup = r"""unshare -n sleep 900 & echo $! > /tmp/spx.pid; sleep 1; A=$(cat /tmp/spx.pid)
/sbin/ip link add spx0 type veth peer name spx1 && /sbin/ip link set spx1 netns $A
/sbin/ip addr add 10.96.0.1/24 dev spx0 && /sbin/ip link set spx0 up
nsenter -t $A -n sh -c '/sbin/ip addr add 10.96.0.2/24 dev spx1; /sbin/ip link set spx1 up; /sbin/ip link set lo up'
ziroctl firewall allow 18080/tcp >/dev/null 2>&1; echo SETUP=$?"""
    rc, out = con.run(setup, timeout=120)
    check("syn proxy: test network up", "SETUP=0" in out, out)
    rc, out = con.run("ziroctl security protect set --synproxy 18080 2>&1 | tail -1; "
                      "nft list table inet ziro_guard | grep -c 'synproxy mss 1460'; "
                      "nft list table inet ziro_guard | grep -c 'notrack'; "
                      "cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose; ziroctl security protect status | grep 'SYN proxy'", timeout=120)
    check("syn proxy: rules loaded, conntrack strict, shown in status", re.findall(r"^\d$", out, re.M)[:3] == ["1", "1", "0"] and "tcp/18080" in out, out)
    rc, out = con.run(r"""A=$(cat /tmp/spx.pid); (echo hello-synproxy | nc -l -p 18080 >/dev/null 2>&1 &); sleep 1
nsenter -t $A -n nc -w 3 10.96.0.1 18080 </dev/null | head -c 20; echo
t=0; while read -r e syn bad valid rest; do [ "$e" = entries ] && continue; t=$((t + 0x$valid)); done </proc/net/stat/synproxy; echo COOKIES=$t""", timeout=120)
    check("syn proxy: a client still connects and the kernel's cookie counter moved",
          "hello-synproxy" in out and (re.search(r"COOKIES=([0-9]+)", out) is not None and int(re.search(r"COOKIES=([0-9]+)", out).group(1)) >= 1), out)
    rc, out = con.run(r"""ziroctl security protect set --no-synproxy >/dev/null 2>&1
nft list table inet ziro_guard | grep -c 'synproxy mss'
A=$(cat /tmp/spx.pid); (echo hello-plain | nc -l -p 18080 >/dev/null 2>&1 &); sleep 1
nsenter -t $A -n nc -w 3 10.96.0.1 18080 </dev/null | head -c 20""", timeout=120)
    check("syn proxy off: rules gone and connections still work", "hello-plain" in out and re.findall(r"^\d$", out, re.M)[:1] == ["0"], out)
    con.run("ziroctl firewall deny 18080/tcp >/dev/null 2>&1; kill $(cat /tmp/spx.pid); /sbin/ip link del spx0 2>/dev/null; true", timeout=60)

    # flow offload: a host that forwards between two namespaces
    fsetup = r"""sysctl -w net.ipv4.ip_forward=1 >/dev/null
unshare -n sleep 900 & echo $! > /tmp/fa.pid
unshare -n sleep 900 & echo $! > /tmp/fb.pid
sleep 1; A=$(cat /tmp/fa.pid); B=$(cat /tmp/fb.pid)
/sbin/ip link add ft0 type veth peer name ft1; /sbin/ip link set ft1 netns $A
/sbin/ip link add ft2 type veth peer name ft3; /sbin/ip link set ft3 netns $B
/sbin/ip addr add 10.97.0.1/24 dev ft0; /sbin/ip link set ft0 up
/sbin/ip addr add 10.98.0.1/24 dev ft2; /sbin/ip link set ft2 up
nsenter -t $A -n sh -c '/sbin/ip addr add 10.97.0.2/24 dev ft1; /sbin/ip link set ft1 up; /sbin/ip link set lo up; /sbin/ip route add default via 10.97.0.1'
nsenter -t $B -n sh -c '/sbin/ip addr add 10.98.0.2/24 dev ft3; /sbin/ip link set ft3 up; /sbin/ip link set lo up; /sbin/ip route add default via 10.98.0.1'
echo FSETUP=$?"""
    rc, out = con.run(fsetup, timeout=120)
    check("flowtable: forwarding test network up", "FSETUP=0" in out, out)
    rc, out = con.run(r"""ziroctl firewall flowtable ft0 ft2 2>&1 | tail -1; ziroctl firewall flowtable
nft list table inet ziro_flow | grep devices | grep -c 'ft0.*ft2'""", timeout=120)
    check("flowtable: loaded for the named interfaces and shown", "flow offload on ft0, ft2" in out and re.findall(r"^\d$", out, re.M)[-1:] == ["1"], out)
    rc, out = con.run(r"""A=$(cat /tmp/fa.pid); B=$(cat /tmp/fb.pid)
(nsenter -t $B -n nc -l -p 9000 >/dev/null 2>&1 &); sleep 1
(sh -c 'dd if=/dev/zero bs=1k count=800 2>/dev/null; sleep 3' | nsenter -t $A -n nc -w 8 10.98.0.2 9000 >/dev/null 2>&1 &)
sleep 6
echo SLOWPATH=$(nft list chain inet ziro_flow forward | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | head -1)""", timeout=120)
    m = re.search(r"SLOWPATH=([0-9]+)", out)
    check("flowtable: a forwarded 800 KB transfer is offloaded (only the handshake takes the slow path)", m is not None and int(m.group(1)) < 40, out)
    rc, out = con.run(r"""ziroctl firewall flowtable off 2>&1 | tail -1; nft list table inet ziro_flow >/dev/null 2>&1; echo GONE=$?
ziroctl firewall flowtable nothere0 2>&1 | tail -2; nft list table inet ziro_flow >/dev/null 2>&1; echo ABSENT=$?
ziroctl firewall flowtable off >/dev/null 2>&1; ziroctl firewall status | head -3""", timeout=120)
    check("flowtable: off removes the table; an interface that does not exist breaks nothing",
          "GONE=1" in out and "ABSENT=1" in out and "inet ziro" not in out.replace("inet ziro_", ""), out)
    con.run("kill $(cat /tmp/fa.pid) $(cat /tmp/fb.pid); /sbin/ip link del ft0 2>/dev/null; /sbin/ip link del ft2 2>/dev/null; true", timeout=60)


def sandbox_checks(con, check):
    rc, out = con.run("ziroctl module enable sandbox 2>&1 | tail -2", timeout=900)
    check("module enable sandbox: gVisor runsc + ziro-sandboxd", "Module sandbox enabled" in out, out)
    rc, out = con.run("ziroctl sandbox create alpine --timeout 10m --meta smoke=1 2>&1 | tail -2", timeout=600)
    sid = out.split()[0] if out.split() else ""
    check("sandbox create (gVisor) runs", "running" in out and len(sid) == 12, out)
    rc, out = con.run(f"ziroctl sandbox exec {sid} -- dmesg | head -1; ziroctl sandbox exec {sid} -- sh -c 'exit 7'; echo RC=$?", timeout=120)
    check("sandbox exec runs under gVisor's kernel and passes the exit code", "gVisor" in out and "RC=7" in out, out)
    rc, out = con.run(f"ziroctl sandbox exec {sid} -- sh -c 'grep CapEff /proc/self/status; ls /sys/class/net; "
                      f"wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1; echo NET=$?'", timeout=120)
    check("sandbox: reduced capabilities, loopback only, no network",
          "00000000000004fb" in out and "NET=0" not in out and "eth0" not in out, out)
    # Observability: list filters, stats from the cgroup, the main command's output.
    rc, out = con.run("o=$(ziroctl sandbox create alpine --timeout 10m --meta obs=1 -- sh -c 'echo OBS-STARTED; sleep 3600' 2>&1 | tail -2 | head -1) && sleep 2 && "
                      "ziroctl sandbox ls --label obs=1 --state running | grep -c \"$o\"; ziroctl sandbox ls --label obs=2 --json; "
                      "ziroctl sandbox stats $o --json; ziroctl sandbox logs $o --tail 5; ziroctl sandbox rm $o >/dev/null", timeout=300)
    check("sandbox ls filters, stats (memory, pids) and logs of the main command",
          "OBS-STARTED" in out and '"memory_bytes":' in out and '"memory_bytes": 0' not in out and "[]" in out, out)
    # Network policy: an allowlisted name works, anything else is refused; open never reaches private ranges.
    rc, out = con.run("ziroctl sandbox create alpine --timeout 10m --allow dl-cdn.alpinelinux.org 2>&1 | tail -2", timeout=300)
    nid = out.split()[0] if out.split() else ""
    rc, out = con.run(f"ziroctl sandbox exec {nid} -- sh -c 'wget -q -T 10 -O /dev/null https://dl-cdn.alpinelinux.org/alpine/ && echo ALLOWED; "
                      f"nslookup example.com >/dev/null 2>&1 || echo NXDOMAIN; wget -q -T 5 -O /dev/null http://1.1.1.1 || echo IPBLOCKED'", timeout=120)
    check("sandbox allowlist: the allowed name works, other names and addresses are refused",
          "ALLOWED" in out and "NXDOMAIN" in out and "IPBLOCKED" in out, out)
    rc, out = con.run(f"ziroctl sandbox network {nid} --net open >/dev/null && ziroctl sandbox exec {nid} -- sh -c "
                      f"'wget -q -T 10 -O /dev/null http://example.com && echo OPEN; wget -q -T 5 -O /dev/null http://169.254.169.254 || echo META; "
                      f"wget -q -T 5 -O /dev/null http://10.0.2.2 || echo LAN; wget -q -T 5 -O /dev/null http://10.250.0.1:8443 || echo HOST'", timeout=120)
    check("sandbox open: the internet, never metadata, the LAN or the host",
          "OPEN" in out and "META" in out and "LAN" in out and "HOST" in out, out)
    con.run(f"ziroctl sandbox rm {nid}", timeout=60)
    # SSH gateway (token in the user name) and the files API.
    rc, out = con.run(f"ziroctl sandbox ssh {sid} -- 'echo via-ssh; exit 5'; echo RC=$?; "
                      f"ziroctl sandbox access create {sid} --ttl 5m | grep -c 'ssh -p 22998 zsbx_'", timeout=120)
    check("sandbox ssh: a session through the gateway passes output and exit status; access prints the ssh command",
          "via-ssh" in out and "RC=5" in out and out.split()[-1] == "1", out)
    rc, out = con.run(f"echo hello > /tmp/up.txt && ziroctl sandbox cp /tmp/up.txt {sid}:/workspace/d/up.txt && "
                      f"ziroctl sandbox exec {sid} -- cat /workspace/d/up.txt && ziroctl sandbox exec {sid} -- sh -c 'ln -s /etc/shadow /workspace/s' && "
                      f"ziroctl sandbox cp {sid}:/workspace/s - 2>&1 | head -1", timeout=120)
    check("sandbox files: upload lands in /workspace; a planted symlink can't read the host", "hello" in out and "root:" not in out, out)
    # Port previews through the gateway (a private domain: the gateway's own CA).
    rc, out = con.run("ziroctl gateway domain set sbx.internal >/dev/null 2>&1; "
                      "ziroctl sandbox create alpine --timeout 10m --net open 2>&1 | tail -2", timeout=300)
    pid = out.split()[0] if out.split() else ""
    rc, out = con.run(f"ziroctl sandbox exec {pid} -- sh -c 'apk add -q busybox-extras && mkdir -p /w && echo preview-ok > /w/index.html && "
                      f"(httpd -p 8080 -h /w >/dev/null 2>&1 &)' && url=$(ziroctl sandbox expose {pid} 8080) && sleep 3 && "
                      f"curl -sk -o /dev/null -w 'NOTOKEN=%{{http_code}}\\n' --resolve 8080-{pid}.sbx.internal:443:127.0.0.1 https://8080-{pid}.sbx.internal/ && "
                      f"curl -sk -L -c /tmp/cj -b /tmp/cj --resolve 8080-{pid}.sbx.internal:443:127.0.0.1 \"$url\"", timeout=300)
    check("sandbox preview: https://<port>-<id>.<domain> needs its token, then serves the sandbox's port",
          "NOTOKEN=401" in out and "preview-ok" in out, out)
    con.run(f"ziroctl sandbox rm {pid}; ziroctl gateway domain rm >/dev/null 2>&1", timeout=120)
    # Credential injection: the sandbox holds a placeholder; the bound host gets the value, another host is refused.
    rc, out = con.run("SMOKE_TOKEN=s3cr3t-value ziroctl sandbox create alpine --timeout 10m --net open "
                      "--secret SMOKE_TOKEN@httpbin.org 2>&1 | tail -2", timeout=300)
    kid = out.split()[0] if out.split() else ""
    rc, out = con.run(f"ziroctl sandbox exec {kid} -- sh -c 'echo IN=$SMOKE_TOKEN; "
                      f"wget -q -T 15 -O- --header \"Authorization: Bearer $SMOKE_TOKEN\" https://httpbin.org/headers; "
                      f"wget -q -T 15 -O- --header \"Host: example.org\" --header \"Authorization: Bearer $SMOKE_TOKEN\" https://httpbin.org/headers 2>&1 | head -2'", timeout=180)
    check("sandbox secrets: a placeholder inside, the value only for its host",
          "IN=zsec_" in out and "Bearer s3cr3t-value" in out and "s3cr3t-value" not in out.split("IN=")[1].split()[0], out)
    con.run(f"ziroctl sandbox rm {kid}", timeout=60)
    # gvisor-kvm: runs where /dev/kvm exists, and says why not elsewhere (QEMU without nested KVM).
    rc, out = con.run("if [ -e /dev/kvm ] || modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null; then "
                      "k=$(ziroctl sandbox create alpine --runtime gvisor-kvm --timeout 5m 2>&1 | tail -2 | head -1) && "
                      "ziroctl sandbox exec $k -- dmesg | head -1 && ziroctl sandbox rm $k >/dev/null; "
                      "else ziroctl sandbox create alpine --runtime gvisor-kvm 2>&1 | tail -1; fi", timeout=300)
    check("sandbox gvisor-kvm: runs on KVM hosts, or refuses clearly without /dev/kvm",
          "Starting gVisor" in out or "needs /dev/kvm" in out, out)
    # Templates, a warm pool (create = resume), snapshots.
    rc, out = con.run("echo '{\"image\":\"alpine\"}' > /tmp/t.json && ziroctl sandbox template add tiny /tmp/t.json >/dev/null && "
                      "echo '{\"pools\":{\"tiny\":1}}' > /etc/ziro/sandbox.json && "
                      "for i in $(seq 60); do ziroctl sandbox ls | grep -q 'paused.*pool:tiny' && break; sleep 2; done; "
                      "s=$(date +%s%N); w=$(ziroctl sandbox create --template tiny 2>/dev/null | head -1); e=$(date +%s%N); "
                      "echo CLAIM_MS=$(( (e - s) / 1000000 )); ziroctl sandbox get $w --json | grep -c '\"owner\": \"root\"'; "
                      "ziroctl sandbox exec $w -- sh -c 'echo snap > /etc/marker; echo ws-kept > /workspace/data; ln -s data /workspace/link' && "
                      "ziroctl sandbox pause $w >/dev/null && img=$(ziroctl sandbox snapshot create $w marker) && ziroctl sandbox get $w | grep -c paused && "
                      "ziroctl sandbox resume $w >/dev/null && "
                      "f=$(ziroctl sandbox create $img 2>/dev/null | head -1) && ziroctl sandbox exec $f -- cat /etc/marker /workspace/link; "
                      "ziroctl sandbox rm $w $f >/dev/null; echo '{}' > /etc/ziro/sandbox.json", timeout=600)
    check("sandbox pool + snapshot: a warm create is a resume; a snapshot (of a paused sandbox) carries the rootfs and /workspace",
          "snap" in out and "ws-kept" in out and "CLAIM_MS=" in out, out)
    # MCP over stdio, through the REST API with a scoped token.
    rc, out = con.run("ziroctl service start ziro-api >/dev/null 2>&1; sleep 3; t=$(ziroctl api token create mcp --role deployer --scope sandboxes 2>/dev/null) && "
                      "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}' "
                      "'{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"sandbox_create\",\"arguments\":{\"image\":\"alpine\",\"timeout\":\"5m\"}}}' "
                      "| ZIRO_API_TOKEN=$t ziroctl sandbox mcp | tail -1 | grep -o 'running' | head -1; "
                      "for i in $(ziroctl sandbox ls --json | grep -o '\"id\": \"[a-z2-7]*\"' | cut -d'\"' -f4); do ziroctl sandbox get $i --json | grep -q '\"owner\": \"mcp\"' && ziroctl sandbox rm $i >/dev/null && echo MCP_OWNED; done", timeout=300)
    check("sandbox mcp: an agent creates a sandbox over MCP, owned by its scoped token", "running" in out and "MCP_OWNED" in out, out)
    # The same tools over Streamable HTTP on the API itself (no ziroctl on the agent's side).
    rc, out = con.run("t=$(ziroctl api token create mcph --role deployer --scope sandboxes 2>/dev/null) && "
                      "m() { curl -sk -H \"Authorization: Bearer $t\" -H 'Content-Type: application/json' https://127.0.0.1:8443/api/v1/sandboxes/mcp -d \"$1\"; echo; }; "
                      "m '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sandbox_create\",\"arguments\":{\"image\":\"alpine\",\"timeout\":\"5m\"}}}' | grep -o '\"state\": *\"running\"' | head -1; "
                      "m '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"sandbox_run_code\",\"arguments\":{\"language\":\"sh\",\"code\":\"echo HTTP-MCP-$((6*7))\"}}}' | grep -o 'HTTP-MCP-42' | head -1; "
                      "m '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"sandbox_list\",\"arguments\":{}}}' | grep -o '\"id\": *\"[a-z2-7]\\{12\\}\"' | cut -d'\"' -f4 | "
                      "while read i; do ziroctl sandbox rm $i >/dev/null && echo HTTP_OWNED; done", timeout=300)
    check("sandbox mcp over HTTP: create and run code through POST /api/v1/sandboxes/mcp with a scoped token",
          "running" in out and "HTTP-MCP-42" in out and "HTTP_OWNED" in out, out)
    # Paused past a reaper pass (15 s) is still paused, and resumes.
    rc, out = con.run(f"ziroctl sandbox pause {sid} && sleep 20 && ziroctl sandbox get {sid} | grep -c paused && "
                      f"ziroctl sandbox resume {sid} && ziroctl sandbox exec {sid} -- echo RESUMED && ziroctl sandbox rm {sid}; "
                      "ziroctl sandbox ls --json; nerdctl ps -a --format '{{.Names}}' | grep -c '^ziro-sbx-'", timeout=120)
    check("sandbox pause survives the reaper, resumes, and rm leaves nothing behind",
          "RESUMED" in out and "[]" in out and out.split()[-1] == "0", out)


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "custom"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    ap.add_argument("--no-pull", action="store_true", help="skip the container run check (no internet)")
    ap.add_argument("--installed", action="store_true", help="also install to a disk and boot it (tiny initramfs)")
    ap.add_argument("--modules", action="store_true", help="also test the clamav module (downloads ~250 MB of signatures)")
    ap.add_argument("--sandbox", action="store_true", help="also test the sandbox module (gVisor, downloads ~170 MB)")
    ap.add_argument("--nft-accel", action="store_true", help="also test the SYN proxy and the flow offload table against the kernel")
    ap.add_argument("--backup", action="store_true", help="also test backup, verify, restore and retention from a host without /var/backups/ziro")
    ap.add_argument("--docker-api", action="store_true", help="also test the Docker API socket and Coolify's docker commands")
    ap.add_argument("--apps", action="store_true",
                    help="also test the official catalogs: s3-ziro backups, apps deploy postgres/valkey, a one-node mysql-cluster (~1.5 GB of images, 4 GB VM)")
    args = ap.parse_args()
    if args.apps or args.modules:
        # Live hosts keep the root filesystem (and ClamAV signatures) in RAM; clamd needs ~1.5 GB.
        os.environ.setdefault("ZIRO_SMOKE_MEM", "6144")

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

    def check(name, passed, detail="", limit=200):
        results.append(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[limit:] if limit < 0 else detail.strip()[:limit]}" if detail and not passed else ""))

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
        if args.flavor == "custom":
            # Hardened Ziro kernel: LSM stack, network defaults, module signing, attack surface.
            rc, out = con.run("cat /sys/kernel/security/lsm; echo; sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc; "
                              "zcat /proc/config.gz | grep -cE '^CONFIG_(INIT_ON_FREE_DEFAULT_ON|FANOTIFY_ACCESS_PERMISSIONS|IMA|MODULE_SIG_FORCE)=y'; "
                              "zcat /proc/config.gz | grep -c '^CONFIG_KEXEC=y'")
            lines = out.split()
            check("custom kernel: ima+landlock+bpf LSMs, bbr/fq, hardening options built in",
                  "ima" in out and "landlock" in out and "bbr" in lines and "fq" in lines and lines[-2:] == ["4", "0"], out)
        # Machine-dependent tuning by ziro-init: zram swap on small hosts, reclaim headroom, I/O
        # schedulers; static sysctls from 99-ziro.conf.
        rc, out = con.run("echo SWAP=$(grep -c zram0 /proc/swaps) MINFREE=$(cat /proc/sys/vm/min_free_kbytes) "
                          "SCHED=$(cat /sys/block/vda/queue/scheduler 2>/dev/null | grep -o '\\[[a-z-]*\\]') "
                          "PIDMAX=$(sysctl -n kernel.pid_max) DIRTY=$(sysctl -n vm.dirty_bytes)")
        m = re.search(r"MINFREE=(\d+)", out)
        check("memory/IO tuning: zram swap, min_free_kbytes >= 16 MiB, pid_max, bounded dirty pages",
              "SWAP=1" in out and m is not None and int(m.group(1)) >= 16384 and "PIDMAX=4194304" in out and "DIRTY=268435456" in out, out)
        if args.flavor == "custom":
            rc, out = con.run("zcat /proc/config.gz | grep -cE '^CONFIG_(PREEMPT_DYNAMIC|PREEMPT_VOLUNTARY|ZRAM|SLAB_BUCKETS|INIT_STACK_ALL_ZERO|IMA_READ_POLICY)=y'; "
                              "zcat /proc/config.gz | grep -c '^CONFIG_IMA_WRITE_POLICY=y'")
            check("custom kernel: dynamic preemption (voluntary), zram, slab buckets, zeroed stacks, IMA policy locked",
                  out.split()[:2] == ["6", "0"], out)
        rc, out = con.run("test -e /dev/fd/0 && test -e /dev/stdin && bash -c 'cat <(echo PSUB)'")
        check("/dev/fd + bash process substitution", "PSUB" in out, out)
        rc, out = con.run("ziroctl wg init >/dev/null && ziroctl wg up && ziroctl wg up && "
                          "wg show wg0 listen-port && ziroctl wg down && echo WGOK")
        check("wireguard init/up/up(idempotent)/down", "WGOK" in out, out)
        rc, out = con.run("ziroctl service start zirocd >/dev/null; for i in 1 2 3 4 5 6 7 8 9 10; do "
                          "zirocd status --json 2>/dev/null | grep -q needs-login && break; sleep 1; done; "
                          "zirocd status --json | grep -q needs-login && zirocd version && echo ZCDOK; "
                          "ziroctl service stop zirocd >/dev/null", timeout=60)
        check("zirocd ships in the image and answers on its control socket (ziro-init service)", "ZCDOK" in out, out)

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

        # Memory protection: platform daemons in ziro/system (reserved memory, OOM-protected),
        # plugin services in ziro/workloads, bounded by their limits; tmpfs mounts capped.
        rc, out = con.run("cat /proc/$(cat /run/sshd.pid)/cgroup /proc/$(cat /run/ziro-sentinel.pid)/cgroup; "
                          "cat /proc/$(cat /run/ziro-sentinel.pid)/oom_score_adj /sys/fs/cgroup/ziro/system/memory.min; "
                          "df -k /tmp /run | awk 'NR>1{print $2}'; awk '/MemTotal/{print $2}' /proc/meminfo")
        f = out.split()
        tmp_kb, run_kb, mem_kb = (int(x) for x in f[-3:]) if len(f) >= 3 and all(x.isdigit() for x in f[-3:]) else (0, 0, 1)
        check("service cgroups: sshd/sentinel in ziro/system, OOM-protected, memory reserved; /tmp and /run capped",
              "0::/ziro/system/sshd" in out and "0::/ziro/system/sentinel" in out and "-900" in f and len(f) > 3 and f[3].isdigit() and int(f[3]) > 0
              and tmp_kb < mem_kb * 0.3 and run_kb < mem_kb * 0.15, out)
        hog = ('{"name":"hog","version":"1","description":"memory hog","services":[{"name":"hog","description":"hog",'
               '"exec":"/usr/bin/tail","args":"/dev/zero","pidfile":"/run/ziro-hog.pid","logfile":"/var/log/hog.log",'
               '"user":"nobody","resources":{"memory":"64Mi"}}]}')
        con.run(f"printf '%s' '{hog}' > /tmp/hog.json && ziroctl plugin install -f /tmp/hog.json >/dev/null 2>&1", timeout=120)
        ok, out = retry(con, "cat /sys/fs/cgroup/ziro/workloads/hog/memory.max /sys/fs/cgroup/ziro/workloads/hog/memory.events",
                        lambda rc, o: "67108864" in o and "oom_kill 0" not in o and "oom_kill" in o, 60)
        # init logs the hog's restarts on this console, so read tagged values, not whole lines.
        rc, out2 = con.run("echo SSHD=$(ziroctl service status sshd | grep -c RUNNING) KILLED=$(ziroctl motd | grep -c 'hog killed')")
        check("plugin over its memory limit is OOM-killed in its own cgroup; sshd unaffected; login summary says so",
              ok and "SSHD=1" in out2 and "KILLED=1" in out2, out + out2)
        con.run("ziroctl plugin disable hog --purge >/dev/null 2>&1; rm -f /tmp/hog.json", timeout=120)

        # Service capabilities: an unprivileged user with exactly the listed capabilities (nothing else in the
        # bounding set), no_new_privs, and a pid that is the daemon itself (the launcher execs it).
        capsvc = ('{"name":"capsvc","version":"1","description":"caps","services":[{"name":"capsvc","description":"caps",'
                  '"exec":"/usr/bin/tail","args":"-f /dev/null","pidfile":"/run/ziro-capsvc.pid","logfile":"/var/log/capsvc.log",'
                  '"user":"nobody","caps":["net_admin","net_raw"]}]}')
        con.run(f"printf '%s' '{capsvc}' > /tmp/capsvc.json && ziroctl plugin install -f /tmp/capsvc.json >/dev/null 2>&1", timeout=120)
        ok, out = retry(con, "P=$(cat /run/ziro-capsvc.pid); grep -E '^(Name|Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$P/status",
                        lambda rc, o: "NoNewPrivs:\t1" in o, 30)
        st = {k: " ".join(v.split()) for k, _, v in (l.partition(":") for l in out.splitlines())}
        check("service caps: runs as nobody with only net_admin+net_raw, no_new_privs set",
              ok and st.get("Name") == "tail" and st.get("Uid") == "65534 65534 65534 65534"
              and all(st.get(k) == "0000000000003000" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")), out)
        con.run("ziroctl plugin disable capsvc --purge >/dev/null 2>&1; rm -f /tmp/capsvc.json", timeout=120)

        # Tailscale module wiring (no tailnet in CI): a stand-in module plus fake binaries exercise what the real
        # one does on enable: its own user, state/socket directories, tun device, tailscaled as that user with
        # only net_admin+net_raw, and the tailnet-only firewall rule.
        # The stand-in declares the plugin directory so the framework records (and purge removes) it, as it
        # does for the real module's artifacts.
        ts_stub = ('{"name":"tailscale","version":"1","description":"smoke stand-in",'
                   '"dirs":[{"path":"/var/lib/ziro/plugins/tailscale","mode":"0755"}]}')
        con.run(f"printf '%s' '{ts_stub}' > /tmp/ts.json && ziroctl plugin install -f /tmp/ts.json >/dev/null 2>&1; "
                "mkdir -p /var/lib/ziro/plugins/tailscale && chmod 755 /var/lib/ziro/plugins/tailscale && "
                "printf '#!/bin/sh\\nexec /usr/bin/tail -f /dev/null\\n' > /var/lib/ziro/plugins/tailscale/tailscaled && "
                "printf '#!/bin/sh\\necho \"$@\" >> /tmp/ts-cli.log\\nexit 0\\n' > /var/lib/ziro/plugins/tailscale/tailscale && "
                "chmod 755 /var/lib/ziro/plugins/tailscale/tailscaled /var/lib/ziro/plugins/tailscale/tailscale", timeout=120)
        # The stand-in tailscaled is a script that execs tail: wait until it has (slow arm64 TCG runners
        # can still show the script, or a restart by the healer, a few seconds later).
        rc, out = con.run("ziroctl tailscale setup 2>&1; echo SETUP=$?; for i in $(seq 30); do P=$(cat /run/ziro-tailscaled.pid 2>/dev/null); "
                          "grep -qx 'Name:.tail' /proc/$P/status 2>/dev/null && break; sleep 1; done; "
                          "grep -E '^(Name|Uid|CapEff|CapBnd|NoNewPrivs):' /proc/$P/status; "
                          "echo TSUID=$(id -u tailscale); "
                          "echo MODES=$(stat -c '%a:%U' /var/lib/ziro/tailscale /run/tailscale /etc/ziro/tailscale/tailscaled.env | tr '\\n' ' '); "
                          "echo TUN=$([ -c /dev/net/tun ] && echo yes); echo ENV=$(grep -c TS_NO_LOGS_NO_SUPPORT /etc/ziro/tailscale/tailscaled.env); "
                          "echo NF=$(grep -c -e 'set --netfilter-mode=off' /tmp/ts-cli.log 2>/dev/null || true)", timeout=120)
        st = {k: " ".join(v.split()) for k, _, v in (l.partition(":") for l in out.splitlines())}
        uid = re.search(r"TSUID=(\d+)", out)
        check("tailscale setup: own user, 0700 state, 0750 socket dir, tun device, tailscaled with only net_admin+net_raw, host firewall left alone",
              "SETUP=0" in out and uid is not None and st.get("Name") == "tail" and st.get("Uid", "").split(" ")[0] == uid.group(1) and uid.group(1) != "0"
              and st.get("CapEff") == "0000000000003000" and st.get("CapBnd") == "0000000000003000" and st.get("NoNewPrivs") == "1"
              and "700:tailscale" in out and "750:tailscale" in out and "600:root" in out and "TUN=yes" in out and "ENV=1" in out
              and re.search(r"NF=[1-9]", out) is not None, out)
        rc, out = con.run("ziroctl tailscale allow ssh >/dev/null 2>&1; "
                          "echo RULE=$(nft list chain inet ziro input | grep -c 'iifname \"tailscale0\" tcp dport 22 accept'); "
                          "ziroctl tailscale ls; ziroctl tailscale deny ssh >/dev/null 2>&1; "
                          "echo GONE=$(nft list chain inet ziro input | grep -c 'iifname \"tailscale0\"')")
        check("tailscale allow ssh opens 22/tcp for tailscale0 only; deny closes it", "RULE=1" in out and "22/tcp" in out and "GONE=0" in out, out)
        # The rule `setup`/`up` adds for a joined node (the unit tests cover that step: ziroctl does not count this
        # stand-in daemon as running, it turns into tail) and a rule of the operator's: teardown removes ours only.
        rc, out = con.run("ziroctl dns forward add smoke.ts.net 100.100.100.100 >/dev/null 2>&1; "
                          "ziroctl dns forward add corp.example 10.0.0.53 >/dev/null 2>&1; "
                          "echo BEFORE=$(grep -c -e 'smoke.ts.net' /etc/ziro/dns.json 2>/dev/null); "
                          "ziroctl tailscale teardown >/dev/null 2>&1; "
                          "echo OURS=$(grep -c -e 'smoke.ts.net' /etc/ziro/dns.json 2>/dev/null); "
                          "echo THEIRS=$(grep -c -e 'corp.example' /etc/ziro/dns.json 2>/dev/null); "
                          "ziroctl dns forward remove corp.example >/dev/null 2>&1; "
                          "ziroctl plugin disable tailscale --purge >/dev/null 2>&1; rm -f /tmp/ts.json /tmp/ts-cli.log", timeout=120)
        check("tailscale teardown removes its tailnet forward and leaves the operator's rules",
              "BEFORE=1" in out and "OURS=0" in out and "THEIRS=1" in out, out)
        rc, out = con.run("echo CONF=$([ -e /etc/ziro/services/tailscaled.conf ] && echo kept || echo gone); echo PLUGIN=$([ -e /var/lib/ziro/plugins/tailscale ] && echo kept || echo gone)")
        check("tailscale disable --purge removes the service and the binaries", "CONF=gone" in out and "PLUGIN=gone" in out, out)

        # Login summary: each address once (no container veths), nothing hardcoded.
        rc, out = con.run("ziroctl motd; echo JSONADDR=$(ziroctl motd --json | grep -c '\"addresses\"')")
        addrs = re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", out.split("Network", 1)[-1].split("\n")[0]) if "Network" in out else []
        check("motd: summary with each address once", rc == 0 and "Memory" in out and len(addrs) == len(set(addrs)) > 0
              and "AI Threat" not in out and "JSONADDR=1" in out, out)
        rc, out = con.run("echo TOP=$(ziroctl system top --once --json | grep -c '\"processes\"') DF=$(ziroctl system df --json | grep -c logs); "
                          "ziroctl system prune --dry-run --only logs,tmp >/dev/null && echo PRUNEOK")
        check("system top snapshot, df, prune dry-run", "TOP=1" in out and "DF=1" in out and "PRUNEOK" in out, out)

        # REST API: one route table drives auth, roles, audit and JSON errors.
        rc, out = con.run("ziroctl service start ziro-api >/dev/null 2>&1; sleep 2; "
                          "A=$(ziroctl api token create smoke-admin --role admin 2>/dev/null); "
                          "V=$(ziroctl api token create smoke-viewer --role viewer 2>/dev/null); "
                          "U=https://127.0.0.1:8443/api/v1; c() { curl -sk -o /tmp/api.out -w '%{http_code}' \"$@\"; }; "
                          "echo NOAUTH=$(c $U/system) FORBID=$(c -X POST -H \"Authorization: Bearer $V\" $U/firewall/allow -d '{\"port\":\"9999/tcp\"}') "
                          "NF=$(c -H \"Authorization: Bearer $A\" $U/nope) CODE=$(grep -o '\"code\":\"[a-z_]*\"' /tmp/api.out) "
                          "READ=$(c -H \"Authorization: Bearer $V\" $U/system/df) "
                          "ALLOW=$(c -X POST -H \"Authorization: Bearer $A\" $U/firewall/allow -d '{\"port\":\"9999/tcp\"}') "
                          "AUDIT=$(grep -c 'api POST /api/v1/firewall/allow' /var/log/ziro/audit.log); "
                          "ziroctl firewall deny 9999/tcp >/dev/null; ziroctl api token revoke smoke-admin >/dev/null; "
                          "ziroctl api token revoke smoke-viewer >/dev/null; ziroctl service stop ziro-api >/dev/null", timeout=120)
        check("api: 401 without token, viewer 403 on change, JSON 404, admin change audited",
              all(k in out for k in ["NOAUTH=401", "FORBID=403", "NF=404", '"code":"not_found"', "READ=200", "ALLOW=200"])
              and re.search(r"AUDIT=[1-9]", out) is not None, out)
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
        # Blocked sources become interval sets and unscoped ports one set rule: the kernel must accept them.
        rc, out = con.run("ziroctl firewall block-ip 203.0.113.0/24 >/dev/null 2>&1; ziroctl firewall block-ip 203.0.113.7 >/dev/null 2>&1; "
                          "ziroctl firewall block-ip 2001:db8::/32 >/dev/null 2>&1; "
                          "ziroctl firewall allow 18081/tcp >/dev/null 2>&1; ziroctl firewall allow 18082/tcp >/dev/null 2>&1; "
                          "nft list set inet ziro blocked4; nft list set inet ziro blocked6; nft list chain inet ziro input", timeout=120)
        check("firewall sets load in nftables (blocked4/blocked6 intervals, merged), ports grouped",
              "203.0.113.0/24" in out and "2001:db8::/32" in out and "ip saddr @blocked4 drop" in out and "ip6 saddr @blocked6 drop" in out
              and "18081, 18082 } accept" in out and "203.0.113.7" not in out, out, limit=-700)
        rc, out = con.run("ziroctl firewall unblock-ip 203.0.113.0/24 >/dev/null 2>&1; ziroctl firewall unblock-ip 203.0.113.7 >/dev/null 2>&1; "
                          "ziroctl firewall unblock-ip 2001:db8::/32 >/dev/null 2>&1; ziroctl firewall deny 18081/tcp >/dev/null 2>&1; "
                          "ziroctl firewall deny 18082/tcp >/dev/null 2>&1; nft list table inet ziro | grep -c 'blocked\\|1808[12]'", timeout=120)
        check("firewall sets removed again when the blocks are lifted", out.split()[-1] == "0", out)

        # Declarative provisioning: a YAML host file with a stack (local app) is applied, a second
        # run plans no change, and the stack comes down cleanly.
        if not args.no_pull:
            app = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "examples",
                                    "provisioning", "shop", "apps", "web", "app.yaml"), "rb").read()
            kv = (b"schema: 1\nname: kv\ndescription: kv\ndefault: '1'\nversions:\n  '1': {images: {kv: "
                  b"'docker.io/valkey/valkey:8-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507'}}\n"
                  b"components: [{name: kv, port: 6379, health: [valkey-cli, ping]}]\noutputs: {url: 'redis://{{host}}:{{port}}'}\n")
            stack = (b"stack: shop\nversion: 1\napps:\n  kv: {app: ./kv.yaml, publish: 16379}\n"
                     b"  web: {app: ./web.yaml, publish: 18080, resources: {memory: 128Mi}, depends_on: [kv], links: {KV_URL: kv.url}}\n")
            host = b"host:\n  version: 1\n  firewall: {allow: [18080/tcp]}\n  stacks: [./shop.yaml]\n"
            files = {"web.yaml": app, "kv.yaml": kv, "shop.yaml": stack, "host.yaml": host}
            cmd = "mkdir -p /tmp/prov && cd /tmp/prov && " + " && ".join(
                f"echo {base64.b64encode(b).decode()} | base64 -d > {n}" for n, b in files.items())
            con.run(cmd)
            # Pulling and starting two containers under emulation (arm64 on a runner without KVM) can run
            # into containerd's own deadlines; apply is idempotent, so a failed first run is retried
            # once. Both outputs are kept: a real bug fails twice, with the reason in the log.
            rc, out = con.run("cd /tmp/prov && { ziroctl apply -f host.yaml >/tmp/apply.out 2>&1 || "
                              "{ cp /tmp/apply.out /tmp/apply.first; echo APPLY_RETRY; sleep 10; ziroctl apply -f host.yaml >/tmp/apply.out 2>&1; }; }; echo APPLY=$?; "
                              "echo SECOND=$(ziroctl apply -f host.yaml --dry-run --json | grep -c '\"action\": \"update\"'); "
                              "echo LIMIT=$(nerdctl inspect ziro-app-shop-web --format '{{.HostConfig.Memory}}'); "
                              "echo WEB=$(wget -qO- http://127.0.0.1:18080/ | grep -c nginx); "
                              "echo LINK=$(nerdctl exec ziro-app-shop-web sh -c 'echo $KV_URL'); "
                              "echo REACH=$(nerdctl exec ziro-app-shop-web sh -c 'nc -z -w 3 ziro-app-shop-kv 6379 && echo yes'); "
                              "ziroctl stack down shop --purge >/dev/null 2>&1; echo DOWN=$(ziroctl apps list | grep -c shop-web); "
                              "ziroctl firewall deny 18080/tcp >/dev/null", timeout=600)
            applied = (all(k in out for k in ["APPLY=0", "SECOND=0", "LIMIT=134217728", "DOWN=0", "LINK=redis://ziro-app-shop-kv:6379", "REACH=yes"])
                       and re.search(r"WEB=[1-9]", out) is not None)
            why = ""
            if not applied:  # the reason (not just the first 200 characters of the result lines)
                why = (out + "\n--- apply.first\n" + con.run("cat /tmp/apply.first 2>/dev/null")[1] +
                       "\n--- apply.out\n" + con.run("cat /tmp/apply.out")[1] +
                       "\n--- containers\n" + con.run("nerdctl ps -a 2>&1 | tail -8; tail -20 /var/log/containerd.log 2>/dev/null")[1])
            check("apply: YAML host file with a stack deploys (limits, link by name), a second apply changes nothing, stack down cleans up",
                  applied, why, limit=-3000)

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

        # Smart DNS (127.0.0.53): local records, blocking, upstream resolution, DHCP interplay.
        rc, out = con.run("ziroctl dns enable 2>&1 | tail -1; head -3 /etc/resolv.conf", timeout=60)
        check("dns enable: resolver up, resolv.conf -> 127.0.0.53", "Smart DNS enabled" in out and "nameserver 127.0.0.53" in out, out)
        rc, out = con.run("ziroctl dns record add db.internal A 10.0.0.20 >/dev/null && ziroctl dns block add blocked.example >/dev/null && "
                          "sleep 3; echo LOCAL=$(nslookup db.internal 2>&1 | grep -c 10.0.0.20); "
                          "echo BLOCKED=$(nslookup ads.blocked.example 2>&1 | grep -c NXDOMAIN); "
                          "echo UPSTREAM=$(nslookup dl-cdn.alpinelinux.org 2>&1 | grep -c '^Address')", timeout=60)
        check("dns: local record, blocked subdomain (NXDOMAIN), upstream names resolve",
              "LOCAL=1" in out and "BLOCKED=0" not in out and "UPSTREAM=0" not in out, out)  # A + AAAA lookups
        rc, out = con.run("kill -USR1 $(cat /run/udhcpc.eth0.pid); sleep 4; "
                          "echo RESOLV=$(grep -c '^nameserver 127.0.0.53' /etc/resolv.conf) DHCPNS=$(grep -c ^nameserver /run/ziro/dhcp-resolv.conf); "
                          "sleep 11; ziroctl dns status --json | grep -o '\"queries\":[0-9]*'", timeout=60)
        check("DHCP renewal feeds the resolver's upstreams (resolv.conf stays on 127.0.0.53); stats",
              "RESOLV=1" in out and "DHCPNS=0" not in out and re.search(r'"queries":[1-9]', out) is not None, out)
        rc, out = con.run("ziroctl dns disable 2>&1 | tail -1; grep -c 127.0.0.53 /etc/resolv.conf; nslookup dl-cdn.alpinelinux.org >/dev/null 2>&1 && echo RESOLVES", timeout=60)
        check("dns disable restores working resolvers", "disabled" in out and "RESOLVES" in out and "\n0\n" in out, out)

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
        rc, out = con.run("ziroctl service restart sshd")
        # restart returns once init has respawned sshd; binding the new port can take a moment
        # on slow (emulated) runners, so wait for it. ';' so a 0 count can't skip the next one.
        ok, out2 = retry(con, "netstat -ltn | grep -c ':2222 '; ps -o args | grep -c '[l]istener'",
                         lambda rc_, o: o.split()[-2:] == ["2", "1"], 15, every=1)
        check("service restart sshd applies new config (one listener)", rc == 0 and ok, out + out2)
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
        if not args.no_pull:
            # Standalone gateway: one-command expose with the internal CA, HTTP->HTTPS, HTTP/3, a TCP route.
            # The upstream is a busybox httpd container (the image is pulled by the container check above).
            rc, out = con.run("mkdir -p /tmp/www && echo gw-ok > /tmp/www/index.html && nerdctl run -d --name gwup -p 127.0.0.1:8081:8080 "
                              "-v /tmp/www:/www docker.io/library/busybox:latest httpd -f -p 8080 -h /www >/dev/null 2>&1; sleep 3; "
                              "ziroctl gateway expose 127.0.0.1:8081 --host smoke.internal --tls internal --name smoke 2>&1 | tail -1; sleep 4; "
                              "ziroctl gateway ca > /tmp/gwca.pem; "
                              "curl -s --cacert /tmp/gwca.pem --resolve smoke.internal:443:127.0.0.1 https://smoke.internal/; "
                              "curl -sI --cacert /tmp/gwca.pem --resolve smoke.internal:443:127.0.0.1 https://smoke.internal/ | grep -ci '^alt-svc: h3'; "
                              "curl -s -o /dev/null -w 'HTTP=%{http_code}\\n' --resolve smoke.internal:80:127.0.0.1 http://smoke.internal/; "
                              "netstat -uln | grep -c ':443 '", timeout=120)
            check("gateway expose: HTTPS with the internal CA, HTTP->HTTPS, HTTP/3 advertised and listening",
                  "is live at https://smoke.internal" in out and "gw-ok" in out and "HTTP=308" in out and out.split()[-1] != "0", out)
            rc, out = con.run("ziroctl gateway route add echo --tcp --listen 9099 --to 127.0.0.1:8081 >/dev/null; sleep 3; "
                              "curl -s http://127.0.0.1:9099/; ziroctl gateway status | grep -c healthy", timeout=60)
            check("gateway tcp route proxies; status reports upstream health", "gw-ok" in out and out.split()[-1] != "0", out)
            rc, out = con.run("ziroctl gateway route rm echo >/dev/null; ziroctl gateway route rm smoke >/dev/null; sleep 2; "
                              "ziroctl service status gateway | grep -c RUNNING; ziroctl firewall list | grep -c 'Ziro gateway'; "
                              "nerdctl rm -f gwup >/dev/null 2>&1", timeout=60)
            check("gateway stops with its last route and closes its firewall ports", out.split()[:2] == ["0", "0"], out)
        # Opt-in modules (need the Alpine repositories, like the container pull above).
        if not args.no_pull:
            rc, out = con.run("ziroctl module enable auditd 2>&1 | tail -3; auditctl -s | head -1; "
                              "touch /etc/ziro/.smoke; sleep 1; ausearch -k ziro-config 2>/dev/null | grep -c '.smoke'", timeout=300)
            check("module enable auditd: installed, rules loaded, changes audited",
                  "Module auditd enabled" in out and "enabled 1" in out and out.split()[-1] != "0", out)
            rc, out = con.run("auditctl -D >/dev/null; ziroctl service boot >/dev/null 2>&1; auditctl -l | grep -c ziro-config")
            check("module rules restored at boot (service boot hooks)", out.split()[-1:] != ["0"] and rc == 0, out)
            if args.flavor == "custom":
                rc, out = con.run("ziroctl plugin enable integrity 2>&1 | tail -1; ziroctl security integrity", timeout=180)
                check("integrity module: IMA policy loaded, every measured system file matches the image",
                      "Module integrity enabled" in out and "every measured system file is intact" in out, out)
                rc, out = con.run("printf '#!/bin/sh\\necho hi\\n' > /usr/bin/zz-smoke && chmod +x /usr/bin/zz-smoke && /usr/bin/zz-smoke >/dev/null; "
                                  "ziroctl security integrity; echo RC=$?; rm -f /usr/bin/zz-smoke", timeout=60)
                check("integrity: a binary outside the image and packages is reported (exit 1)",
                      "/usr/bin/zz-smoke" in out and "RC=1" in out, out)
                con.run("ziroctl plugin disable integrity >/dev/null 2>&1", timeout=60)
            rc, out = con.run("ziroctl plugin purge auditd 2>&1 | tail -1; apk info -e audit; "
                              "ls /etc/ziro/services/auditd.conf /etc/ziro/modules/auditd.json /var/log/auditd-daemon.log 2>&1 | grep -c 'No such'", timeout=120)
            check("plugin purge auditd removes packages, service, state and logs",
                  "Module auditd disabled" in out and out.split()[-1] == "3", out)
            # NFS: the first export installs the server (nfs module); the kernel mounts NFSv4 directly.
            rc, out = con.run("mkdir -p /srv/share && chmod 0777 /srv/share && ziroctl nfs export add /srv/share --clients 127.0.0.1 2>&1 | tail -1; "
                              "cat /proc/fs/nfsd/versions", timeout=600)
            check("nfs export: server installed on demand, NFSv4 only (no v2/v3)",
                  "Exported /srv/share" in out and "-3" in out and "+4.2" in out, out)
            # A fresh NFSv4 server has a 30s grace period: the first write waits for it.
            rc, out = con.run("ziroctl nfs mount 127.0.0.1:/srv/share /mnt/nfs 2>&1 | tail -1; echo hi > /mnt/nfs/t.txt; "
                              "cat /srv/share/t.txt; stat -c %U /srv/share/t.txt; awk '$2==\"/mnt/nfs\"{print $3, $4}' /proc/mounts", timeout=180)
            check("nfs mount (kernel client, v4.2): write lands on the export; root is squashed",
                  "hi" in out and "nobody" in out and "nfs4" in out and "vers=4.2" in out, out)
            rc, out = con.run("ziroctl nfs clients", timeout=30)
            check("nfs clients lists the connected client and its export", "127.0.0.1" in out and "/srv/share" in out, out)
            # --owner: every client write lands as that owner instead of nobody.
            rc, out = con.run("ziroctl nfs umount /mnt/nfs; mkdir -p /srv/owned && "
                              "ziroctl nfs export add /srv/owned --clients 127.0.0.1 --owner 1000:1000 2>&1 | tail -1; "
                              "ziroctl nfs mount 127.0.0.1:/srv/owned /mnt/owned >/dev/null 2>&1; echo hi > /mnt/owned/o.txt; "
                              "stat -c '%u:%g' /srv/owned/o.txt /srv/owned", timeout=120)
            check("nfs export --owner: client writes land as the owner", out.split()[-2:] == ["1000:1000", "1000:1000"], out)
            con.run("ziroctl nfs umount /mnt/owned; ziroctl nfs export remove /srv/owned; ziroctl nfs export remove /srv/share", timeout=60)
        if args.modules:
            rc, out = con.run("(sleep 300 | nc -l -p 9998 > /tmp/av.txt &); "
                              "ziroctl security alerting add av --url http://127.0.0.1:9998/h --events av >/dev/null; "
                              "ziroctl module enable clamav 2>&1 | tail -3", timeout=1800)
            check("module enable clamav (signatures, clamd, freshclam)", "Module clamav enabled" in out, out)
            rc, out = con.run("printf 'X5O!P%%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /root/eicar.com; "
                              "ziroctl security scan --av /root 2>&1 | grep -v alerts; sleep 3; grep -c X-Ziro-Signature /tmp/av.txt", timeout=300)
            check("clamav detects EICAR in a root-only path and alerts", "Eicar" in out and out.split()[-1] == "1", out)
            if args.flavor == "custom":
                # On-access: opening an infected file under a watched path is denied (fanotify).
                rc, out = con.run("ziroctl plugin enable clamav-onaccess 2>&1 | tail -1; sleep 20; "
                                  "cp /root/eicar.com /tmp/eicar.txt 2>/dev/null; cat /tmp/eicar.txt >/dev/null 2>&1; echo CAT_RC=$?; "
                                  "ziroctl plugin disable clamav-onaccess 2>&1 | tail -1; rm -f /tmp/eicar.txt", timeout=300)
                check("clamav-onaccess blocks opening EICAR", "Module clamav-onaccess enabled" in out and "CAT_RC=1" in out, out)
            rc, out = con.run("ziroctl module disable clamav 2>&1 | tail -1; netstat -tln | grep -c 3310", timeout=300)
            check("module disable clamav", "Module clamav disabled" in out, out)
        if args.sandbox and not args.no_pull:
            sandbox_checks(con, check)
        if args.nft_accel:
            nft_accel_checks(con, check)
        if args.backup:
            backup_checks(con, check)
        if args.docker_api and not args.no_pull:
            docker_api_checks(con, check)
        if args.apps:
            apps_checks(con, check)
        # Logging out of a console clears it (screen + scrollback) before the next login prompt.
        with con.lock:
            mark = len(con.buf)
        con.proc.stdin.write(b"exit\n")
        con.proc.stdin.flush()
        cleared = con.wait_for(re.escape("\x1b[H\x1b[2J\x1b[3J"), 30, mark)
        check("console cleared on logout", cleared is not None)
        time.sleep(2)
        con.proc.stdin.write(b"\n")
        con.proc.stdin.flush()
        con.run("stty -echo 2>/dev/null; true", timeout=30)
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

#!/usr/bin/env python3
"""Two-node cluster smoke test: boots two Ziro-OS VMs joined by a private QEMU socket link and checks
cluster init/join, the WireGuard mesh, app deploy across nodes, service discovery
(<app>.cluster.ziro), a rolling update, failure reporting and rollback.

Needs internet in the guests (pulls nginx:alpine). Slow-ish: run nightly / on demand.

usage: tests/qemu/cluster-smoke.py [--arch x86_64|arm64] [--flavor alpine|custom] [--build-dir build]
"""
import argparse
import importlib.util
import json
import os
import platform
import re
import sys
import time

_spec = importlib.util.spec_from_file_location("bootsmoke", os.path.join(os.path.dirname(__file__), "boot-smoke.py"))
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)

LINK_PORT = 47000 + os.getpid() % 1000


def vm(args, idx):
    cmd, accel = bs.qemu_command(args.arch, args.build_dir, args.flavor)
    sock = f"listen=:{LINK_PORT}" if idx == 1 else f"connect=127.0.0.1:{LINK_PORT}"
    cmd += ["-netdev", f"socket,id=n1,{sock}", "-device", f"virtio-net-pci,netdev=n1,mac=52:54:00:77:00:0{idx}"]
    con = bs.Console(cmd, os.path.join(args.build_dir, f"qemu-cluster-{args.arch}-node{idx}.log"))
    if not con.wait_for(re.escape(bs.BOOT_MARKER), args.boot_timeout):
        raise RuntimeError(f"node{idx} did not boot")
    time.sleep(3)
    con.proc.stdin.write(b"\n")
    con.proc.stdin.flush()
    # Private link on the second NIC (the one with our MAC).
    rc, out = con.run(f"IF=$(grep -l 52:54:00:77:00:0{idx} /sys/class/net/*/address | cut -d/ -f5); "
                      f"ip addr add 192.168.77.{idx}/24 dev $IF && ip link set $IF up && echo LINKOK")
    if "LINKOK" not in out:
        raise RuntimeError(f"node{idx} private link: {out}")
    return con


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "alpine"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    args = ap.parse_args()

    results = []

    def check(name, passed, detail=""):
        passed = bool(passed)
        results.append(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[:300]}" if detail and not passed else ""))
        return passed

    m = w = None
    try:
        m = vm(args, 1)
        w = vm(args, 2)

        rc, out = m.run("ziroctl cluster init --advertise 192.168.77.1", timeout=60)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        if not check("cluster init on node1", rc == 0 and tok, out):
            return 1
        rc, out = w.run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} --ca-hash {tok.group(3)}", timeout=60)
        check("node2 joins with env token (not argv)", rc == 0 and "Joined cluster" in out, out)

        ok, out = bs.retry(m, "ziroctl cluster nodes --json",
                           lambda rc, o: o.count('"status": "Ready"') == 2 and o.count('"mesh_ip": "10.200.') == 2, 90)
        check("both nodes Ready with mesh IPs", ok, out)
        ok, out = bs.retry(w, "ping -c1 -W2 10.200.0.1 >/dev/null && echo MESHOK", lambda rc, o: "MESHOK" in o, 90)
        check("WireGuard mesh: node2 -> node1 (10.200.0.1)", ok, out)

        rc, out = m.run("ziroctl cluster deploy --name web --image docker.io/library/nginx:alpine --replicas 2 --port 8080:80")
        check("deploy web x2", rc == 0, out)
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: "2/2 running" in o and "updating" not in o, 400, every=10)
        check("2/2 replicas running across nodes", ok, out)
        rc, out = m.run("ziroctl cluster nodes --json")
        try:
            spread = all(n.get("running") for n in json.loads(out[out.index("["):]))
        except ValueError:
            spread = False
        check("one replica per node (port anti-affinity)", spread, out)

        ok, out = bs.retry(w, "grep -c 'web.cluster.ziro' /etc/hosts; wget -qO- -T5 http://web.cluster.ziro:8080 | grep -o 'Welcome to nginx'",
                           lambda rc, o: "Welcome to nginx" in o, 90)
        check("service discovery: web.cluster.ziro over the mesh", ok, out)

        rc, out = m.run("ziroctl cluster deploy --name web --env RELEASE=2")
        check("patch deploy (env only) keeps image/port", rc == 0 and "revision 2" in out, out)
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: "2/2 running" in o and "updating" not in o, 300, every=5)
        check("rolling update converges to revision 2", ok and re.search(r"web\s+2\s", out) is not None, out)

        rc, out = m.run("ziroctl cluster deploy --name web --image docker.io/library/nginx:does-not-exist-ziro")
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: "error:" in o and "updating" in o, 300, every=10)
        check("bad image: rollout pauses and reports the error", ok, out)
        ok, out = bs.retry(w, "wget -qO- -T5 http://web.cluster.ziro:8080 | grep -o 'Welcome to nginx'",
                           lambda rc, o: "Welcome to nginx" in o, 30)
        check("app keeps serving during the stalled rollout", ok, out)

        rc, out = m.run("ziroctl cluster rollback web")
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: "2/2 running" in o and "updating" not in o and "error" not in o, 300, every=10)
        check("rollback restores a healthy app", ok, out)
    finally:
        for c in (w, m):
            if c:
                c.close()

    print(f"{sum(results)}/{len(results)} cluster checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

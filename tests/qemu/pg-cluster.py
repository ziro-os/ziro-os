#!/usr/bin/env python3
"""Three-node Postgres cluster test: boots three Ziro-OS VMs on one private QEMU multicast link, creates a
`ziroctl pg` cluster with two replicas, writes, kills the primary's node and checks the failover keeps every
committed row, then adds a replica while writing and runs a planned switchover.

Needs internet in the guests (pulls the postgres image). Slow: run nightly / on demand.

Written without access to a QEMU host: run it before relying on it.

usage: tests/qemu/pg-cluster.py [--arch x86_64|arm64] [--flavor alpine|custom] [--build-dir build]
"""
import argparse
import importlib.util
import os
import platform
import re
import sys
import time

_spec = importlib.util.spec_from_file_location("bootsmoke", os.path.join(os.path.dirname(__file__), "boot-smoke.py"))
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)

LINK = f"230.0.{os.getpid() % 200}.1:{47000 + os.getpid() % 1000}"
NODES = 4  # three members and one spare for the replica added later


def vm(args, idx):
    cmd, _ = bs.qemu_command(args.arch, args.build_dir, args.flavor)
    cmd += ["-netdev", f"socket,id=n1,mcast={LINK}", "-device", f"virtio-net-pci,netdev=n1,mac=52:54:00:78:00:0{idx}"]
    con = bs.Console(cmd, os.path.join(args.build_dir, f"qemu-pg-{args.arch}-node{idx}.log"))
    if not con.wait_for(re.escape(bs.BOOT_MARKER), args.boot_timeout):
        raise RuntimeError(f"node{idx} did not boot")
    time.sleep(3)
    con.proc.stdin.write(b"\n")
    con.proc.stdin.flush()
    rc, out = con.run(f"IF=$(grep -l 52:54:00:78:00:0{idx} /sys/class/net/*/address | cut -d/ -f5); "
                      f"ip addr add 192.168.78.{idx}/24 dev $IF && ip link set $IF up && echo LINKOK")
    if "LINKOK" not in out:
        raise RuntimeError(f"node{idx} private link: {out}")
    return con


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "custom"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    args = ap.parse_args()

    results = []

    def check(name, passed, detail=""):
        passed = bool(passed)
        results.append(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[:300]}" if detail and not passed else ""))
        return passed

    vms = []
    try:
        for i in range(1, NODES + 1):
            vms.append(vm(args, i))
        m = vms[0]
        rc, out = m.run("ziroctl cluster init --advertise 192.168.78.1", timeout=60)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        if not check("cluster init", rc == 0 and tok, out):
            return 1
        for w in vms[1:]:
            rc, out = w.run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} --ca-hash {tok.group(3)}", timeout=60)
            check("node joins", rc == 0 and "Joined cluster" in out, out)
        ok, out = bs.retry(m, "ziroctl cluster nodes --json", lambda rc, o: o.count('"status": "Ready"') == NODES, 120)
        check("all nodes Ready", ok, out)

        rc, out = m.run("ziroctl pg create t --replicas 2 --memory 1Gi", timeout=60)
        check("pg create", rc == 0, out)
        ok, out = bs.retry(m, "ziroctl pg status t", lambda rc, o: o.count("primary") >= 1 and o.count("replica") >= 2 and "streaming" in o, 600, every=10)
        check("a primary and two streaming replicas", ok, out)

        # Clients reach the primary through a gateway TCP route on the master (host network).
        rc, out = m.run("ziroctl pg expose t --port 5432", timeout=60)
        check("pg expose", rc == 0, out)
        psql = lambda sql: ("URL=$(ziroctl pg credentials t | sed -n 's/^write: //p' | sed 's/@[^:/]*/@127.0.0.1/'); "
                            f"nerdctl run --rm --network host docker.io/library/postgres:17 psql \"$URL\" -Atc \"{sql}\"")
        rc, out = m.run(psql("create table if not exists t (n int primary key); insert into t select generate_series(1,1000)"), timeout=120)
        check("writes through -rw", rc == 0, out)
        ok, out = bs.retry(m, psql("select count(*) from t"), lambda rc, o: o.strip().endswith("1000"), 60)
        check("reads the rows back", ok, out)

        rc, out = m.run("ziroctl pg status t --json", timeout=30)
        node = re.search(r'"role": "primary"[^}]*"node": "([^"]+)"', out)
        primary_vm = next((v for i, v in enumerate(vms[1:], 2) if node and v.run("hostname")[1].strip() == node.group(1)), None)
        if primary_vm is not None:
            primary_vm.run("poweroff -f", timeout=5)
            ok, out = bs.retry(m, "ziroctl pg status t", lambda rc, o: "promoting" not in o and o.count("primary") == 1 and node.group(1) not in o.split("primary")[0], 300, every=10)
            check("failover moves the primary to another node", ok, out)
            ok, out = bs.retry(m, psql("select count(*) from t"), lambda rc, o: o.strip().endswith("1000"), 120)
            check("every committed row survived the failover", ok, out)
            rc, out = m.run(psql("insert into t values (1001)"), timeout=60)
            check("the new primary takes writes", rc == 0, out)
        else:
            check("find the node of the primary", False, out)

        rc, out = m.run("ziroctl pg add-replica t", timeout=60)
        check("add-replica while the cluster serves writes", rc == 0, out)
        ok, out = bs.retry(m, "ziroctl pg status t", lambda rc, o: o.count("replica") >= 2 and "streaming" in o, 600, every=10)
        check("the new replica catches up", ok, out)

        rc, out = m.run("ziroctl pg switchover t", timeout=120)
        check("planned switchover", rc == 0, out)
        ok, out = bs.retry(m, psql("select count(*) from t"), lambda rc, o: o.strip().endswith("1001"), 120)
        check("no row lost by the switchover", ok, out)
    finally:
        for c in reversed(vms):
            c.close()

    print(f"{sum(results)}/{len(results)} postgres cluster checks passed")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

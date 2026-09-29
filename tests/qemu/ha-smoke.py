#!/usr/bin/env python3
"""HA control-plane smoke test: three Ziro-OS VMs on a full mesh of QEMU point-to-point links form a three-master
Raft control plane (init + 2x join --control-plane). It checks reads and writes through followers,
then kills the leader's VM and checks that a new leader is elected, writes keep working, the dead
master's replicas are rescheduled, and the dead member can be removed.

Needs internet in the guests (pulls nginx:alpine). Slow-ish: run nightly / on demand.

usage: tests/qemu/ha-smoke.py [--arch x86_64|arm64] [--flavor alpine|custom] [--build-dir build]
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

BASE_PORT = 47000 + (os.getpid() % 300) * 3
LINKS = {(1, 2): BASE_PORT, (1, 3): BASE_PORT + 1, (2, 3): BASE_PORT + 2}


def vm(args, idx):
    """Boot node idx with a point-to-point link to every other node (a full mesh: killing one VM
    leaves the other two directly connected). The node's address 192.168.78.idx lives on a dummy
    link and each peer's /32 is routed over the direct link to it."""
    cmd, _ = bs.qemu_command(args.arch, args.build_dir, args.flavor)
    peers = []
    for (a, b), port in LINKS.items():
        if idx not in (a, b):
            continue
        peer = b if idx == a else a
        mode = f"listen=:{port}" if idx == a else f"connect=127.0.0.1:{port}"  # lower index listens (boots first)
        cmd += ["-netdev", f"socket,id=l{peer},{mode}", "-device", f"virtio-net-pci,netdev=l{peer},mac=52:54:00:78:0{idx}:0{peer}"]
        peers.append(peer)
    con = bs.Console(cmd, os.path.join(args.build_dir, f"qemu-ha-{args.arch}-node{idx}.log"))
    if not con.wait_for(re.escape(bs.BOOT_MARKER), args.boot_timeout):
        raise RuntimeError(f"node{idx} did not boot")
    time.sleep(3)
    con.proc.stdin.write(b"\n")
    con.proc.stdin.flush()
    setup = [f"/sbin/ip link add ha0 type dummy && /sbin/ip addr add 192.168.78.{idx}/32 dev ha0 && /sbin/ip link set ha0 up"]
    for peer in peers:
        setup.append(f"IF=$(grep -l 52:54:00:78:0{idx}:0{peer} /sys/class/net/*/address | cut -d/ -f5) && /sbin/ip link set $IF up && "
                     f"/sbin/ip route add 192.168.78.{peer}/32 dev $IF src 192.168.78.{idx}")
    rc, out = con.run(" && ".join(setup) + " && echo LINKOK")
    if "LINKOK" not in out:
        raise RuntimeError(f"node{idx} links: {out}")
    return con


def members(con):
    rc, out = con.run("ziroctl cluster members --json", timeout=30)
    try:
        return json.loads(out[out.index("["):])
    except ValueError:
        return []


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
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[:400]}" if detail and not passed else ""), flush=True)
        return passed

    nodes = {}
    try:
        for i in (1, 2, 3):
            nodes[i] = vm(args, i)
        n1 = nodes[1]
        rc, out = n1.run("ping -c1 -W2 192.168.78.3 >/dev/null && echo HUBOK", timeout=15)
        check("mesh link: node1 <-> node3", "HUBOK" in out, out)

        rc, out = n1.run("ziroctl cluster init --advertise 192.168.78.1", timeout=90)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        check("cluster init prints a CA-pinned join command", rc == 0 and tok, out)
        if not tok:
            return 1
        for i in (2, 3):
            rc, out = nodes[i].run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} "
                                   f"--ca-hash {tok.group(3)} --control-plane", timeout=90)
            check(f"node{i} joins the control plane", rc == 0 and "control-plane master" in out, out)

        ok, out = bs.retry(n1, "ziroctl cluster members --json",
                           lambda rc, o: o.count('"Voter"') == 3 and '"leader": true' in o, 180, every=5)
        check("three voting masters with one leader", ok, out)
        ok, out = bs.retry(n1, "ziroctl cluster nodes --json", lambda rc, o: o.count('"status": "Ready"') == 3, 120, every=5)
        check("all three nodes Ready", ok, out)

        rc, out = n1.run("ziroctl cluster secret set db PASS=ha-secret && "
                         "ziroctl cluster deploy --name web --image docker.io/library/nginx:alpine --replicas 3 --secret db", timeout=60)
        check("deploy web x3 (with a secret)", rc == 0, out)
        for i in (1, 2, 3):
            ok, out = bs.retry(nodes[i], "ziroctl cluster keys status --json",
                               lambda rc, o: '"sealed": true' in o and re.search(r'"local_key": "(\w+)",\s*"cluster_key": "\1"', o), 120, every=5)
            check(f"node{i} holds the cluster data key (secrets sealed)", ok, out)

        # Data key rotation: distributed to every master first, then secrets re-sealed; the old key is retired.
        rc, out = n1.run("ziroctl cluster keys status --json", timeout=30)
        old = re.search(r'"cluster_key": "(\w+)"', out)
        old_key = old.group(1) if old else "missing"
        rc, out = n1.run("ziroctl cluster keys rotate", timeout=60)
        check("data key rotation requested", rc == 0, out)
        for i in (1, 2, 3):
            ok, out = bs.retry(nodes[i], "ziroctl cluster keys status --json",
                               lambda rc, o: re.search(r'"local_key": "(\w+)",\s*"cluster_key": "\1"', o) is not None
                               and old_key not in o and '"next_key"' not in o, 180, every=5)
            if not check(f"node{i} moved to the rotated data key", ok, out):
                for j in (1, 2, 3):  # the masters' own view of what went wrong
                    rc, log = nodes[j].run("grep -i -e 'data key' -e rotat -e 'dek' /var/log/cluster-master.log | tail -8; "
                                           "ls -l /etc/ziro/cluster/dek*.bin", timeout=20)
                    print(f"    node{j} cluster-master.log:\n" + "\n".join("      " + l for l in log.splitlines()), flush=True)
            rc, out = nodes[i].run(f"grep -l {old_key} /etc/ziro/cluster/dek*.bin || echo RETIRED", timeout=15)
            check(f"node{i} no longer stores the retired key", "RETIRED" in out, out)
        ok, out = bs.retry(n1, "ziroctl cluster services", lambda rc, o: "3/3 running" in o and "updating" not in o, 400, every=10)
        check("3/3 replicas running", ok, out)

        # Reads and writes work from any master (followers forward to the leader).
        ms = members(n1)
        leader_id = next((m["id"] for m in ms if m.get("leader")), "")
        ids = {}
        for i in (1, 2, 3):
            rc, out = nodes[i].run("grep -o '\"node_id\": \"[^\"]*' /etc/ziro/cluster/config.json | cut -d'\"' -f4", timeout=15)
            ids[i] = out.strip().splitlines()[-1] if out.strip() else f"?{i}"
        follower = next(i for i in (1, 2, 3) if ids[i] != leader_id)
        rc, out = nodes[follower].run("ziroctl cluster deploy --name web --env RELEASE=2", timeout=60)
        check("write through a follower", rc == 0 and "revision 2" in out, out)
        rc, out = nodes[follower].run("ziroctl cluster services", timeout=30)
        check("read through a follower", "web" in out, out)

        # Kill the leader's VM.
        dead = next(i for i in (1, 2, 3) if ids[i] == leader_id)
        nodes[dead].close()
        del nodes[dead]
        survivor = nodes[min(nodes)]
        def new_leader(o):
            try:
                ms = json.loads(o[o.index("["):])
            except ValueError:
                return False
            return any(m.get("leader") and m["id"] != leader_id for m in ms)
        ok, out = bs.retry(survivor, "ziroctl cluster members --json", lambda rc, o: new_leader(o), 120, every=5)
        check(f"a new leader is elected after the leader ({leader_id}) died", ok, out)
        rc, out = survivor.run("ziroctl cluster deploy --name web --env RELEASE=3", timeout=60)
        check("writes keep working after failover", rc == 0 and "revision 3" in out, out)
        ok, out = bs.retry(survivor, "ziroctl cluster services", lambda rc, o: "3/3 running" in o and "updating" not in o, 400, every=10)
        check("the dead master's replicas are rescheduled (3/3 running on two nodes)", ok, out)
        rc, names = survivor.run("nerdctl ps --filter label=ziro.app=web --format '{{.Names}}'", timeout=20)
        name = re.search(r"zc-web-\S+", names)
        rc, env = survivor.run(f"nerdctl exec {name.group(0) if name else 'missing'} printenv PASS", timeout=20)
        check("containers started by the new leader still get their secret", "ha-secret" in env, env)
        ok, out = bs.retry(survivor, "ziroctl cluster nodes --json", lambda rc, o: o.count('"status": "Ready"') == 2, 120, every=5)
        check("surviving agents keep reporting to the new leader", ok, out)
        rc, out = survivor.run(f"ziroctl cluster member rm {leader_id} && ziroctl cluster members --json", timeout=60)
        try:
            left = [m["id"] for m in json.loads(out[out.index("["):])]
        except ValueError:
            left = []
        check("dead master removed from the control plane", rc == 0 and len(left) == 2 and leader_id not in left, out)
    finally:
        for c in nodes.values():
            c.close()

    print(f"{sum(results)}/{len(results)} HA checks passed")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

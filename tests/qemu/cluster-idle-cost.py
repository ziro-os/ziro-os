#!/usr/bin/env python3
"""What an idle two-node cluster costs: boots two Ziro-OS VMs (the cluster-smoke.py link), forms a
cluster, lets it settle, then measures over a window, per minute:

  - the master's cluster-master process: bytes it writes (/proc/<pid>/io wchar: files, sockets; the test VMs have no disk);
  - each node: processes started (/proc/stat "processes"), i.e. the forks an idle agent makes.

It prints the numbers (no pass/fail): run it before and after a control-plane change.

usage: tests/qemu/cluster-idle-cost.py [--arch x86_64|arm64] [--build-dir build] [--window 120]
"""
import argparse
import importlib.util
import os
import platform
import re
import sys
import time

_here = os.path.dirname(__file__)
_spec = importlib.util.spec_from_file_location("clustersmoke", os.path.join(_here, "cluster-smoke.py"))
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

PROBE = ("p=$(pgrep -f 'ziroctl cluster serve' | head -1); "
         "echo FORKS=$(awk '/^processes/{print $2}' /proc/stat) "
         "WRITES=$( [ -n \"$p\" ] && awk '/^wchar/{print $2}' /proc/$p/io || echo 0)")


# Polls /proc with shell builtins only (the probe itself barely forks); a process that lives
# shorter than one pass can be missed, so counts are a lower bound.
TOP = ("end=$(( $(date +%s) + 40 )); while [ $(date +%s) -lt $end ]; do for p in /proc/[0-9]*; do "
       "{ read -r c < $p/comm; } 2>/dev/null || continue; { read -r s < $p/stat; } 2>/dev/null; set -- $s; "
       "{ read -r pc < /proc/$4/comm; } 2>/dev/null; echo \"${p#/proc/} $c <- $pc\"; done; done > /tmp/s.txt; "
       "sort -u /tmp/s.txt | awk '{print $2, $3, $4}' | grep -v kworker | sort | uniq -c | sort -rn | head -15")


def sample(node):
    _, out = node.run(PROBE, timeout=30)
    m = re.search(r"FORKS=(\d+) WRITES=(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "custom"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    ap.add_argument("--window", type=int, default=120, help="seconds to measure")
    ap.add_argument("--top", action="store_true", help="also list the processes each node starts most often")
    args = ap.parse_args()
    os.environ.setdefault("ZIRO_SMOKE_MEM", "2048")
    m = w = None
    try:
        m, w = cs.vm(args, 1), cs.vm(args, 2)
        _, out = m.run("ziroctl cluster init --advertise 192.168.77.1 --pod-cidr none", timeout=60)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        if not tok:
            print("cluster init failed:\n" + out)
            return 1
        w.run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} --ca-hash {tok.group(3)}", timeout=60)
        time.sleep(60)  # settle: joins, first mesh, certificates
        m0, w0 = sample(m), sample(w)
        time.sleep(args.window)
        m1, w1 = sample(m), sample(w)
        per_min = 60.0 / args.window
        print(f"master: {(m1[1] - m0[1]) * per_min / 1024:.0f} KiB written/min by cluster-master (wchar), "
              f"{(m1[0] - m0[0]) * per_min:.0f} processes started/min", flush=True)
        print(f"worker: {(w1[0] - w0[0]) * per_min:.0f} processes started/min", flush=True)
        if args.top:
            for name, node in (("master", m), ("worker", w)):
                _, out = node.run(TOP, timeout=120)
                print(f"--- {name}: processes seen in 40 s (name <- parent)\n{out}", flush=True)
    finally:
        for c in (m, w):
            if c:
                c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

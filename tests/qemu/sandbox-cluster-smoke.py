#!/usr/bin/env python3
"""Sandboxes on a two-node cluster: boots two Ziro-OS VMs (the cluster-smoke.py link), enables the
sandbox module on both, and checks that the master's API places sandboxes on both nodes, forwards
requests to the node that owns a sandbox, and that the SSH gateway on the master relays a token for
a sandbox on the worker.

Needs internet in the guests (gVisor and an alpine image), ~5 GB of RAM for the two VMs.

usage: tests/qemu/sandbox-cluster-smoke.py [--arch x86_64|arm64] [--flavor alpine|custom] [--build-dir build]
"""
import argparse
import importlib.util
import json
import os
import platform
import re
import sys

_here = os.path.dirname(__file__)
_spec = importlib.util.spec_from_file_location("clustersmoke", os.path.join(_here, "cluster-smoke.py"))
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)
bs = cs.bs


def main():
    ap = argparse.ArgumentParser()
    default_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    ap.add_argument("--arch", default=default_arch, choices=["x86_64", "arm64"])
    ap.add_argument("--flavor", default=os.environ.get("KERNEL_FLAVOR", "custom"), choices=["alpine", "custom"])
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--boot-timeout", type=int, default=600)
    args = ap.parse_args()
    os.environ.setdefault("ZIRO_SMOKE_MEM", "2560")
    results = []

    def check(name, passed, detail=""):
        passed = bool(passed)
        results.append(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f": {detail.strip()[-400:]}" if detail and not passed else ""), flush=True)
        return passed

    m = w = None
    try:
        m = cs.vm(args, 1)
        w = cs.vm(args, 2)
        rc, out = m.run("ziroctl cluster init --advertise 192.168.77.1 --pod-cidr none", timeout=60)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        if not check("cluster init", rc == 0 and tok, out):
            return 1
        rc, out = w.run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} --ca-hash {tok.group(3)}", timeout=60)
        check("worker joins", rc == 0, out)
        for name, node in (("master", m), ("worker", w)):
            rc, out = node.run("ziroctl module enable sandbox 2>&1 | tail -1", timeout=900)
            check(f"sandbox module on the {name}", "Module sandbox enabled" in out, out)
        ok, out = bs.retry(m, "ziroctl cluster nodes --json",
                           lambda rc, o: o.count('"sandbox"') >= 2 and o.count('"status": "Ready"') == 2, 180, every=5)
        check("both nodes report the sandbox capability", ok, out)
        ok, out = bs.retry(w, "cat /etc/ziro/sandbox-mesh.json 2>/dev/null | grep -c 7446", lambda rc, o: o.strip().endswith("1"), 120, every=5)
        check("the worker got its sandbox mesh config", ok, out)

        # The master's API: an agent token, two sandboxes (one per node: the emptier node wins).
        rc, out = m.run("ziroctl service start ziro-api >/dev/null 2>&1; sleep 3; "
                        "ziroctl api token create agent --role deployer --scope sandboxes 2>/dev/null > /tmp/t; wc -c < /tmp/t", timeout=60)
        api = "curl -s --cacert /etc/ziro/tls/server.crt -H \"Authorization: Bearer $(cat /tmp/t)\" https://127.0.0.1:8443/api/v1/sandboxes"
        ids = []
        for i in range(2):
            rc, out = m.run(f"{api} -d '{{\"image\":\"alpine\",\"timeout\":\"15m\"}}'", timeout=600)
            mm = re.search(r'"id":"([a-z2-7]{12})"', out)
            if mm:
                ids.append(mm.group(1))
        check("two sandboxes created through the master", len(ids) == 2, out)
        rc, wout = w.run("ziroctl sandbox ls --json", timeout=30)
        rc, mout = m.run("ziroctl sandbox ls --json", timeout=30)
        remote = next((i for i in ids if i in wout), "")
        check("placement: one sandbox on each node", remote and any(i in mout for i in ids), mout + wout)
        rc, out = m.run(f"{api} | grep -o '\"id\":\"[a-z2-7]*\"' | wc -l", timeout=30)
        check("the master lists both (fan-out)", out.strip().endswith("2"), out)

        # Requests for the worker's sandbox are forwarded there.
        rc, out = m.run(f"{api}/{remote}/exec -d '{{\"command\":[\"sh\",\"-c\",\"echo on-$(hostname)-$((6*7))\"]}}'", timeout=120)
        check("exec through the master runs on the worker", "on-sandbox-42" in out and '"exit_code":0' in out, out)

        # One SSH address: the master's gateway relays a token for the worker's sandbox.
        rc, out = m.run(f"{api}/{remote}/access -d '{{\"ttl\":\"5m\"}}' > /tmp/acc; "
                        "U=$(grep -o 'zsbx_[a-z2-7]*' /tmp/acc | head -1); "
                        "grep -o '\\[[^]]*\\]:22998 ssh-ed25519 [A-Za-z0-9+/=]*' /tmp/acc | sed 's/^\\[[^]]*\\]/[127.0.0.1]/' > /tmp/kh; "
                        "ssh -p 22998 -o UserKnownHostsFile=/tmp/kh -o StrictHostKeyChecking=yes -o PubkeyAuthentication=no -o BatchMode=yes -o LogLevel=ERROR "
                        "$U@127.0.0.1 'echo relayed-from-$(cat /etc/hostname 2>/dev/null || hostname); exit 3'; echo RC=$?", timeout=120)
        check("ssh to the master reaches the worker's sandbox (relay), exit status kept", "relayed-from-sandbox" in out and "RC=3" in out, out)

        # Cluster warm pools: only the worker keeps one; a template create through the master goes there
        # and is a resume (no new container).
        w.run("echo '{\"image\":\"alpine\"}' > /tmp/t.json && ziroctl sandbox template add tiny /tmp/t.json >/dev/null && "
              "echo '{\"pools\":{\"tiny\":1}}' > /etc/ziro/sandbox.json", timeout=60)
        m.run("echo '{\"image\":\"alpine\"}' > /tmp/t.json && ziroctl sandbox template add tiny /tmp/t.json >/dev/null", timeout=60)
        ok, out = bs.retry(w, "ziroctl sandbox ls", lambda rc, o: "paused" in o and "pool:tiny" in o, 300, every=5)
        check("the worker fills its warm pool", ok, out)
        rc, out = m.run(f"{api} -d '{{\"template\":\"tiny\",\"timeout\":\"10m\"}}'", timeout=120)
        pid = re.search(r'"id":"([a-z2-7]{12})"', out)
        rc, wout = w.run(f"ziroctl sandbox get {pid.group(1) if pid else 'none'} --json", timeout=30)
        check("a template create through the master claims the worker's warm sandbox", pid and '"owner": "agent"' in wout and '"running"' in wout, out + wout)
        w.run("echo '{}' > /etc/ziro/sandbox.json", timeout=30)
        if pid:
            m.run(f"curl -s -X DELETE --cacert /etc/ziro/tls/server.crt -H \"Authorization: Bearer $(cat /tmp/t)\" "
                  f"https://127.0.0.1:8443/api/v1/sandboxes/{pid.group(1)} >/dev/null", timeout=60)

        # Delete through the master: gone on the worker and from the directory.
        rc, out = m.run(f"curl -s -X DELETE --cacert /etc/ziro/tls/server.crt -H \"Authorization: Bearer $(cat /tmp/t)\" "
                        f"https://127.0.0.1:8443/api/v1/sandboxes/{remote}", timeout=120)
        rc, wout = w.run("ziroctl sandbox ls --json", timeout=30)
        check("delete through the master removes it on the worker", '"ok"' in out and remote not in wout, out + wout)
        for i in ids:
            m.run(f"curl -s -X DELETE --cacert /etc/ziro/tls/server.crt -H \"Authorization: Bearer $(cat /tmp/t)\" "
                  f"https://127.0.0.1:8443/api/v1/sandboxes/{i} >/dev/null", timeout=60)
    except Exception as e:  # noqa: BLE001 - report and fail
        check("run", False, str(e))
    finally:
        for c in (m, w):
            if c:
                c.close()
    print("ALL OK" if results and all(results) else "FAILURES", flush=True)
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

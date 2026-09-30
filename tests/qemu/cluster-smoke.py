#!/usr/bin/env python3
"""Two-node cluster smoke test: boots two Ziro-OS VMs joined by a private QEMU socket link and checks
cluster init/join, the WireGuard mesh, app deploy across nodes, service discovery
(<app>.cluster.ziro), a rolling update, failure reporting and rollback.

Needs internet in the guests (pulls nginx:alpine). Slow-ish: run nightly / on demand.

usage: tests/qemu/cluster-smoke.py [--arch x86_64|arm64] [--flavor alpine|custom] [--build-dir build]
"""
import argparse
import base64
import hashlib
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

        # Start without the pod network (legacy host-port checks below), then migrate to it.
        rc, out = m.run("ziroctl cluster init --advertise 192.168.77.1 --pod-cidr none", timeout=60)
        tok = re.search(r"ZIRO_CLUSTER_TOKEN=(\w+) ziroctl cluster join (\S+) --ca-hash (\S+)", out)
        if not check("cluster init on node1", rc == 0 and tok, out):
            return 1
        rc, out = w.run(f"ZIRO_CLUSTER_TOKEN={tok.group(1)} ziroctl cluster join {tok.group(2)} --ca-hash {tok.group(3)}", timeout=60)
        check("node2 joins with env token (not argv)", rc == 0 and "Joined cluster" in out, out)

        ok, out = bs.retry(m, "ziroctl cluster nodes --json",
                           lambda rc, o: o.count('"status": "Ready"') == 2 and o.count('"mesh_ip": "10.200.') == 2, 90)
        check("both nodes Ready with mesh IPs", ok, out)

        # An agent from before the cluster CA (pinned to the first master's own certificate)
        # must switch to the CA on its own, over the channel it already trusts.
        rc, pem = m.run("cat /etc/ziro/tls/server.crt", timeout=15)
        b64 = "".join(l for l in pem.splitlines() if l and "CERTIFICATE" not in l)
        legacy = "sha256:" + hashlib.sha256(base64.b64decode(b64 + "==")).hexdigest() if b64 else "missing"
        rc, reset = w.run("ziroctl service stop cluster-agent; "
                        f"sed -i 's#\"ca_hash\": \"[^\"]*\"#\"ca_hash\": \"{legacy}\"#' /etc/ziro/cluster/config.json && "
                        "rm -f /etc/ziro/cluster/ca.crt && ziroctl service start cluster-agent && echo RESET", timeout=60)
        ok, out = bs.retry(w, "grep -o 'ca_hash\": \"[^\"]*' /etc/ziro/cluster/config.json; ls /etc/ziro/cluster/ca.crt",
                           lambda rc, o: tok.group(3) in o and "No such file" not in o, 90, every=5)
        check("a pre-CA agent adopts the cluster CA by itself", "RESET" in reset and ok, reset + out)
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
        rc, out = m.run("C=$(nerdctl ps --filter label=ziro.app=web --format '{{.Names}}' | head -1); "
                        "nerdctl exec $C grep -E 'NoNewPrivs|CapBnd' /proc/1/status")
        # NET_RAW is capability 13: bit 0x2000 must be clear in the bounding set.
        capbnd = re.search(r"CapBnd:\s*([0-9a-f]+)", out)
        check("cluster containers: no-new-privileges and no NET_RAW by default",
              re.search(r"NoNewPrivs:\s*1", out) is not None and capbnd is not None and int(capbnd.group(1), 16) & 0x2000 == 0, out)

        # New clusters default to deny: node2 must not reach the master's replica over the mesh
        # until web allows itself (both nodes run web).
        rc, out = w.run("wget -qO- -T5 http://10.200.0.1:8080 >/dev/null && echo REACHED || echo BLOCKED", timeout=30)
        check("policy: mesh traffic to an app is denied by default", "BLOCKED" in out, out)
        rc, out = m.run("ziroctl cluster deploy --name web --allow-from web")
        check("policy change does not start a new revision", rc == 0 and "unchanged" in out, out)
        ok, out = bs.retry(w, "wget -qO- -T5 http://10.200.0.1:8080 | grep -o 'Welcome to nginx'",
                           lambda rc, o: "Welcome to nginx" in o, 60)
        check("policy: allow_from admits the allowed app's nodes", ok, out)
        rc, out = m.run("ziroctl cluster policy ls --json")
        check("policy ls shows the rule", '"default": "deny"' in out and '"10.200.0.2"' in out, out)

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

        # Pod network: migrate the running cluster; apps roll onto routed pod IPs one by one.
        rc, out = m.run("ziroctl cluster network enable")
        check("pod network enable", rc == 0, out)
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: "2/2 running" in o and "updating" not in o, 400, every=10)
        check("apps roll onto the pod network", ok, out)
        rc, out = m.run("ziroctl cluster network status --json")
        try:
            net = json.loads(out[out.index("{"):])
            ips = {(r["replica"].rsplit("-", 1)[0], r["node"]): r["ip"] for r in net["replicas"]}
        except (ValueError, KeyError):
            ips = {}
        web_master = ips.get(("web", "master-1"), "")
        web_worker = next((ip for (app, node), ip in ips.items() if app == "web" and node != "master-1"), "")
        check("replicas have pod IPs in their node's /24", web_master.startswith("10.201.") and web_worker.startswith("10.201."), out)

        def pod_of(c, app):
            ok, out = bs.retry(c, f"nerdctl ps --filter label=ziro.app={app} --format '{{{{.Names}}}}'",
                               lambda rc, o: f"zc-{app}-" in o, 300, every=10)
            m_ = re.search(rf"zc-{app}-\S+", out)
            return m_.group(0) if m_ else "missing"

        wc = pod_of(w, "web")
        ok, out = bs.retry(w, f"nerdctl exec {wc} wget -qO- -T5 http://{web_master}/ | grep -o 'Welcome to nginx'",
                           lambda rc, o: "Welcome to nginx" in o, 90)
        check("pod network: web pod on node2 reaches web pod on node1 (allow_from web)", ok, out)
        ok, out = bs.retry(w, f"nerdctl exec {wc} wget -qO- -T5 http://web.cluster.ziro/ | grep -o 'Welcome to nginx'",
                           lambda rc, o: "Welcome to nginx" in o, 60)
        check("pod DNS: web.cluster.ziro resolves to pod IPs", ok, out)
        rc, out = w.run(f"nerdctl exec {wc} nslookup docker.io", timeout=30)
        check("pod DNS forwards external names", rc == 0 and "Address" in out.split("docker.io", 1)[-1], out)

        # Smart DNS on a node: cluster-wide records, and <app>.cluster.ziro via the node's pod DNS.
        rc, out = w.run("ziroctl dns enable 2>&1 | tail -1", timeout=60)
        check("node2: smart DNS enabled", "Smart DNS enabled" in out, out)
        rc, out = m.run("ziroctl cluster dns add registry.internal A 10.0.0.40")
        ok, out = bs.retry(w, "nslookup registry.internal 127.0.0.53 2>&1 | grep -c 10.0.0.40", lambda rc, o: o.strip().endswith("1"), 90, every=5)
        check("cluster DNS record resolves on node2 (heartbeat -> host resolver)", ok, out)
        ok, out = bs.retry(w, "nslookup web.cluster.ziro 127.0.0.53 2>&1 | grep -c 'Address.*10.201.'", lambda rc, o: o.strip()[-1:] not in ("", "0"), 60, every=5)
        check("host resolver answers <app>.cluster.ziro through the pod DNS", ok, out)

        # Egress control: the app may reach only its allowed domain (learned from its DNS answers).
        rc, out = m.run("ziroctl cluster deploy --name egr --image docker.io/library/nginx:alpine --replicas 2 "
                        "--egress dl-cdn.alpinelinux.org")
        check("deploy with --egress", rc == 0, out)
        ec = pod_of(w, "egr")
        ok, out = bs.retry(w, f"nerdctl exec {ec} wget -q -O /dev/null -T 8 http://dl-cdn.alpinelinux.org/alpine/ && echo ALLOWED",
                           lambda rc, o: "ALLOWED" in o, 120, every=10)
        check("egress: allowed domain reachable from the app's pod", ok, out)
        rc, out = w.run(f"nerdctl exec {ec} wget -q -O /dev/null -T 5 http://example.com/ 2>&1 || echo BLOCKED_NAME; "
                        f"nerdctl exec {ec} wget -q -O /dev/null -T 5 http://1.1.1.1/ 2>&1 || echo BLOCKED_IP; "
                        "nft list chain inet ziro_egress forward | grep -o 'packets [1-9][0-9]* bytes [0-9]* drop'", timeout=60)
        check("egress: other domains and raw IPs are dropped (counted)", "BLOCKED_NAME" in out and "BLOCKED_IP" in out and "drop" in out, out)
        m.run("ziroctl cluster remove egr")

        rc, out = m.run("ziroctl cluster deploy --name other --image docker.io/library/nginx:alpine --replicas 2")
        oc = pod_of(w, "other")
        rc, out = w.run(f"nerdctl exec {oc} wget -qO- -T5 http://{web_master}/ >/dev/null && echo REACHED || echo BLOCKED", timeout=30)
        check("pod policy: a disallowed app's pod is denied across nodes", "BLOCKED" in out, out)
        rc, out = w.run(f"nerdctl exec {oc} wget -qO- -T5 http://{web_worker}/ >/dev/null && echo REACHED || echo BLOCKED", timeout=30)
        check("pod policy: same-node pod traffic is policed too", "BLOCKED" in out, out)

        # zirogate: api is mesh-only with no allow_from, so under deny only the route admits the
        # gateway (node1) to api's replica on node2.
        rc, out = m.run("ziroctl cluster deploy --name api --image docker.io/library/nginx:alpine --replicas 2 --port 9090:80 --mesh-only")
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: re.search(r"api .*2/2 running", o) is not None, 400, every=10)
        check("mesh-only api x2 running", ok, out)
        rc, out = m.run("ziroctl gateway node enable master-1 && ziroctl gateway route add api --host api.test --app api --tls off --rate 5")
        check("gateway route add", rc == 0, out)
        gw = "curl -s -o /dev/null -w '%{http_code} ' -H 'Host: api.test' http://192.168.77.1/"
        ok, out = bs.retry(w, f"for i in 1 2 3 4 5 6; do {gw}; sleep 0.3; done",
                           lambda rc, o: o.split().count("200") == 6, 120, every=5)
        check("gateway proxies to api on both nodes (route admits the gateway)", ok, out)
        rc, out = w.run(f"for i in $(seq 1 25); do {gw}; done")
        check("gateway rate limit returns 429", "429" in out and "200" in out, out)
        rc, out = w.run("curl -s -o /dev/null -w '%{http_code}' -H 'Host: nope.test' http://192.168.77.1/")
        check("gateway: unknown host is 404", out.strip().endswith("404"), out)

        # Remote peer "alice": a WireGuard client in a netns on node2 (own key, NATed out), relayed by
        # the hub (node1, the gateway) into the mesh. Under deny it reaches api only once allowed.
        rc, out = w.run("umask 077; wg genkey > /tmp/alice.key && wg pubkey < /tmp/alice.key")
        pub = re.search(r"[A-Za-z0-9+/]{43}=", out)
        rc, out = m.run(f"ziroctl gateway peer add alice --pubkey {pub.group(0) if pub else 'missing'}")
        conf = re.search(r"Address = (\S+)/32.*PublicKey = (\S+).*Endpoint = (\S+)", out, re.S)
        check("gateway peer add prints a client config", rc == 0 and conf is not None, out)
        if conf:
            ip, hubkey, ep = conf.groups()
            ns = "/sbin/ip netns exec cli"  # iproute2: /bin/ip is BusyBox (no netns)
            rc, out = w.run(" && ".join([
                "/sbin/ip netns add cli", "/sbin/ip link add vcli0 type veth peer name vcli1", "/sbin/ip link set vcli1 netns cli",
                "/sbin/ip addr add 10.99.0.1/30 dev vcli0", "/sbin/ip link set vcli0 up",
                f"{ns} /sbin/ip addr add 10.99.0.2/30 dev vcli1", f"{ns} /sbin/ip link set vcli1 up", f"{ns} /sbin/ip link set lo up",
                f"{ns} /sbin/ip route add default via 10.99.0.1",
                "iptables -t nat -A POSTROUTING -s 10.99.0.0/30 -j MASQUERADE",
                f"{ns} /sbin/ip link add wgc type wireguard",
                f"{ns} wg set wgc private-key /tmp/alice.key peer {hubkey} endpoint {ep} allowed-ips 10.200.0.0/16 persistent-keepalive 25",
                f"{ns} /sbin/ip addr add {ip}/32 dev wgc", f"{ns} /sbin/ip link set wgc up", f"{ns} /sbin/ip route add 10.200.0.0/16 dev wgc",
                "echo PEERUP"]), timeout=60)
            check("remote peer client configured", "PEERUP" in out, out)
            # Bounded: a ping sent before the WireGuard handshake completes can hang past -W.
            ok, out = bs.retry(w, f"timeout 5 {ns} ping -c1 -W2 10.200.0.2 >/dev/null && echo RELAYOK",
                               lambda rc, o: "RELAYOK" in o, 150)
            check("peer reaches node2 through the hub (relay + return route)", ok, out)
            rc, out = w.run(f"{ns} curl -s -m5 -o /dev/null -w '%{{http_code}}' http://10.200.0.2:9090/ || echo BLOCKED", timeout=30)
            check("policy: peer denied by default", ok and ("BLOCKED" in out or "000" in out), out)
            rc, out = m.run("ziroctl cluster deploy --name api --allow-from peer:alice")
            ok, out = bs.retry(w, f"{ns} curl -s -m5 -o /dev/null -w '%{{http_code}}' http://10.200.0.2:9090/",
                               lambda rc, o: "200" in o, 60)
            allowed = ok
            check("policy: allow_from peer:alice admits the peer", ok, out)
            rc, out = m.run("ziroctl gateway peer rm alice")
            ok, out = bs.retry(w, f"{ns} curl -s -m3 -o /dev/null -w '%{{http_code}}' http://10.200.0.2:9090/ || echo REVOKED",
                               lambda rc, o: "REVOKED" in o or "000" in o, 60)
            check("peer rm revokes access", ok and allowed, out)

        # Secrets at rest: sealed with the cluster data key, delivered to the app, never on disk in clear.
        rc, out = m.run("ziroctl cluster secret set db PASS=hunter2-ziro && "
                        "ziroctl cluster deploy --name sec --image docker.io/library/nginx:alpine --secret db", timeout=60)
        check("secret set + an app that uses it", rc == 0, out)
        ok, out = bs.retry(m, "ziroctl cluster keys status --json",
                           lambda rc, o: '"sealed": true' in o and re.search(r'"local_key": "(\w+)",\s*"cluster_key": "\1"', o), 90, every=5)
        check("cluster secrets sealed with a data key this master holds", ok, out)
        ok, out = bs.retry(m, "ziroctl cluster services", lambda rc, o: re.search(r"sec .*1/1 running", o) is not None, 300, every=10)
        check("app with a secret running", ok, out)
        env = ""
        for c in (m, w):
            rc, names = c.run("nerdctl ps --filter label=ziro.app=sec --format '{{.Names}}'", timeout=20)
            name = re.search(r"zc-sec-\S+", names)
            if name:
                rc, env = c.run(f"nerdctl exec {name.group(0)} printenv PASS", timeout=20)
                break
        check("the app receives the secret", "hunter2-ziro" in env, env)
        rc, out = m.run("test ! -e /etc/ziro/cluster/secrets.json && test ! -e /etc/ziro/cluster/ca.key && "
                        "test -s /etc/ziro/cluster/sealed.bin && ! grep -rqs hunter2-ziro /etc/ziro/cluster && echo ATREST", timeout=30)
        check("no plaintext secret or CA key at rest (state files and Raft data)", "ATREST" in out, out)

        # Image policy: registry allowlist, and cosign signatures (verified against real Docker Hub).
        rc, out = m.run("ziroctl cluster policy images --allow-registry ghcr.io/acme && "
                        "ziroctl cluster deploy --name imgdeny --image docker.io/library/nginx:alpine; echo RC=$?", timeout=60)
        check("image policy: a registry outside the allowlist is refused", "RC=1" in out and "not allowed" in out, out)
        rc, out = m.run("ziroctl cluster policy images --clear >/dev/null && "
                        "printf '%s\\n' '-----BEGIN PUBLIC KEY-----' "
                        "'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECjYMzMj+DYcyMIPM5dwTp7HwV8gn' "
                        "'9bpRs/nAY8KSFROCZAfiNGJfnwZFCgrgytz6ak0AZIlkzrd4lfGxcI6nVQ==' '-----END PUBLIC KEY-----' > /tmp/untrusted.pub; "
                        "ziroctl cluster policy images --require-signed --cosign-key /tmp/untrusted.pub; "
                        "ziroctl cluster deploy --name imgsig --image docker.io/library/nginx:alpine; echo RC=$?", timeout=120)
        check("image policy: an image without a signature by a trusted key is refused (after resolving its digest)",
              "RC=1" in out and "sha256:" in out and ("cosign" in out or "signature" in out), out)
        rc, out = m.run("ziroctl cluster policy images --clear && ziroctl cluster policy images", timeout=30)
        check("image policy cleared", "none" in out, out)

        # Scoped API tokens on the admin API.
        api = "https://127.0.0.1:8443/api/v1"
        rc, out = m.run("ziroctl service start ziro-api; sleep 2; "
                        "V=$(ziroctl api token create viewer1 --role viewer 2>/dev/null); "
                        "O=$(ziroctl api token create ops1 --role operator 2>/dev/null); "
                        f"echo GET=$(curl -sk -o /dev/null -w '%{{http_code}}' -H \"Authorization: Bearer $V\" {api}/system) "
                        f"VPOST=$(curl -sk -o /dev/null -w '%{{http_code}}' -X POST -H \"Authorization: Bearer $V\" {api}/services/crond/restart) "
                        f"OPOST=$(curl -sk -o /dev/null -w '%{{http_code}}' -X POST -H \"Authorization: Bearer $O\" {api}/services/crond/restart); "
                        "ziroctl api token revoke viewer1 >/dev/null; "
                        f"echo REVOKED=$(curl -sk -o /dev/null -w '%{{http_code}}' -H \"Authorization: Bearer $V\" {api}/system)", timeout=90)
        check("API RBAC: viewer reads, viewer cannot act, operator can, revoked is refused",
              all(x in out for x in ("GET=200", "VPOST=403", "OPOST=200", "REVOKED=401")), out)

        # Prometheus metrics with a viewer token.
        rc, out = m.run("P=$(ziroctl api token create prom --role viewer 2>/dev/null); "
                        "curl -sk -H \"Authorization: Bearer $P\" https://127.0.0.1:8443/api/v1/metrics", timeout=60)
        check("metrics: host, services and cluster state in Prometheus format",
              all(x in out for x in ("ziro_up 1", 'ziro_service_up{service="cluster-master"} 1',
                                      'ziro_cluster_app_replicas{app="web",state="running"}',
                                      'ziro_cluster_security{control="secrets_sealed"} 1', "# TYPE ziro_cluster_raft_leader gauge")), out)

        # Credential rotation: node tokens (agents send new ones) and master certificates.
        rc, before = w.run("grep -o 'node_token\": \"[^\"]*' /etc/ziro/cluster/config.json", timeout=15)
        rc, out = m.run("sha256sum /etc/ziro/cluster/master.crt | cut -c1-16; ziroctl cluster rotate tokens && ziroctl cluster rotate certs", timeout=60)
        cert_before = out.strip().splitlines()[0] if out.strip() else ""
        ok, out = bs.retry(w, "grep -o 'node_token\": \"[^\"]*' /etc/ziro/cluster/config.json",
                           lambda rc, o: o.strip() and o.strip() != before.strip(), 90, every=5)
        check("node token rotated by the agent", ok, before + " -> " + out)
        ok, out = bs.retry(m, "sha256sum /etc/ziro/cluster/master.crt | cut -c1-16",
                           lambda rc, o: o.strip() and o.strip() != cert_before, 150, every=10)
        check("master certificate re-issued", ok, out)
        ok, out = bs.retry(m, "ziroctl cluster nodes --json", lambda rc, o: o.count('"status": "Ready"') == 2, 90, every=5)
        check("nodes stay Ready after rotating tokens and certificates", ok, out)

        rc, out = m.run("ziroctl audit verify && ziroctl audit log | grep -c -e 'cluster deploy' -e 'cluster node join'")
        check("audit: chain intact and records deploys and joins", rc == 0 and "chain intact" in out, out)
    finally:
        for c in (w, m):
            if c:
                c.close()

    print(f"{sum(results)}/{len(results)} cluster checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

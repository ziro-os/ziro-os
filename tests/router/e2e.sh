#!/bin/sh
# End-to-end test of the router and zirocd in Docker (Linux containers with real TUN devices):
# a router, device "client" (plain key) and device "web" (tag:web). Checks join, the WireGuard
# tunnel, the default-deny ACL (tcp/8080 only towards tag:web), name resolution and reports
# userspace throughput. Needs docker; runs on amd64 or arm64 hosts.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
work=$(mktemp -d)
net=zr-e2e-$$
cleanup() {
	docker rm -f "$net-router" "$net-client" "$net-web" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	docker run --rm -v "$work:/w" alpine:3.22 rm -rf /w/shared >/dev/null 2>&1 || true # root-owned
	rm -rf "$work"
}
trap cleanup EXIT

echo "== build (linux/$arch)"
(cd "$root/tools/ziroctl" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -o "$work/router.test" ./cmd)
(cd "$root/tools/zirocd" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/zirocd" .)
mkdir -p "$work/shared"

docker network create "$net" >/dev/null
docker run -d --name "$net-router" --network "$net" --network-alias router -v "$work:/w" \
	-e ZIRO_E2E_LISTEN=0.0.0.0:7443 -e ZIRO_E2E_ADVERTISE=router:7443 -e ZIRO_E2E_OUT=/w/shared \
	alpine:3.22 /w/router.test -test.run TestRouterServeE2E -test.v >/dev/null
for d in client web; do
	docker run -d --name "$net-$d" --network "$net" --cap-add NET_ADMIN --device /dev/net/tun -v "$work:/w" \
		alpine:3.22 sh -c 'apk add -q --no-cache iproute2 iperf3 >/dev/null && /w/zirocd daemon' >/dev/null
done
for _ in $(seq 60); do docker exec "$net-router" test -s /w/shared/key-web 2>/dev/null && docker exec "$net-web" test -S /run/zirocd.sock 2>/dev/null && docker exec "$net-client" test -S /run/zirocd.sock 2>/dev/null && break; sleep 1; done

echo "== join"
# The router writes the keys as root (0600): read them through its container, not the host.
key_plain=$(docker exec "$net-router" cat /w/shared/key-plain)
key_web=$(docker exec "$net-router" cat /w/shared/key-web)
[ -n "$key_plain" ] && [ -n "$key_web" ] || { echo "✗ router wrote no keys"; docker logs "$net-router" | tail -20; exit 1; }
docker exec -e ZIROCD_KEY="$key_plain" "$net-client" /w/zirocd up --name client
docker exec -e ZIROCD_KEY="$key_web" "$net-web" /w/zirocd up --name web
ip_of() { docker exec "$net-$1" /w/zirocd status --json | sed -n 's/.*"ipv4": "\([0-9.]*\)".*/\1/p' | head -1; }
for _ in $(seq 30); do
	n=$(docker exec "$net-client" /w/zirocd status --json | grep -c '"name": "web"' || true)
	[ "$n" -ge 1 ] && break; sleep 1
done
cip=$(ip_of client); wip=$(ip_of web)
echo "client=$cip web=$wip"
[ -n "$cip" ] && [ -n "$wip" ] || { docker logs "$net-router" | tail -20; exit 1; }

fail=0
check() { if "$@" >/dev/null 2>&1; then echo "✓ $desc"; else echo "✗ $desc"; fail=1; fi; }
desc="client pings web over the tunnel"; check docker exec "$net-client" ping -c 3 -W 2 "$wip"
desc="web pings client"; check docker exec "$net-web" ping -c 3 -W 2 "$cip"
docker exec -d "$net-web" iperf3 -s -p 8080
docker exec -d "$net-client" iperf3 -s -p 8080
sleep 1
desc="client reaches web:8080 (tag:web rule)"; check docker exec "$net-client" sh -c "nc -z -w 3 $wip 8080"
desc="web cannot reach client:8080 (default deny)"; check sh -c "! docker exec $net-web nc -z -w 3 $cip 8080"
desc="DNS: web.e2e.ziro resolves on the tunnel resolver"
check sh -c "docker exec $net-client nslookup web.e2e.ziro $cip 2>/dev/null | grep -q $wip"
echo "== throughput (userspace WireGuard, client -> web)"
docker exec "$net-client" iperf3 -c "$wip" -p 8080 -t 5 -f m | grep -E "sender|receiver" || true
docker exec "$net-client" /w/zirocd status
exit $fail

#!/bin/sh
# End-to-end test of the router, relays and zirocd in Docker (Linux containers, real TUN devices).
#
#   pub  172.30.0.0/24   router + relay (.10), natA (.11), natB (.12)
#   lanA 172.31.1.0/24   natA (.2) -- client (.10)      each LAN reaches "pub" only through
#   lanB 172.31.2.0/24   natB (.2) -- web (.10)         its NAT (iptables MASQUERADE)
#
# Checks: join; subnet routing (web routes its LAN, approved by the harness); hole punching (direct path between two NATed devices); the default-deny ACL
# (tcp/8080 only towards tag:web); DNS; relay fallback when UDP between the NATs is blocked;
# recovery to a direct path. Reports direct and relayed throughput. Needs docker.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
work=$(mktemp -d)
p=zr-e2e-$$
img=alpine:3.22
cleanup() {
	[ -n "${KEEP:-}" ] && { echo "kept containers with prefix $p"; return; }
	docker rm -f "$p-router" "$p-natA" "$p-natB" "$p-client" "$p-web" "$p-lanhost" >/dev/null 2>&1 || true
	for n in pub lanA lanB; do docker network rm "$p-$n" >/dev/null 2>&1 || true; done
	docker run --rm -v "$work:/w" $img rm -rf /w/shared >/dev/null 2>&1 || true # root-owned
	rm -rf "$work"
}
trap cleanup EXIT

echo "== build (linux/$arch)"
(cd "$root/tools/ziroctl" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -o "$work/router.test" ./cmd)
(cd "$root/tools/zirocd" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/zirocd" .)
mkdir -p "$work/shared"

echo "== topology"
docker network create --subnet 172.30.0.0/24 "$p-pub" >/dev/null
docker network create --internal --subnet 172.31.1.0/24 "$p-lanA" >/dev/null
docker network create --internal --subnet 172.31.2.0/24 "$p-lanB" >/dev/null
docker run -d --name "$p-router" --network "$p-pub" --ip 172.30.0.10 -v "$work:/w" \
	-e ZIRO_E2E_LISTEN=0.0.0.0:7443 -e ZIRO_E2E_ADVERTISE=172.30.0.10:7443 -e ZIRO_E2E_RELAY=172.30.0.10 \
	-e ZIRO_E2E_OUT=/w/shared $img /w/router.test -test.run TestRouterServeE2E -test.v >/dev/null
nat() { # name pubIP lan lanIP
	docker run -d --name "$p-$1" --network "$p-pub" --ip "$2" --cap-add NET_ADMIN \
		--sysctl net.ipv4.ip_forward=1 $img sh -c 'apk add -q --no-cache iptables >/dev/null && sleep infinity' >/dev/null
	docker network connect --ip "$4" "$p-$3" "$p-$1"
}
nat natA 172.30.0.11 lanA 172.31.1.2
nat natB 172.30.0.12 lanB 172.31.2.2
dev() { # name lan ip gw
	docker run -d --name "$p-$1" --network "$p-pub" --cap-add NET_ADMIN --device /dev/net/tun -v "$work:/w" \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
		$img sh -c 'apk add -q --no-cache iproute2 iperf3 iptables >/dev/null && touch /ready && sleep infinity' >/dev/null
	for _ in $(seq 60); do docker exec "$p-$1" test -f /ready 2>/dev/null && break; sleep 1; done
	# Move the device behind its NAT: LAN only, default route via the NAT.
	docker network connect --ip "$3" "$p-$2" "$p-$1"
	docker network disconnect "$p-pub" "$p-$1"
	docker exec "$p-$1" ip route replace default via "$4"
	docker exec -d "$p-$1" /w/zirocd daemon
}
dev client lanA 172.31.1.10 172.31.1.2
dev web lanB 172.31.2.10 172.31.2.2
# A plain host on web's LAN (no zirocd): reached through web as a subnet router.
docker run -d --name "$p-lanhost" --network "$p-lanB" --ip 172.31.2.20 $img sleep infinity >/dev/null
for n in natA natB; do
	for _ in $(seq 60); do docker exec "$p-$n" which iptables >/dev/null 2>&1 && break; sleep 1; done
	docker exec "$p-$n" iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	# Like a home router: devices reach only the public side, never the other private LANs, and
	# unsolicited packets from the WAN are dropped by the firewall (not left in conntrack).
	docker exec "$p-$n" iptables -A FORWARD -o eth0 -d 172.31.0.0/16 -j DROP
	docker exec "$p-$n" iptables -A INPUT -i eth0 -m conntrack --ctstate NEW -j DROP
done
KEEP=${KEEP:-}
for _ in $(seq 60); do docker exec "$p-router" test -s /w/shared/key-web 2>/dev/null && break; sleep 1; done

echo "== join"
# The router writes the keys as root (0600): read them through its container, not the host.
key_plain=$(docker exec "$p-router" cat /w/shared/key-plain)
key_web=$(docker exec "$p-router" cat /w/shared/key-web)
for _ in $(seq 30); do docker exec "$p-client" test -S /run/zirocd.sock 2>/dev/null && docker exec "$p-web" test -S /run/zirocd.sock 2>/dev/null && break; sleep 1; done
docker exec -e ZIROCD_KEY="$key_plain" "$p-client" /w/zirocd up --name client
docker exec -e ZIROCD_KEY="$key_web" "$p-web" /w/zirocd up --name web --advertise-routes 172.31.2.0/24
ip_of() { docker exec "$p-$1" /w/zirocd status --json | sed -n 's/.*"ipv4": "\([0-9.]*\)".*/\1/p' | head -1; }
path_to_web() { docker exec "$p-client" /w/zirocd status --json | sed -n 's/.*"path": "\([^"]*\)".*/\1/p' | head -1; }
cip=$(ip_of client); wip=$(ip_of web)
echo "client=$cip web=$wip"

fail=0
check() { if "$@" >/dev/null 2>&1; then echo "✓ $desc"; else echo "✗ $desc"; fail=1; fi; }
wait_path() { # prefix seconds
	for _ in $(seq "$2"); do
		docker exec "$p-client" ping -c 1 -W 1 "$wip" >/dev/null 2>&1 || true
		case $(path_to_web) in "$1"*) return 0 ;; esac
		sleep 1
	done
	return 1
}
desc="client pings web (two NATs apart)"; check docker exec "$p-client" ping -c 3 -W 2 "$wip"
desc="hole punching: direct path through both NATs"; check wait_path direct 20
echo "  path: $(path_to_web)"
desc="web pings client"; check docker exec "$p-web" ping -c 3 -W 2 "$cip"
docker exec -d "$p-web" iperf3 -s -p 8080
docker exec -d "$p-client" iperf3 -s -p 8080
sleep 1
desc="client reaches web:8080 (tag:web rule)"; check docker exec "$p-client" nc -z -w 3 "$wip" 8080
desc="web cannot reach client:8080 (default deny)"; check sh -c "! docker exec $p-web nc -z -w 3 $cip 8080"
desc="DNS: web.e2e.ziro resolves on the tunnel resolver"
check sh -c "docker exec $p-client nslookup web.e2e.ziro $cip 2>/dev/null | grep -q $wip"
desc="subnet router: client reaches a plain host on web's LAN through web"
check sh -c "for i in \$(seq 15); do docker exec $p-client ping -c 1 -W 1 172.31.2.20 && exit 0; sleep 1; done; exit 1"
echo "== throughput direct (userspace WireGuard through two NATs)"
docker exec "$p-client" iperf3 -c "$wip" -p 8080 -t 4 -f m | grep receiver || true

echo "== block UDP between the NATs: traffic must move to the relay"
for n in natA natB; do
	other=172.30.0.12; [ $n = natB ] && other=172.30.0.11
	docker exec "$p-$n" iptables -I FORWARD -p udp -d $other -j DROP
	docker exec "$p-$n" iptables -I FORWARD -p udp -s $other -j DROP
	docker exec "$p-$n" iptables -I OUTPUT -p udp -d $other -j DROP
done
desc="relay fallback within 15s"; check wait_path relay 15
echo "  path: $(path_to_web)"
desc="ping over the relay"; check docker exec "$p-client" ping -c 3 -W 2 "$wip"
echo "== throughput relayed (TLS relay)"
docker exec "$p-client" iperf3 -c "$wip" -p 8080 -t 4 -f m | grep receiver || true
for n in natA natB; do
	other=172.30.0.12; [ $n = natB ] && other=172.30.0.11
	docker exec "$p-$n" iptables -D FORWARD -p udp -d $other -j DROP
	docker exec "$p-$n" iptables -D FORWARD -p udp -s $other -j DROP
	docker exec "$p-$n" iptables -D OUTPUT -p udp -d $other -j DROP
done
desc="back to a direct path once UDP returns"; check wait_path direct 20
echo "  path: $(path_to_web)"
docker exec "$p-client" /w/zirocd netcheck || true
[ $fail = 0 ] || docker logs "$p-router" 2>&1 | tail -20
exit $fail

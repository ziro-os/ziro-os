#!/bin/sh
# End-to-end test of the router, relays and zirocd in Docker (Linux containers, real TUN devices).
#
#   pub  172.30.0.0/24   router + relay (.10), natA (.11), natB (.12)
#   lanA 172.31.1.0/24   natA (.2) -- client (.10)      each LAN reaches "pub" only through
#   lanB 172.31.2.0/24   natB (.2) -- web (.10)         its NAT (iptables MASQUERADE)
#
# Checks: join; sign-in (OIDC device flow, fake provider in the router harness); subnet routing (web routes its LAN, approved by the harness); hole punching (direct path between two NATed devices); the default-deny ACL
# (tcp/8080 only towards tag:web); DNS; relay fallback when UDP between the NATs is blocked;
# UDP relay, TLS relay when UDP to the relay is blocked too; recovery to a direct path. Reports direct and relayed throughput. Needs docker.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')
work=$(mktemp -d)
p=zr-e2e-$$
img=alpine:3.22
cleanup() {
	[ -n "${KEEP:-}" ] && { echo "kept containers with prefix $p"; return; }
	docker rm -f "$p-router" "$p-natA" "$p-natB" "$p-natC" "$p-client" "$p-web" "$p-lanhost" "$p-laptop" >/dev/null 2>&1 || true
	for n in pub lanA lanB lanC; do docker network rm "$p-$n" >/dev/null 2>&1 || true; done
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
		--sysctl net.ipv4.ip_forward=1 $img sh -c 'apk add -q --no-cache iptables conntrack-tools miniupnpd >/dev/null && sleep infinity' >/dev/null
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
	docker exec -d -e ZIROCD_DEBUG=disco "$p-$1" sh -c '/w/zirocd daemon > /tmp/zirocd.log 2>&1'
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
path_to_web() { # the path of the peer named web (peers are sorted by name)
	docker exec "$p-client" /w/zirocd status --json |
		awk '/"name": "web"/ {w=1} w && /"path"/ {sub(/.*"path": "/, ""); sub(/".*/, ""); print; exit}'
}
cip=$(ip_of client); wip=$(ip_of web)
echo "client=$cip web=$wip"

fail=0
check() { if "$@" >/dev/null 2>&1; then echo "✓ $desc"; else echo "✗ $desc"; fail=1; fi; }
wait_path() { # prefix seconds
	for _ in $(seq "$2"); do
		docker exec "$p-client" ping -c 1 -W 1 "$wip" >/dev/null 2>&1 || true
		# shellcheck disable=SC2254 # $1 is a glob on purpose ("relay r? udp")
		case $(path_to_web) in $1*) return 0 ;; esac
		sleep 1
	done
	return 1
}
# First contact may cost one WireGuard handshake retry (5s) while both netmaps settle.
desc="client pings web (two NATs apart)"
check sh -c "for i in \$(seq 10); do docker exec $p-client ping -c 1 -W 1 $wip && exit 0; sleep 1; done; exit 1"
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
echo "== sign-in (OIDC device flow through the router)"
docker run -d --name "$p-laptop" --network "$p-pub" --cap-add NET_ADMIN --device /dev/net/tun -v "$work:/w" \
	$img sh -c 'apk add -q --no-cache iproute2 >/dev/null; /w/zirocd daemon' >/dev/null
for _ in $(seq 60); do docker exec "$p-laptop" test -S /run/zirocd.sock 2>/dev/null && break; sleep 1; done
key_sso=$(docker exec "$p-router" cat /w/shared/key-sso)
docker exec -e ZIROCD_KEY="$key_sso" "$p-laptop" /w/zirocd up --sso --name laptop | sed 's/^/  /'
desc="signed-in device is connected, as alice with an expiring key"
check sh -c "docker exec $p-laptop /w/zirocd status | grep -q 'signed in until'"
# A first handshake can reach web just before web's netmap lists laptop: WireGuard retries in 5s.
desc="signed-in device pings web"
check sh -c "for i in \$(seq 10); do docker exec $p-laptop ping -c 1 -W 1 $wip && exit 0; sleep 1; done; exit 1"
echo "== throughput direct (userspace WireGuard through two NATs)"
docker exec "$p-client" iperf3 -c "$wip" -p 8080 -t 4 -f m | grep receiver || true

echo "== block UDP between the NATs: traffic must move to the relay"
for n in natA natB; do
	other=172.30.0.12; [ $n = natB ] && other=172.30.0.11
	docker exec "$p-$n" iptables -I FORWARD -p udp -d $other -j DROP
	docker exec "$p-$n" iptables -I FORWARD -p udp -s $other -j DROP
	docker exec "$p-$n" iptables -I OUTPUT -p udp -d $other -j DROP
done
desc="relay fallback within 15s, as UDP datagrams"; check wait_path "relay r? udp" 15
echo "  path: $(path_to_web)"
# web may still trust its dead direct path for a few seconds: allow for it.
desc="ping over the UDP relay"
check sh -c "for i in \$(seq 10); do docker exec $p-client ping -c 1 -W 1 $wip && exit 0; sleep 1; done; exit 1"
echo "== throughput relayed (UDP relay)"
docker exec "$p-client" iperf3 -c "$wip" -p 8080 -t 4 -f m | grep receiver || true
echo "== block UDP to the relay too: relayed traffic must move to TLS"
for n in natA natB; do docker exec "$p-$n" iptables -I FORWARD -p udp -d 172.30.0.10 --dport 3478:3479 -j DROP; done
desc="TLS relay fallback within 15s"; check wait_path "relay r? tls" 15
echo "  path: $(path_to_web)"
# Each side notices the dead UDP session on its own (within ~8s): allow for the other one.
desc="ping over the TLS relay"
check sh -c "for i in \$(seq 10); do docker exec $p-client ping -c 1 -W 1 $wip && exit 0; sleep 1; done; exit 1"
echo "== throughput relayed (TLS relay)"
docker exec "$p-client" iperf3 -c "$wip" -p 8080 -t 4 -f m | grep receiver || true
for n in natA natB; do docker exec "$p-$n" iptables -D FORWARD -p udp -d 172.30.0.10 --dport 3478:3479 -j DROP; done
desc="back to the UDP relay once UDP to it returns"; check wait_path "relay r? udp" 15
for n in natA natB; do
	other=172.30.0.12; [ $n = natB ] && other=172.30.0.11
	docker exec "$p-$n" iptables -D FORWARD -p udp -d $other -j DROP
	docker exec "$p-$n" iptables -D FORWARD -p udp -s $other -j DROP
	docker exec "$p-$n" iptables -D OUTPUT -p udp -d $other -j DROP
done
desc="back to a direct path once UDP returns"; check wait_path direct 20
echo "  path: $(path_to_web)"

echo "== roaming: client moves to another LAN behind another NAT"
docker network create --internal --subnet 172.31.3.0/24 "$p-lanC" >/dev/null
nat natC 172.30.0.13 lanC 172.31.3.2
for _ in $(seq 60); do docker exec "$p-natC" which iptables >/dev/null 2>&1 && break; sleep 1; done
docker exec "$p-natC" iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
docker exec "$p-natC" iptables -A FORWARD -o eth0 -d 172.31.0.0/16 -j DROP
docker exec "$p-natC" iptables -A INPUT -i eth0 -m conntrack --ctstate NEW -j DROP
docker network connect --ip 172.31.3.10 "$p-lanC" "$p-client"
docker network disconnect "$p-lanA" "$p-client"
docker exec "$p-client" ip route replace default via 172.31.3.2
desc="direct again within 20s of roaming"; check wait_path direct 20
echo "  path: $(path_to_web)"

# A hard NAT gives each destination its own random port (here from a 32-port pool).
echo "== hard NAT on natB: client (easy NAT) must reach web by probing its ports"
docker exec "$p-natB" iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
docker exec "$p-natB" iptables -t nat -A POSTROUTING -o eth0 -p udp -j MASQUERADE --to-ports 40000-40031 --random
docker exec "$p-natB" iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
docker exec "$p-natB" conntrack -F >/dev/null 2>&1 || true
nat_is() { # device nat
	for _ in $(seq 30); do
		docker exec "$p-$1" /w/zirocd netcheck --json 2>/dev/null | grep -q "\"nat\": \"$2\"" && return 0
		sleep 1
	done
	return 1
}
desc="web detects its hard NAT (two relays see different ports)"; check nat_is web hard
desc="direct path through the hard NAT, on a port found by probing (40000-40031)"
check wait_path "direct 172.30.0.12:400[0-3]" 60
echo "  path: $(path_to_web)"

echo "== port mapping against a real gateway (miniupnpd: PCP, NAT-PMP, UPnP IGD)"
# miniupnpd maps only for a public WAN address; legacy iptables chains for its netfilter backend.
docker exec "$p-natB" sh -c 'apk add -q --no-cache iptables-legacy >/dev/null 2>&1; ip addr add 11.22.33.44/32 dev eth0
	iptables-legacy -t nat -N MINIUPNPD; iptables-legacy -t nat -A PREROUTING -i eth0 -j MINIUPNPD
	iptables-legacy -t nat -N MINIUPNPD-POSTROUTING; iptables-legacy -t nat -A POSTROUTING -o eth0 -j MINIUPNPD-POSTROUTING
	iptables-legacy -N MINIUPNPD; iptables-legacy -A FORWARD -i eth0 ! -o eth0 -j MINIUPNPD
	printf "%s\n" ext_ifname=eth0 ext_ip=11.22.33.44 listening_ip=eth1 enable_natpmp=yes enable_upnp=yes secure_mode=yes \
		uuid=3d3cec3a-8cf0-11e0-98ee-001a6bd2d07b "allow 1024-65535 172.31.2.0/24 1024-65535" "deny 0-65535 0.0.0.0/0 0-65535" > /etc/miniupnpd/t.conf
	miniupnpd -f /etc/miniupnpd/t.conf'
desc="web maps its WireGuard port on the gateway"
check sh -c "for i in \$(seq 45); do docker exec $p-web /w/zirocd netcheck --json | grep -q '\"mapped\": \"11.22.33.44:' && exit 0; sleep 1; done; exit 1"
docker exec "$p-web" /w/zirocd netcheck | grep -E "Port mapping|NAT:" | sed 's/^/  /'
docker exec "$p-client" /w/zirocd netcheck || true
[ $fail = 0 ] || docker logs "$p-router" 2>&1 | tail -20
exit $fail

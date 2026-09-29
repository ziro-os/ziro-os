# zirogate: cluster ingress

zirogate is the cluster's HTTP(S) entry point. It is built into `ziroctl`, runs as the `gateway` service on the nodes you pick, and routes by host and path to cluster apps over the WireGuard mesh. It needs no Traefik, Nginx, Caddy or Envoy image and has no config files to hand-edit.

## Quick start

```sh
# On the master
ziroctl cluster deploy --name web --image nginx:alpine --replicas 3 --port 8080:80 --mesh-only
ziroctl gateway node enable master-1              # any number of nodes; each serves :80/:443
ziroctl gateway acme --email ops@example.com      # once, for TLS certificates
ziroctl gateway route add web --host www.example.com --app web
ziroctl gateway route add api --host www.example.com --path /api --app api \
    --rate 50 --allow-cidr 203.0.113.0/24 --max-body-mb 50
ziroctl gateway route ls                          # routes and live upstreams
```

Point DNS for `www.example.com` at the gateway nodes, or put a cloud load balancer in front of them.

## Routes

| Flag | Meaning |
|---|---|
| `--host` | Exact hostname. Case and port are ignored. |
| `--path` | Path prefix, matched on `/` boundaries (`/api` matches `/api` and `/api/x`, not `/apix`). The longest prefix wins. Default `/`. |
| `--app` | Target cluster app. It must have a tcp `--port`. Requests go to that host port on each node where a replica is **running**. |
| `--tls auto\|off` | `auto` (default) gets a certificate over ACME HTTP-01 and redirects HTTP to HTTPS with a 308. `off` serves plain HTTP. |
| `--allow-cidr` | Only these client networks, repeatable. Everyone else gets 403. |
| `--rate` | Requests per second per client IP (token bucket, burst of max(rate, 10)). Over the limit gets 429 with `Retry-After`. |
| `--max-body-mb` | Request body limit in MB, default 10. Over the limit gets 413. |

`route add` with an existing name replaces that route. Two routes can't share the same host and path.

## How it works

1. Routes are stored in cluster state on the master (`gateway route …`, all audited).
2. Every heartbeat, the master resolves each route to `meshIP:port` of the nodes where the app is running. It uses the same health signal as service discovery, so crashed replicas and stalled rollouts drop out.
3. The agent on a gateway node writes the result to `/run/ziro/gateway/config.json` (0600, tmpfs) and starts the `gateway` service. When the node's gateway label is removed, the agent stops the service and deletes the file.
4. `ziroctl gateway serve` checks that file every 2s and **re-validates** it: hosts, paths, CIDRs and upstream addresses. A bad file keeps the previous routes.
5. **Proxying:**
   - Requests are proxied with Go's `httputil.ReverseProxy` and round-robined across upstreams. An upstream that fails a dial is skipped for 10s (passive health check).
   - WebSocket and streaming responses pass through.
   - The client's `Host` is preserved. `X-Forwarded-For/Host/Proto` are **replaced**, never appended, so clients can't spoof them.
   - HTTPS responses get HSTS unless the app sets its own.
6. **Policy:** routing an app counts as consent to expose it. Gateway nodes are added to that app's allowed sources under the cluster network policy, with no `allow_from` change needed. See `ziroctl cluster policy ls`.

## Security and limits

- **TLS:** TLS 1.2 minimum. HTTP/2 over TLS. Certificates are cached in `/var/lib/ziro/gateway/certs` (0700). Only hosts of `tls auto` routes can trigger issuance, so random SNI can't make the gateway request certificates.
- **Private ACME CA:** use `gateway acme --directory https://ca.internal/acme/directory` (for example step-ca), or Let's Encrypt staging. Restart the `gateway` service after changing ACME settings.
- **Timeouts:** 10s to read headers (slowloris), 5 min to read a request, 120s idle, 64 KiB of headers, 5s to dial an upstream.
- **Firewall:** the service opens tcp/80 and tcp/443 in the host firewall when it starts. Disabling a gateway node leaves those rules in place; remove them with `ziroctl firewall deny 80` / `443`.
- **Logs:** one JSON access-log line per request in `/var/log/gateway.log` (client, host, method, path, status, bytes, ms, upstream). It is rotated with the other service logs.
- **Certificates on several gateway nodes:** each gateway node gets its own certificate, which counts against Let's Encrypt's limit of 50 certificates per domain per week. For many gateways, use a private CA or terminate TLS at a cloud load balancer and use `--tls off`.
- **Behind a load balancer:** the client IP used for `--allow-cidr` and `--rate` is the TCP peer, which is the load balancer if there is one. There is no PROXY-protocol or trusted-proxy setting yet.
- **Protocols:** HTTP(S) only. There is no TCP/UDP (L4) routing.

## Remote access (WireGuard peers)

Laptops, CI runners or other sites can join the mesh as WireGuard clients of the **hub**, the first gateway node by ID:

```sh
# On the client (recommended: the private key never leaves it)
wg genkey | tee client.key | wg pubkey            # -> <pubkey>

# On the master
ziroctl gateway peer add alice --pubkey <pubkey> > alice.conf   # add --endpoint vpn.example.com:51821 behind NAT
ziroctl cluster deploy --name api --allow-from web,peer:alice   # or 'peers' for every peer
ziroctl gateway peer ls
ziroctl gateway peer rm alice                                   # revoke
```

Put the client's private key into `alice.conf` and run `wg-quick up ./alice.conf`. Without `--pubkey`, the master generates a key pair and prints the private key **once**. It is never stored. Running `peer add` again with the same name rotates the key and keeps the mesh IP.

How it works:
- The peer gets a mesh IP from the mesh CIDR, and its `AllowedIPs` is the whole mesh.
- The hub has it as an endpoint-less WireGuard peer and relays its traffic into `ziro0`. Every other node routes the peer's /32 back through the hub.
- **Policy:** the hub only relays; its forward chain admits the peer's traffic as transit. Each destination node still enforces `allow_from`, so under the default deny a peer reaches nothing until an app names it. Clusters in `allow` mode give peers the whole mesh.
- `ziroctl audit log` records `peer add` and `peer rm`, including the public key argument. The private key isn't recorded.
- **Limits:**
  - There is one hub. If the first gateway node changes, clients need a new config (`peer add` again).
  - Peers get no DNS for `<app>.cluster.ziro`. Use mesh IPs from `ziroctl cluster endpoints`.

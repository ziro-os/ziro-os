# Smart DNS

`ziroctl dns` runs a caching, split-horizon resolver for the host on `127.0.0.53`. It is off until you enable
it.

```sh
ziroctl dns enable        # start it and point /etc/resolv.conf at 127.0.0.53
ziroctl dns status        # queries, cache hit rate, upstream latency and health
ziroctl dns disable       # stop it and restore plain resolvers
```

## What it does

- **Caching:** answers are cached for their TTL, bounded by an LRU (10,000 answers by default). NXDOMAIN and
  "no data" answers are cached for the zone's SOA minimum, at most 5 minutes (RFC 2308). Identical queries in
  flight are sent upstream once.
- **Smart upstream selection:** the fastest healthy upstream is used, by latency EWMA. After 3 consecutive
  failures an upstream is benched for 30 seconds and the next one takes over. SERVFAIL tries another upstream.
- **Serve-stale:** when every upstream is unreachable, answers expired within the last hour are still served,
  with TTL 30.
- **DNS-over-TLS:** `tls://1.1.1.1#cloudflare-dns.com`. The certificate must match the name, and connections are
  reused.
- **Split DNS:** forward a domain (and its subdomains) to specific resolvers, for VPNs, on-prem AD/DNS or cloud
  private zones.
- **Local records:** A, AAAA, CNAME (resolved one hop locally) and TXT, answered authoritatively. Cluster-wide
  records come from the cluster (below).
- **Blocking:** domains and their subdomains get NXDOMAIN. You can subscribe to HTTPS blocklists in hosts or
  domain-per-line format; cron refreshes them daily, and a failed download keeps the previous copy.
- **Safety:**
  - Only loopback and networks you allow may query, so it's never an open resolver.
  - Clients are rate-limited to 200 queries/second each by default.
  - UDP answers are truncated to the client's EDNS size, and the client retries over TCP.
  - Query logging is off.

```sh
ziroctl dns upstream tls://1.1.1.1#cloudflare-dns.com tls://9.9.9.9#dns.quad9.net
ziroctl dns upstream auto                         # from DHCP (the default)
ziroctl dns forward add corp.example 10.0.0.2 10.0.0.3
ziroctl dns record add db.internal A 10.0.0.20 --ttl 60
ziroctl dns block add ads.example
ziroctl dns blocklist add https://example.org/hosts.txt
ziroctl dns record list
```

Changes take effect within 2 seconds, without a restart, and the cache stays warm. The configuration is
`/etc/ziro/dns.json`:

```json
{
  "upstreams": [{"addr": "1.1.1.1", "tls_name": "cloudflare-dns.com"}],
  "forwards": [{"domain": "corp.example", "upstreams": [{"addr": "10.0.0.2"}]}],
  "records": [{"name": "db.internal", "type": "A", "value": "10.0.0.20", "ttl": 60}],
  "block": ["ads.example"],
  "blocklists": ["https://example.org/hosts.txt"],
  "listen": ["127.0.0.53"],
  "allow": [],
  "cache_size": 10000,
  "rate_limit": 200
}
```

## How it fits the host

- **DHCP:** with smart DNS on, the DHCP client writes the resolvers it learns to `/run/ziro/dhcp-resolv.conf`,
  which feeds `upstream auto`, instead of `/etc/resolv.conf`. That file stays on `127.0.0.53`.
- **`ziroctl network dns <servers>`** sets the upstreams while smart DNS runs (and plain resolvers when it
  doesn't).
- **Cluster pods** keep using their node's pod DNS responder, which forwards non-cluster names to the host
  resolver, so pods get the cache, records and blocklists too.
- **Standalone containers:** Docker-compatible runtimes replace a loopback resolver with public DNS. To make
  standalone containers use smart DNS, add the bridge address to `listen` and the bridge subnet to `allow`.

## Cluster DNS

```sh
ziroctl cluster dns add registry.internal A 10.0.0.40   # on a master: every node resolves it
ziroctl cluster dns ls
ziroctl cluster dns rm registry.internal
```

- **Delivery:** cluster records are stored in the replicated cluster state and reach every node with its next
  heartbeat.
- **App names:** on pod-network nodes, the host resolver also answers `<app>.cluster.ziro` through the node's pod
  DNS.

## Container egress control

```sh
ziroctl cluster deploy --name billing --image registry.example/billing:1.4 --egress api.stripe.com,10.20.0.0/16
ziroctl cluster deploy --name billing --egress ''    # unrestricted again
```

- **Scope:** an app deployed with `--egress` may open connections only to the listed IPv4 CIDRs and to the
  addresses its allowed domains resolve to (subdomains included). Everything else leaving its pods is dropped
  and counted. Traffic inside the cluster (pods, mesh) is still governed by `allow_from` policies.
- **How:** each node keeps an `inet ziro_egress` nftables table. When a pod of the app resolves an allowed domain
  through the node's pod DNS, the addresses in the answer, including CNAME targets, are added to the app's set
  *before* the pod receives the answer. They expire after the TTL, with at least 5 minutes of grace. Re-applying
  rules never drops addresses already learned.
- **Limits:** pod-network apps only. IPv4 (the pod network is IPv4).

## API

| Route | Role |
|---|---|
| `GET /api/v1/dns` (config, stats, cluster records, enabled) | viewer |
| `POST /api/v1/dns/records`, `DELETE /api/v1/dns/records?name=&type=`, `PUT /api/v1/dns/block` | operator |
| `PUT /api/v1/dns/upstreams`, `PUT /api/v1/dns/forwards` (they control where every lookup goes) | admin |

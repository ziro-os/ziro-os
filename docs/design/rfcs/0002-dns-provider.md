# RFC 0002: Public DNS provider for the gateway's names

- **Status:** Accepted
- **Pull request:** the pull request that adds this file
- **Follow-up:** ACME DNS-01 (wildcard certificates, no inbound :80) builds on this and is a separate RFC section in its own pull request.

## Summary

The gateway publishes apps under a base domain and route hosts, but the operator creates the public DNS records by
hand (`gateway domain` prints them). This adds a **DNS provider**: Cloudflare first, behind a small interface. The
records are derived from the gateway's own state and reconciled at the provider, touching only records ziro created.
User guide: [dns.md](../../dns.md#public-dns-provider-cloudflare).

## Motivation

A name that is not in public DNS does not work, and a hand-made record drifts from the gateway: a route is
deleted or the gateway node changes address and the record stays. Cloudflare is where many operators already keep
their zones. `ziroctl cf` already has a hardened client and token storage to build on.

## Design

**Interface** (`dnsprovider.go`): `Zones`, `List(zone)`, `Upsert(zone, record)`, `Delete(zone, id)`. Cloudflare
implements it on the existing client (`dnsprovider_cf.go`). Another provider is one more implementation and a kind name.

**Desired state** is derived, not stored: a wildcard for the base domain, a record for every http/tls route host
the wildcard does not cover, and the explicit records the operator added. Private names (`.local`, `.internal`, no
dot) stay with the built-in DNS. The published address is the gateway nodes' own, or an operator-set one (NAT, load balancer).

**Configuration** is stored with the gateway's data, so it replicates with the routes in a cluster: providers (name,
kind, zone allowlist), explicit records, published addresses, and an `epoch` that every route or domain change bumps.
The sync loop reconciles when the epoch moves and every 5 minutes.

**Token.** In a cluster a provider's token is a cluster secret (`dns-provider-<name>`), like gateway
certificates: sealed at rest by the cluster data key, replicated, so a new leader keeps syncing. On a standalone host it
is a root-only file (`0600` in a `0700` directory), sealed in the TPM when there is one: the same storage as the
`ziroctl cf` token, and without a TPM only as private as the file. It is read from a file, a hidden prompt or
stdin; never argv or the environment; never logged or returned by the API.

**Ownership.** Every record the sync creates carries the comment `ziro:<cluster id>` (`ziro:host-<hostname>` on a
standalone host; renaming the host orphans what it made). Only records with exactly that comment are updated or deleted; at plan time and again at apply time.
A foreign record at a wanted name is reported as `skip`. Records with no comment, another cluster's comment, or an
ACME challenge comment (`ziro-acme:`) are never touched.

**Reconcile** (`dnsprovider_sync.go`): list each managed zone once, diff per (name, type): exact matches are left alone, a
record with the right content but another TTL or proxy flag is updated, a changed address reuses a record that is no
longer wanted, the rest are created or deleted. Creates and updates run before deletes. A provider that cannot be opened,
or a zone that cannot be listed, is left untouched. A sync that would delete more than three records and more than half
of those owned is refused unless an operator passes `--force` (the daemon never does).

**One writer.** The service `ziroctl gateway dns-sync` (module `dns-cloudflare`) asks its local cluster-master
whether it is the Raft leader (`/leader` on the local socket) and only then reconciles. `ziroctl dns cloud sync` and
`doctor --fix` check the same. A host outside a cluster is always its own leader.

**Cloudflare client.** TLS-verified HTTPS, redirects refused (the bearer token never follows one). Throttled (429) and
5xx answers are retried with jittered exponential backoff, honouring `Retry-After`; a POST is repeated only after a
429. The proxied flag is sent on every write, so a replace never turns proxying off.

**Surfaces.** `ziroctl dns provider add|ls|rm` and `dns cloud add|rm|ls|plan|sync|status|addresses`;
`/api/v1/dns/cloud/*` (read: viewer; everything else: admin); `ziroctl doctor` row `DNS provider`; audit entries
`dns create|update|delete` and `dns provider add|rm`; a `dns` alert when a sync fails.

## Security

- **Reachable by:** the `admin` role alone can add a provider (it supplies a token), edit explicit records or addresses,
  plan or sync. A viewer can read the configuration, which holds no token.
- **Token scope.** The documented token has only Zone › DNS › Edit and Zone › Zone › Read, limited to chosen zones; the
  zone allowlist narrows what ziroctl itself manages. A leaked token is limited to DNS of those zones.
- **Blast radius of a bad desired state** (an empty route list, a vanished gateway node): the ownership rule limits it
  to records ziro created, and the mass-delete refusal stops the rest.
- **Input.** Provider names, zones, record names and content go through the same validators as the built-in DNS
  records (`validName`, `hostRe`, `parseRecord`); API bodies are decoded strictly.
- **Secret in the cluster state.** A provider token is replicated to every master (sealed at rest by the cluster data
  key, as every cluster secret is). Masters can read it; workers do not receive it.

## Compatibility

Additive. The new fields (`dns_cloud` in the gateway data and cluster state) are ignored by older masters; the
sync runs only where a provider is configured and the module is enabled. Without a provider, `gateway domain` prints
the records as before. New API routes are documented in `sdk/openapi.yaml`; the SDK gains the matching client methods.

## Alternatives

- **A provider-neutral DNS library (libdns/lego).** A large dependency for one provider and no gain in safety; the
  interface is five methods.
- **Storing the desired records.** They would drift from the gateway, which is what we are removing. Deriving them
  keeps the gateway the single source of truth.
- **Per-host token files in a cluster.** A leader change would silently stop the sync until each master was configured.
- **Syncing from the CLI process on every route change.** On a follower master that makes two writers. The epoch makes
  the leader's loop do it instead.

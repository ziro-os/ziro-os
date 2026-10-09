# RFC 0003: Tailscale module, service capabilities and interface-bound firewall rules

- **Status:** Draft (service capabilities in the first pull request; the rest follows)
- **Pull request:** the one that adds service capabilities, then the firewall, module and API pull requests

## Summary

Add Tailscale as an optional module: installed only when enabled, joined with one command, kept on the newest stable
release, and run with no more privilege than it needs. Two framework changes make that possible without weakening the
security model: **service capabilities** (a non-root service that keeps only the capabilities it lists) and an
**interface match on firewall rules** (open a port to a tailnet, not to the whole host).

## Motivation

A tailnet is a convenient way to reach a host without a public address. Tailscale needs `CAP_NET_ADMIN` (and
`CAP_NET_RAW`) to create its tun device and routes. Today a service is either root (every capability, no
`no_new_privs`) or an unprivileged user (none), so tailscaled would have to run as root. A review of the base found no
capability, `no_new_privs`, seccomp or Landlock use for any host daemon, so the same gap exists for every other module.
A host firewall rule can only name a source address, which is spoofable from another interface (`rp_filter=2`), so
"allow SSH from the tailnet" cannot be expressed safely.

## Design

**Service capabilities** (this pull request). A service definition gains `caps`, a list from a short reviewed
allowlist (`net_admin`, `net_raw`, `net_bind_service`), valid only with an unprivileged `user`:

```json
{"name": "tailscaled", "exec": "/var/lib/ziro/plugins/tailscale/tailscaled", "user": "tailscale",
 "caps": ["net_admin", "net_raw"], "resources": {"memory": "256Mi", "pids": 256}}
```

`ziroctl service start` runs such a service through the hidden `ziroctl service exec <name>`. The launcher (as root, on
one locked OS thread, with per-thread syscalls) drops every capability not listed from the bounding set, switches to the
user with no supplementary groups, sets the permitted, effective, inheritable and ambient sets to exactly the list, sets
`no_new_privs`, and execs the daemon. So the daemon holds those capabilities and nothing else, and neither a setuid
binary nor a file capability can add to them. Services without `caps` start as before. The conf file key is
`caps=net_admin,net_raw`; the manifest field is `caps`. Only the validated service name is on the launcher's command line.

**Interface-bound firewall rules** (next pull request). `AllowedPort` gains an optional `iface`; the rule matches
`iifname` as well as the source CIDR. Nothing is added to the trusted interfaces.

**The Tailscale module** (following pull requests).
- Binaries come from the signed catalog (`ziro-os/pkgs`), pinned by sha256 and re-verified on every boot, like
  cloudflared. A daily job there takes the newest stable release, checks Tailscale's own signature, pins it and re-signs
  the catalog. Hosts update daily (`ziroctl tailscale update`) and restore the previous binary if the node does not come
  back healthy.
- `ziroctl module enable tailscale` installs on demand; the base image is unchanged.
- `ziroctl tailscale up` joins a tailnet: with no key it prints the login URL; with `--auth-key-file`, stdin or a hidden
  prompt it joins non-interactively. An auth key is never on a command line and is never stored; the node key lives in a
  0700 state directory owned by the service user.
- Defaults are closed: DNS and routes from the tailnet are not accepted, no SSH, no exit node or subnet router, no log
  upload, and nothing on the host is reachable from the tailnet until `ziroctl tailscale allow ssh|<port>` opens it
  (`tailscale0` only, from the tailnet range only).
- tailscaled uses its own port (41642, not zirocd's 41641) and the `100.64.0.0/10` range is checked against the router
  mesh before joining.

## Security

- A compromised tailscaled holds only `CAP_NET_ADMIN`/`CAP_NET_RAW` as the `tailscale` user, cannot gain more, is limited
  by a cgroup, and cannot read root's files. Previously the only option was root.
- The allowlist is short on purpose: adding a capability to it is a security review (a test fails until it is updated).
  Capabilities that load code, read memory or disks raw, override permissions or become root are not available.
- The launcher is root only until it execs; it re-checks the executable (root-owned, not group- or world-writable) and
  reads the env file as root before dropping privileges.
- An auth key can be used to join the host to a tailnet: it is treated like any secret (file, stdin or prompt, scrubbed
  from the environment, not logged, not part of backups).

## Compatibility

`caps` is a new optional field. A ziroctl that predates it rejects a manifest that uses it (strict decoding) and skips
that catalog entry with a warning, so the module is not offered on an old host instead of running with the wrong
privileges. Existing services and modules are unchanged.

## Alternatives

- **Root with cgroup limits only** (what other modules do): simplest, but a compromised daemon owns the host.
- **Userspace networking (`--tun=userspace-networking`) as an unprivileged user:** needs no capability, but gives the host
  no tailnet interface (only SOCKS/HTTP proxying), so ssh to the host and routing do not work.
- **The Alpine `tailscale` package:** signed, but months behind upstream and never upgraded after install.
- **Trusting the whole `tailscale0` interface:** easy, but every peer then reaches every host port and Ziro Guard skips
  the interface.

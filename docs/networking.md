# Networking

Without configuration, Ziro-OS runs DHCP on every Ethernet interface. To set static addresses, VLANs, bonds,
MTUs and routes, describe them once in `/etc/ziro/network.json`. ziro-init applies that file at every boot
instead of the blanket DHCP.

## Hostname and DNS resolvers

These take effect immediately and persist:

```sh
ziroctl network hostname web01.prod.example.com   # /etc/hostname, /etc/hosts (127.0.1.1), kernel
ziroctl network dns 1.1.1.1 9.9.9.9 --search corp.example   # pinned: DHCP no longer rewrites resolv.conf
ziroctl network dns auto                            # follow DHCP again
ziroctl network dns                                 # show
```

Pinned resolvers are recorded in `/etc/udhcpc/udhcpc.conf` (`RESOLV_CONF=no`), which the DHCP client honours on
every lease renewal.

## Interfaces, VLANs, bonds and routes

These commands edit the pending configuration. `network apply` then applies it:

```sh
ziroctl network set eth0 --mode static --address 10.0.0.5/24 --address 2001:db8::5/64 \
    --gateway 10.0.0.1 --gateway6 2001:db8::1 --ipv6 static --mtu 9000
ziroctl network vlan add eth0 100
ziroctl network set eth0.100 --mode static --address 172.16.100.5/24
ziroctl network bond add bond0 eth1 eth2 --mode 802.3ad
ziroctl network route add 10.20.0.0/16 --via 10.0.0.254
ziroctl network remove eth0.100
ziroctl network show                  # the pending config and the exact steps apply will run
ziroctl network apply --confirm-timeout 120s
ziroctl network confirm               # keep it; otherwise it rolls back after 120s
```

- **Modes:** `dhcp` (the default), `static`, `manual` (link up, no address; used for bond members) and `off`.
- **IPv6:** `auto` (SLAAC, the default), `static` or `off`.
- **`apply` changes only what differs** from the last applied configuration. It removes VLANs, bonds and routes you
  deleted, and swaps DHCP for static addresses without restarting other interfaces.
- **Automatic rollback:** with `--confirm-timeout`, a detached timer restores the previous configuration unless
  `network confirm` runs in time. It also rolls back when the host reboots before you confirm. Always use it over
  SSH: a wrong gateway or address can't strand the host, because it comes back with the last working config. A
  rollback raises a `network` alert.
- **`network setup`** (the interactive wizard) and `network restart` use the same configuration.

`/etc/ziro/network.json` example:

```json
{
  "interfaces": [
    {"name": "eth0", "mode": "static", "addresses": ["10.0.0.5/24"], "gateway": "10.0.0.1", "mtu": 9000},
    {"name": "eth1", "mode": "manual"},
    {"name": "eth2", "mode": "manual"},
    {"name": "bond0", "mode": "dhcp", "bond_mode": "active-backup", "slaves": ["eth1", "eth2"]},
    {"name": "bond0.100", "mode": "static", "parent": "bond0", "vlan_id": 100, "addresses": ["172.16.100.5/24"]}
  ],
  "routes": [{"to": "10.20.0.0/16", "via": "10.0.0.254", "metric": 50}]
}
```

## API

| Route | Role |
|---|---|
| `GET /api/v1/network` (hostname, pending and applied config, resolvers, whether a confirm is pending) | viewer |
| `POST /api/v1/network/hostname` `{"hostname": ...}` | operator |
| `POST /api/v1/network/dns` `{"servers": [...], "search": [...]}` (empty servers: follow DHCP) | operator |
| `PUT /api/v1/network` `{"config": {...}, "confirm_timeout": "120s"}` (a confirm timeout is required) | admin |
| `POST /api/v1/network/confirm` | admin |

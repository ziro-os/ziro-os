# Ziro OS documentation

Ziro OS is a small, hardened Linux for running containers: one static CLI (`ziroctl`), containerd, and opt-in
plugins for everything else. New here? Read [getting started](getting-started.md), then the
[first app tutorial](tutorials/01-first-application.md).

## Start

- [Getting started](getting-started.md): container base image, boot a VM, where to go next.
- [Installation](installation-guide.md): ISO, interactive and unattended installs, PXE.
- [Running in the cloud](cloud.md): metadata keys, user-data, cloud images, Terraform.
- [Tutorial: your first app](tutorials/01-first-application.md): deploy from git, HTTPS, rollback, a database.

## Run workloads

- [Containers, Compose and cron](containers.md): `ziroctl container`, `compose`, scheduled jobs.
- [Apps](apps.md): one-command databases and services from signed catalogs.
- [Deploy from git](deploy.md): build and release your code, with rollback and webhooks.
- [Stacks and host provisioning](provisioning.md): YAML for apps and whole hosts, `stack up`, `apply`,
  first-boot `#ziro-config`.

## Networking

- [Networking](networking.md): hostname, resolvers, interfaces, VLANs, bonds and routes, with rollback.
- [Smart DNS](dns.md): caching resolver, split DNS, records, blocklists, egress control.
- [Gateway](gateway.md): HTTP(S), HTTP/3 and TCP routing with automatic TLS.
- [WireGuard VPN](wireguard.md): remote access to a host.
- [Global router](router.md): private networks for devices anywhere (zirocd, ACLs, SSO), and
  [running it in production](router-deploy.md).

## Storage and data

- [Storage](storage.md): automatic disk growth, data disks, NFS, cluster storage.
- [Backup and restore](backup.md): host configuration and cluster state, local or off-host.

## Clusters

- [Clustering](clustering.md): join, scheduling, HA control plane, pod network, policy, secrets.

## Security

- [Security](security.md): firewall, SSH keys, hardening and secure defaults.
- [Compliance](compliance.md): NIST SP 800-190, CIS Controls and SOC 2 mapping.
- [Security policy](../SECURITY.md): how to report a vulnerability.

## Operate

- [Operating a host](operations.md): login summary, `system top`, disk usage, memory protection, tools updates.
- [Upgrades](upgrade.md): OS upgrades and rollback.
- [REST API](api.md): tokens, roles and endpoints.

## Extend

- [Modules and plugins](modules.md): opt-in plugins, signed catalogs, writing your own.
- [SDK](sdk.md): Go packages, typed API client and OpenAPI spec, `ziroctl dev`.

## Build and contribute

- [Building](building.md): architectures, kernel flavors, build and test commands.
- [Architecture](architecture.md): how the pieces fit, with design notes and the threat model.
- [Design standard](design/README.md) and [RFCs](design/rfcs/README.md): conventions for APIs, CLIs and extensions.
- [Project goals](project-goals.md), [contributing](../community/CONTRIBUTING.md) and
  [governance](../GOVERNANCE.md).

# Ziro-OS documentation

Ziro-OS is under active development and is not ready for production use. Start with the
[project README](../README.md) for an overview and a local container quick start.

## Start here

- [Getting started](getting-started.md): container image, QEMU, and ISO basics.
- [Building](building.md): architectures, kernel flavors, build commands, and verification.
- [Installation](installation-guide.md): installing from bootable media.
- [Project goals](project-goals.md): intended use cases and future directions.
- [Contributing](../community/CONTRIBUTING.md): development workflow and pull requests.

## System and operations

- [Architecture](architecture.md): host components and cluster design.
- [Security](security.md): current controls and limitations.
- [Virtualization](virtualization.md) and [multi-architecture builds](multi-architecture-guide.md).
- [Clustering](clustering.md), and the [gateway](gateway.md): L4/L7 routing with TLS and HTTP/3, managed by CLI and API, on clusters and standalone hosts.
- [Networking](networking.md): hostname, resolvers, interfaces, VLANs, bonds and routes with rollback.
- [Storage](storage.md): automatic disk growth and data disks.
- [Smart DNS](dns.md): caching resolver, split DNS, cluster records, container egress control.
- [Apps](apps.md): one-command deployments (postgres, mysql, mysql-cluster, valkey) from signed catalogs.
- [Modules and plugins](modules.md): opt-in plugins (ClamAV, auditd, S3 storage, rclone), signed catalogs, and how to write and publish a plugin.
- [Upgrades](upgrade.md) and [compliance mapping](compliance.md).
- [Advanced deployment](advanced-deployment-guide.md) and
  [first application tutorial](tutorials/01-first-application.md).

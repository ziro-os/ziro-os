# Ziro-OS

**Minimal by design. Born for the cloud.**

> [!WARNING]
> **Ziro-OS is under active development and is not ready for production use.**
> Build and run it in test environments. Interfaces, images, and behavior may change.

Ziro-OS is an open source, lightweight Linux operating system for hosting OCI containers. It combines a small
BusyBox and musl userland with `ziro-init`, `containerd`, `runc`, CNI networking, and the `ziroctl` management CLI.
The repository also builds a minimal container base image. The project targets virtual machines, cloud hosts, and
other environments dedicated to container workloads.

## Get started

```sh
docker run --rm -it ghcr.io/ziro-os/ziro-os:latest sh     # the 16 MB userland
```

To run the full host, boot the release kernel and initramfs in QEMU, or install the ISO on a VM or server:
see [getting started](docs/getting-started.md) and [installation](docs/installation-guide.md). Then follow the
[first app tutorial](docs/tutorials/01-first-application.md). To build from source, see [building](docs/building.md).

## What's in it

- **Containers:** containerd, runc and CNI; `ziroctl container` and `compose`; signed app catalogs; deploys from git
  with rollback ([containers](docs/containers.md), [apps](docs/apps.md), [deploy](docs/deploy.md)).
- **Networking:** a gateway with automatic TLS and HTTP/3, smart DNS, WireGuard, and a global mesh router for
  devices anywhere ([gateway](docs/gateway.md), [router](docs/router.md)).
- **Clusters:** Raft HA control plane, WireGuard mesh, pod network, policies and sealed secrets in the same binary
  ([clustering](docs/clustering.md)).
- **Operations:** declarative host config, signed tools updates and OS upgrades with rollback, backups, an
  audited REST API ([provisioning](docs/provisioning.md), [upgrade](docs/upgrade.md), [api](docs/api.md)).
- **Security:** default-drop firewall, flood and brute-force bans, key-only SSH, a hardened kernel flavor, and
  opt-in plugins from signed catalogs ([security](docs/security.md), [modules](docs/modules.md)).

## Project goals

- Keep the host focused on container workloads, with a bootable ISO and initramfs under 300 MB for each kernel
  flavor. CI enforces that limit; the minimal container rootfs is approximately 16 MB.
- Support `x86_64` and `arm64` builds with `containerd`, an OCI runtime, and CNI networking at the core.
- Keep configuration and extension points understandable. An immutable root filesystem and broader module support
  remain design goals; the current installer uses a writable ext4 root, and live boot uses writable tmpfs.

Read the [project goals](docs/project-goals.md) for intended use cases and future directions. Current design and
limitations are described in the [architecture](docs/architecture.md) and [security](docs/security.md) guides.

## Documentation and community

- [Documentation index](docs/README.md)
- [Installation guide](docs/installation-guide.md)
- [Contributing guide](community/CONTRIBUTING.md)
- [Report an issue](https://github.com/ziro-os/ziro-os/issues)

Contributions, questions, and feedback are welcome. Please use the contributing guide for development and pull
request guidance. Report security vulnerabilities privately as described there.

## Security partners

Ziro-OS is part of the [Snyk Secure Developer Program](https://snyk.io/open-source/) for open-source projects.
[Snyk](https://snyk.io) scans our code (Snyk Code), Go modules (Snyk Open Source), infrastructure as code (Snyk IaC) and
container images (Snyk Container) on every pull request and on `main`; see [SECURITY.md](SECURITY.md).

We permit and grant Snyk a license to use, reproduce and display the Ziro-OS name, logo and related project content
on Snyk's website and materials.

## License

Ziro-OS is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Sambo Chea and Ziro-OS Contributors.

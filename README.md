# Ziro OS

Minimal by design. Born for the cloud.

> [!WARNING]
> Ziro OS is under active development and is not ready for production use.
> Build and run it in test environments. Interfaces, images, and behavior may change.

Ziro OS is an open source, lightweight Linux operating system for hosting OCI containers. It combines a small
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
- **Networking:** a gateway with automatic TLS, HTTP/3, traffic management, a web application firewall and Prometheus
  metrics, DNS, WireGuard, and a global mesh router for devices anywhere ([gateway](docs/gateway.md), [router](docs/router.md)).
- **Clusters:** Raft HA control plane, WireGuard mesh, pod network, policies and sealed secrets in the same binary
  ([clustering](docs/clustering.md)).
- **Operations:** declarative host config, signed tools updates and OS upgrades with rollback, backups, an
  audited REST API ([provisioning](docs/provisioning.md), [upgrade](docs/upgrade.md), [api](docs/api.md)).
- **Security:** default-drop firewall, flood and brute-force bans, key-only SSH, a hardened kernel flavor, and
  opt-in modules from signed catalogs ([security](docs/security.md), [modules](docs/modules.md)).

## Project goals

- Keep the host focused on container workloads, with a bootable ISO and initramfs under 300 MB for each kernel
  flavor. CI enforces that limit; the minimal container rootfs is approximately 16 MB.
- Support `x86_64` and `arm64` builds with `containerd`, an OCI runtime, and CNI networking at the core.
- Keep configuration and extension points understandable. An immutable root filesystem and broader module support
  remain design goals. The current installer uses a writable ext4 root, and live boot uses writable tmpfs.

Read the [project goals](docs/project-goals.md) for intended use cases and future directions. Current design and
limitations are described in the [architecture](docs/architecture.md) and [security](docs/security.md) guides.

## Documentation and community

- [Documentation index](docs/README.md)
- [Installation guide](docs/installation-guide.md)
- [Contributing guide](community/CONTRIBUTING.md)
- [Report an issue](https://github.com/ziro-os/ziro-os/issues)

Contributions, questions, and feedback are welcome. The contributing guide covers development and pull request
workflow. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Security partners

Ziro OS is part of the [Snyk Secure Developer Program](https://snyk.io/open-source/) for open-source projects.
Snyk scans the code, Go modules, infrastructure as code and container images on every pull request and on `main`; see
[SECURITY.md](SECURITY.md#automated-scanning). Snyk is licensed to use, reproduce and display the Ziro OS name, logo
and related project content on its website and materials.

## License

Ziro OS is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Sambo Chea and Ziro-OS Contributors.

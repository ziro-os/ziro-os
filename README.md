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

The local container image is the simplest way to explore the userland. You will need Make, Go, and a running Docker
daemon. On macOS, build from a case-sensitive filesystem; see the
[building instructions](docs/building.md#building-on-macos).

```sh
make all
docker run --rm -it ziro-os:latest sh
```

Inside the container, run `ziroctl version` or explore the BusyBox tools. For host boot in QEMU and ISO builds, see
the [getting started guide](docs/getting-started.md). The [build guide](docs/building.md) covers supported
architectures, kernel flavors, prerequisites, and tests.

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

## License

Ziro-OS is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Sambo Chea and Ziro-OS Contributors.

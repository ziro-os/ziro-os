# Project goals

Ziro-OS aims to provide a small, understandable Linux host for OCI container workloads. The project favors a
minimal base, clear configuration, and components that can be inspected and replaced independently. It is under
active development and is not ready for production use.

## Intended use cases

- Learn, build, and test a container-focused host in QEMU or another virtual machine.
- Experiment with dedicated container hosts on bare metal, cloud VMs, and edge devices.
- Develop and evaluate container networking, storage, security, and management tooling.
- Explore future integration with orchestrators such as Kubernetes.

These are intended use cases, not a certification or support guarantee for a platform or workload.

## Design goals and measures

| Goal | How the project evaluates it |
| --- | --- |
| Small images | Keep every bootable ISO and initramfs below 300 MB for both kernel flavors in CI; target an approximately 16 MB minimal container rootfs. |
| Fast startup | Measure time from VM start to a usable container runtime across supported boot paths. No fixed boot-time guarantee is established. |
| Container compatibility | Test container pull, run, stop, networking, and storage with the shipped `containerd` and OCI tooling. |
| Minimal, auditable host | Limit bundled services and track the runtime, memory, and CPU cost of the base system. |
| Community usability | Keep build, test, architecture, and contribution instructions current and accessible. |

## Current direction

The current build centers on a Linux kernel, BusyBox and musl userland, `ziro-init`, `containerd`, `runc`, CNI,
`ziroctl`, and `ziropkg`. It produces a container base image and bootable host artifacts for `x86_64` and `arm64`.
See the [architecture](architecture.md) and [build guide](building.md) for implementation details.

Further work includes an immutable installed root, clearer module and package interfaces, broader Docker and
Podman compatibility, cloud and edge validation, and stronger update and rollback workflows. These are directions
for contributors, not commitments that the features are complete. The current upgrade behavior and limitations
are documented in the [upgrade guide](upgrade.md).

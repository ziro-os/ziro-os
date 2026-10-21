# AGENTS.md

## Project overview

- **Name**: Ziro OS
- **Purpose**: A minimal, cloud-native Linux host for OCI container workloads. Small base, fast boot, small footprint,
  with `containerd`, `runc`, CNI networking and the `ziroctl` management CLI.
- **Design philosophy**: Minimal by design. Born for the cloud.
- **Status**: Under active development; not ready for production use (see `README.md`).

## Repository layout

| Path | Contents |
|---|---|
| `kernel/` | Kernel configs and `build-kernel.sh` (`custom` hardened flavor by default, `alpine` as the fallback) |
| `init/` | `ziro-init`, the static C99 PID 1 supervisor |
| `rootfs/` | Files copied into the host image (`/etc`, installer) |
| `packages/` | `build-rootfs.sh` and the pinned base components |
| `images/` | ISO, QEMU, Docker, `zirocd` and cloud image builders |
| `tools/` | `ziroctl` (host CLI and daemons), `ziropkg` (package manager), `zirocd` (router client), all in Go |
| `sdk/` | Go SDK: schemas, catalogs, API client, `openapi.yaml` |
| `scripts/` | Installer, release and `zirocd` install scripts |
| `deploy/` | Example deployments (Terraform for AWS) |
| `security/` | Host hardening script |
| `tests/` | Smoke tests, QEMU boot and cluster tests, router end to end, security |
| `docs/` | User and design documentation; technical decisions live in `docs/architecture.md` |

## Build and test commands

- Build everything for the host architecture: `make all` (tools, rootfs, Docker base image)
- Build the CLIs: `make tools` (`ziroctl`, `ziropkg`); cross-compile with `make tools-all`. Build `zirocd` with
  `make zirocd-all`
- Build the kernel: `make kernel` (runs `kernel/build-kernel.sh`; set `KERNEL_FLAVOR=alpine` for the distribution
  kernel)
- Build images: `make rootfs`, `make image-iso`, `make docker-image`
- Unit tests: `make test-unit`, or `cd tools/ziroctl && go test ./...` (also `tools/ziropkg`, `tools/zirocd`, `sdk`)
- Container smoke tests: `make test-smoke`
- Boot test in QEMU: `make test-boot`
- Manage modules on a host: `ziroctl module enable|disable|purge|list|info|upgrade`

`community/CONTRIBUTING.md` has the full target list and the lint gate that CI enforces.

## Core goals and constraints

- **Minimal base**: every bootable host image (ISO and initramfs, for both kernel flavors) stays under 300 MB, enforced
  in CI. The minimal container base rootfs is about 16 MB.
- **Controlled mutable state**: an immutable installed root is a goal, not a current property. The installer mounts
  ext4 read/write and live boot uses writable tmpfs. Keep writable paths few and documented.
- **Cloud-native first**: `containerd` and `runc`, with Docker-style commands through `nerdctl`. This is not a
  complete Docker Engine or Podman replacement.
- **Modular and extensible**: optional software ships as modules (`ziroctl module`) from signed catalogs, not in the
  base image.
- **Security hardened**: least privilege, a default-drop firewall, seccomp, and capability restrictions. The
  `security/harden-system.sh` script, used by the AWS example deployment, adds AppArmor profiles. SELinux is not
  supported.

## Code style and conventions

- Prefer static linking (`CGO_ENABLED=0` for Go, musl for C).
- Keep dependencies minimal. Add one only when a few lines of code cannot do the job.
- One responsibility per module or file.
- Configuration is declarative (YAML or JSON), validated by `sdk/schema` at every trust boundary.
- Format Go with `gofmt`. Run the lint gate in `community/CONTRIBUTING.md` before pushing.
- Mark an accepted limitation in a code comment as `// Known limitation: <what is not handled>; <what to change when
  it matters>`. Use `TODO` only for unfinished work that should not ship.

## Testing and CI

- Unit tests live next to the code (`_test.go`). Documentation examples are checked by `TestDocCommands`.
- CI runs `gofmt`, `go vet`, `staticcheck`, `shellcheck`, unit tests, multi-architecture rootfs builds, container
  smoke tests, and security scans.
- QEMU tests in `tests/qemu/` boot an image and check containers, networking, storage and cluster behavior.

## Pull request guidelines

- Run `make test` and the lint gate before submitting.
- Include a manifest with metadata (name, version, dependencies) for every new module or package recipe.
- Do not introduce configuration defaults that break existing hosts.
- Document new features in `docs/`, and record technical decisions in `docs/architecture.md`. Larger changes need an
  [RFC](docs/design/rfcs/README.md).

## Security and deployment notes

- Keep writable paths minimal and documented.
- Seccomp and capability restrictions apply by default.
- Cloud images install SSH keys from instance metadata or user data at first boot.
- Never embed secrets. Pass them at runtime through the environment or the sealed cluster secrets.

## Notes for agents

- Place generated files under the layout above.
- Reference `docs/architecture.md` and `docs/design/README.md` when making architectural changes.
- When in doubt, choose the smaller, clearer design.

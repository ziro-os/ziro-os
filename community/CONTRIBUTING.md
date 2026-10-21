# Contributing to Ziro OS

Thank you for contributing to Ziro OS, a minimal, container-native operating system for cloud workloads. This guide
covers the development workflow, coding standards, and how changes are reviewed and merged.

## Design principles

Every contribution should respect these principles:

1. **Minimal by design.** Ship only what container workloads need. The minimal container rootfs is about 16 MB, and
   CI keeps bootable host images under 300 MB.
2. **Container-native first.** The host exists to run and schedule OCI containers through `containerd` and `runc`.
3. **Controlled mutable state.** An immutable installed root is a goal. Today the installer mounts ext4 read/write,
   and live boot uses writable tmpfs. Document and minimize writable paths.
4. **Multi-architecture.** Support both `x86_64` and `arm64`.
5. **Static linking.** Prefer statically compiled Go and C99 binaries linked against musl libc.

The [design standard](../docs/design/README.md) turns these principles into concrete rules: the resource model, API
and CLI conventions, extension points, and the security model. Larger changes need an
[RFC](../docs/design/rfcs/README.md).

## Development environment

### Prerequisites

- **Go 1.27.1 or later** for `ziroctl`, `ziropkg`, `zirocd` and the SDK.
- **Docker 24.0 or later** with Buildx, for rootfs extraction and the container base image.
- **GCC, Clang or `musl-gcc`** to compile the `ziro-init` PID 1 supervisor.
- **QEMU** (`qemu-system-x86_64` or `qemu-system-aarch64`) for boot and cluster tests.
- **xorriso, mtools and dosfstools** (optional) to build the bootable hybrid ISO.
- **Make**.

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/ziro-os.git
cd ziro-os

# Verify the build tools
go version
docker version
make --version

# Build the tools, rootfs and Docker base image
make all

# Run the unit and smoke tests
make test
```

## Repository layout

```text
ziro-os/
├── Makefile                # build orchestrator: tools, kernel, rootfs, images, tests
├── docs/                   # user and design documentation (start at docs/README.md)
├── init/                   # ziro-init, the C99 static PID 1 supervisor
├── kernel/                 # kernel configs and build-kernel.sh (alpine and custom flavors)
├── rootfs/                 # files copied into the host image (/etc, installer)
├── packages/               # build-rootfs.sh and the pinned base components
├── images/                 # ISO, QEMU, Docker, zirocd and cloud image builders
├── tools/
│   ├── ziroctl/            # host CLI and daemons (Go)
│   ├── ziropkg/            # extra package manager (Go)
│   └── zirocd/             # router client and moon relay (Go)
├── sdk/                    # Go SDK: schemas, catalogs, API client, openapi.yaml
├── scripts/                # installer, release and zirocd install scripts
├── deploy/terraform/aws/   # example AWS deployment
├── security/               # host hardening script
├── tests/                  # smoke, QEMU boot and cluster, router end to end, security
└── community/              # contributing guide
```

Keep each directory focused on one responsibility. Put base configuration in `rootfs/etc/`, package recipes in
`packages/`, image assembly in `images/`, and technical documentation in `docs/`. Include version and dependency
metadata with new package or module recipes, keep optional components independently buildable where practical, and
document how configuration overrides are applied before relying on them.

## Build and test commands

| Target | Description |
|---|---|
| `make all` | Build `ziroctl`, `ziropkg`, the rootfs and the Docker base image for the host architecture |
| `make tools` | Compile static `ziroctl` and `ziropkg` binaries into `bin/` |
| `make tools-all` | Cross-compile `ziroctl` and `ziropkg` for `x86_64` and `arm64` |
| `make zirocd-all` | Cross-compile `zirocd` for Linux, macOS and Windows |
| `make kernel` | Build the kernel (`KERNEL_FLAVOR=custom` by default, `alpine` for the distribution kernel) |
| `make rootfs` | Build the minimal rootfs (about 16 MB) and the host initramfs (under 300 MB) |
| `make rootfs-all` | Build rootfs archives for `x86_64` and `arm64` |
| `make docker-image` | Build the local `ziro-os:latest` Docker base image |
| `make docker-multiarch` | Build a multi-architecture OCI image with Buildx |
| `make image-iso` | Build the bootable hybrid UEFI/BIOS ISO |
| `make run-qemu` | Boot a local virtual machine with an interactive terminal |
| `make test` | Run the unit tests and the container smoke tests |
| `make test-unit` | Run the `ziroctl`, `ziropkg` and SDK unit tests |
| `make test-smoke` | Run the base container verification tests |
| `make test-boot` | Boot the image in QEMU and check the running host (needs `qemu-system-*`) |
| `make release`, `release-minor`, `release-major`, `release-force` | Maintainer release targets; see [Releases](#releases) |
| `make clean` | Remove transient build artifacts in `build/` |

## Coding standards

### Go (`tools/ziroctl`, `tools/ziropkg`, `tools/zirocd`, `sdk`)

- Format with `gofmt`.
- Build with `CGO_ENABLED=0` so binaries link statically without libc.
- Organize CLI commands as Cobra subcommands under `cmd/`.
- Every command supports `--help` and returns clear error messages.
- Write unit tests (`_test.go`) next to the code they cover.

```bash
cd tools/ziroctl && go test ./...
cd tools/ziropkg && go test ./...
cd tools/zirocd && go test ./...
cd sdk && go test ./...
```

### C99 (`init/ziro-init.c`)

- Write portable C99.
- Do not call `malloc` or `free` in the init and reaping paths, to avoid leaks and fragmentation over long uptimes.
- Link statically against musl libc (`musl-gcc -static`).
- Handle signals correctly: `SIGCHLD` with non-blocking `waitpid(-1, &status, WNOHANG)` to reap zombies, and
  `SIGINT` and `SIGTERM` for graceful shutdown.

### Shell scripts (`packages/`, `images/`, `kernel/`, `scripts/`)

- Start with `#!/bin/bash` and `set -euo pipefail`.
- Quote variables (`"$VAR"`) to prevent word splitting.
- Support both `x86_64` (`amd64`) and `arm64` (`aarch64`).
- Avoid hard-coded paths. Resolve the repository root from the script location, for example
  `$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)`.

### Known limitations in code

Mark a limitation that is accepted on purpose with a comment of this form, on the declaration it limits:

```go
// Known limitation: whole-state entries; switch to deltas if the state grows past ~1 MB.
```

State what is not handled and what to change when it starts to matter. Use `TODO` only for unfinished work that
should not ship. Document limitations that affect users in the relevant guide under `docs/` as well.

### Lint gate

CI runs the following on every pull request. Run them before pushing, and fix findings at their source rather than
suppressing them.

```bash
gofmt -l tools/ziroctl tools/ziropkg tools/zirocd sdk   # must print nothing
for m in sdk tools/ziroctl tools/ziropkg tools/zirocd; do
  (cd "$m" && go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...)
done
shellcheck -S warning kernel/*.sh scripts/*.sh scripts/*/*.sh packages/*.sh images/*/*.sh
npx markdownlint-cli2@0.23.3 "**/*.md" "#node_modules"  # Markdown style, see .markdownlint.json
```

The Go tests also check the documentation: every `ziroctl` command in `docs/` must exist with valid flags, and every
relative link and heading anchor in the Markdown files must resolve.

## Adding a command

Every operation has one implementation that the CLI, the REST API, declarative files, and the SDK share (see the
[design standard](../docs/design/README.md#how-to-add-a-feature)). The steps and their order are defined there.

## Testing your changes

Before opening a pull request, run:

```bash
# Unit tests
make test-unit

# Container smoke tests
make test-smoke

# Package manager end to end, inside the container
docker run --rm ziro-os:latest /bin/sh -c "ziropkg install curl && curl --version"
```

Changes that touch boot, the kernel, or cluster behavior also need `make test-boot` or the matching script in
`tests/qemu/`. Documentation changes are checked by `go test ./cmd -run TestDocCommands` in `tools/ziroctl`, which
verifies that every `ziroctl` example in `docs/` uses real commands and flags. All tests must pass.

## Pull requests

### Branch names

- `feature/<name>`, for example `feature/cni-wireguard`
- `fix/<name>`, for example `fix/apk-tls-ca-cert`
- `docs/<name>`, for example `docs/boot-instructions`

### Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(ziropkg): add search command with filter flags
fix(rootfs): resolve relative symlinks for busybox applets
docs(getting-started): clarify QEMU boot instructions
test(smoke): add package installation verification test
```

### Submitting

1. Push your branch to your fork.
2. Open a pull request against `main`.
3. Complete the pull request template: a summary and motivation, the components affected, and the test results.
4. CI runs unit tests, multi-architecture rootfs generation, container smoke tests, and security scans.

## Releases

Maintainers publish releases with the release script or the `make` targets:

```bash
# Preview the changes without committing or tagging
./scripts/release.sh --dry-run patch

# Bump the patch version (1.0.0 -> 1.0.1)
make release            # or: ./scripts/release.sh patch

# Re-release the same tag, for example after a failed CI build
make release-force      # or: ./scripts/release.sh --force

# Bump the minor or major version
make release-minor      # 1.0.0 -> 1.1.0
make release-major      # 1.0.0 -> 2.0.0

# Set an exact version
./scripts/release.sh 1.2.0
```

The script:

1. Calculates the next semantic version and the UTC build date. An OS release also publishes `tools/vX.Y.Z`, which
   must be higher than every existing tools version (clients install only the newest tag). `patch`, `minor` and
   `major` therefore bump from the newest tools version when it is ahead of `VERSION` (tools-only builds do not bump
   `VERSION`), and a version at or below it is refused before anything is tagged.
2. Updates `VERSION`, `rootfs/etc/os-release`, `tools/ziroctl/cmd/version.go`, `tools/ziropkg/cmd/root.go`, and
   `images/docker/Dockerfile`.
3. Commits the changes (`chore(release): bump version to vX.Y.Z`).
4. Creates an annotated Git tag (`vX.Y.Z`) with a generated changelog summary.
5. Pushes the branch and the tag.
6. Triggers GitHub Actions, which build multi-architecture images, publish release assets, push container images to
   GitHub Container Registry (`ghcr.io`), and deploy the release catalog to GitHub Pages.

### Tools-only releases (`x.y.z.N`)

A fix that touches only `ziroctl`, `ziropkg`, `zirocd` or the SDK does not need an OS release. It is published as the
next tools build, `tools/vX.Y.Z.N`: `X.Y.Z` is the newest tools version and `N` counts the builds of it
(`1.0.25` → `1.0.25.1` → `1.0.25.2`). `N` starts at 1. `.0`, leading zeros, and a fifth part are invalid, and the
order is numeric (`.10` is newer than `.9`).

- **Automatic number.** Run the Tools Release workflow by hand on `main` with the version left empty. It takes the
  next `N` of the newest `tools/v*` tag (`scripts/release/tools-version.sh`).
- **Manual tag.** Push the tag yourself: `git tag tools/v1.0.25.2 && git push origin tools/v1.0.25.2`. The workflow
  refuses a version that is not higher than every existing tools tag, because clients install only the newest one.
- **OS tags stay three parts.** `vX.Y.Z.N` never starts an OS release (`scripts/release/check-tag.sh`), and the OS
  workflow ignores it.
- **Compatibility.** A build must stay wire- and state-compatible with the other builds of its `X.Y.Z`. Nodes of a
  cluster can run different tools builds, and `ziroctl update --rollback` restores the previous binary. A change to
  the cluster protocol, or to state that needs a migration, needs a new OS release.
- **No automatic downgrades.** `ziroctl update --version <older>` needs `--allow-downgrade`.

## Security vulnerabilities

Do not open a public issue for a security vulnerability. Report it privately as described in
[SECURITY.md](../SECURITY.md).

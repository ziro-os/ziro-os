# Contributing to Ziro-OS

Thank you for your interest in contributing to **Ziro-OS**! We are building an ultra-lightweight, container-native operating system designed from first principles for cloud-native workloads, microVMs, and container infrastructure.

This guide outlines our development workflow, coding standards, and how to get your contributions reviewed and merged smoothly.

---

## 🌟 Principles & Design Philosophy

Every contribution to Ziro-OS should respect our core design tenets:

1. **Minimal by Design**: Ship only what is needed for container workloads. The minimal container rootfs is about
   16 MB; CI keeps bootable host images under 300 MB.
2. **Container-Native First**: The host OS exists to host and schedule OCI containers via `containerd` and `runc`. Containers are first-class citizens.
3. **Controlled mutable state**: An immutable installed root is a goal. Today the installer mounts ext4 read/write,
   while live boot uses writable tmpfs. Document and minimize writable paths.
4. **True Multi-Architecture**: Full support for both `x86_64` (Intel/AMD) and `arm64` (Apple Silicon & ARM64 cloud instances).
5. **Static Linking & Zero Bloat**: Prefer statically compiled Go and C99 binaries with musl libc to avoid runtime dynamic library dependency issues.

The [design standard](../docs/design/README.md) turns these into concrete rules: the resource model, API and CLI
conventions, extension points and the security model. Larger changes need an [RFC](../docs/design/rfcs/README.md).

---

## 🚀 Development Environment Setup

### Prerequisites

To build and test Ziro-OS locally, ensure you have the following installed:

- **Go 1.27.1+**: Required by the `ziroctl` and `ziropkg` modules.
- **Docker 24.0+** (with Buildx support): For rootfs extraction and container base building.
- **GCC / Clang** (or `musl-gcc`): For compiling `ziro-init` PID 1 supervisor.
- **QEMU** (`qemu-system-x86_64` and/or `qemu-system-aarch64`): For running microVM tests.
- **xorriso / mtools / dosfstools** (optional): For generating bootable hybrid ISO images.
- **Make**: Standard build orchestrator.

### Setup Instructions

```bash
# 1. Fork and clone the repository
git clone https://github.com/<your-username>/ziro-os.git
cd ziro-os

# 2. Verify build tools
go version
docker version
make --version

# 3. Build the default target (tools, rootfs, Docker base image)
make all

# 4. Run the test suite
make test
```

---

## 🏗️ Repository Architecture

Understanding the project layout:

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
├── tests/                  # smoke, QEMU boot/cluster, router e2e, security
└── community/              # contributing guide
```

Keep each directory focused on one responsibility. Put base configuration in `rootfs/etc/`, package recipes in
`packages/`, image assembly in `images/`, and user-facing technical documentation in `docs/`. Include version and
dependency metadata with new package or module recipes. Keep optional components independently buildable where
practical, and document how configuration overrides are applied before relying on them.

---

## 🛠️ Common Build & Test Commands

We provide standard `make` targets to keep development reproducible:

| Target | Description |
|---|---|
| `make all` | Build `ziroctl`, `ziropkg`, rootfs, and Docker base image for host architecture |
| `make tools` | Compile static `ziroctl` and `ziropkg` binaries into `bin/` |
| `make tools-all` | Cross-compile `ziroctl` and `ziropkg` for `x86_64` and `arm64` |
| `make rootfs` | Build minimal rootfs (≈16 MB) and full host initramfs (< 300 MB) |
| `make rootfs-all` | Build rootfs archives for both `x86_64` and `arm64` |
| `make docker-image` | Build local `ziro-os:latest` Docker base image |
| `make docker-multiarch` | Build multi-arch OCI image with Docker buildx (`amd64` + `arm64`) |
| `make image-iso` | Generate bootable hybrid UEFI/BIOS ISO |
| `make run-qemu` | Launch local microVM with interactive terminal |
| `make test` | Run complete unit tests and container smoke test suite |
| `make test-unit` | Run unit tests for `ziroctl` and `ziropkg` |
| `make test-smoke` | Run base container verification tests |
| `make clean` | Clean transient build artifacts in `build/` |

---

## 📋 Coding Standards

### 1. Go (`tools/ziroctl/`, `tools/ziropkg/`)

- Format code using `gofmt` (`go fmt ./...`).
- Always use `CGO_ENABLED=0` for static compilation without libc dependencies.
- Organize CLI commands with Cobra subcommands under `cmd/`.
- Every command should support `--help` and clean error messaging.
- Write unit tests (`_test.go`) alongside command implementations.

```bash
cd tools/ziroctl && go test -v ./...
cd tools/ziropkg && go test -v ./...
```

### 2. C99 (`init/ziro-init.c`)

- Written in clean, ANSI C99.
- No dynamic memory allocation (`malloc`/`free`) in critical init/reaping paths to prevent memory leaks or fragmentation during long uptimes.
- Statically link against musl libc (`musl-gcc -static`).
- Handle signals properly: `SIGCHLD` for non-blocking zombie reaping (`waitpid(-1, &status, WNOHANG)`), `SIGINT`/`SIGTERM` for graceful shutdown.

### 3. Shell Scripts (`packages/`, `images/`, `kernel/`)

- Always begin with:
  ```bash
  #!/bin/bash
  set -euo pipefail
  ```
- Always quote variables to prevent word splitting (`"$VAR"`).
- Make scripts architecture-aware: support both `x86_64` (or `amd64`) and `arm64` (or `aarch64`).
- Avoid hardcoded paths; resolve repository roots dynamically via `$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)`.

### Lint gate

CI runs these on every pull request; run them before pushing. Fix findings at their source rather than suppressing
them.

```bash
gofmt -l tools/ziroctl tools/ziropkg sdk          # must print nothing
for m in sdk tools/ziroctl tools/ziropkg; do
  (cd "$m" && go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...)
done
shellcheck -S warning kernel/*.sh scripts/*.sh scripts/*/*.sh packages/*.sh images/*/*.sh
```

---

## 🧩 How to Add a Command

Every operation has one implementation that the CLI, the REST API, declarative files and the SDK share (see the
[design standard](../docs/design/README.md#how-to-add-a-feature)):

1. **Operation:** a function in `tools/ziroctl/cmd` that validates its input with `sdk/schema` and does the work.
2. **CLI:** a Cobra command (noun, then verb) that parses flags, calls the operation, and prints through
   `printResult` so `--json` works.
3. **API:** one entry in the route table (`api_routes.go` and the `register*Routes` functions) with the least role
   that is safe; request and response types in `sdk/api`.
4. **OpenAPI:** the route and its `x-ziro-role` in `sdk/openapi.yaml` (`TestOpenAPIMatchesRoutes` fails otherwise).
5. **SDK:** a typed method in `sdk/client`.
6. **Tests:** unit tests next to the code; `tests/qemu/boot-smoke.py` when it needs a booted host.
7. **Docs:** the user guide in `docs/`.

---

## 🧪 Testing Your Changes

Before opening a pull request, run the test suites locally:

```bash
# 1. Run unit tests
make test-unit

# 2. Run container smoke tests
make test-smoke

# 3. Test package manager end-to-end inside the container
docker run --rm ziro-os:latest /bin/sh -c "ziropkg install curl && curl --version"
```

All tests must pass cleanly.

---

## 🔄 Development Workflow & Pull Requests

### 1. Branch Naming

Follow structured branch names:
- `feature/<feature-name>` (e.g., `feature/cni-wireguard`)
- `fix/<issue-name>` (e.g., `fix/apk-tls-ca-cert`)
- `docs/<doc-update>` (e.g., `docs/quickstart-guide`)

### 2. Conventional Commits

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(ziropkg): add search command with filter flags
fix(rootfs): resolve relative symlinks for busybox applets
docs(getting-started): clarify QEMU boot instructions
test(smoke): add package installation verification test
```

### 3. Submitting a Pull Request

1. Push your branch to your GitHub fork.
2. Open a Pull Request targeting the `main` branch.
3. Fill out the PR template with:
   - Summary of changes and motivation.
   - Architectures tested (`x86_64`, `arm64`).
   - Test results (`make test` output).
4. CI checks will run automatically across unit tests, multi-arch rootfs generation, container smoke tests, and security scans.

---

## 🚀 Release Management & Automation

Maintainers can trigger an automated release using the release utility or `make` targets:

```bash
# 1. Preview changes without committing or tagging
./scripts/release.sh --dry-run patch

# 2. Automatically bump patch version (e.g., 1.0.0 -> 1.0.1)
make release
# or: ./scripts/release.sh patch

# 3. Force re-release the same tag (e.g., if CI build failed or needs replacing)
make release-force
# or: ./scripts/release.sh --force

# 4. Bump minor or major versions
make release-minor   # 1.0.0 -> 1.1.0
make release-major   # 1.0.0 -> 2.0.0

# 5. Or specify an exact version
./scripts/release.sh 1.2.0
```

The script automatically:
1. Calculates the next semantic version and UTC build date.
2. Updates `VERSION`, `rootfs/etc/os-release`, `tools/ziroctl/cmd/version.go`, `tools/ziropkg/cmd/root.go`, and `images/docker/Dockerfile`.
3. Commits the changes (`chore(release): bump version to vX.Y.Z`).
4. Creates an annotated Git tag (`vX.Y.Z`) with an automated changelog summary.
5. Pushes the branch and tag to the remote repository.
6. Triggers GitHub Actions to build multi-arch images, publish release assets, push container images to GitHub Container Registry (`ghcr.io`), and deploy the release catalog to GitHub Pages.

---

## 🔒 Security Vulnerability Reporting

If you discover a security vulnerability in Ziro-OS, please do **NOT** open a public issue. Report it privately as
described in [SECURITY.md](../SECURITY.md).

---

> _Ziro-OS — Minimal by design. Born for the cloud._

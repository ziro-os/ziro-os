# Project Structure — Ziro‑OS

This document defines the folder layout, responsibilities, and conventions for the Ziro‑OS project.

```
ziro-os/
├── kernel/ # Kernel sources, patches, configuration files
│ ├── linux/ # If using Linux kernel, store patches etc.
│ └── config/ # Kernel configuration files for target platforms
├── rootfs/ # The minimal userland root filesystem
│ ├── etc/ # Config files (init, services, etc)
│ ├── bin/ # Essential executables (busybox, core tools)
│ ├── sbin/ # System binaries
│ └── lib/ # Libraries (e.g. musl)
├── packages/ # Build recipes for additional packages & modules
│ ├── cni/ # CNI plugins (bridge, flannel, etc)
│ ├── network/ # network modules (DHCP, DNS)
│ ├── logging/ # optional logging backends
│ └── storage/ # volume drivers, storage modules
├── containerd/ # containerd integration, configs, shims
├── docker/ # (Optional) Docker Engine support modules
├── podman/ # (Optional) Podman integration / compatibility layers
├── images/ # Scripts & definitions for building images (ISO, VM, cloud)
│ ├── qemu/ # QEMU image / scripts
│ ├── aws/ # AWS AMI builder scripts
│ ├── azure/ # Azure VM image scripts
│ └── generic/ # Generic VM / ISO builder
├── tools/ # Utilities, CLI tools (e.g. ziroctl)
├── docs/ # Design docs, architecture, contributor guides
├── tests/ # Integration / automated test harnesses
├── .github/ # GitHub CI, issue templates
├── LICENSE
└── README.md
```

### 🧠 Conventions & Guidelines

- **One responsibility per directory**: keep cross-cutting concerns separate
- **Immutable rootfs**: after build, rootfs should not mutate in normal operations
- **Recipe format**: each package module should include a recipe (e.g. `.mk` script or manifest) with metadata (name, version, dependencies, build steps)
- **Versioning and CI**: each commit must build core + optional modules; CI will validate minimal smoke tests
- **Modularity**: modules should compile independently and be plug-and-play — minimal coupling
- **Configuration layering**: base configs in `rootfs/etc/`, override via modules or user config files

---

## 🧪 Build & Deployment Flow (Sketch)

1. Build the kernel (from `kernel/`)
2. Compile base userland (musl, busybox, essential tools) into `rootfs/`
3. Install containerd, Docker / Podman modules (from respective dirs)
4. Package rootfs + kernel into an image (ISO, VM, cloud) via `images/` scripts
5. Run tests (in `tests/`) via QEMU or containerized env
6. Publish images / deliver artifacts

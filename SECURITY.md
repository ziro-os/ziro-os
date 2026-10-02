# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/ziro-os/ziro-os/security/advisories/new) (Security tab → "Report a
vulnerability"). Don't open a public issue or pull request for a vulnerability.

Include the affected version (`ziroctl version`), the steps to reproduce, and the impact you expect. We aim to
acknowledge a report within 3 working days, agree on a fix and a disclosure date with you, and credit you in the
advisory unless you ask us not to.

## Supported versions

Only the latest release is supported: the latest `vX.Y.Z` OS release, the latest `tools/vX.Y.Z` release of
`ziroctl` and `ziropkg`, and the latest `sdk/vX.Y.Z`. Fixes ship in a new release; `ziroctl update` and
`ziroctl upgrade` install it.

## Scope

In scope: everything in this repository, including the kernel configuration, `ziro-init`, the rootfs and images,
`ziroctl` (CLI, REST API, cluster, gateway), `ziropkg`, the SDK, the installer, the official catalogs and the
release pipeline.

Examples: authentication or role bypass in the API, secrets exposed in argv, logs or environment, escaping a
signature or sha256 check, container-to-host escapes caused by Ziro's configuration, and audit-log tampering that
`ziroctl audit verify` doesn't detect.

Out of scope: vulnerabilities in upstream projects (Linux, containerd, runc, BusyBox, Alpine packages) that Ziro
doesn't make worse — report those upstream, though we're glad to hear about them to update quickly — and anything
that needs root on the host already, unless it defeats a documented control.

## Signing keys

| What | Key | Verified by |
|---|---|---|
| Tools and OS releases (`SHA256SUMS.sig`, ed25519) | public half in [`tools/ziroctl/cmd/release.pub`](tools/ziroctl/cmd/release.pub) | `ziroctl update` / `ziroctl upgrade` before installing |
| Kernel modules | certificate [`kernel/certs/ziro-modules.crt`](kernel/certs/ziro-modules.crt) | the kernel (`MODULE_SIG_FORCE`) |
| Official catalogs (ed25519-signed index; separate keys for plugins and apps) | public keys in [`tools/ziroctl/cmd/catalog_keys.go`](tools/ziroctl/cmd/catalog_keys.go) | `ziroctl` on every catalog sync |

The private halves are CI secrets: `ZIRO_RELEASE_KEY` and `ZIRO_MODULE_SIGNING_KEY` here, `ZIRO_CATALOG_KEY` in
[ziro-os/pkgs](https://github.com/ziro-os/pkgs) and [ziro-os/apps](https://github.com/ziro-os/apps). See [docs/security.md](docs/security.md) for the
controls and their known limits, and the [design standard](docs/design/README.md#security-model) for the security
model.

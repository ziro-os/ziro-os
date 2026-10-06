# Governance

## Maintainers

Maintainers review and merge pull requests, run releases and handle security reports. They are listed in
[`.github/CODEOWNERS`](.github/CODEOWNERS). Contributors who have made sustained, high-quality contributions can be
invited to become maintainers by the existing maintainers.

## Decisions

- Maintainers decide by consensus, usually in the pull request. If consensus can't be reached, the project lead
  (@sombochea) decides and records why.
- Every change lands through a pull request against `main` with green CI. Code owners of the files it touches are
  asked to review it.
- Larger changes (new resource kinds, API or schema changes, security model changes) need an accepted
  [RFC](docs/design/rfcs/README.md) first. All changes follow the [design standard](docs/design/README.md).

## Releases

- **OS releases** are tagged `vX.Y.Z` with `scripts/release.sh` ([CONTRIBUTING](community/CONTRIBUTING.md#-release-management--automation)).
- **Tools** (`ziroctl`, `ziropkg`, `zirocd`) release on their own stream, tagged `tools/vX.Y.Z` or `tools/vX.Y.Z.N` (the Nth tools-only build, so a CLI fix never needs a new OS version).
- **The SDK** is tagged `sdk/vX.Y.Z` and follows semantic versioning.
- Release artifacts are built and signed in CI ([SECURITY.md](SECURITY.md#signing-keys)). Only the latest release
  receives fixes.

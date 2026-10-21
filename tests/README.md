# Tests

| Suite | What it checks | Run |
|---|---|---|
| Go unit tests | `ziroctl`, `ziropkg`, `zirocd` and the SDK, including the documentation examples | `make test-unit` |
| `smoke/` | the container base image | `make test-smoke` |
| `qemu/boot-smoke.py` | boots the kernel and initramfs: containerd, firewall, disks, modules (`--installed` also installs) | `make test-boot` |
| `qemu/cluster-smoke.py`, `qemu/ha-smoke.py` | multi-VM clusters and master failover | `python3 tests/qemu/cluster-smoke.py --arch arm64` |
| `qemu/sandbox-cluster-smoke.py` | sandbox placement, request forwarding and SSH relay across a two-node cluster | `python3 tests/qemu/sandbox-cluster-smoke.py --arch arm64` |
| `router/e2e.sh` | router, relays and `zirocd` across NATs in Docker | `tests/router/e2e.sh` |
| `release/test-release-scripts.sh` | the release and tools-version scripts | `sh tests/release/test-release-scripts.sh` |
| `integration/` | container runtime checks on a host | run the scripts directly |
| `security/` | hardening and artifact metadata checks | run the scripts directly |

CI runs the unit tests, the size limit and the boot tests on every pull request.

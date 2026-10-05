# Tests

| Suite | What it checks | Run |
|---|---|---|
| Go unit tests | ziroctl, ziropkg, zirocd, the SDK, including doc commands | `make test-unit` |
| `smoke/` | the container base image | `make test-smoke` |
| `qemu/boot-smoke.py` | boots the kernel and initramfs: containerd, firewall, disks, plugins (`--installed` also installs) | `make test-boot` |
| `qemu/cluster-smoke.py`, `qemu/ha-smoke.py` | multi-VM clusters and master failover | `python3 tests/qemu/cluster-smoke.py --arch arm64` |
| `router/e2e.sh` | router, relays and zirocd across NATs in Docker | `tests/router/e2e.sh` |
| `integration/`, `security/` | container runtime and hardening checks on a host | see the scripts |

CI runs the unit tests, the size limit and the boot tests on every pull request.

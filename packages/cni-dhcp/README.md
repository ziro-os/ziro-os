# DHCP CNI dependency override

The host builder retains Alpine's CNI plugin set and replaces both shipped copies
of DHCP with upstream CNI v1.9.1 compiled against `golang.org/x/net v0.59.0`.
The DHCP client dependency is also pinned to its patched July 2026 revision,
closing GO-2026-6237 (a malformed IPv4 packet can panic the DHCP client).
Alpine's 1.9.1-r3 binary embeds v0.43.0, which triggers five high-severity
dependency advisories. Their presence does not establish exploitability through
the DHCP plugin. The default bridge configuration uses host-local IPAM.

`go.mod` and `go.sum` lock this external command build. Build with
`go build -mod=readonly github.com/containernetworking/plugins/plugins/ipam/dhcp`
from this directory; it is a dependency build module, not a local Go application.
The rootfs builder sets Linux, target architecture, and static linking, and fails
if compilation or replacement fails. Neither source nor the Go toolchain ships.

This replaces an APK-owned file; an in-place `apk upgrade cni-plugins` can restore
Alpine's binary. Update hosts through rebuilt Ziro images, or reapply and verify
the override after a package upgrade. Remove the override only after the signed
Alpine package ships a patched dependency and both copies pass an artifact scan.

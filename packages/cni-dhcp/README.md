# DHCP CNI dependency override

The host builder retains Alpine's CNI plugin set and replaces both shipped copies
of DHCP with upstream CNI v1.9.1 compiled against `golang.org/x/net v0.59.0`.
The DHCP client dependency is also pinned to its patched July 2026 revision,
closing GO-2026-6237 (a malformed IPv4 packet can panic the DHCP client).
Alpine's 1.9.1-r3 binary embeds v0.43.0, which triggers five high-severity
dependency advisories. Their presence does not establish exploitability through
the DHCP plugin. The default bridge configuration uses host-local IPAM.

The module graph also raises dependencies that CNI v1.9.1 requires but the DHCP binary never links,
so graph-level scanners (Snyk, OSV) stay clean: `google.golang.org/grpc` v1.83.2 (GHSA-p77j-4mvh-x3m3 and
nine other advisories; 1.84.0 is still affected by GO-2026-6443), `github.com/buger/jsonparser` v1.1.2,
and `go.opentelemetry.io/otel/sdk` v1.45.0. `go version -m` on the built binary shows none of them, and
CI runs govulncheck on the build target. GO-2026-5932 (`golang.org/x/crypto/openpgp` is unmaintained) has
no fixed version, and nothing here imports that package.

`go.mod` and `go.sum` lock this external command build. Build with
`go build -mod=readonly github.com/containernetworking/plugins/plugins/ipam/dhcp`
from this directory; it is a dependency build module, not a local Go application.
Do not run `go mod tidy` here: with no Go files of its own it would drop every requirement. Change
versions with `go get <module>@<version>`, then run
`GOOS=linux go get github.com/containernetworking/plugins/plugins/ipam/dhcp@v1.9.1` to complete `go.sum`.
The rootfs builder sets Linux, target architecture, and static linking, and fails
if compilation or replacement fails. Neither source nor the Go toolchain ships.

This replaces an APK-owned file; an in-place `apk upgrade cni-plugins` can restore
Alpine's binary. Update hosts through rebuilt Ziro images, or reapply and verify
the override after a package upgrade. Remove the override only after the signed
Alpine package ships a patched dependency and both copies pass an artifact scan.

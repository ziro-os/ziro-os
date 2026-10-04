Empty stand-in for `gvisor.dev/gvisor`, used by `replace` in `tools/ziroctl` and `tools/zirocd`.
wireguard-go requires gVisor only for `tun/netstack`, which neither tool imports. If a build fails
with "does not contain package gvisor.dev/gvisor/...", something started importing netstack:
remove the replace deliberately rather than adding packages here. In `tools/zirocd` (and `tools/ziroctl`, which imports its daemon), run
`go mod tidy -e` (wireguard's own tun tests import gVisor).

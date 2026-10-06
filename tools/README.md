# Tools

| Tool | What it is | Docs |
|---|---|---|
| [`ziroctl`](ziroctl) | The host CLI and its daemons (API server, gateway, deploy daemon, cluster agent). One static Go binary. | [docs/](../docs/README.md) |
| [`ziropkg`](ziropkg) | Extra Alpine packages that survive OS upgrades (`ziropkg install htop`). | [operations](../docs/operations.md) |
| [`zirocd`](zirocd) | The router client for Linux, macOS and Windows, and the `moon` relay. | [router](../docs/router.md) |
| [`gvisor-stub`](gvisor-stub) | Replaces the gVisor module pulled in by wireguard-go; see its README. | |

```sh
cd tools/ziroctl && go test ./... && CGO_ENABLED=0 go build -o ../../bin/ziroctl .
```

Releases ship on their own signed stream (`tools/vX.Y.Z` and `tools/vX.Y.Z.N`); hosts update with `ziroctl update`.

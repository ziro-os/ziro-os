# Images

| Directory | Builds | How |
|---|---|---|
| `iso/` | hybrid BIOS/UEFI ISO with the installer | `make image-iso` |
| `qemu/` | direct-kernel boot runner for local testing | `make run-qemu` |
| `docker/` | the `FROM scratch` container base image | `make docker-image`, `make docker-multiarch` |
| `zirocd/` | the router client/moon image (`ghcr.io/ziro-os/zirocd`) | release workflow |
| `aws/`, `gcp/`, `azure/` | cloud images with Packer (experimental) | the scripts, or the **Build Cloud Images** workflow |

See [building](../docs/building.md), [installation](../docs/installation-guide.md) and [cloud](../docs/cloud.md).

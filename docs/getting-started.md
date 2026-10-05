# Getting started

There are three ways to try Ziro OS, from quickest to most complete.

| | What you get | Time |
|---|---|---|
| [Container base image](#1-container-base-image) | the 16 MB userland as a Docker base image | seconds |
| [VM from the release](#2-boot-a-vm) | the full host (containerd, ziroctl, firewall...) in RAM, nothing installed | a minute |
| [Install](installation-guide.md) | a persistent host on a VM or bare metal | five minutes |

## 1. Container base image

```sh
docker run --rm -it ghcr.io/ziro-os/ziro-os:latest sh
```

Use it as a small base for your own images:

```dockerfile
FROM ghcr.io/ziro-os/ziro-os:latest
COPY app /usr/local/bin/app
USER 65532
ENTRYPOINT ["/usr/local/bin/app"]
```

This is the userland only. Host features (ziro-init, containerd, the firewall) need a VM or an install.

## 2. Boot a VM

Ziro OS boots straight from a kernel and initramfs: no bootloader, no disk. Download both from the
[latest release](https://github.com/ziro-os/ziro-os/releases/latest) (`vmlinuz-<arch>` and
`ziro-initramfs-<arch>.cpio.gz`), then:

```sh
# Apple Silicon (arm64, Hypervisor.framework)
qemu-system-aarch64 -machine virt -accel hvf -cpu host -m 2048 -smp 2 -nographic \
  -kernel vmlinuz-arm64 -initrd ziro-initramfs-arm64.cpio.gz -append "console=ttyAMA0 rdinit=/init" \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n0

# Linux x86_64 (KVM)
qemu-system-x86_64 -accel kvm -cpu host -m 2048 -smp 2 -nographic \
  -kernel vmlinuz-x86_64 -initrd ziro-initramfs-x86_64.cpio.gz -append "console=ttyS0 rdinit=/init" \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n0
```

From a source checkout, `make run-qemu` does the same with your own build (see [building](building.md)). Install
QEMU with `brew install qemu` or `apt install qemu-system`. Quit QEMU with `Ctrl-A`, then `X`.

The live system gives you a root shell:

```sh
ziroctl motd                                    # what's running and what needs attention
ziroctl container run -d --name web -p 8080:80 nginx:1.27
ziroctl gateway route add web --host web.localhost --to 127.0.0.1:8080 --tls off
ziroctl security audit
```

Live mode keeps everything in RAM. To keep it, run `ziroctl install` from inside the VM with a disk attached.

## Hypervisors

| Hypervisor | Notes |
|---|---|
| QEMU/KVM, Apple HVF | direct kernel boot as above, or the ISO |
| Proxmox VE, VMware, VirtualBox | boot the ISO and install ([installation](installation-guide.md)); BIOS or UEFI; VirtIO, SCSI, SATA and NVMe disks |
| AWS, OpenStack, Alibaba Cloud | metadata SSH keys and user-data on first boot ([cloud](cloud.md)) |

## Where next

- **Run workloads:** [containers](containers.md), [apps](apps.md), [deploy from git](deploy.md),
  [stacks](provisioning.md).
- **Publish them:** [gateway](gateway.md).
- **Operate:** [operations](operations.md), [security](security.md), [backup](backup.md).
- **Grow:** [clustering](clustering.md) and the [global router](router.md).

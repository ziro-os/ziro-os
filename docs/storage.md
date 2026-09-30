# Storage

## Growing disks

Resize the VM or cloud volume, and Ziro-OS grows the partition and ext4 filesystem to fill it. No reboot is
needed:

- at boot (for a disk resized while the host was off)
- every minute from cron, which is a cheap read of sysfs when nothing changed
- on demand:

```sh
ziroctl disk expand --dry-run   # what would grow
ziroctl disk expand
```

- **What grows:** the root filesystem and every data disk added below. Only the last partition on a disk can grow
  (the installer puts the root partition last).
- **How:** the backup GPT header moves to the new end of the disk, the partition is extended with `sfdisk`, the
  kernel is told with `partx -u` (which works while the partition is mounted), and ext4 grows online with
  `resize2fs`.
- **Alerts:** each growth is audited and raises a low-severity `disk` alert. A filesystem 90% or more full raises
  a high-severity `disk` alert.

## Data disks

```sh
ziroctl disk add /dev/vdb --mount /data                  # label ZIRO_DATA_1
ziroctl disk add /dev/nvme1n1 --mount /var/lib/containerd --label CONTAINERS
ziroctl disk remove /data                                # unmount and forget; the data stays
```

- **Formatting:** `disk add` creates a GPT with one partition and ext4 (1% reserved blocks, lazy init, so it's
  fast even on large disks).
- **Mounting:** it mounts with `noatime,nodev,nosuid` and records the disk in `/etc/ziro/disks.json`. Disks are
  mounted by label at boot **before containerd starts**, so `/var/lib/containerd` can live on one.
- **Safety:** it refuses the disk holding the root filesystem, disks with partitions or a filesystem, non-empty
  mount points (whose files would be hidden), and system paths (`/etc`, `/usr`, `/boot`, ...). `--force` overrides
  the data checks on the CLI, never over the API.
- **Growing:** data disks grow automatically like the root.

API: `GET /api/v1/disks` (viewer); `POST /api/v1/disks` `{"device", "mount", "label"}` and
`POST /api/v1/disks/expand` (admin).

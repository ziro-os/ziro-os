#!/usr/bin/env python3
"""Verify shipped archive ownership, sensitive modes, and host image size."""
import gzip
import pathlib
import stat
import sys
import tarfile


def inspect(path):
    members = {}
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            for entry in archive:
                assert (entry.uid, entry.gid) == (0, 0), (entry.name, entry.uid, entry.gid)
                members[entry.name.removeprefix("./")] = entry.mode
    else:
        assert path.stat().st_size < 300_000_000, f"oversized host image: {path}"
        with gzip.open(path, "rb") as archive:
            while True:
                header = archive.read(110)
                assert len(header) == 110 and header[:6] in (b"070701", b"070702"), "invalid newc header"
                fields = [int(header[i:i+8], 16) for i in range(6, 110, 8)]
                mode, uid, gid, size, name_size = fields[1], fields[2], fields[3], fields[6], fields[11]
                name = archive.read(name_size)[:-1].decode().removeprefix("./")
                archive.read(-(110 + name_size) % 4)
                if name == "TRAILER!!!":
                    break
                assert (uid, gid) == (0, 0), (name, uid, gid)
                members[name] = stat.S_IMODE(mode)
                if name == "dev/console":
                    assert stat.S_ISCHR(mode) and fields[9:11] == [5, 1], "invalid console device"
                remaining = size
                while remaining:
                    chunk = archive.read(min(remaining, 1 << 20))
                    assert chunk, "truncated member"
                    remaining -= len(chunk)
                archive.read(-size % 4)
    for name, expected in {"root": 0o700, "etc/shadow": 0o600, "tmp": 0o1777}.items():
        assert members.get(name) == expected, (name, members.get(name), expected)
    for name in ("bin/busybox", "usr/bin/ziroctl", "usr/bin/ziropkg"):
        assert name in members and members[name] & 0o111, f"missing executable: {name}"
        assert not members[name] & 0o022, f"writable privileged binary: {name}"
    print(f"PASS {path}: {len(members)} members owned by root; private modes preserved")


if __name__ == "__main__":
    assert len(sys.argv) > 1, "provide tar.gz/cpio.gz artifact paths"
    for argument in sys.argv[1:]:
        inspect(pathlib.Path(argument))

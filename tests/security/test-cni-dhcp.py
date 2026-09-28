#!/usr/bin/env python3
"""Check both shipped DHCP copies and the upstream CNI VERSION contract."""
import json
import pathlib
import struct
import subprocess
import sys


def inspect(root, arch):
    goarch = {"x86_64": "amd64", "arm64": "arm64"}[arch]
    files = [root / "usr/libexec/cni/dhcp", root / "opt/cni/bin/dhcp"]
    assert files[0].read_bytes() == files[1].read_bytes(), "DHCP copies differ"
    for path in files:
        metadata = subprocess.check_output(["go", "version", "-m", str(path)], text=True)
        assert "golang.org/x/net\tv0.59.0\t" in metadata, metadata
        assert "github.com/containernetworking/plugins\tv1.9.1\t" in metadata, metadata
        assert "github.com/insomniacslk/dhcp\tv0.0.0-20260719225207-c76316d4aa82\t" in metadata, metadata
        assert "CGO_ENABLED=0" in metadata and f"GOARCH={goarch}" in metadata, metadata
        data = path.read_bytes()
        assert data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64"
        assert struct.unpack_from("<H", data, 18)[0] == {"amd64": 62, "arm64": 183}[goarch]
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        assert all(struct.unpack_from("<I", data, offset + i * size)[0] != 3 for i in range(count)), "dynamic interpreter"
        assert path.stat().st_mode & 0o111 and not path.stat().st_mode & 0o022, "unsafe executable mode"
    output = subprocess.check_output([
        "docker", "run", "--rm", "--network=none", "--platform", f"linux/{goarch}",
        "-e", "CNI_COMMAND=VERSION", "-v", f"{files[0].resolve()}:/dhcp:ro",
        "alpine:3.24", "/dhcp",
    ], text=True)
    assert "1.0.0" in json.loads(output)["supportedVersions"], output
    print(f"PASS {root}: both DHCP copies use patched x/net, static {goarch}, CNI 1.0.0 supported")


if __name__ == "__main__":
    inspect(pathlib.Path(sys.argv[1]), sys.argv[2])

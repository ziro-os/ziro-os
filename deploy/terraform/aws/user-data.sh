#!/bin/bash
# AWS user-data for Ziro-OS nodes (rendered by Terraform templatefile()).
# Shell variables are written as $${VAR} so Terraform leaves them alone.
set -eu

CLUSTER_NAME="${cluster_name}"
ZIRO_REF="${ziro_version}"   # git tag: scripts are fetched from this pinned release, never 'main'
RAW="https://raw.githubusercontent.com/ziro-os/ziro-os/$${ZIRO_REF}"

# IMDSv2 (the launch template sets http_tokens = required)
IMDS_TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
imds() { curl -fsS -H "X-aws-ec2-metadata-token: $${IMDS_TOKEN}" "http://169.254.169.254/latest/meta-data/$1"; }

# fetch_run <path> <sha256|empty>: download to a private file, verify when a hash is given, then run.
fetch_run() {
    f=$(mktemp)
    curl -fsSL "$${RAW}/$1" -o "$f"
    if [ -n "$2" ]; then
        echo "$2  $f" | sha256sum -c - >/dev/null || { echo "checksum mismatch for $1" >&2; rm -f "$f"; exit 1; }
    fi
    bash "$f"
    rm -f "$f"
}

NODE_NAME=$(imds instance-id)
echo "=== Ziro-OS Node Bootstrap ==="
echo "Cluster: $${CLUSTER_NAME}  Node: $${NODE_NAME}  Release: $${ZIRO_REF}"

# Wait (max 5 min) for containerd, which ziro-init supervises
i=0
until ziroctl service status containerd | grep -q RUNNING; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { echo "containerd not ready" >&2; exit 1; }
    sleep 5
done
echo "✓ Containerd is ready"

if [ ! -f /etc/security/limits.d/ziro-os.conf ]; then
    echo "Applying security hardening..."
    fetch_run security/harden-system.sh "${harden_sha256}"
fi

echo "✅ Ziro-OS node bootstrap complete"

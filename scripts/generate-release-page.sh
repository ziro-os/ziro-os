#!/usr/bin/env bash
# Ziro-OS GitHub Pages Release & Download Catalog Generator
# Generates a modern, static release portal for GitHub Pages.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/public}"

REPO_NAME="${GITHUB_REPOSITORY:-ziro-os/ziro-os}"
RELEASE_VERSION="${GITHUB_REF_NAME:-v1.0.0}"
# If not a tag, strip refs/heads/ or default to v1.0.0
RELEASE_VERSION="${RELEASE_VERSION#refs/tags/}"
RELEASE_VERSION="${RELEASE_VERSION#refs/heads/}"
if [[ "$RELEASE_VERSION" == "main" || "$RELEASE_VERSION" == "master" ]]; then
    RELEASE_VERSION="v1.0.0"
fi

DOWNLOAD_BASE="https://github.com/${REPO_NAME}/releases/download/${RELEASE_VERSION}"
REGISTRY_IMAGE="ghcr.io/${REPO_NAME}:latest"

mkdir -p "$OUTPUT_DIR"

cat > "$OUTPUT_DIR/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ziro-OS — Release & Download Catalog</title>
  <meta name="description" content="Official releases, bootable ISOs, rootfs tarballs, and container base images for Ziro-OS.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --accent: #10b981;
      --mono: 'JetBrains Mono', monospace;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.6;
      padding: 0 1.5rem;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 3rem 0;
    }
    header {
      text-align: center;
      margin-bottom: 3.5rem;
    }
    .badge {
      display: inline-block;
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      background: rgba(56, 189, 248, 0.12);
      color: var(--primary);
      border: 1px solid rgba(56, 189, 248, 0.3);
      font-size: 0.85rem;
      font-weight: 600;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 1rem;
    }
    h1 {
      font-size: 3rem;
      font-weight: 800;
      letter-spacing: -0.03em;
      margin-bottom: 0.75rem;
      background: linear-gradient(135deg, #ffffff 40%, var(--primary) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .lead {
      font-size: 1.25rem;
      color: var(--text-muted);
      max-width: 650px;
      margin: 0 auto 1.5rem auto;
    }
    .header-links a {
      color: var(--primary);
      text-decoration: none;
      margin: 0 0.75rem;
      font-weight: 500;
      font-size: 0.95rem;
    }
    .header-links a:hover { text-decoration: underline; }
    
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.5rem;
      margin-bottom: 3rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .card:hover {
      transform: translateY(-2px);
      border-color: rgba(56, 189, 248, 0.4);
    }
    .card-title {
      font-size: 1.35rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .card-desc {
      color: var(--text-muted);
      font-size: 0.95rem;
      margin-bottom: 1.25rem;
      flex-grow: 1;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      background: var(--primary);
      color: #04101e;
      font-weight: 700;
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      text-decoration: none;
      transition: background 0.15s ease;
      font-size: 0.95rem;
      width: 100%;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary {
      background: #1f2937;
      color: var(--text);
      margin-top: 0.5rem;
    }
    .btn-secondary:hover { background: #374151; }

    .docker-box {
      background: #0d131f;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 3rem;
    }
    .docker-box h2 {
      font-size: 1.5rem;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    pre {
      background: #05080f;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      font-family: var(--mono);
      font-size: 0.9rem;
      overflow-x: auto;
      color: #7dd3fc;
      margin-bottom: 1rem;
    }
    .spec-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1.5rem;
    }
    .spec-table th, .spec-table td {
      text-align: left;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }
    .spec-table th { color: var(--text-muted); font-weight: 600; }
    .spec-table td code { font-family: var(--mono); color: var(--accent); }

    footer {
      text-align: center;
      padding: 3rem 0 1rem 0;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.875rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge">Official Release Catalog • ${RELEASE_VERSION}</div>
      <h1>Ziro-OS</h1>
      <p class="lead">Ultra-lightweight, container-native operating system designed for speed, security, and cloud scale.</p>
      <div class="header-links">
        <a href="https://github.com/${REPO_NAME}" target="_blank">GitHub Repository</a>
        <a href="https://github.com/${REPO_NAME}/blob/main/community/docs/getting-started.md" target="_blank">Getting Started</a>
        <a href="https://github.com/${REPO_NAME}/blob/main/community/CONTRIBUTING.md" target="_blank">Contributing</a>
        <a href="https://github.com/${REPO_NAME}/releases" target="_blank">All Releases</a>
      </div>
    </header>

    <div class="docker-box">
      <h2>🐳 Multi-Architecture Container Base</h2>
      <p class="card-desc">Pull the official minimal base container image built directly FROM scratch with musl libc, BusyBox, ziroctl, and ziropkg:</p>
      <pre>docker pull ${REGISTRY_IMAGE}</pre>
      <pre>docker run -it --rm ${REGISTRY_IMAGE} sh</pre>
      <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.5rem;">
        ⚡ Built for both <code>linux/amd64</code> and <code>linux/arm64</code>. Typical footprint &lt; 15MB.
      </p>
    </div>

    <h2 style="font-size: 1.75rem; font-weight: 700; margin-bottom: 1.25rem;">💿 Output Images &amp; Binaries</h2>

    <div class="grid">
      <!-- Bootable ISO -->
      <div class="card">
        <div>
          <div class="card-title">💿 Bootable Hybrid ISO</div>
          <p class="card-desc">Universal hybrid UEFI/BIOS bootable ISO image for bare-metal, VMware, Proxmox, and VirtualBox virtualization.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/ziro-os-x86_64.iso">Download x86_64 ISO</a>
        </div>
      </div>

      <!-- Docker / Rootfs Tarball -->
      <div class="card">
        <div>
          <div class="card-title">📦 Minimal Rootfs Archive</div>
          <p class="card-desc">Stripped, minimal root filesystem archives for custom container images and lightweight microVM roots.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/ziro-rootfs-x86_64.tar.gz">Download x86_64 Rootfs</a>
          <a class="btn btn-secondary" href="${DOWNLOAD_BASE}/ziro-rootfs-arm64.tar.gz">Download arm64 Rootfs</a>
        </div>
      </div>

      <!-- Initramfs -->
      <div class="card">
        <div>
          <div class="card-title">⚡ Full Host Initramfs</div>
          <p class="card-desc">Complete standalone container host system containing ziro-init (PID 1), containerd, runc, and CNI networking plugins.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/ziro-initramfs-x86_64.cpio.gz">Download x86_64 Initramfs</a>
          <a class="btn btn-secondary" href="${DOWNLOAD_BASE}/ziro-initramfs-arm64.cpio.gz">Download arm64 Initramfs</a>
        </div>
      </div>

      <!-- ziroctl CLI -->
      <div class="card">
        <div>
          <div class="card-title">🛠️ ziroctl Management CLI</div>
          <p class="card-desc">Statically linked command-line utility for system inspection, container lifecycles, and security auditing.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/ziroctl-x86_64">Download ziroctl (x86_64)</a>
          <a class="btn btn-secondary" href="${DOWNLOAD_BASE}/ziroctl-arm64">Download ziroctl (arm64)</a>
        </div>
      </div>

      <!-- ziropkg CLI -->
      <div class="card">
        <div>
          <div class="card-title">📦 ziropkg Package Manager</div>
          <p class="card-desc">Official package manager CLI for installing verified packages (curl, jq, htop, git) on Ziro-OS hosts and containers.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/ziropkg-x86_64">Download ziropkg (x86_64)</a>
          <a class="btn btn-secondary" href="${DOWNLOAD_BASE}/ziropkg-arm64">Download ziropkg (arm64)</a>
        </div>
      </div>

      <!-- Verification Checksums -->
      <div class="card">
        <div>
          <div class="card-title">🔒 SHA256 Checksums</div>
          <p class="card-desc">Cryptographic hash manifest for verifying integrity of all release artifacts.</p>
        </div>
        <div>
          <a class="btn" href="${DOWNLOAD_BASE}/SHA256SUMS">Download SHA256SUMS</a>
        </div>
      </div>
    </div>

    <div class="docker-box">
      <h2>🚀 Quick Start with ziropkg</h2>
      <p class="card-desc">Install additional packages into any Ziro-OS environment:</p>
      <pre># Inside Ziro-OS container or host
ziropkg install curl
ziropkg install jq git htop
ziropkg search redis
ziroctl security audit</pre>
    </div>

    <footer>
      <p>Ziro-OS — Minimal by design. Born for the cloud. MIT Licensed.</p>
    </footer>
  </div>
</body>
</html>
EOF

echo "✅ Generated GitHub Pages release portal at $OUTPUT_DIR/index.html"

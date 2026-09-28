#!/usr/bin/env bash
# Ziro-OS GitHub Pages Release & Download Catalog Generator
# Generates a modern, clean, engineering-focused static release portal for GitHub Pages.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/public}"

REPO_NAME="${GITHUB_REPOSITORY:-ziro-os/ziro-os}"

# Determine release version accurately
RELEASE_VERSION="${GITHUB_REF_NAME:-}"
RELEASE_VERSION="${RELEASE_VERSION#refs/tags/}"
RELEASE_VERSION="${RELEASE_VERSION#refs/heads/}"

# If on main/master or empty, resolve from VERSION file or latest git tag
if [[ -z "$RELEASE_VERSION" || "$RELEASE_VERSION" == "main" || "$RELEASE_VERSION" == "master" ]]; then
    if [ -f "$REPO_ROOT/VERSION" ]; then
        RELEASE_VERSION=$(tr -d ' \t\n\r' < "$REPO_ROOT/VERSION")
    else
        RELEASE_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "1.0.1")
    fi
fi

# Ensure leading 'v'
[[ "$RELEASE_VERSION" =~ ^v ]] || RELEASE_VERSION="v${RELEASE_VERSION}"
VERSION_NUM="${RELEASE_VERSION#v}"

DOWNLOAD_BASE="https://github.com/${REPO_NAME}/releases/download/${RELEASE_VERSION}"
REGISTRY_IMAGE="ghcr.io/${REPO_NAME}:latest"
REGISTRY_TAGGED="ghcr.io/${REPO_NAME}:${RELEASE_VERSION}"

mkdir -p "$OUTPUT_DIR"

# Real asset sizes come from the GitHub Releases API, never hardcoded numbers.
# GITHUB_TOKEN (set in CI) only raises the API rate limit; the release data is public.
ASSET_SIZES=""
API_URL="https://api.github.com/repos/${REPO_NAME}/releases/tags/${RELEASE_VERSION}"
AUTH_HEADER=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH_HEADER=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
if RELEASE_JSON=$(curl -fsSL ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} "$API_URL" 2>/dev/null); then
    ASSET_SIZES=$(printf '%s' "$RELEASE_JSON" | python3 -c 'import json,sys
for a in json.load(sys.stdin).get("assets", []): print(a["name"], a["size"])')
    echo "Resolved $(printf '%s\n' "$ASSET_SIZES" | grep -c . || true) release assets for ${RELEASE_VERSION}"
else
    echo "Warning: could not query ${API_URL}; sizes are filled in by the browser from the live release." >&2
fi

asset_bytes() { printf '%s\n' "$ASSET_SIZES" | awk -v n="$1" '$1 == n { print $2 }'; }

# Decimal megabytes (1 MB = 1,000,000 bytes), matching the CI size gate.
fmt_mb() { awk -v b="$1" 'BEGIN { if (b < 1000000) printf "%.1f KB", b / 1000; else printf "%.1f MB", b / 1000000 }'; }

# dl <asset>: download link with the real size, or a dash when the release does not
# ship that file. "-" marks a combination that is never built (e.g. an arm64 ISO).
dl() {
    local name="$1" bytes label="Download"
    if [ "$name" = "-" ]; then printf '<span class="na" title="Not built">&mdash;</span>'; return 0; fi
    bytes=$(asset_bytes "$name")
    if [ -z "$bytes" ] && [ -n "$ASSET_SIZES" ]; then printf '<span class="na" title="Not in this release">&mdash;</span>'; return 0; fi
    [ -n "$bytes" ] && label=$(fmt_mb "$bytes")
    printf '<a class="dl" data-asset="%s" href="%s/%s" title="%s"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" aria-hidden="true"><path d="M12 4v12m0 0-5-5m5 5 5-5M5 20h14"/></svg><span class="size">%s</span></a>' \
        "$name" "$DOWNLOAD_BASE" "$name" "$name" "$label"
}

has() { [ "$1" != "-" ] && { [ -z "$ASSET_SIZES" ] || [ -n "$(asset_bytes "$1")" ]; }; }

# row <name> <description> <x86_64 asset> <arm64 asset>: skipped when neither file exists.
row() {
    has "$3" || has "$4" || return 0
    printf '<tr><th scope="row"><span class="a-name">%s</span><span class="a-desc">%s</span></th><td data-arch="x86_64">%s</td><td data-arch="arm64">%s</td></tr>' \
        "$1" "$2" "$(dl "$3")" "$(dl "$4")"
}

# group <title> <note> <rows>: a titled block of rows, omitted when empty.
group() {
    [ -n "$3" ] || return 0
    local note=""
    [ -n "$2" ] && note="<span>$2</span>"
    printf '<tbody><tr class="group"><th colspan="3" scope="colgroup">%s%s</th></tr>%s</tbody>\n' "$1" "$note" "$3"
}

# One checksum file covers every architecture, so its link spans both columns.
sums_row() {
    printf '<tr><th scope="row"><span class="a-name">SHA256SUMS</span><span class="a-desc">SHA-256 of every file above</span></th><td colspan="2">%s</td></tr>' "$(dl SHA256SUMS)"
}

ARTIFACTS="$(group "Host OS &middot; Alpine kernel" "Default. linux-virt LTS, tuned for virtual machines." \
    "$(row "ISO" "Live system and disk installer, UEFI and BIOS" ziro-os-x86_64.iso -)$(row "Host image" "initramfs for direct boot and <code>ziroctl upgrade</code>" ziro-initramfs-x86_64.cpio.gz ziro-initramfs-arm64.cpio.gz)$(row "Kernel" "vmlinuz for QEMU, Firecracker and Cloud Hypervisor" vmlinuz-x86_64 vmlinuz-arm64)")
$(group "Host OS &middot; Ziro kernel" "kernel.org LTS with drivers for bare metal, KVM, Xen, Hyper-V, VMware, AWS Nitro and GCP." \
    "$(row "ISO" "Live system and disk installer, UEFI and BIOS" ziro-os-x86_64-custom.iso -)$(row "Host image" "initramfs for direct boot and <code>ziroctl upgrade</code>" ziro-initramfs-x86_64-custom.cpio.gz ziro-initramfs-arm64-custom.cpio.gz)$(row "Kernel" "vmlinuz for QEMU, Firecracker and Cloud Hypervisor" vmlinuz-x86_64-custom vmlinuz-arm64-custom)$(row "Kernel config" "The .config this kernel was built from" kernel-config-x86_64-custom kernel-config-arm64-custom)")
$(group "Container base" "" \
    "$(row "Rootfs" "Minimal root filesystem for container images and microVMs" ziro-rootfs-x86_64.tar.gz ziro-rootfs-arm64.tar.gz)")
$(group "Tools" "Static binaries, no dependencies." \
    "$(row "ziroctl" "Manage the host: containers, network, security, upgrades" ziroctl-x86_64 ziroctl-arm64)$(row "ziropkg" "Install signed Alpine packages" ziropkg-x86_64 ziropkg-arm64)")
$(group "Checksums" "" "$(sums_row)")"

MINIMAL_BYTES=$(asset_bytes "ziro-rootfs-x86_64.tar.gz")
MINIMAL_STAT="&asymp; 16 MB"
[ -n "$MINIMAL_BYTES" ] && MINIMAL_STAT=$(fmt_mb "$MINIMAL_BYTES")

cat > "$OUTPUT_DIR/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ziro-OS — Cloud-Native Container Operating System</title>
  <meta name="description" content="Ultra-lightweight, container-native operating system designed for microVMs, containerd workloads, and edge infrastructure.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #101522;
      --card-hover: #151c2e;
      --border: #1e2638;
      --border-accent: rgba(56, 189, 248, 0.4);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --accent: #10b981;
      --code-bg: #05080f;
      --font-mono: 'JetBrains Mono', monospace;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      background-color: var(--bg);
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(56, 189, 248, 0.12), transparent),
        radial-gradient(ellipse 60% 40% at 80% 80%, rgba(16, 185, 129, 0.05), transparent);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }
    .wrapper {
      max-width: 1080px;
      margin: 0 auto;
      padding: 0 1.5rem;
      width: 100%;
    }

    /* Navigation Bar */
    nav {
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      background: rgba(9, 13, 22, 0.85);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 0.875rem 0;
    }
    .nav-inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      text-decoration: none;
      color: var(--text);
    }
    .brand-icon {
      width: 28px;
      height: 28px;
      background: linear-gradient(135deg, var(--primary), #0284c7);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 0.9rem;
      color: #04101e;
    }
    .brand-name {
      white-space: nowrap;
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .version-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--accent);
      font-size: 0.75rem;
      font-family: var(--font-mono);
      font-weight: 600;
    }
    .version-pill::before {
      content: '';
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent);
      display: inline-block;
    }
    .nav-links {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }
    .nav-links a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      transition: color 0.15s ease;
    }
    .nav-links a:hover {
      color: var(--text);
    }

    /* Hero Section */
    .hero {
      padding: 3.5rem 0 2rem 0;
      text-align: center;
    }
    .hero h1 {
      font-size: clamp(2.25rem, 5vw, 3.5rem);
      font-weight: 800;
      letter-spacing: -0.035em;
      line-height: 1.15;
      margin-bottom: 0.875rem;
    }
    .hero-tagline {
      font-size: clamp(1.05rem, 2vw, 1.25rem);
      color: var(--text-muted);
      max-width: 620px;
      margin: 0 auto 2rem auto;
      font-weight: 400;
    }

    /* Quick Run Bar */
    .run-box {
      max-width: 640px;
      margin: 0 auto 3rem auto;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.6rem 0.85rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      transition: border-color 0.2s ease;
    }
    .run-box:focus-within, .run-box:hover {
      border-color: rgba(56, 189, 248, 0.4);
    }
    .run-code {
      font-family: var(--font-mono);
      font-size: 0.875rem;
      color: #7dd3fc;
      overflow-x: auto;
      white-space: nowrap;
      text-align: left;
    }
    .copy-btn {
      background: #1e293b;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.4rem 0.75rem;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      transition: all 0.15s ease;
      flex-shrink: 0;
    }
    .copy-btn:hover {
      background: #334155;
      color: #fff;
    }

    /* Stats Strip */
    .stats-strip {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 3.5rem;
    }
    .stat-item {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }
    .stat-val {
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.01em;
      font-family: var(--font-mono);
    }
    .stat-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 0.25rem;
    }

    /* Section Headings */
    .section-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      margin-bottom: 1.25rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .section-head h2 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .section-head span {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    /* Artifact list */
    .artifacts {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      font-size: 0.875rem;
    }
    .artifacts thead th {
      text-align: left;
      font-size: 0.7rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 0.7rem 1rem;
      border-bottom: 1px solid var(--border);
    }
    .artifacts thead th:not(:first-child) {
      text-transform: none;
      letter-spacing: 0;
    }
    .artifacts thead th:not(:first-child),
    .artifacts td {
      width: 9.5rem;
      font-family: var(--font-mono);
    }
    .artifacts tr.group th {
      text-align: left;
      padding: 1.1rem 1rem 0.45rem;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--primary);
    }
    .artifacts tr.group th span {
      display: block;
      margin-top: 0.15rem;
      font-weight: 400;
      color: var(--text-muted);
    }
    .artifacts tbody + tbody tr.group th {
      border-top: 1px solid var(--border);
    }
    .artifacts th[scope="row"],
    .artifacts td {
      padding: 0.55rem 1rem;
      text-align: left;
      vertical-align: middle;
    }
    .artifacts tbody tr:not(.group):hover {
      background: var(--card-hover);
    }
    .a-name {
      display: block;
      font-weight: 600;
    }
    .a-desc {
      display: block;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-weight: 400;
    }
    .a-desc code {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: #7dd3fc;
    }
    .dl {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.3rem 0.6rem;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      text-decoration: none;
      white-space: nowrap;
      min-width: 7.25rem;
      transition: border-color 0.15s ease, color 0.15s ease;
    }
    .dl svg {
      flex-shrink: 0;
    }
    .dl:hover,
    .dl:focus-visible {
      border-color: var(--border-accent);
      color: var(--primary);
    }
    .na {
      color: #475569;
      padding-left: 0.6rem;
    }
    .hint {
      margin: 0.75rem 0 3.5rem;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    .hint code {
      font-family: var(--font-mono);
      color: #7dd3fc;
    }

    /* Commands Snippets Box */
    .commands-container {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 3.5rem;
    }
    .cmd-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.25rem;
      margin-top: 1rem;
    }
    .cmd-item label {
      display: block;
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 0.4rem;
    }
    .cmd-item pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.65rem 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: #38bdf8;
      overflow-x: auto;
    }

    /* Footer */
    footer {
      margin-top: auto;
      border-top: 1px solid var(--border);
      padding: 2rem 0;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    footer a {
      color: var(--text);
      text-decoration: none;
    }
    footer a:hover {
      text-decoration: underline;
    }

    @media (max-width: 768px) {
      .stats-strip {
        grid-template-columns: repeat(2, 1fr);
      }
      .cmd-grid {
        grid-template-columns: 1fr;
      }
      .stat-val {
        font-size: 0.95rem;
        white-space: nowrap;
      }
      .nav-links {
        gap: 0.75rem;
      }
    }
    @media (max-width: 640px) {
      .artifacts thead {
        display: none;
      }
      .artifacts,
      .artifacts tbody,
      .artifacts tr,
      .artifacts th {
        display: block;
      }
      .artifacts tr:not(.group) {
        display: flex;
        flex-wrap: wrap;
        gap: 0.4rem 0.75rem;
        padding: 0.6rem 1rem;
      }
      .artifacts th[scope="row"] {
        flex-basis: 100%;
        padding: 0;
      }
      .artifacts td {
        flex: 1 1 0;
        min-width: 0;
        width: auto;
        padding: 0;
        display: flex;
        align-items: center;
        gap: 0.4rem;
      }
      .dl {
        min-width: 0;
      }
      /* The Downloads header already shows the version */
      nav .version-pill {
        display: none;
      }
      .artifacts td[data-arch]::before {
        content: attr(data-arch);
        color: var(--text-muted);
        font-size: 0.75rem;
      }
      .na {
        padding-left: 0;
      }
    }
  </style>
</head>
<body>

  <!-- Navigation Bar -->
  <nav>
    <div class="wrapper nav-inner">
      <a href="https://github.com/${REPO_NAME}" class="brand">
        <div class="brand-icon">Z</div>
        <span class="brand-name">Ziro-OS</span>
        <span class="version-pill release-tag">${RELEASE_VERSION}</span>
      </a>
      <div class="nav-links">
        <a href="https://github.com/${REPO_NAME}#readme" target="_blank">Docs</a>
        <a href="https://github.com/${REPO_NAME}/releases" target="_blank">Releases</a>
        <a href="https://github.com/${REPO_NAME}" target="_blank">GitHub</a>
      </div>
    </div>
  </nav>

  <main class="wrapper">
    <!-- Hero Header -->
    <section class="hero">
      <h1>Built for Containers.<br>Born for the Cloud.</h1>
      <p class="hero-tagline">
        Ultra-lightweight host OS for microVMs and container workloads. Minimal base, fast boot, pure clarity.
      </p>

      <!-- Instant Pull Box -->
      <div class="run-box">
        <span class="run-code" id="cmd-snippet">docker run -it --rm ${REGISTRY_IMAGE} sh</span>
        <button class="copy-btn" id="copy-btn" onclick="copyCommand()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span id="copy-label">Copy</span>
        </button>
      </div>
    </section>

    <!-- Metrics Strip -->
    <section class="stats-strip">
      <div class="stat-item">
        <div class="stat-val">${MINIMAL_STAT}</div>
        <div class="stat-label">Container base</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">&lt; 300 MB</div>
        <div class="stat-label">Host image</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">containerd</div>
        <div class="stat-label">Runtime</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">x86_64 &middot; arm64</div>
        <div class="stat-label">Architectures</div>
      </div>
    </section>

    <section aria-labelledby="downloads">
      <div class="section-head">
        <h2 id="downloads">Downloads</h2>
        <span class="release-tag-label">${RELEASE_VERSION} · <span class="release-date">latest</span></span>
      </div>
      <table class="artifacts">
        <thead>
          <tr><th scope="col">File</th><th scope="col">x86_64</th><th scope="col">arm64</th></tr>
        </thead>
        ${ARTIFACTS}
      </table>
      <p class="hint">Verify after download: <code>sha256sum -c SHA256SUMS --ignore-missing</code></p>
    </section>

    <!-- Quick Usage -->
    <section class="commands-container">
      <div class="section-head" style="margin-bottom: 0.5rem;">
        <h2>Quick start</h2>
      </div>
      <div class="cmd-grid">
        <div class="cmd-item">
          <label>Install to disk</label>
          <pre>ziroctl install -d /dev/sda -y</pre>
        </div>
        <div class="cmd-item">
          <label>Check health</label>
          <pre>ziroctl doctor</pre>
        </div>
        <div class="cmd-item">
          <label>Run a container</label>
          <pre>ziroctl container run -d -p 80:80 nginx</pre>
        </div>
        <div class="cmd-item">
          <label>Harden the host</label>
          <pre>ziroctl security harden</pre>
        </div>
        <div class="cmd-item">
          <label>Upgrade</label>
          <pre>ziroctl upgrade</pre>
        </div>
        <div class="cmd-item">
          <label>Install packages</label>
          <pre>ziropkg install curl jq git</pre>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrapper">
      <p>
        <strong>Ziro-OS</strong> &middot;
        <a href="https://github.com/${REPO_NAME}" target="_blank">GitHub</a> &middot;
        <a href="https://github.com/${REPO_NAME}/blob/main/LICENSE" target="_blank">MIT License</a>
      </p>
    </div>
  </footer>

  <script>
    function copyCommand() {
      const code = document.getElementById('cmd-snippet').textContent;
      navigator.clipboard.writeText(code).then(() => {
        const label = document.getElementById('copy-label');
        label.textContent = 'Copied!';
        setTimeout(() => { label.textContent = 'Copy'; }, 2000);
      });
    }

    // Refresh version, date and sizes from the live release.
    (function fetchLiveRelease() {
      const repo = "${REPO_NAME}";
      fetch('https://api.github.com/repos/' + repo + '/releases/latest')
        .then(res => res.ok ? res.json() : null)
        .then(data => {
          if (!data || !data.tag_name) return;
          const tag = data.tag_name;
          document.querySelectorAll('.release-tag').forEach(el => el.textContent = tag);
          if (data.published_at) {
            const dateStr = new Date(data.published_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            document.querySelectorAll('.release-date').forEach(el => el.textContent = dateStr);
          }
          if (data.assets && data.assets.length) {
            data.assets.forEach(asset => {
              const link = document.querySelector('[data-asset="' + asset.name + '"]');
              if (link) {
                link.href = asset.browser_download_url;
                const size = link.querySelector('.size');
                if (size) size.textContent = asset.size < 1000000 ? (asset.size / 1000).toFixed(1) + ' KB' : (asset.size / 1000000).toFixed(1) + ' MB';
              }
            });
          }
        })
        .catch(() => {});
    })();
  </script>
</body>
</html>
EOF

echo "=================================================="
echo "✅ Generated clean Ziro-OS release portal for $RELEASE_VERSION"
echo " Target: $OUTPUT_DIR/index.html"
echo "=================================================="

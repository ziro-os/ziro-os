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

# btn <asset> <label> [subtle]: a download button with its real size; omitted when the
# release is known and does not contain the asset (e.g. a flavor not built for that arch).
btn() {
    local name="$1" label="$2" cls="btn" bytes size=""
    [ "${3:-}" = "subtle" ] && cls="btn btn-subtle"
    bytes=$(asset_bytes "$name")
    if [ -z "$bytes" ] && [ -n "$ASSET_SIZES" ]; then return 0; fi
    [ -n "$bytes" ] && size=" ($(fmt_mb "$bytes"))"
    printf '<a class="%s" data-asset="%s" href="%s/%s">%s<span class="size">%s</span></a>' \
        "$cls" "$name" "$DOWNLOAD_BASE" "$name" "$label" "$size"
}

CUSTOM_BTNS="$(btn ziro-os-x86_64-custom.iso "ISO x86_64")$(btn ziro-initramfs-x86_64-custom.cpio.gz "initramfs x86_64" subtle)$(btn ziro-initramfs-arm64-custom.cpio.gz "initramfs arm64" subtle)$(btn vmlinuz-x86_64-custom "kernel x86_64" subtle)$(btn vmlinuz-arm64-custom "kernel arm64" subtle)$(btn kernel-config-x86_64-custom ".config x86_64" subtle)$(btn kernel-config-arm64-custom ".config arm64" subtle)"
if [ -z "$CUSTOM_BTNS" ]; then
    CUSTOM_BTNS='<span class="card-desc">Not in this release yet; published from the next release onward.</span>'
fi

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
      text-transform: uppercase;
      letter-spacing: 0.05em;
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

    /* Downloads Grid */
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
      gap: 1.25rem;
      margin-bottom: 3.5rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.35rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.15s ease;
    }
    .card:hover {
      border-color: var(--border-accent);
      background: var(--card-hover);
      transform: translateY(-2px);
    }
    .card-top {
      margin-bottom: 1rem;
    }
    .card-header-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.4rem;
    }
    .card-title {
      font-size: 1.05rem;
      font-weight: 700;
    }
    .badge-arch {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      background: rgba(56, 189, 248, 0.12);
      border: 1px solid rgba(56, 189, 248, 0.25);
      color: var(--primary);
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-weight: 500;
    }
    .card-desc {
      color: var(--text-muted);
      font-size: 0.825rem;
      line-height: 1.4;
    }
    
    .btn-group {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      background: var(--primary);
      color: #04101e;
      font-size: 0.8rem;
      font-weight: 600;
      padding: 0.5rem 0.85rem;
      border-radius: 6px;
      text-decoration: none;
      flex: 1;
      min-width: 120px;
      transition: background 0.15s ease;
      white-space: nowrap;
    }
    .btn:hover {
      background: var(--primary-hover);
    }
    .btn-subtle {
      background: #1e2638;
      color: var(--text);
      border: 1px solid var(--border);
    }
    .btn-subtle:hover {
      background: #2a3449;
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
      .nav-links {
        gap: 0.75rem;
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
        <div class="stat-label">Minimal Container Base</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">&lt; 300 MB</div>
        <div class="stat-label">Full Host Image (CI-enforced)</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">containerd</div>
        <div class="stat-label">Native OCI Runtime</div>
      </div>
      <div class="stat-item">
        <div class="stat-val">x86_64 &amp; arm64</div>
        <div class="stat-label">Multi-Architecture</div>
      </div>
    </section>

    <!-- Downloads Grid -->
    <section>
      <div class="section-head">
        <h2>Release Artifacts</h2>
        <span class="release-tag-label">${RELEASE_VERSION} · <span class="release-date">Latest Release</span></span>
      </div>

      <div class="grid">
        <!-- Host image: Alpine kernel -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">💿 Host Image &middot; Alpine Kernel</span>
              <span class="badge-arch">Default</span>
            </div>
            <p class="card-desc">Alpine <code>linux-virt</code> LTS kernel, tuned for virtual machines (KVM, QEMU, Proxmox, cloud VMs). UEFI/BIOS ISO, host initramfs with containerd, and the matching kernel for direct boot.</p>
          </div>
          <div class="btn-group">
            $(btn ziro-os-x86_64.iso "ISO x86_64")
            $(btn ziro-initramfs-x86_64.cpio.gz "initramfs x86_64" subtle)
            $(btn ziro-initramfs-arm64.cpio.gz "initramfs arm64" subtle)
            $(btn vmlinuz-x86_64 "kernel x86_64" subtle)
            $(btn vmlinuz-arm64 "kernel arm64" subtle)
          </div>
        </div>

        <!-- Host image: Ziro custom kernel -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">🧬 Host Image &middot; Ziro Custom Kernel</span>
              <span class="badge-arch">Any Hardware</span>
            </div>
            <p class="card-desc">Ziro kernel built from kernel.org LTS sources: the upstream defconfig plus drivers for bare metal, KVM, Xen, Hyper-V/Azure, VMware, AWS Nitro and GCP, with the security hardening built in. Boot-tested in CI on every build.</p>
          </div>
          <div class="btn-group">
            ${CUSTOM_BTNS}
          </div>
        </div>

        <!-- Rootfs Card -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">📦 Minimal Rootfs</span>
              <span class="badge-arch">Dual Arch</span>
            </div>
            <p class="card-desc">Stripped root filesystem archive for custom container builds and lightweight microVM roots.</p>
          </div>
          <div class="btn-group">
            $(btn ziro-rootfs-x86_64.tar.gz "x86_64")
            $(btn ziro-rootfs-arm64.tar.gz "arm64" subtle)
          </div>
        </div>

        <!-- ziroctl CLI -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">🛠️ ziroctl CLI</span>
              <span class="badge-arch">Binary</span>
            </div>
            <p class="card-desc">Statically linked CLI for system inspection, container lifecycles, and security auditing.</p>
          </div>
          <div class="btn-group">
            $(btn ziroctl-x86_64 "x86_64")
            $(btn ziroctl-arm64 "arm64" subtle)
          </div>
        </div>

        <!-- ziropkg CLI -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">📦 ziropkg CLI</span>
              <span class="badge-arch">Binary</span>
            </div>
            <p class="card-desc">Package manager CLI for installing verified packages (curl, jq, git, htop) on Ziro-OS.</p>
          </div>
          <div class="btn-group">
            $(btn ziropkg-x86_64 "x86_64")
            $(btn ziropkg-arm64 "arm64" subtle)
          </div>
        </div>

        <!-- SHA256SUMS -->
        <div class="card">
          <div class="card-top">
            <div class="card-header-row">
              <span class="card-title">🔒 Verification Checksums</span>
              <span class="badge-arch">Manifest</span>
            </div>
            <p class="card-desc">Cryptographic SHA256 checksum manifest for verifying artifact integrity.</p>
          </div>
          <div class="btn-group">
            $(btn SHA256SUMS "Download SHA256SUMS" subtle)
          </div>
        </div>
      </div>
    </section>

    <!-- Quick Usage -->
    <section class="commands-container">
      <div class="section-head" style="margin-bottom: 0.5rem;">
        <h2>Quick Start</h2>
        <span>CLI Reference</span>
      </div>
      <div class="cmd-grid">
        <div class="cmd-item">
          <label>Disk Installation</label>
          <pre>ziro-install   # or: ziroctl install -d /dev/sda -y</pre>
        </div>
        <div class="cmd-item">
          <label>Network Configuration</label>
          <pre>ziroctl network setup   # or: ziroctl network status</pre>
        </div>
        <div class="cmd-item">
          <label>Cloud & Diagnostics</label>
          <pre>ziroctl doctor          # or: ziroctl cloud inspect</pre>
        </div>
        <div class="cmd-item">
          <label>Container Management</label>
          <pre>ziroctl container run -d -p 80:80 nginx</pre>
        </div>
        <div class="cmd-item">
          <label>Security Hardening</label>
          <pre>ziroctl security harden # or: ziroctl security audit</pre>
        </div>
        <div class="cmd-item">
          <label>Install Packages</label>
          <pre>ziropkg install curl jq git</pre>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrapper">
      <p>
        <strong>Ziro-OS</strong> &middot; Cloud-Native Container Operating System &middot; 
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

    // Dynamic Live Release Resolution from GitHub API
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
                if (size) size.textContent = asset.size < 1000000 ? ' (' + (asset.size / 1000).toFixed(1) + ' KB)' : ' (' + (asset.size / 1000000).toFixed(1) + ' MB)';
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

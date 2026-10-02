#!/usr/bin/env bash
# Ziro-OS GitHub Pages Release & Download Catalog Generator
# Generates the project website (GitHub Pages) in the Ziro OS brand: Cloud Ink, Ziro Blue, Compute Cyan.

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

DOWNLOAD_BASE="https://github.com/${REPO_NAME}/releases/download/${RELEASE_VERSION}"
REGISTRY_IMAGE="ghcr.io/${REPO_NAME}:latest"

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
  <title>Ziro OS — Minimal cloud-native host OS</title>
  <meta name="description" content="Ultra-lightweight host OS for microVMs and container workloads. Minimal base, fast boot, pure clarity.">
  <meta name="theme-color" content="#0B1220">
  <meta property="og:title" content="Ziro OS — Minimal by design. Born for the cloud.">
  <meta property="og:description" content="Ultra-lightweight host OS for microVMs and container workloads. Minimal base, fast boot, pure clarity.">
  <meta property="og:type" content="website">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%230B1220'/%3E%3Cpath fill='%234F6BFF' d='M4 4h16v3.4H4zM8.2 13h7.2L11.6 16.6H4.4zM4.4 16.6H20V20H4.4z'/%3E%3Cpath fill='%2322D3EE' d='M12.4 7.4H20L15.4 13H8.2z'/%3E%3C/svg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      /* Ziro OS core palette */
      --ink: #0B1220;
      --ink-2: #111A2E;
      --ink-3: #16213A;
      --code: #070C17;
      --line: rgba(255, 255, 255, 0.08);
      --line-strong: rgba(255, 255, 255, 0.14);
      --blue: #4F6BFF;
      --blue-hover: #6A82FF;
      --cyan: #22D3EE;
      --white: #FFFFFF;
      --text: #E6EAF2;
      --muted: #94A3B8;
      --faint: #5B6B86;
      --radius: 14px;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color-scheme: dark;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--ink);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }
    a { color: inherit; }
    code { font-family: var(--font-mono); font-size: 0.85em; color: var(--cyan); }
    :focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; border-radius: 4px; }
    .wrapper { max-width: 1120px; margin: 0 auto; padding: 0 1.5rem; width: 100%; }
    .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

    /* Brand lockup: mark, "Ziro", OS pill */
    .lockup { display: inline-flex; align-items: center; gap: 0.6rem; text-decoration: none; color: var(--white); }
    .lockup svg { width: 28px; height: 28px; flex-shrink: 0; }
    .lockup-name { font-size: 1.3rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1; }
    .os-pill {
      display: inline-block;
      background: var(--white);
      color: var(--ink);
      font-size: 0.62rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      padding: 0.22rem 0.45rem;
      border-radius: 5px;
      line-height: 1;
    }

    /* Navigation */
    nav {
      position: sticky;
      top: 0;
      z-index: 50;
      background: rgba(11, 18, 32, 0.86);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--line);
    }
    .nav-inner { display: flex; align-items: center; justify-content: space-between; gap: 1rem; height: 64px; }
    .nav-left { display: flex; align-items: center; gap: 0.85rem; min-width: 0; }
    .version-pill {
      font-family: var(--font-mono);
      font-size: 0.72rem;
      font-weight: 500;
      color: var(--muted);
      border: 1px solid var(--line-strong);
      border-radius: 999px;
      padding: 0.15rem 0.55rem;
      white-space: nowrap;
    }
    .nav-links { display: flex; align-items: center; gap: 1.5rem; }
    .nav-links a { color: var(--muted); text-decoration: none; font-size: 0.9rem; font-weight: 500; transition: color 0.15s ease; }
    .nav-links a:hover { color: var(--white); }

    /* Hero */
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 3rem;
      padding: 5rem 0 3.5rem;
    }
    .eyebrow {
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--blue-hover);
      margin-bottom: 1rem;
    }
    .hero h1 {
      font-size: clamp(2.2rem, 5.2vw, 3.6rem);
      font-weight: 700;
      letter-spacing: -0.035em;
      line-height: 1.08;
      color: var(--white);
      max-width: 16ch;
    }
    .hero-lead { font-size: clamp(1.02rem, 1.8vw, 1.18rem); color: var(--muted); max-width: 34rem; margin-top: 1.25rem; }
    .accent { display: flex; gap: 0.4rem; margin: 1.75rem 0; }
    .accent span { height: 4px; border-radius: 2px; }
    .accent span:first-child { width: 2rem; background: var(--cyan); }
    .accent span:last-child { width: 4.5rem; background: var(--blue); }
    .actions { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.5rem; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.7rem 1.2rem;
      border-radius: 10px;
      font-size: 0.92rem;
      font-weight: 600;
      text-decoration: none;
      border: 1px solid transparent;
      transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
    }
    .btn-primary { background: var(--blue); color: var(--white); }
    .btn-primary:hover { background: var(--blue-hover); }
    .btn-ghost { border-color: var(--line-strong); color: var(--text); }
    .btn-ghost:hover { border-color: var(--blue); color: var(--white); }
    .run-box {
      max-width: 34rem;
      background: var(--code);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.5rem 0.5rem 0.5rem 0.9rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .run-box::before { content: '\$'; font-family: var(--font-mono); color: var(--faint); font-size: 0.85rem; }
    .run-code { flex: 1; min-width: 0; font-family: var(--font-mono); font-size: 0.85rem; color: var(--cyan); overflow-x: auto; white-space: nowrap; }
    .copy-btn {
      flex-shrink: 0;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      background: var(--ink-3);
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 0.4rem 0.7rem;
      font: 600 0.75rem var(--font-sans);
      cursor: pointer;
      transition: background 0.15s ease;
    }
    .copy-btn:hover { background: #1D2A48; }
    .status-note { margin-top: 1rem; font-size: 0.8rem; color: var(--faint); }
    .hero-mark {
      width: 220px;
      height: 220px;
      border-radius: 52px;
      background: var(--ink-2);
      border: 1px solid var(--line);
      display: grid;
      place-items: center;
    }
    .hero-mark svg { width: 120px; height: 120px; }

    /* Key facts */
    .facts {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--ink-2);
      margin-bottom: 5rem;
    }
    .fact { padding: 1.25rem 1.5rem; }
    .fact + .fact { border-left: 1px solid var(--line); }
    .fact-val { font-family: var(--font-mono); font-size: 1.15rem; font-weight: 600; color: var(--white); white-space: nowrap; }
    .fact-label { font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }

    /* Sections */
    section.block { margin-bottom: 5rem; }
    .section-head { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem 1rem; margin-bottom: 1.5rem; }
    .section-head h2 { font-size: clamp(1.35rem, 2.6vw, 1.75rem); font-weight: 700; letter-spacing: -0.02em; color: var(--white); }
    .section-head p { color: var(--muted); font-size: 0.95rem; max-width: 40rem; }
    .section-meta { font-family: var(--font-mono); font-size: 0.8rem; color: var(--muted); }

    /* Features */
    .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
    .feature {
      background: var(--ink-2);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 1.4rem 1.5rem;
    }
    .feature h3 { display: flex; align-items: center; gap: 0.6rem; font-size: 1rem; font-weight: 600; color: var(--white); margin-bottom: 0.45rem; }
    .feature h3::before { content: ''; width: 8px; height: 8px; border-radius: 2px; background: var(--blue); box-shadow: 4px 4px 0 var(--cyan); margin-right: 4px; }
    .feature p { color: var(--muted); font-size: 0.9rem; }

    /* Artifact list */
    .artifacts {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      background: var(--ink-2);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      overflow: hidden;
      font-size: 0.875rem;
    }
    .artifacts thead th {
      text-align: left;
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--muted);
      letter-spacing: 0.06em;
      padding: 0.8rem 1.25rem;
      border-bottom: 1px solid var(--line);
    }
    .artifacts thead th:first-child { text-transform: uppercase; }
    .artifacts thead th:not(:first-child), .artifacts td { width: 10rem; font-family: var(--font-mono); }
    .artifacts tr.group th { text-align: left; padding: 1.25rem 1.25rem 0.5rem; font-size: 0.85rem; font-weight: 600; color: var(--cyan); }
    .artifacts tr.group th span { display: block; margin-top: 0.15rem; font-weight: 400; color: var(--muted); }
    .artifacts tbody + tbody tr.group th { border-top: 1px solid var(--line); }
    .artifacts th[scope="row"], .artifacts td { padding: 0.6rem 1.25rem; text-align: left; vertical-align: middle; }
    .artifacts tbody tr:not(.group):hover { background: var(--ink-3); }
    .a-name { display: block; font-weight: 600; color: var(--white); }
    .a-desc { display: block; color: var(--muted); font-size: 0.82rem; font-weight: 400; }
    .a-desc code { font-size: 0.75rem; }
    .dl {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.32rem 0.65rem;
      border: 1px solid var(--line-strong);
      border-radius: 7px;
      color: var(--text);
      text-decoration: none;
      white-space: nowrap;
      min-width: 7.5rem;
      transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
    }
    .dl svg { flex-shrink: 0; color: var(--blue-hover); }
    .dl:hover, .dl:focus-visible { border-color: var(--blue); background: rgba(79, 107, 255, 0.1); color: var(--white); }
    .na { color: var(--faint); padding-left: 0.65rem; }
    .hint { margin-top: 0.9rem; color: var(--muted); font-size: 0.85rem; }

    /* Quick start */
    .cmd-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
    .cmd-item { background: var(--ink-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 1rem 1.1rem; min-width: 0; }
    .cmd-item h3 { font-size: 0.72rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.55rem; }
    .cmd-item pre {
      background: var(--code);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0.65rem 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.82rem;
      color: var(--cyan);
      overflow-x: auto;
    }

    /* Footer */
    footer { margin-top: auto; border-top: 1px solid var(--line); padding: 2rem 0; font-size: 0.85rem; color: var(--muted); }
    .footer-inner { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem 2rem; }
    .footer-inner .lockup svg { width: 22px; height: 22px; }
    .footer-inner .lockup-name { font-size: 1.05rem; }
    .footer-links { display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; list-style: none; }
    .footer-links a { color: var(--muted); text-decoration: none; }
    .footer-links a:hover { color: var(--white); }
    .copyright { flex-basis: 100%; color: var(--faint); font-size: 0.8rem; }

    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      * { transition: none !important; }
    }
    @media (max-width: 860px) {
      .hero { grid-template-columns: minmax(0, 1fr); padding: 3.5rem 0 2.5rem; }
      .hero-mark { display: none; }
    }
    @media (max-width: 768px) {
      .facts { grid-template-columns: repeat(2, 1fr); }
      .fact:nth-child(3) { border-left: 0; }
      .fact:nth-child(n+3) { border-top: 1px solid var(--line); }
      .fact-val { font-size: 1rem; }
      section.block, .facts { margin-bottom: 3.5rem; }
    }
    @media (max-width: 640px) {
      .wrapper { padding: 0 1rem; }
      .nav-links { gap: 1rem; }
      .nav-links a { font-size: 0.85rem; }
      /* The Downloads header already shows the version */
      nav .version-pill { display: none; }
      .fact { padding: 1rem; }
      .cmd-grid { grid-template-columns: 1fr; }
      .artifacts thead { display: none; }
      .artifacts, .artifacts tbody, .artifacts tr, .artifacts th { display: block; }
      .artifacts tr:not(.group) { display: flex; flex-wrap: wrap; gap: 0.4rem 0.75rem; padding: 0.65rem 1rem; }
      .artifacts tr.group th { padding: 1.1rem 1rem 0.35rem; }
      .artifacts th[scope="row"] { flex-basis: 100%; padding: 0; }
      .artifacts td { flex: 1 1 0; min-width: 0; width: auto; padding: 0; display: flex; align-items: center; gap: 0.4rem; }
      .artifacts td[data-arch]::before { content: attr(data-arch); color: var(--muted); font-size: 0.75rem; }
      .dl { min-width: 0; }
      .na { padding-left: 0; }
    }
  </style>
</head>
<body>
  <svg width="0" height="0" style="position:absolute" aria-hidden="true">
    <symbol id="ziro-mark" viewBox="0 0 24 24">
      <path fill="#4F6BFF" d="M4 4h16v3.4H4zM8.2 13h7.2L11.6 16.6H4.4zM4.4 16.6H20V20H4.4z"/>
      <path fill="#22D3EE" d="M12.4 7.4H20L15.4 13H8.2z"/>
    </symbol>
  </svg>

  <nav aria-label="Main">
    <div class="wrapper nav-inner">
      <div class="nav-left">
        <a href="https://github.com/${REPO_NAME}" class="lockup" aria-label="Ziro OS on GitHub">
          <svg aria-hidden="true"><use href="#ziro-mark"/></svg>
          <span class="lockup-name">Ziro</span><span class="os-pill">OS</span>
        </a>
        <span class="version-pill release-tag">${RELEASE_VERSION}</span>
      </div>
      <div class="nav-links">
        <a href="https://github.com/${REPO_NAME}/tree/main/docs" target="_blank" rel="noopener">Docs</a>
        <a href="https://github.com/${REPO_NAME}/releases" target="_blank" rel="noopener">Releases</a>
        <a href="https://github.com/${REPO_NAME}" target="_blank" rel="noopener">GitHub</a>
      </div>
    </div>
  </nav>

  <main class="wrapper">
    <section class="hero">
      <div>
        <p class="eyebrow">Ziro OS &middot; Cloud-native host OS</p>
        <h1>Minimal by design. Born for the cloud.</h1>
        <p class="hero-lead">
          Ultra-lightweight host OS for microVMs and container workloads. Minimal base, fast boot, pure clarity.
        </p>
        <div class="accent" aria-hidden="true"><span></span><span></span></div>
        <div class="actions">
          <a class="btn btn-primary" href="#downloads">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" aria-hidden="true"><path d="M12 4v12m0 0-5-5m5 5 5-5M5 20h14"/></svg>
            Download
          </a>
          <a class="btn btn-ghost" href="https://github.com/${REPO_NAME}/blob/main/docs/getting-started.md" target="_blank" rel="noopener">Read the docs</a>
        </div>
        <div class="run-box">
          <span class="run-code" id="cmd-snippet">docker run -it --rm ${REGISTRY_IMAGE} sh</span>
          <button class="copy-btn" id="copy-btn" type="button" onclick="copyCommand()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span id="copy-label">Copy</span>
          </button>
        </div>
        <p class="status-note">Ziro OS is in active development. Use it in test environments for now.</p>
      </div>
      <div class="hero-mark" aria-hidden="true">
        <svg><use href="#ziro-mark"/></svg>
      </div>
    </section>

    <section class="facts" aria-label="Key facts">
      <div class="fact"><div class="fact-val">${MINIMAL_STAT}</div><div class="fact-label">Container base</div></div>
      <div class="fact"><div class="fact-val">&lt; 300 MB</div><div class="fact-label">Host image</div></div>
      <div class="fact"><div class="fact-val">containerd</div><div class="fact-label">Runtime</div></div>
      <div class="fact"><div class="fact-val">x86_64 &middot; arm64</div><div class="fact-label">Architectures</div></div>
    </section>

    <section class="block" aria-labelledby="why">
      <div class="section-head">
        <h2 id="why">Why Ziro OS</h2>
        <p>A host OS that runs containers and little else, so there is less to patch, less to boot and less to go wrong.</p>
      </div>
      <div class="features">
        <article class="feature">
          <h3>Small and fast</h3>
          <p>The host image stays under 300 MB and the container base is ${MINIMAL_STAT}. Every build checks the size.</p>
        </article>
        <article class="feature">
          <h3>Containers first</h3>
          <p>containerd, runc and CNI networking ship in the base system, with Docker-style commands through nerdctl.</p>
        </article>
        <article class="feature">
          <h3>Secure by default</h3>
          <p>Signed kernel modules, updates and catalogs, a deny-by-default firewall and seccomp. Every change is audited.</p>
        </article>
        <article class="feature">
          <h3>Declarative</h3>
          <p>Describe a host or a stack of apps in YAML or JSON, and <code>ziroctl apply</code> makes the host match it.</p>
        </article>
        <article class="feature">
          <h3>Clusters built in</h3>
          <p>Join hosts over WireGuard and schedule apps across them, with no separate orchestrator to install.</p>
        </article>
        <article class="feature">
          <h3>Runs anywhere</h3>
          <p>Bare metal, KVM, Xen, Hyper-V, VMware, AWS and GCP, plus microVMs on Firecracker and Cloud Hypervisor.</p>
        </article>
      </div>
    </section>

    <section class="block" aria-labelledby="downloads">
      <div class="section-head">
        <h2 id="downloads">Downloads</h2>
        <span class="section-meta"><span class="release-tag">${RELEASE_VERSION}</span> &middot; <span class="release-date">latest</span></span>
      </div>
      <table class="artifacts">
        <thead>
          <tr><th scope="col">File</th><th scope="col">x86_64</th><th scope="col">arm64</th></tr>
        </thead>
        ${ARTIFACTS}
      </table>
      <p class="hint">Verify after download: <code>sha256sum -c SHA256SUMS --ignore-missing</code></p>
    </section>

    <section class="block" aria-labelledby="quickstart">
      <div class="section-head">
        <h2 id="quickstart">Quick start</h2>
        <p>Common first commands on a running host.</p>
      </div>
      <div class="cmd-grid">
        <div class="cmd-item"><h3>Install to disk</h3><pre>ziroctl install -d /dev/sda -y</pre></div>
        <div class="cmd-item"><h3>Check health</h3><pre>ziroctl doctor</pre></div>
        <div class="cmd-item"><h3>Run a container</h3><pre>ziroctl container run -d -p 80:80 nginx</pre></div>
        <div class="cmd-item"><h3>Harden the host</h3><pre>ziroctl security harden</pre></div>
        <div class="cmd-item"><h3>Upgrade</h3><pre>ziroctl upgrade</pre></div>
        <div class="cmd-item"><h3>Install packages</h3><pre>ziropkg install curl jq git</pre></div>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrapper footer-inner">
      <a href="https://github.com/${REPO_NAME}" class="lockup" aria-label="Ziro OS on GitHub">
        <svg aria-hidden="true"><use href="#ziro-mark"/></svg>
        <span class="lockup-name">Ziro</span><span class="os-pill">OS</span>
      </a>
      <ul class="footer-links">
        <li><a href="https://github.com/${REPO_NAME}" target="_blank" rel="noopener">GitHub</a></li>
        <li><a href="https://github.com/${REPO_NAME}/tree/main/docs" target="_blank" rel="noopener">Docs</a></li>
        <li><a href="https://github.com/${REPO_NAME}/blob/main/SECURITY.md" target="_blank" rel="noopener">Security</a></li>
        <li><a href="https://github.com/${REPO_NAME}/blob/main/LICENSE" target="_blank" rel="noopener">MIT License</a></li>
        <li>Security by <a href="https://snyk.io" target="_blank" rel="noopener">Snyk</a></li>
      </ul>
      <p class="copyright">&copy; 2026 Sambo Chea and Ziro-OS Contributors. Minimal by design. Born for the cloud.</p>
    </div>
  </footer>

  <script>
    function copyCommand() {
      const code = document.getElementById('cmd-snippet').textContent;
      navigator.clipboard.writeText(code).then(() => {
        const label = document.getElementById('copy-label');
        label.textContent = 'Copied';
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

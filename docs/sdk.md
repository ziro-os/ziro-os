# Ziro OS SDK

The SDK is the toolkit for building on Ziro OS: plugins, apps, catalogs, and programs that manage hosts and
clusters. It's the same code `ziroctl` runs, so whatever passes validation in your editor or CI is exactly what
a host accepts.

| Piece | What it's for |
|---|---|
| [`sdk/schema`](../sdk/schema) | The formats: plugin manifests, app definitions, gateway routes, supervised services, settings and placeholders, generated secrets. It includes their validators. |
| [`sdk/catalog`](../sdk/catalog) | Build, sign (ed25519) and verify catalogs, like `ziro-os/pkgs` and `ziro-os/apps`, or your own. |
| [`sdk/client`](../sdk/client) | A typed Go client for the API server (`ziroctl api`). |
| [`sdk/api`](../sdk/api) | The API's request and response types, shared by the server and the client. |
| [`sdk/openapi.yaml`](../sdk/openapi.yaml) | The OpenAPI 3.1 description of every `/api/v1` route, so you can generate a client in any language. |
| [`ziroctl dev`](#the-dev-toolchain) | Scaffold, validate and run plugins and apps in a throwaway Ziro VM, and sign your own catalog. |
| [Kernel kit](#kernel-modules-and-ebpf) | Out-of-tree kernel modules and CO-RE eBPF programs for the Ziro kernel. |

```sh
go get github.com/ziro-os/ziro-os/sdk@latest      # module tags: sdk/vX.Y.Z
```

## Manage a host or cluster from Go

```go
c, err := client.New("https://10.0.0.5:8443", os.Getenv("ZIRO_TOKEN"), client.WithCAFile("api.crt"))

// Publish an app on a hostname (validated locally with the server's rules, live within a second)
_, err = c.PutGatewayRoute(ctx, schema.GatewayRoute{
    Name: "web", Hosts: []string{"www.example.com"},
    To:   []schema.GatewayUpstream{{App: "web", Weight: 90}, {App: "web-next", Weight: 10}},
    LB:   "least_conn", Health: &schema.GatewayHealth{Path: "/healthz"},
})

// Deploy postgres from the signed catalog, then follow it
_, err = c.DeployApp(ctx, api.AppDeployRequest{App: "postgres:18", Expose: "db.internal"})
apps, err := c.Apps(ctx)
```

Errors are `*client.Error` values carrying the HTTP status and the server's message; `client.IsNotFound(err)`
helps with lookups. A token is never sent over plain HTTP to a remote host. `Do` and `Get` reach any route.
[`sdk/examples/canary`](../sdk/examples/canary) is a complete program: it shifts traffic to a new app in steps
and rolls back on failed health checks.

Tokens and roles (`ziroctl api token create <name> --role viewer|operator|admin`) work as described in the spec's
header. Every change made through the API is audited on the host.

## Validate plugins and apps in your own tooling

```go
m, err := schema.ParseManifest(data)   // a plugin manifest: strict decoding, then every security rule
d, err := schema.ParseAppDef(data)     // an app definition: images pinned by digest, no secrets in argv, ...
r.Normalize(); err = r.Validate()      // a gateway route
```

These are the rules in [modules.md](modules.md#writing-a-plugin) and [apps.md](apps.md#writing-an-app-definition).

## Your own catalog

```go
idx, err := catalog.Build("./my-plugins", "public", "acme", "module", 30*24*time.Hour, time.Now(), check)
err = catalog.Sign("public", privatePEM)
idx, err = catalog.VerifyIndex(repo, raw, sig, time.Now())
```

`ziroctl catalog build|sign|verify` wraps the same functions for CI. Hosts add your catalog with
`ziroctl plugin repo add <name> <url> --key <pem>`.

## The dev toolchain

`ziroctl dev` runs on Linux and macOS (it needs QEMU, and Docker for the kernel kit):

```sh
ziroctl dev new plugin hello            # modules/hello/manifest.json, README.md, .github/workflows/catalog.yml
ziroctl dev new app web                 # apps/web/app.json (a pinned, non-root web server to start from)
ziroctl dev validate .                  # the host's rules, plus lints; --strict makes warnings fail (CI)
ziroctl dev run modules/hello/manifest.json --check 'wget -qO- http://127.0.0.1:8080/'
ziroctl dev run apps/web/app.json --forward 8080:8080   # then http://127.0.0.1:8080 on your machine
```

- `dev validate` reports a service running as root, a missing health check, a `bind` setting not on loopback by
  default, an arch-specific artifact without `arch`, and an app command wrapped in a shell that never drops
  privileges.
- `dev run` boots the latest release (`--release vX.Y.Z` for another, `--image-dir build` for a local build). It
  downloads it once into your cache and verifies it against the release's `SHA256SUMS`. The VM boots in live mode,
  so nothing persists. It installs the plugin (`plugin install -f`) or deploys the app (`apps deploy -f`).
  - With `--check`, each command runs in the VM, and `dev run` fails if any fails. Use this in CI.
  - Without `--check`, you're attached to the VM's root console. Ctrl-C stops the VM.
  - `--copy file:/path` puts files in the VM first.
  - `--forward` ports listen on your machine's loopback only. QEMU uses KVM (Linux) or HVF (macOS) when the arch
    matches.
- **Your own catalog:**
  1. `ziroctl dev catalog keygen acme` creates the signing key.
  2. Store `acme.key` as the `ZIRO_CATALOG_KEY` secret, and commit `acme.pub` as `catalog.pub`.
  3. The generated workflow validates pull requests. On `main` it builds, signs and verifies the catalog, publishes
     it to GitHub Pages, and re-signs it weekly before the index expires.
  4. Hosts add it with `ziroctl plugin repo add acme https://<owner>.github.io/<repo> --key catalog.pub`.

## Kernel modules and eBPF

Each release publishes a kernel kit, `kernel-devel-<arch>.tar.gz`, listed in `SHA256SUMS`. It holds the
headers, scripts and `Module.symvers` of the release kernel, plus `vmlinux.h` (every kernel type, from its BTF)
and the module signing certificate.

```sh
ziroctl dev kmod build ./mydriver --sign-key my-modules.pem   # .ko files in ./mydriver
ziroctl dev bpf build probe.bpf.c                             # probe.bpf.o (CO-RE)
```

Builds run in the container image the kit was built in, so the compiler matches the kernel's. `--kit` uses a
local kit, and `--arch` cross-builds through Docker's emulation. See
[`sdk/examples/kmod-hello`](../sdk/examples/kmod-hello) and [`sdk/examples/bpf`](../sdk/examples/bpf).

- **Module signing:** the Ziro kernel loads only signed modules (`MODULE_SIG_FORCE`), and the official kernel
  trusts only the Ziro key. Modules built in Ziro CI are signed with it and ship as catalog artifacts. For your own
  modules:
  1. Sign them with your key (`--sign-key`, a PEM that holds the key and the certificate, or add `--sign-cert`).
  2. Build a kernel that also trusts your certificate:
     `ZIRO_EXTRA_TRUSTED_CERT=my-modules.crt make kernel rootfs`.
  The kernel never accepts keys at runtime.
- **eBPF:** CO-RE programs need no kernel headers on the host. libbpf relocates them to the running kernel through
  its BTF (`/sys/kernel/btf/vmlinux`).

## Other languages

Generate a client from [`sdk/openapi.yaml`](../sdk/openapi.yaml) with any OpenAPI 3.1 generator. A test in
`ziroctl` (`TestOpenAPICoversEveryRoute`) fails when a route is added without documenting it, or documented
without being served, so the spec stays complete.

## Compatibility

- The SDK follows semantic versioning (`sdk/vX.Y.Z` tags).
- Every validator also runs on the host, so an SDK older than the host can still produce definitions the host
  accepts, as long as they don't use newer fields.
- Unknown fields are always rejected, so a typo never silently drops a setting.

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

## Other languages

Generate a client from [`sdk/openapi.yaml`](../sdk/openapi.yaml) with any OpenAPI 3.1 generator. A test in
`ziroctl` (`TestOpenAPICoversEveryRoute`) fails when a route is added without documenting it, or documented
without being served, so the spec stays complete.

## Compatibility

- The SDK follows semantic versioning (`sdk/vX.Y.Z` tags).
- Every validator also runs on the host, so an SDK older than the host can still produce definitions the host
  accepts, as long as they don't use newer fields.
- Unknown fields are always rejected, so a typo never silently drops a setting.

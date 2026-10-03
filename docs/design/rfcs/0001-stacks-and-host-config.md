# RFC 0001: Stacks and declarative host config

- **Status:** Accepted (implemented in #49)
- **Pull request:** #49

## Summary

Two new resource kinds: a **stack** deploys several apps together, in dependency order, with links between them; a
**host config** describes a whole host and is applied with `ziroctl apply`. Every definition (plugin, app, stack,
host config) can be written in YAML or JSON with the same strict rules. User guide: [provisioning.md](../../provisioning.md).

## Motivation

Real workloads are several apps (a web app and its database), and hosts were configured with a series of
imperative commands or a user-data shell script. Neither could be reviewed as a plan, re-applied safely, or
versioned in git.

## Design

**Formats** (`sdk/schema`). YAML is converted to JSON (one document, string keys only) and decoded strictly: unknown
fields are errors. The kind follows from the shape: `stack:` is a stack, `host:` a host config, `components:` an
app, anything else a plugin manifest. Stacks and host configs carry `version: 1`.

```yaml
stack: shop
version: 1
apps:
  db:  { app: postgres, resources: { memory: 1Gi } }
  web:
    app: ./apps/web/app.yaml        # a catalog app[:version], or a definition next to the stack file
    expose: shop.example.com
    depends_on: [db]
    links: { DATABASE_URL: db.url }
```

```yaml
#ziro-config
host:
  version: 1
  hostname: web-1
  ssh: { keys: ["ssh-ed25519 AAAA... ops"] }
  firewall: { allow: [443/tcp] }
  stacks: [ ./shop/stack.yaml ]
  cluster: { join: { address: 10.0.0.10:7443, token_file: /run/secrets/join } }
```

**Stacks.** Each app becomes an ordinary app instance `<stack>-<key>`. Apps deploy in dependency order (a cycle is
an error) and each waits until healthy before its dependents start. Apps removed from the file are removed after
the rest is up; data is kept unless `stack down --purge`. A stack's apps share a network (`ziro-stack-<name>`) on a
host, or the mesh DNS on a cluster. `./` paths must stay inside the stack's directory; over the API only catalog
apps are accepted. Catalogs can publish stacks, signed and pinned in the same index; those may only use catalog apps.

**Links** pass a dependency's declared output (for example a connection URL with its password) into an app as an
environment variable. A link must name an app in `depends_on` and an output its definition declares, and may not
clash with the app's own variables; all of this is checked before anything deploys.

**Host config.** Each section calls the same operation as its command (`hostname` → `network hostname`, `ssh` →
`ssh key`, `firewall`, `packages`, `plugins`, `stacks` → `stack up`, `update`, `network` → `network apply`,
`cluster.join` → `cluster join`). `--dry-run` prints the plan; applying twice is a no-op. A file whose first line is
`#ziro-config` is applied at first boot (cloud user-data or the installer's `ziro.userdata=`).

**API.** `GET /api/v1/stacks[/{name}]` (viewer), `POST /api/v1/stacks/{name}/plan` (operator),
`PUT /api/v1/stacks/{name}` (admin, 202), `DELETE /api/v1/stacks/{name}` (admin), `POST /api/v1/apply` (admin).

## Security

- **Linked values travel only like generated secrets:** through the app's 0600 env file on a host, or the sealed
  cluster secret on a cluster. They never go into settings, argv or plain env, so `nerdctl inspect` and process
  listings don't show them.
- **The cluster join token is read from a file** (`token_file`), never written in the config. The applied config is
  kept 0600 (`/etc/ziro/applied.yaml`).
- **SSH keys:** `apply` manages only the keys listed in the file and never touches keys added another way.
- **Paths:** local app references can't escape the stack's directory; the API refuses them entirely, so an API
  caller can't make the host read arbitrary files.
- **First-boot downloads** are HTTPS-only, like any user-data.
- Applying stacks and host configs needs `admin`; planning needs `operator`.

## Compatibility

Additive. JSON definitions keep working unchanged; user-data without the `#ziro-config` header still runs as a shell
script. `docker-compose` files are converted with `ziroctl stack import`, which reports what has no safe equivalent
(bind mounts, `privileged`, typed-in credentials) instead of dropping it.

## Alternatives

- **Run docker-compose files directly as the deployment format:** rejected. Compose allows privileged containers,
  bind mounts and credentials in the file, and has no signed catalog or pinned images. `ziroctl compose` (nerdctl compose
  behind a security preflight) stays for development; `stack import` converts.
- **Pass link values as plain environment variables:** rejected. They often hold passwords, and plain env is visible
  in `inspect`.
- **A `kind:` field:** unnecessary. The shapes don't overlap, and files stay shorter.

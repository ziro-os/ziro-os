# Stacks and host provisioning

Ziro OS is configured declaratively. You describe what a host or a group of apps should look like
in a YAML (or JSON) file, `ziroctl` shows the plan, and then changes only what differs. Applying
the same file again changes nothing.

| File | What it describes | Command |
|---|---|---|
| plugin manifest | a host service and its packages | `ziroctl plugin install -f manifest.yaml` |
| app definition | containers, images pinned by digest | `ziroctl apps deploy -f app.yaml` |
| stack | several apps deployed together, in order | `ziroctl stack up -f stack.yaml` |
| host config | a whole host | `ziroctl apply -f host.yaml` |

## One format, strict rules

- **YAML or JSON:** every definition can be written in either, with the same schema. YAML is converted to JSON and
  both go through the same validation.
- **Strict:** an unknown field is an error, so a typo never silently drops a setting. Duplicate keys and multiple
  YAML documents in one file are refused.
- **Kind:** what a file is follows from its shape. A top-level `stack:` makes it a stack, `host:` a host config,
  `components:` an app definition, and anything else a plugin manifest.
- **Catalogs:** signed catalogs accept `manifest.yaml` and `app.yaml`. They serve canonical JSON, which is what the
  signature pins.
- **Tooling:** `ziroctl dev new` writes YAML (`--format json` for JSON), and `ziroctl dev validate` checks all four
  kinds.

## Stacks

```yaml
stack: shop
version: 1
apps:
  cache:
    app: valkey                  # a catalog app (name[:version])
    resources: { memory: 256Mi }
  web:
    app: ./apps/web/app.yaml     # or a definition next to the stack file
    publish: 8080
    expose: shop.example.com     # through the gateway, with TLS
    resources: { memory: 128Mi, cpus: 0.5 }
    depends_on: [cache]
```

```sh
ziroctl stack up -f shop.yaml --dry-run   # + create, ~ update, = unchanged, - remove
ziroctl stack up -f shop.yaml
ziroctl stack status shop
ziroctl stack down shop [--purge]
```

**How it deploys:**
- Each app becomes an ordinary app instance named `<stack>-<key>` (`shop-cache`, `shop-web`). `apps list`,
  `apps credentials` and the gateway work on it as usual.
- Apps deploy in dependency order, and each waits until it's healthy before its dependents start.
- A dependency cycle is an error.
- An app removed from the file is removed from the host, after the rest is up. Its data is kept unless you run
  `stack down --purge`.

**Per-app options:**
- `set` (settings), `replicas`, `publish`, `expose` / `expose_tls`.
- `resources` applies to every component of the app.

**Local definitions:** `./` paths must stay inside the stack's directory. Over the API (`PUT /api/v1/stacks/{name}`)
only catalog apps are accepted.

**Published stacks:** an app catalog can publish stacks next to its apps (`stacks/<name>/stack.yaml`). They are
signed and pinned in the same index, and may only use catalog apps.

```sh
ziroctl stack search            # stacks in the signed catalogs
ziroctl stack up wordpress      # deploy one by name
```

To publish your own, add `stacks/<name>/stack.yaml` to your catalog repository. `ziroctl dev new stack <name>`
scaffolds one, and `ziroctl catalog build . --kind app` signs it with the apps.

**From docker-compose:**

```sh
ziroctl stack import docker-compose.yml -o shop   # shop/stack.yaml + shop/apps/<service>/app.yaml
```

| Compose | Becomes |
|---|---|
| service | an app definition with one component |
| image | pinned by digest, resolved from its registry now |
| first port | the component's port, plus the stack's `publish` |
| named volumes | persistent `data` |
| `command`, `healthcheck`, `environment` | args, health, env |
| `depends_on` | `depends_on` |

What has no safe equivalent is reported instead of silently dropped:
- bind mounts
- `build`, `privileged`, `network_mode`, `cap_add`, `devices`
- additional ports
- `${...}` interpolation
- credentials typed into the file (move them to secrets or links)

Review the result, then run `ziroctl stack up -f shop/stack.yaml --dry-run`.

`ziroctl compose up|down|ps|logs` still runs a compose file directly, and reads the full YAML syntax (list or map
`environment`, string or list `command`).

**Wiring apps together: links**

An app can receive a dependency's output, such as a connection URL with its password, as an environment variable:

```yaml
apps:
  db:  { app: postgres }
  web:
    app: ./apps/web/app.yaml
    depends_on: [db]
    links:
      DATABASE_URL: db.url       # <dependency>.<output>, from the dependency's definition
```

- Outputs can hold credentials, so linked values travel only like generated secrets: through the app's env file
  (0600), or the sealed cluster secret on a cluster. They never go into settings, argv or plain env, and
  `nerdctl inspect` doesn't show them in the command line.
- The address in a linked value is the one containers use:
  - On a host, a stack's apps share a network (`ziro-stack-<name>`) and reach each other by container name.
  - On a cluster, they use the mesh DNS name.
- A link must name an app in `depends_on` and an output its definition declares. A link that clashes with one of
  the app's own variables is refused before anything deploys.

## Host provisioning: `ziroctl apply`

```yaml
#ziro-config
host:
  version: 1
  hostname: web-1
  ssh:
    keys: ["ssh-ed25519 AAAA... ops"]
    import: [gh:alice]
  firewall: { allow: [80/tcp, 443/tcp], block: [203.0.113.0/24] }
  packages: [htop]
  plugins: [ { name: clamav, set: { onaccess: /srv } } ]
  stacks: [ ./shop/stack.yaml ]
  update: { auto: true }
  network: { interfaces: [ { name: eth0, mode: dhcp } ] }   # the `ziroctl network` schema
  cluster: { join: { address: 10.0.0.10:7443, token_file: /run/secrets/join } }
```

```sh
ziroctl apply -f host.yaml --dry-run
ziroctl apply -f host.yaml [--confirm-timeout 5m]
```

Every section calls the same operation as its command:

| Section | Behaves like |
|---|---|
| `hostname` | `network hostname` |
| `ssh` | `ssh key` |
| `firewall` | `firewall allow` / `firewall block-ip` |
| `packages` | `pkg install` (kept across OS upgrades) |
| `plugins` | `plugin enable --set`; a plugin already enabled with other settings is reinstalled with the new ones |
| `stacks` | `stack up` |
| `update` | the auto-update switch of `ziroctl update` |
| `network` | `network apply` (`--confirm-timeout` rolls back unless confirmed) |
| `cluster.join` | `cluster join` |

**SSH keys:** `apply` manages only the keys listed in the file. Removing a key from the file removes it from the
host, and keys added any other way are never touched.

**Join token:** it is always read from a file (`token_file`), never written into the config.

**Record:** the applied file is kept in `/etc/ziro/applied.yaml` (0600).

## First boot

A host config whose first line is `#ziro-config` is applied automatically.

- **Cloud user-data:** pass the file as user-data (for example Terraform's `user_data = file("host.yaml")`). The
  first-boot `cloud-init` service applies it once per instance.
- **Installer:** `ziro.userdata=https://example.com/host.yaml` (or `--user-data`). The installer stages it as
  `/etc/ziro/provision.yaml` and the first boot applies it. The download is HTTPS-only, like any user-data.
- **Shell scripts still work:** user-data without the header runs as a shell script, as before.

Stack files named by a first-boot config are looked up in `/etc/ziro/provision.d/`.

## API and SDK

| Operation | Route | Role |
|---|---|---|
| list | `GET /api/v1/stacks` (`?source=catalog` for published stacks) | viewer |
| status | `GET /api/v1/stacks/{name}` | viewer |
| plan | `POST /api/v1/stacks/{name}/plan` | operator |
| apply (background) | `PUT /api/v1/stacks/{name}` | admin |
| remove | `DELETE /api/v1/stacks/{name}?purge=true` | admin |
| host config | `POST /api/v1/apply?dry_run=true` | admin |

In Go:
- `client.PlanStack`, `ApplyStack`, `RemoveStack`, `CatalogStacks` and `ApplyHost`. Definitions are validated locally with the
  host's own rules (`schema.ParseStack`, `schema.ParseHostConfig`) before anything is sent.
- `schema.ToYAML` writes any definition as YAML.

Examples: [`sdk/examples/provisioning`](../sdk/examples/provisioning).

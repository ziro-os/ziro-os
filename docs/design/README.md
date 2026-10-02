# Ziro OS design standard

How Ziro OS is designed, and the rules every change follows. It describes what the code does today; when the
code and this page disagree, fix one of them in the same pull request. Larger changes go through an
[RFC](rfcs/README.md).

## Principles

- **Minimal.** Ship only what container hosts need. Bootable images stay under 300 MB (CI enforces it). Prefer the
  standard library and static binaries; add a dependency only when a few lines can't do the job.
- **Secure by default.** The default configuration is the hardened one. Opting out is explicit, local and audited.
- **Declarative.** Users describe the state they want in a file; `ziroctl` shows the plan, then changes only what
  differs.
- **One implementation per operation.** The CLI, the REST API, declarative files and the SDK all call the same
  operation function. Validation lives in one place (`sdk/schema`) and runs at every trust boundary: CLI, API,
  catalog CI and the host.

## Resource model

Every managed thing is a named resource with one schema in [`sdk/schema`](../../sdk/schema):

| Resource | Schema | Name |
|---|---|---|
| plugin (host service + packages) | `ModuleManifest` (`module.go`) | `name` |
| app (containers) | `AppDef` (`app.go`) | `name` |
| gateway route | `GatewayRoute` (`gateway.go`) | `name` |
| stack, host config | `Stack` (`stack.go`), `HostConfig` (`host.go`), see [RFC 0001](rfcs/0001-stacks-and-host-config.md) | `stack:` / the host |
| cluster app | an `AppDef` placed on the cluster | `name` |
| catalog | signed index of plugins, apps and stacks (`sdk/catalog`) | repository name |

Rules for every format:

- **Names** match `^[a-z0-9][a-z0-9_.-]{0,62}$` (`schema.ValidName`); a name is safe in a file path.
- **YAML or JSON**, same schema, same rules. YAML is converted to JSON and both go through the same strict decoder.
- **Strict:** an unknown field is an error, so a typo never silently drops a setting. Duplicate keys and multi-document
  YAML files are refused.
- **Kind by shape:** a top-level `stack:` is a stack, `host:` a host config, `components:` an app definition, anything
  else a plugin manifest. No `kind:` field is needed.
- **Versions:** stacks and host configs carry `version:` (currently `1`); the validator refuses versions it doesn't
  know. Plugins carry a package `version`; apps list `versions` with images pinned by digest.
- **Deprecation:** a field is marked deprecated (in its schema comment and in the docs) for at least one minor
  release before it is removed. Removing a field or changing its meaning is a breaking change. The SDK
  follows semantic versioning (`sdk/vX.Y.Z` tags), so a breaking schema change needs a major SDK release.

## API conventions

The REST API is one route table ([`tools/ziroctl/cmd/api_routes.go`](../../tools/ziroctl/cmd/api_routes.go)): each
entry names the method, path, minimum role and handler. Authentication, role checks, rate limits (per client
address, then per token) and the audit record are all applied from that table, so a route can't be served without
being authorized and audited.

- **Paths:** `/api/v1/<resource>[/{name}[/<action>]]`, for example `/api/v1/services/{name}/restart` and
  `/api/v1/cluster/apps/{name}/scale`.
- **Methods:** `GET` reads, `POST` creates or runs an action, `PUT` replaces a resource with the body, `DELETE`
  removes it. Bodies are decoded strictly (unknown fields are a 400) with a size limit.
- **Long work** (deploys, pulls, backups, updates) answers `202 {"status":"accepted","message":...}` and names the
  `GET` that shows the result.
- **Errors:** `{"status":"error","code":"invalid|unauthorized|forbidden|not_found|conflict|too_large|rate_limited|internal","message":...}`.
- **Roles** (each includes the ones before it):

  | Role | May |
  |---|---|
  | `public` | health only, no token |
  | `viewer` | read state |
  | `operator` | day-to-day changes: services, containers, DNS records, scaling, cordon/drain, logs |
  | `admin` | anything that grants or removes access, installs software, deletes data, or changes where traffic or lookups go |

- **OpenAPI:** [`sdk/openapi.yaml`](../../sdk/openapi.yaml) documents every route, with its role in `x-ziro-role`.
  `TestOpenAPIMatchesRoutes` fails when a route is served but not documented, documented but not served, or
  documented with a different role.

## CLI conventions

- **Noun, then verb:** `ziroctl apps deploy`, `ziroctl gateway route add`, `ziroctl api token create`.
- **`--json`** is a global flag: commands print their result (and errors, as `{"status":"error",...}`) as JSON.
- **Files:** `-f <file>` reads a definition; `--dry-run` prints the plan and changes nothing (declarative commands
  mark each item `+` create, `~` update, `=` unchanged, `-` remove).
- **Idempotent:** applying the same definition twice changes nothing the second time.
- Errors say what was wrong and what is allowed; commands exit non-zero on failure.

## Extension points

| Extend with | What it adds | Trust | Guide |
|---|---|---|---|
| Plugin | a host service and its packages, in its own cgroup | signed catalog, or `-f` locally | [modules.md](../modules.md) |
| App | containers, images pinned by digest, generated secrets | signed catalog, or `-f` locally | [apps.md](../apps.md) |
| Stack | several apps deployed together, with links between them | signed catalog, or `-f` locally | [provisioning.md](../provisioning.md) |
| Catalog | your own repository of plugins, apps and stacks | ed25519-signed index; every entry pinned by sha256 | [modules.md](../modules.md) |
| Kernel module / eBPF | drivers and programs for the Ziro kernel (kernel kit) | modules must be signed (`MODULE_SIG_FORCE`) | [sdk.md](../sdk.md) |
| API client | automation in Go or any language | scoped API token | [sdk.md](../sdk.md) |

## Security model

- **Least privilege.** API tokens are scoped to a role and expire; services can run as a non-root user; plugin
  services run in their own cgroup and apps take `resources` limits. Host daemons are OOM-protected (score -900) and workloads are
  reclaimed first (+300), so a runaway container can't take the host down.
- **Secrets** never go into argv, logs or plain environment variables. Generated credentials reach containers only
  through 0600 env files (or the sealed cluster secret on a cluster). API tokens are shown once; only their SHA-256
  is stored.
- **Every change is audited.** The audit log is hash-chained (`ziroctl audit verify` detects an edited or removed
  record), and API changes are recorded under the token's name with their result.
- **Signed artifacts.** Catalogs (ed25519 index, sha256-pinned entries), `ziroctl` tools releases (ed25519-signed
  `SHA256SUMS`, public key in `tools/ziroctl/cmd/release.pub`) and kernel modules
  (`kernel/certs/ziro-modules.crt`). Downloads are verified before use.
- **Input is validated at every boundary** (CLI, API, catalog, host) by the same `sdk/schema` code.

See [security.md](../security.md) for the controls in detail and their known limits, and
[SECURITY.md](../../SECURITY.md) to report a vulnerability.

## How to add a feature

1. **Operation:** one function in `tools/ziroctl/cmd` that validates its input (with `sdk/schema`) and does the work.
2. **CLI:** a Cobra command that parses flags and calls the operation; support `--json` through `printResult`.
3. **API:** one entry in the route table with the least role that is safe; request and response types in
   `sdk/api`.
4. **OpenAPI:** document the route and its `x-ziro-role` in `sdk/openapi.yaml`.
5. **SDK:** a typed method in `sdk/client`.
6. **Tests:** unit tests next to the code; extend `tests/qemu/boot-smoke.py` when it needs a real host.
7. **Docs:** the user guide in `docs/`, and this page or [architecture.md](../architecture.md) if a design rule
   changes.

Before opening the pull request, run the [lint gate](../../community/CONTRIBUTING.md#lint-gate).

# Sandboxes

A sandbox is a disposable, isolated machine for code you don't trust: an AI agent's tools, a code interpreter or a CI
step. Each one is a container that runs under [gVisor](https://gvisor.dev). gVisor is a kernel in user space, so the
workload's system calls never reach the host kernel. A sandbox keeps a short list of privileges, has no network unless
you ask
for one (and then only what its policy allows), and has resource limits and a lifetime. You manage sandboxes with
`ziroctl sandbox`, the REST API or the Go SDK. The
design is [RFC 0004](design/rfcs/0004-sandboxes.md).

```sh
ziroctl module enable sandbox                          # gVisor + ziro-sandboxd (downloads ~170 MB once)
ziroctl sandbox create python:3.13-slim --timeout 30m  # prints the id when it runs
ziroctl sandbox exec <id> -- python3 -c 'print(6*7)'
ziroctl sandbox ls
ziroctl sandbox rm <id>
```

## What a sandbox can and can't do

| | Default | Can the caller change it? |
|---|---|---|
| Kernel | gVisor (systrap: no KVM needed, works in cloud VMs and on arm64) | `--runtime gvisor-kvm` puts gVisor's kernel behind hardware virtualization ([below](#hardware-isolation-gvisor-kvm)); `runc` only for operators, and only if the host allows it |
| Privileges | every capability dropped except chown, dac_override, fowner, fsetid, kill, net_bind_service, setgid, setuid (inside gVisor); `no-new-privileges` | no |
| Files | the image's own copy-on-write root, a `/workspace` directory, a 256 MiB `/tmp` | no host mounts, no devices |
| Network | none: no interface at all | `--net open` (the public internet) or `--allow` entries (default-deny); never the host, other sandboxes, cloud metadata or private networks ([below](#network-policy)) |
| Resources | 1 GiB memory, 1 CPU, 512 processes | up to the host limits (8 GiB, 4 CPUs, 4096 processes) |
| Lifetime | 1 hour, then the sandbox is deleted | `--timeout` up to 24 h, `renew` to extend, `--idle-timeout` to delete it sooner |

Root inside a sandbox is root inside gVisor, so installing packages works. A process that exits stops the sandbox,
and it shows as `failed`. By default a sandbox runs `sleep infinity`, so it stays up for `exec`.

## Commands

```sh
ziroctl sandbox create node:22 --memory 2Gi --cpus 2 --timeout 2h --idle-timeout 15m --meta agent=claude
ziroctl sandbox create alpine -e MODE=test -u 1000:1000 -- sh -c 'sleep 3600'
ziroctl sandbox exec <id> -w /workspace -e DEBUG=1 --timeout 2m -- make test
echo 'print(42)' | ziroctl sandbox exec <id> -i -- python3
ziroctl sandbox get <id> --json
ziroctl sandbox ls --state running --label agent=claude
ziroctl sandbox stats <id>                 # cpu, memory, processes, network and disk I/O
ziroctl sandbox logs <id> --tail 50        # the main command's output
ziroctl sandbox pause <id>                 # freeze its processes (memory is kept)
ziroctl sandbox resume <id>
ziroctl sandbox renew <id> --timeout 1h    # expires one hour from now
```

`exec` streams the command's output as it runs and exits with the command's exit code. A command may run for up to
1 hour, and its output is capped at 64 MiB.

## Hardware isolation (gvisor-kvm)

On hosts with KVM (bare metal, or VMs with nested virtualization), `--runtime gvisor-kvm` runs gVisor on its KVM
platform. The sandbox's kernel then runs inside a hardware virtual machine context, so escaping it would also need a
CPU virtualization escape. It is a microVM-grade boundary without a guest kernel or image to download: it is the same
`runsc`, and it usually runs syscall-heavy workloads faster than the default platform.

```sh
ziroctl sandbox create python:3.13-slim --runtime gvisor-kvm
```

- Make it the host's default with `"default_runtime": "gvisor-kvm"` in `/etc/ziro/sandbox.json`.
- Without `/dev/kvm`, create fails with a clear error and asks for `gvisor` instead. On x86_64 the KVM module is
  loaded on first use. Both Ziro kernels ship KVM (built in on arm64).

## Network policy

A sandbox has one of three network modes:

| Mode | What it reaches |
|---|---|
| `none` (default) | nothing: the sandbox has no network interface |
| `allowlist` | only the listed domains (and their subdomains), IPv4 addresses and CIDRs |
| `open` | the public internet |

```sh
ziroctl sandbox create python:3.13-slim --allow pypi.org --allow files.pythonhosted.org
ziroctl sandbox create node:22 --net open
ziroctl sandbox network <id> --allow registry.npmjs.org     # replace the policy now
ziroctl sandbox network <id> --net none                     # cut it off (the interface stays, everything is dropped)
```

Whatever the mode, a sandbox never reaches:

- the host itself (except its DNS resolver)
- other sandboxes
- link-local addresses and cloud metadata (`169.254.0.0/16`)
- private, CGNAT, loopback, multicast and reserved ranges

Only an operator can allow one of these ranges, by listing it explicitly (`--allow 10.1.2.0/24`). Nothing outside
can open a connection into a sandbox.

How it is enforced:

- **Outside the sandbox.** The rules live in an nftables table on the host (`inet ziro_sandbox`). Each sandbox has a
  routed address on the sandbox network (`10.250.0.0/16`, set `subnet` in the host config), so all of its traffic
  crosses the host's firewall.
- **Allowed names.** The sandbox's DNS resolver answers `NXDOMAIN` for any name the policy doesn't allow. For allowed
  names, it adds the addresses they resolve to into the sandbox's allowed set, before the sandbox gets the answer.
  An allowed name that resolves to a private address doesn't open that address, so DNS rebinding can't reach your
  LAN.
- **Fails closed.** A new sandbox's rules are in place before it starts. If the rules for a running sandbox can't be
  applied, it is paused and marked `failed`.
- **Fixed at create.** A sandbox created without a network can't get one later. Create a new one instead.

Limits for now: IPv4 only, and a domain allows every port.

## Secrets (credential injection)

An agent needs API keys, and an agent can be tricked into leaking them. With `--secret`, the sandbox never holds the
key at all:

```sh
export GITHUB_TOKEN=ghp_...
ziroctl sandbox create alpine/git --allow api.github.com --secret GITHUB_TOKEN@api.github.com
ziroctl sandbox exec <id> -- sh -c 'echo $GITHUB_TOKEN'      # zsec_7f3k...: a placeholder
```

- **The sandbox sees a placeholder.** Inside the sandbox, `$GITHUB_TOKEN` is a random placeholder.
- **The host fills it in.** The sandbox's HTTPS traffic (port 443) goes through the host's egress proxy. For
  `api.github.com` only, the proxy terminates TLS with a CA that only this sandbox trusts. It replaces the
  placeholder with the real value in headers, Basic auth, the query string and the path, then verifies the real
  server's certificate.
- **Other hosts can't get it.** A placeholder sent to any other host is refused with `403 credential_endpoint_mismatch`.
  Traffic to other hosts passes through untouched, with their real certificates.
- **Where the value lives.** It is taken from your environment (never from the command line), kept only in a
  root-only file in the sandbox's directory, never returned by the API, and deleted with the sandbox. Each use is
  audited with the secret's name and host, never its value.
- **Trusting the sandbox's CA.** The sandbox gets it through `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
  `GIT_SSL_CAINFO` and `NODE_EXTRA_CA_CERTS`, which point to `/etc/ziro/ca-bundle.crt` and
  `/etc/ziro/sandbox-ca.crt`. Tools that ignore these variables need the bundle added to their own trust store.
- **API:**
  `"secrets": [{"name": "GITHUB_TOKEN", "value": "...", "hosts": ["api.github.com", "*.githubusercontent.com"]}]`
  in the create body. Secrets need a network (`--allow` or `--net open`).
- **Policy still applies.** The proxy enforces the sandbox's network policy on what it carries.

Limits for now: request bodies, WebSocket messages and request signing (AWS SigV4) aren't rewritten. Only port 443
is intercepted, and only over HTTP/1.1.

## SSH access

Every sandbox can be reached through one SSH gateway on port `22998`. The session token is the user name, so a
single line gets a person, a CI job or an agent into a sandbox. There are no SSH keys to distribute and no accounts
on the host:

```sh
ziroctl sandbox access create <id> --ttl 30m
# ssh -p 22998 zsbx_7kq2...@sbx.example.com
ziroctl sandbox access create <id> --public-key ~/.ssh/id_ed25519.pub --single-use
ziroctl sandbox access ls <id>
ziroctl sandbox access rm <id> <token-id>
ziroctl sandbox ssh <id>                       # on the host: a shell, with a single-use token
```

Then, from anywhere that can reach the host:

```sh
ssh -p 22998 zsbx_7kq2...@sbx.example.com                   # a shell (bash if the image has it)
ssh -p 22998 zsbx_7kq2...@sbx.example.com 'pytest -q'       # one command, with its exit status
ssh -p 22998 -L 8080:localhost:8080 zsbx_7kq2...@sbx.example.com   # reach a port of the sandbox
```

- **Tokens:**
  - 128 random bits. Only the hash is kept on the host.
  - They expire (1 hour by default, at most 24 hours, never after the sandbox) and are deleted with the sandbox.
  - A `--single-use` token works for one connection.
  - A token bound to `--public-key` also needs that key, so a leaked user name alone opens nothing.
- **Host key:** the gateway has its own host key. `access create` prints its `known_hosts` line, so clients can
  verify it (`ziroctl sandbox ssh` always does).
- **What a session can do:**
  - Run a shell or a command in its own sandbox, with a terminal when the client asks for one.
  - `ssh -L` port forwards, which reach only that sandbox's own address. The sandbox needs a network (`--net` or
    `--allow`), and the server inside must listen on `0.0.0.0`.
- **What is refused:** remote forwarding (`-R`), agent forwarding, X11 and `sftp`.
- **Rate limit and audit:** a client address with too many failed logins is shut out for 10 minutes. Logins are
  audited with the token id, never the token.
- **Turning it off:** set `ssh_port` to `0` to disable the gateway, or change the port. The gateway opens its port
  in the host firewall. Set `ssh_host` to the name clients should use in printed commands; the default is the host
  name the API was called with.

## Preview URLs

Publish a port of a sandbox at an HTTPS address. This works for a dev server an agent started, a notebook, or an
API it built:

```sh
ziroctl gateway domain set apps.example.com      # once: the gateway's base domain
ziroctl sandbox expose <id> 3000                  # https://3000-<id>.apps.example.com/?ziro_token=...
ziroctl sandbox expose <id> 8080 --public         # no token
ziroctl sandbox unexpose <id> 3000                # removes the URL and revokes its tokens
```

- **Through the gateway.** Each preview is a route on the [gateway](gateway.md), so it gets the gateway's TLS (ACME,
  the domain's wildcard certificate, or the gateway's own CA for private names), HTTP/2 and HTTP/3, rate limits and
  WebSockets.
- **Private by default.** A preview needs a signed token. Open the printed link once (the token becomes an HttpOnly
  cookie and leaves the address bar), or send the token in the `X-Ziro-Preview-Token` header. The token is removed
  before the request reaches the sandbox.
- **Token lifetime.** A token lasts as long as the sandbox, or `--ttl`. Running `expose` again prints a new token.
  `unexpose` (or deleting the sandbox) revokes all of a preview's tokens.
- **Needs a network.** The sandbox must have one (`--net` or `--allow`), and the server inside must listen on
  `0.0.0.0`.
- **Single host only.** On a cluster member, previews come with cluster support.
- **Turning it off.** `preview_port` in the host config is the loopback port the gateway's routes use; `0` turns
  previews off.

## Files

Read and write files in a sandbox's `/workspace` from the host side:

```sh
ziroctl sandbox cp ./main.py <id>:/workspace/main.py
ziroctl sandbox cp ./run.sh <id>:/workspace/bin/ --mode 0755
ziroctl sandbox cp <id>:/workspace/out.csv ./out.csv
ziroctl sandbox files <id> /workspace/src
```

Paths are confined to `/workspace`. `..` and symlinks the sandbox created can't lead out of it. Uploads are up to
100 MiB, are written atomically and are owned by the sandbox's user.

## For AI agents: the API and a scoped token

Give each agent a token that can only manage sandboxes:

```sh
ziroctl api token create agent-1 --role deployer --scope sandboxes --ttl 720h
```

A scoped token gets `403` on every other route. Each sandbox belongs to the token that created it. Another
deployer's sandbox answers `404`; operators and admins see all of them.

```sh
H="Authorization: Bearer $TOKEN"
curl -sk -H "$H" https://host:8443/api/v1/sandboxes \
  -d '{"image":"python:3.13-slim","timeout":"30m","network":{"mode":"allowlist","allow":["pypi.org"]}}'
curl -sk -H "$H" https://host:8443/api/v1/sandboxes/<id>/exec -d '{"command":["python3","-c","print(1+1)"]}'
# {"stream":"stdout","data":"2\n"}
# {"exit_code":0}
curl -sk -H "$H" -X DELETE https://host:8443/api/v1/sandboxes/<id>
```

| Route | |
|---|---|
| `GET/POST /api/v1/sandboxes` | list your sandboxes / create one and wait until it runs |
| `GET/DELETE /api/v1/sandboxes/{id}` | show / delete with its workspace |
| `POST /api/v1/sandboxes/{id}/pause`, `/resume`, `/renew` | freeze, thaw, move the expiry (`{"timeout":"1h"}`) |
| `GET /api/v1/sandboxes?state=running&label=task=42` | list, filtered by state and metadata (`label=key` or `key=value`, repeatable) |
| `GET /api/v1/sandboxes/{id}/stats` | CPU %, memory used and limit, processes, network and disk bytes |
| `GET /api/v1/sandboxes/{id}/logs?tail=200` | the end of the main command's output (for sandboxes created with a command) |
| `PUT /api/v1/sandboxes/{id}/metadata` | replace the metadata map |
| `PUT /api/v1/sandboxes/{id}/network` | replace the network policy (`{"mode":"allowlist","allow":["pypi.org"]}`) |
| `POST /api/v1/sandboxes/{id}/previews`, `DELETE .../previews/{port}` | publish a port at `https://<port>-<id>.<domain>` (`{"port":3000,"public":false}`) / remove it |
| `GET/POST /api/v1/sandboxes/{id}/access`, `DELETE .../access/{aid}` | SSH session tokens: list / issue (`{"ttl","public_key","single_use"}`) / revoke |
| `GET/PUT/DELETE /api/v1/sandboxes/{id}/files?path=` | read (or list) / write (raw body, `&mode=`) / remove (`&recursive=true`) in `/workspace` |
| `POST /api/v1/sandboxes/{id}/exec` | run a command; the answer is NDJSON: output lines, then `exit_code` or `error` |

With the Go SDK:

```go
c, _ := client.New("https://host:8443", token)
sb, err := c.CreateSandbox(ctx, schema.SandboxSpec{Image: "python:3.13-slim", Timeout: "30m"})
res, err := c.ExecSandbox(ctx, sb.ID, api.SandboxExecRequest{Command: []string{"python3", "-c", "print(1+1)"}})
fmt.Print(res.Stdout, res.ExitCode)
_ = c.DeleteSandbox(ctx, sb.ID)
```

Every create, exec and delete through the API is in the audit log (`ziroctl audit log`). Expired sandboxes are logged
as `sandbox expire`.

## For agents: templates, warm pools, snapshots, MCP

**Templates.** These are named specs kept by the host's admin:

```sh
ziroctl sandbox template add python python.json   # {"image":"python:3.13-slim","network":{"mode":"allowlist","allow":["pypi.org"]}}
ziroctl sandbox create --template python --meta task=42
ziroctl sandbox template ls
```

Fields set at create override the template's. Env and metadata are merged. Templates never hold secret values.

**Warm pools.** Set `"pools": {"python": 4}` in the host config to keep 4 sandboxes of a template created and paused.
A create that only names the template (plus `timeout`, `idle_timeout` and `metadata`) is served from the pool: the
sandbox is resumed and handed over, which takes milliseconds instead of a container start. The pool refills in the
background. A pool can't be larger than `max_per_owner`.

**Snapshots.** Save a sandbox's filesystem and start new sandboxes from it (install once, fork many):

```sh
ziroctl sandbox snapshot create <id> deps-installed    # ziro.local/sandbox/<owner>/deps-installed:<time>
ziroctl sandbox create ziro.local/sandbox/root/deps-installed:1760000000
ziroctl sandbox snapshot ls
ziroctl sandbox snapshot rm <image>
```

A snapshot has two parts, taken while the sandbox is briefly paused so they match:

- its root filesystem (packages installed with `apt`, `pip install --user` and so on), committed to the image;
- its `/workspace`, which is a mount the image can't hold. It is archived next to the sandboxes
  (`/var/lib/ziro/sandbox/.snapshots/`) with its modes, owners and symlinks, and unpacked into every sandbox started
  from the snapshot. `workspace_size` in `snapshot ls --json` is its compressed size (at most 8 GiB, 500,000 entries).

You can snapshot a paused sandbox, and it stays paused. Snapshots belong to the owner who took them. They don't need
the host's image policy, because they were built on this host. `/tmp` is not saved, and neither are processes or
memory.

**MCP server.** Any AI agent that speaks the Model Context Protocol gets sandboxes as tools. Give the agent a token
that can only manage its own sandboxes, then connect it in one of two ways:

```sh
ziroctl api token create agent --role deployer --scope sandboxes

# stdio: runs wherever ziroctl runs, and calls the API with the token
claude mcp add ziro-sandbox -e ZIRO_API_URL=https://sbx.example.com:8443 -e ZIRO_API_TOKEN=ziro_... -- ziroctl sandbox mcp

# Streamable HTTP: nothing to install, served by the API itself
claude mcp add --transport http ziro-sandbox https://sbx.example.com:8443/api/v1/sandboxes/mcp \
  --header "Authorization: Bearer ziro_..."
```

| Tools | What they do |
|---|---|
| `sandbox_create` | from an `image`, a `template` or a `snapshot`; `allow` domains or `network_open`; `timeout`, `idle_timeout`, `memory`, `cpus`, `env`, `metadata` |
| `sandbox_exec`, `sandbox_run_code` | a shell command, or a program in python, node, bash or sh passed on stdin: exit code, stdout, stderr |
| `sandbox_read_file`, `sandbox_write_file`, `sandbox_list_files`, `sandbox_delete_file` | `/workspace`. Content that isn't UTF-8 travels as base64 |
| `sandbox_get`, `sandbox_list`, `sandbox_pause`, `sandbox_resume`, `sandbox_renew`, `sandbox_delete` | lifecycle |
| `sandbox_snapshot_create`, `sandbox_snapshot_list`, `sandbox_snapshot_delete` | install once, fork many |
| `sandbox_expose`, `sandbox_unexpose`, `sandbox_templates` | previews, the host's templates |

A tool that takes an `id` uses your newest running or paused sandbox when you leave it out. Tools carry MCP
annotations (read-only, destructive, idempotent), and results come back as text and as `structuredContent` JSON.
Tool calls run concurrently, and a client's `notifications/cancelled` stops a running call. Both transports call
the REST API with the agent's own token, so every action is owned, limited by the token's role and scope, and
audited. Set `ZIRO_API_CA` to the API's certificate when it is self-signed.

## On a cluster

Enable the module on the nodes that should run sandboxes (`ziroctl module enable sandbox`). The cluster then works
as one sandbox platform. Clients, agents and the MCP server talk to the master's API, and users SSH to any node:

- **Placement.** A create through the master's API runs on a ready, schedulable node that has the module (not
  cordoned, not labeled `runner=false`). It picks the node with the fewest sandboxes, then the one with the most
  memory. A sandbox started from a snapshot runs on one of the nodes that hold a copy.
- **Warm pools.** Each node keeps its own pools (`pools` in its `/etc/ziro/sandbox.json`). For a create that a pool
  can serve (a template, plus at most `timeout`, `idle_timeout` and `metadata`), the master first asks the nodes
  which have a warm sandbox of that template. It sends the create to one of those, so the sandbox is resumed in
  milliseconds. When no node has one, placement works as above and the sandbox starts cold.
- **Replicated snapshots.** The cluster leader copies every snapshot (the image and its `/workspace` archive) to
  every sandbox node of the same architecture, within a minute of it being taken and on nodes that join later.
  Copies stream from node to node over the mesh, so the master holds nothing in memory. Each node checks that an
  incoming image carries exactly one name, a snapshot's, before loading it. A snapshot then outlives the node that
  took it, and `snapshot ls` on the master shows how many nodes hold it. Deleting a snapshot removes every copy, and a
  copy still in flight at that moment is removed by the next pass instead of spreading again.
- **Forwarding.** Every request about a sandbox goes to the node that runs it, with the caller's identity, so
  ownership, quotas and audit work as on one host. Lists are merged from all nodes. Each node serves its sandbox API
  only on its mesh address (port 7446, WireGuard), behind a cluster token.
- **The host CLI on a master** works on the whole cluster, through the same forwarding: `ziroctl sandbox ls` lists
  every node's sandboxes, and `get`, `exec`, `cp`, `stats`, `logs`, `pause`, `snapshot` and the rest work on any
  of them. On other nodes the CLI manages that node's own sandboxes.
- **One SSH address.** A token names its sandbox. Any node's gateway asks the owning node to check the token (which
  spends a single-use token there), then relays the session to the owner's gateway. The relay pins the owner's host
  key, which it fetches over the mesh. `ssh -p 22998 zsbx_...@<any node>` works for every sandbox in the cluster. All
  gateways present the same
  cluster host key, created by the master and handed to sandbox nodes over the cluster's pinned TLS, so one
  `known_hosts` line covers every node.
- **Previews.** Preview URLs become routes on the cluster's gateways, pointing at the owning node's preview proxy
  on its mesh address.
- **Node loss.** Sandboxes are ephemeral: if a node goes away, its sandboxes go with it and are never moved. The
  master forgets sandboxes a node no longer reports, and drops their preview routes.

## Host limits

`/etc/ziro/sandbox.json` sets the policy. Every field is optional:

```json
{
  "max_sandboxes": 32,
  "max_per_owner": 8,
  "max_memory": "24Gi",
  "defaults": {"memory": "1Gi", "cpus": 1, "pids": 512},
  "limits": {"memory": "8Gi", "cpus": 4, "pids": 4096},
  "default_timeout": "1h",
  "max_timeout": "24h",
  "allow_runc": false,
  "default_runtime": "gvisor",
  "subnet": "10.250.0.0/16",
  "ssh_port": 22998,
  "preview_port": 22997,
  "secret_proxy_port": 22996,
  "pools": {"python": 4},
  "ssh_host": "sbx.example.com",
  "image_policy": {"allow_registries": ["docker.io/library", "ghcr.io/acme"]}
}
```

`image_policy` has the same format as the cluster image policy. It can also require cosign signatures
(`require_signed`, `cosign_keys`), in which case images are pinned to the verified digest.

## How it works

`ziro-sandboxd` (the `ziroctl` binary under another name) owns the sandboxes. It answers on the root-only socket
`/run/ziro/sandboxd.sock`, and the CLI and the REST API are its clients. The daemon:

- keeps one record per sandbox in `/var/lib/ziro/sandbox/<id>/`, next to its workspace
- starts each sandbox with nerdctl, using `runsc` (pinned gVisor release) as the OCI runtime
- runs a reaper every 15 seconds that deletes expired and idle sandboxes, marks stopped ones as `failed`, and removes
  sandbox containers that have no record

Logs are in `/var/log/ziro-sandboxd.log`.

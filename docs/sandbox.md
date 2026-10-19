# Sandboxes

A sandbox is a disposable, isolated machine for code you don't trust: an AI agent's tools, a code interpreter or a CI
step. Each one is a container that runs under [gVisor](https://gvisor.dev). gVisor is a kernel in user space, so the
workload's system calls never reach the host kernel. A sandbox keeps a short list of privileges, has no network unless you ask
for one (and then only what its policy allows), and has resource limits and a lifetime. You manage sandboxes with `ziroctl sandbox`, the REST API or the Go SDK. The
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
| Kernel | gVisor (systrap: no KVM needed, works in cloud VMs and on arm64) | `runtime: runc` only for operators, and only if the host allows it |
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
ziroctl sandbox pause <id>                 # freeze its processes (memory is kept)
ziroctl sandbox resume <id>
ziroctl sandbox renew <id> --timeout 1h    # expires one hour from now
```

`exec` streams the command's output as it runs and exits with the command's exit code. A command may run for up to
1 hour, and its output is capped at 64 MiB.

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
| `PUT /api/v1/sandboxes/{id}/metadata` | replace the metadata map |
| `PUT /api/v1/sandboxes/{id}/network` | replace the network policy (`{"mode":"allowlist","allow":["pypi.org"]}`) |
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
  "subnet": "10.250.0.0/16",
  "ssh_port": 22998,
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

## Coming next

These are designed in [RFC 0004](design/rfcs/0004-sandboxes.md) and come one release at a time:

- **HTTPS port previews:** `https://<port>-<id>.<your domain>`.
- **Credential injection:** the agent sees only placeholders, and the real secret is added on the way out, only for
  its allowed host.
- **Kata microVMs:** an option on hosts with KVM.
- **For agents:** templates, warm pools, snapshots and an MCP server (`ziroctl sandbox mcp`).
- **Clusters:** sandboxes spread across a cluster's runner nodes.

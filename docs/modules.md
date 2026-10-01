# Modules and plugins

Modules (also called plugins: `ziroctl plugin` and `ziroctl module` are the same command) are opt-in feature
packs. Nothing is preinstalled, so the base image stays small. Enabling a module installs, configures and starts
everything it needs, and disabling it removes exactly what it added.

Modules come from two places:

- **Built in:** ClamAV, auditd, NFS and the security pack ship inside `ziroctl`.
- **Catalogs:** signed repositories. The official one is [ziro-os/pkgs](https://github.com/ziro-os/pkgs)
  (`s3-ziro`, `rclone-ziro`, ...). You can add third-party catalogs with their signing key.

```sh
ziroctl plugin search                     # everything available (refreshes catalogs older than a day)
ziroctl plugin info s3-ziro               # what it installs, runs (and as which user), and its settings
ziroctl plugin enable s3-ziro --set capacity=50G
ziroctl plugin enable security            # the security pack (clamav + auditd)
ziroctl plugin list                       # status; VERSION shows 1.0→1.1 when an upgrade is available
ziroctl plugin upgrade                    # upgrade every enabled plugin (or name them)
ziroctl plugin disable s3-ziro            # data directories are kept
ziroctl plugin purge s3-ziro              # also deletes its data: dirs it created, logs, secrets
ziroctl plugin update                     # refresh the catalogs now
ziroctl plugin enable clamav --background # return at once; progress in /var/log/ziro-modules.log
```

API (admin token to change; any token to read):

```
GET  /api/v1/modules                      # status of every module, with source and available upgrades
POST /api/v1/modules/{name}/enable        # 202 Accepted: runs in the background, poll GET for status
POST /api/v1/modules/{name}/upgrade
POST /api/v1/modules/{name}/disable
POST /api/v1/modules/{name}/purge         # disable and delete the module's data
```

## Catalogs and trust

A catalog is a static HTTPS site with `index.json`, its signature `index.json.sig`, and one manifest per module.

- **Signed:** the index is signed with ed25519. The official catalogs' public keys are compiled into `ziroctl`.
- **Pinned:** the index lists the sha256 of every manifest, and each manifest lists the sha256 of every artifact
  it downloads. Nothing unverified is written or run.
- **Fresh:** an index expires (30 days by default; CI re-signs weekly), which stops an attacker from freezing a
  host on old versions. A host refuses an index with a lower serial than the one it has (rollback).
- **Cached and re-verified:** catalogs are cached in `/var/lib/ziro/catalog/<repo>/` and verified again on
  every read, so editing the cache doesn't help an attacker. A failed refresh never replaces a good cache, and an
  offline host keeps working from its cache.
- **No shadowing:** a catalog can't replace a built-in module, and a third-party catalog can't replace an
  official one.
- **Installed copy:** enabling saves the manifest used (`/etc/ziro/modules/<name>.manifest`), so disable,
  upgrade and boot reconciliation keep working if a catalog later changes or drops the module.

Third-party catalogs (a module runs as root when enabled; add only publishers you trust):

```sh
ziroctl plugin repo add acme https://plugins.acme.example --key acme-catalog.pub
ziroctl plugin repo list
ziroctl plugin repo rm acme
```

## Available modules

| Module | What it does |
|---|---|
| `clamav` | ClamAV antivirus. `clamd` listens on a local socket only (`/run/clamav/clamd.sock`, `clamav:clamav 0660`), never on TCP. `freshclam` updates signatures every 2 hours. A daily scan runs at 03:30. Needs 1.5 GB RAM (`--force` to override). |
| `auditd` | Linux audit with CIS-aligned rules: identity files, sudoers, root's SSH keys, `sshd_config`, `/etc/ziro`, `ziroctl` runs, kernel module loads, time and hostname changes, mounts. Rules are reloaded at every boot. |
| `nfs` | NFSv4.2 server: v2/v3 and UDP off, 30s grace, `rpc.mountd` supervised. Enabled automatically by the first `ziroctl nfs export` or cluster share. See [storage.md](storage.md). |
| `clamav-onaccess` | Blocks opening infected files: `clamonacc` (fanotify permission events) asks `clamd` about every open under the paths in `/etc/clamav/onaccess-paths` (your edits are kept). Needs `clamav`. |
| `integrity` | Host integrity. IMA (the default kernel) measures every executable, library and module the host runs (container overlays excluded). `ziroctl security integrity` (daily, and on demand) checks each one against the OS image's baseline (`/etc/ziro/integrity.sha256`) or the signed apk database; anything else raises a critical `integrity` alert. |
| `security` | The security pack: `clamav` + `auditd` + `integrity`. |
| `s3-ziro` (pkgs) | S3-compatible object storage ([Garage](https://garagehq.deuxfleurs.fr)) for backups, snapshots and apps. Runs as `garage`, S3 API on `127.0.0.1:3900` (`--set bind=0.0.0.0` to expose it; the firewall still applies), RPC and admin API on loopback. Creates the bucket `ziro-backups` and the rclone remote `ziro_s3`. Settings: `capacity` (10G), `bind`, `port`. |
| `rclone-ziro` (pkgs) | rclone for S3, GCS, Azure Blob, B2, SFTP and more. Enables `ziroctl backup create --remote` and `backup restore remote:path`. Your remotes go in `/etc/ziro/rclone.conf` (`rclone --config /etc/ziro/rclone.conf config`). |

### Off-host backups

```sh
ziroctl plugin enable s3-ziro && ziroctl plugin enable rclone-ziro
ziroctl backup create --remote ziro_s3:ziro-backups          # local archive + upload (checksum first)
ziroctl backup restore ziro_s3:ziro-backups/ziro-backup-20260930-020000.tar.gz
ziroctl cron add --schedule "15 2 * * *" --command "/usr/bin/ziroctl backup create --remote ziro_s3:ziro-backups"
```

Plugin secrets (`/etc/ziro/modules/*.secrets`) and storage credentials (`/etc/ziro/rclone.conf`,
`/etc/ziro/rclone.d/`) are left out of backups unless you pass `--include-secrets`, so a backup stored in a
bucket never holds the keys to that bucket.

### Antivirus scans

```sh
ziroctl security scan --av                 # /root /home /tmp /var/tmp /var/lib/ziro/volumes
ziroctl security scan --av /srv/data       # specific paths
```

- **Root-only files:** files are passed to `clamd` by file descriptor (`--fdpass`), so `clamd` (running as
  `clamav`) scans them without being given root.
- **On a detection:**
  - the scan prints the finding and exits 1
  - a critical `av` alert is sent (see `ziroctl security alerting`)
  - the detection is written to the audit log

### Audit trail

```sh
ausearch -k identity        # changes to passwd/group/shadow
ausearch -k ssh-keys        # changes to /root/.ssh
aureport --summary
```

## Writing a plugin

```sh
ziroctl plugin new hello            # scaffolds hello/manifest.json (a small web server as user nobody)
ziroctl plugin validate hello/manifest.json
ziroctl plugin install -f hello/manifest.json   # enable it from the file (unsigned; development only)
```

To publish, open a pull request to [ziro-os/pkgs](https://github.com/ziro-os/pkgs) (`modules/<name>/manifest.json`),
or run your own catalog (below). Built-in modules live in `tools/ziroctl/cmd/modules/<name>.json`.

### Manifest reference

```json
{
  "name": "example",
  "version": "1.0.0",
  "description": "One line shown in `plugin list`",
  "requires": [],
  "packages": ["alpine-package"],
  "min_memory_mb": 0,
  "settings": [{"name": "port", "description": "listen port", "default": "8080", "pattern": "^[0-9]{2,5}$"}],
  "secrets": {"token": "hex:32"},
  "artifacts": [{"url": "https://example.com/tool-v1", "sha256": "<64 hex>", "path": "/var/lib/ziro/plugins/example/tool",
                 "mode": "0755", "arch": "aarch64"}],
  "dirs": [{"path": "/var/lib/example", "mode": "0750", "owner": "example:example"}],
  "files": [{"path": "/etc/example.conf", "mode": "0640", "owner": "root:example",
             "content": "port = {{setting.port}}\ntoken = {{secret.token}}\n"}],
  "cron": ["0 4 * * * /usr/bin/example --nightly"],
  "prepare": [{"exec": "/usr/bin/example-init", "args": [], "creates": "/var/lib/example/db*", "timeout": "10m"}],
  "services": [{"name": "exampled", "description": "...", "exec": "/usr/sbin/exampled", "args": "--port {{setting.port}}",
                "user": "example", "env_file": "/etc/example.env", "resources": {"memory": "512Mi", "cpus": 1},
                "pidfile": "/run/ziro-exampled.pid", "logfile": "/var/log/exampled.log"}],
  "post_start": [],
  "stop": [],
  "health": {"exec": "/usr/bin/example-ctl", "args": ["ping"], "expect": "OK", "timeout": "1m"}
}
```

| Field | Meaning |
|---|---|
| `packages` | Alpine packages from the pinned release repositories (apk verifies signatures). Only packages the module added are removed on disable, and not while another enabled module lists them. |
| `settings` | Values the operator may set with `--set name=value` and read back with `plugin info`. Each value, the default included, must fully match `pattern` (anchored `^...$`). Settings are kept across upgrades. Use them as `{{setting.name}}`. |
| `secrets` | Generated once on the host (`hex:N` or `base64:N` random bytes, `alnum:N` characters, N = 12..64), stored in `/etc/ziro/modules/<name>.secrets` (0600), kept across upgrades, removed on disable. Use them as `{{secret.name}}` in `files` only. |
| `artifacts` | Files that aren't Alpine packages (a static binary, a helper script). Downloaded over HTTPS, checked against `sha256`, placed under `/var/lib/ziro/plugins/<name>/`. `arch` (`x86_64`, `aarch64`) limits one to an architecture. |
| `files` | Config files, written atomically. A package default is kept as `<file>.ziro-orig` and restored on disable. A file you edit is never overwritten or removed. |
| `services` | Supervised daemons (`restart=always`). `user` runs it unprivileged; `env_file` (root-owned, not world-readable) passes secrets outside argv. `resources` (`memory` like `512Mi`, `cpus`, `pids`) bounds it in its own cgroup; over its memory limit only the service is killed and restarted ([operations](operations.md#memory-how-a-host-protects-itself)). |
| `min_memory_mb` | Memory the plugin needs: enabling it is refused unless the host has that much in total *and* available next to what already runs (`--force` overrides). |
| `prepare`, `post_start`, `stop`, `health` | Commands (absolute path, argument list, no shell) run before services start, after they start (and at every boot), on disable, and as the health check (`expect`: text the output must contain). |

Rules, enforced when a manifest is loaded (`plugin validate`, catalog CI, `go test`):

- Unknown fields are errors, so a typo can't silently drop a setting.
- Paths and executables must be absolute and clean. Commands run without a shell; there are no shell strings.
- `{{...}}` only substitutes values: `setting.*` and `secret.*`. An unknown placeholder is an error, and
  substituted values are never expanded again.
- Secrets never go on a command line or in a cron line (they would show in `ps`). A file that holds a secret
  must not be readable by others (for example `0600`, or `0640` with `owner: root:<daemon>`).
- A service's pidfile must be under `/run/`, and its log under `/var/log/`. Use a `ziro-` pidfile when the
  daemon writes its own. Daemons run in the foreground.
- Run daemons as their own user. Never open a network listener unless the plugin exists for that; bind to
  loopback by default and let a setting expose it.

### Enable, upgrade and disable

- **Enable** runs these steps:
  1. Enables the module's dependencies first. Dependencies enabled this way are marked auto.
  2. Checks memory, and resolves settings.
  3. Installs the missing packages, and records which ones this module added.
  4. Generates secrets (once), renders placeholders, and downloads artifacts.
  5. Creates directories and writes config files with their owners.
  6. Adds cron lines tagged `# ziro-module:<name>`.
  7. Runs the prepare steps (for example the first signature download).
  8. Registers services with `restart=always`, supervised by ziro-init.
  9. Runs the post-start steps, then the health check, and saves the manifest it used.
- **Upgrade** installs the new version over the old one with the same settings and secrets, then removes what
  the old version had and the new one dropped (services, files, artifacts, packages).
- **Disable** reverses exactly what enable recorded:
  - it stops services and removes their definitions
  - it removes the cron lines, artifacts and secrets
  - it restores or removes files, but keeps any file you edited
  - it removes the packages this module added, unless another enabled module needs them
  - it disables auto dependencies nothing else needs
  - it keeps data directories; `purge` also deletes the ones the module created (never one that existed before), its logs and its secrets
- **After a reboot or `ziroctl upgrade`:** `ziroctl service boot` reinstalls missing packages and artifacts,
  recreates `/run` directories and re-runs post-start steps (for example loading audit rules). It works from the
  installed copies and never needs the network for a module whose packages are still in place.
- **Failures:** a failed enable leaves status `failed` with the error, and raises a `module` alert. Running
  `enable` again resumes.

### Running your own catalog

A catalog is any HTTPS static host (GitHub Pages works). Lay out `modules/<name>/manifest.json`, then in CI:

```sh
openssl genpkey -algorithm ed25519 -out catalog.key        # once; keep it in your CI secrets
openssl pkey -in catalog.key -pubout -out catalog.pub      # give this to your users

ziroctl catalog build . --repo acme --kind module --out public      # validates every manifest
ZIRO_CATALOG_KEY="$(cat catalog.key)" ziroctl catalog sign public
ziroctl catalog verify public --repo acme --key catalog.pub
# publish public/ (re-sign at least every 30 days: --ttl sets the expiry)
```

[ziro-os/pkgs](https://github.com/ziro-os/pkgs) is a working example, including its CI workflow.

# Modules

Modules are opt-in feature packs. Nothing is preinstalled, so the base image stays small. Enabling a module
installs, configures and starts everything it needs, and disabling it removes exactly what it added.

```sh
ziroctl module list                  # available and enabled modules
ziroctl module info clamav           # what a module installs and configures
ziroctl module enable security       # the security pack (clamav + auditd)
ziroctl module enable clamav         # one module
ziroctl module disable clamav
ziroctl module enable clamav --background   # return at once; progress in /var/log/ziro-modules.log
```

API (admin token to change; any token to read):

```
GET  /api/v1/modules                      # status of every module
POST /api/v1/modules/{name}/enable        # 202 Accepted: runs in the background, poll GET for status
POST /api/v1/modules/{name}/disable
```

## Available modules

| Module | What it does |
|---|---|
| `clamav` | ClamAV antivirus. `clamd` listens on a local socket only (`/run/clamav/clamd.sock`, `clamav:clamav 0660`), never on TCP. `freshclam` updates signatures every 2 hours. A daily scan runs at 03:30. Needs 1.5 GB RAM (`--force` to override). |
| `auditd` | Linux audit with CIS-aligned rules: identity files, sudoers, root's SSH keys, `sshd_config`, `/etc/ziro`, `ziroctl` runs, kernel module loads, time and hostname changes, mounts. Rules are reloaded at every boot. |
| `security` | The security pack: `clamav` + `auditd`. |

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

## How modules work

- **Manifests:** each module is a JSON manifest embedded in `ziroctl` (`tools/ziroctl/cmd/modules/`). Manifests
  are versioned and reviewed with ziroctl and can't be changed on a host.
- **Packages:** they come from the Alpine repositories pinned to the base release (`/etc/apk/repositories`), and
  apk verifies their signatures.
- **Enable** runs these steps:
  1. Enables the module's dependencies first. Dependencies enabled this way are marked auto.
  2. Checks memory.
  3. Installs the missing packages, and records which ones this module added.
  4. Creates directories with their owners.
  5. Writes config files atomically. A package's default is kept as `<file>.ziro-orig`.
  6. Adds cron lines tagged `# ziro-module:<name>`.
  7. Runs the prepare steps (for example the first signature download).
  8. Registers services with `restart=always`, supervised by ziro-init.
  9. Runs the post-start steps, then the health check.
- **Disable** reverses exactly that:
  - it stops services and removes their definitions
  - it removes the cron lines
  - it restores or removes files, but keeps any file you edited
  - it removes the packages this module added, unless another enabled module needs them
  - it disables auto dependencies nothing else needs
- **After a reboot or `ziroctl upgrade`:** `ziroctl service boot` reinstalls missing packages, recreates `/run`
  directories and re-runs post-start steps (for example loading audit rules).
- **Failures:** a failed enable leaves status `failed` with the error, and raises a `module` alert. Running
  `enable` again resumes.

## Adding a module

Add `tools/ziroctl/cmd/modules/<name>.json`:

```json
{
  "name": "example",
  "version": "1.0",
  "description": "One line shown in `module list`",
  "requires": [],
  "packages": ["alpine-package"],
  "min_memory_mb": 0,
  "dirs": [{"path": "/run/example", "mode": "0750", "owner": "example:example"}],
  "files": [{"path": "/etc/example.conf", "mode": "0644", "content": "..."}],
  "cron": ["0 4 * * * /usr/bin/example --nightly"],
  "prepare": [{"exec": "/usr/bin/example-init", "args": [], "creates": "/var/lib/example/db*", "timeout": "10m"}],
  "services": [{"name": "exampled", "description": "...", "exec": "/usr/sbin/exampled", "args": "--foreground",
                "pidfile": "/run/ziro-exampled.pid", "logfile": "/var/log/exampled.log"}],
  "post_start": [],
  "stop": [],
  "health": {"exec": "/usr/bin/example-ctl", "args": ["ping"], "expect": "OK", "timeout": "1m"}
}
```

Rules, enforced by `go test` (`TestEmbeddedManifestsValid`):

- Paths and executables must be absolute and clean. Commands run without a shell.
- A service's pidfile must be under `/run/`, and its log under `/var/log/`. Use a `ziro-` pidfile when the
  daemon writes its own.
- Daemons run in the foreground.
- Never open a network listener unless the module exists for that. Prefer local sockets.

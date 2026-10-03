# Deploying from git: `ziroctl deploy`

`ziroctl deploy` builds an app from a git repository and runs it on the host, the way Vercel or Render do. It keeps
the last builds, so a rollback takes seconds. The work is done by **ziroctld**, the deploy daemon, which ships with
the `builder` plugin.

```sh
ziroctl module enable builder                       # BuildKit + git + ziroctld (needs 2 GB RAM)
ziroctl deploy https://github.com/acme/web --expose web.example.com
ziroctl deploy https://github.com/acme/api --branch release --env LOG_LEVEL=info --secret DATABASE_URL=@db.url
ziroctl deploy https://gitlab.com/acme/mono --path apps/site --git-token-file ~/.gitlab-token
ziroctl deploy ls                                   # deployments, live build, URL
ziroctl deploy status web                           # every build: status, commit, time, error
ziroctl deploy logs web -f                          # the latest build's log, streamed
ziroctl deploy redeploy web                         # build the latest commit again
ziroctl deploy rollback web                         # release the previous build again (no rebuild)
ziroctl deploy rm web --purge
```

## How a deploy works

1. **Fetch.** ziroctld shallow-clones the branch over `https://` only. `file://`, `ext::` and other transports
   are refused, and submodules are off. A private repository's token goes through `GIT_ASKPASS`; it never
   appears in the URL, the arguments or the records.
2. **Detect.** The first match decides how the app is built:

   | Found | Build |
   |---|---|
   | `Dockerfile` | used as is (its `EXPOSE` gives the port) |
   | `package.json` with `next` | Next.js, `next start` on 3000 |
   | `package.json` with `vite`/`astro` and a build script, no start script | static build from `dist/`, served by unprivileged nginx on 8080 |
   | `package.json` | Node, `npm`/`pnpm`/`yarn start` on 3000 (the lockfile picks the package manager) |
   | `go.mod` | a static binary (root package or a single `cmd/<name>`) on distroless, as `nonroot`, on 8080 |
   | `requirements.txt` / `pyproject.toml` | Python, started by the `Procfile`'s `web:` command, on 8000 |
   | `index.html` | static files on 8080 |

   Generated Dockerfiles use base images pinned by digest and run as an unprivileged user. A Compose project is
   pointed at `ziroctl compose` / `ziroctl stack import`.
3. **Build.** BuildKit builds the image with its containerd worker, so it lands straight in the host's image
   store as `ziro.local/<app>:b<N>`, recorded with its digest. Builds run one at a time, with BuildKit capped at
   3 GiB of memory and 2 CPUs.
4. **Release.** The image runs as an app with the same hardening as catalog apps:
   - no-new-privileges and no `NET_RAW`
   - resource limits
   - secrets through env files
   - a port on `127.0.0.1` (a free one from 20000, kept across builds)
   - optionally a gateway route (`--expose`)

   Before running it, the image's digest is checked against the build record. `PORT` is set to the app's port.
5. **Check.** The new build must answer on its port within 2 minutes, with any HTTP status below 500, at `/` or
   the `health` path. If it doesn't, the build is marked failed and the previous build is released again.

The last 5 builds, their logs and their images are kept for rollback.

## `ziro.yaml`

Optional, in the repository root (or `--path`). Unknown keys are errors.

```yaml
build: node          # dockerfile, node, next, static, go, python
dockerfile: deploy/Dockerfile
port: 4000
start: node dist/server.js
output: build        # static builds: the directory to serve (default dist)
health: /healthz     # checked before the build goes live
env:
  NODE_OPTIONS: --max-old-space-size=512
```

`--env` on the command line wins over `env` here.

## Secrets

`--secret KEY=@file`, `--secret KEY` (reads `$KEY`) or `KEY=value` gives the app a secret env var. Values are
stored with the app's other secrets (0600, delivered through an env file) and kept across builds; give a new value
to rotate it.

## API

`ziroctl deploy` talks to ziroctld on a root-only socket, `/run/ziro/ziroctld.sock`. The REST API exposes the same
operations under `/api/v1/deployments`:
- creating a deployment needs `admin`, because it runs code from a repository
- redeploy and rollback need `operator`
- reading needs `viewer`

See `sdk/openapi.yaml`.

## Limits

- Single host for now. Building on cluster builders and running replicas on workers comes next.
- Repositories over `https://` only (no SSH).
- A release replaces the running container, so there are a few seconds without the app. A zero-downtime swap
  comes with cluster rolling updates.

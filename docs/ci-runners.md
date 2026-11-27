# CI runners (GitHub Actions and others)

CI jobs usually need a Docker host: `docker build`, `docker/setup-buildx-action`, `docker/setup-qemu-action`, service
containers and `docker compose`. Ziro OS has no Docker daemon by default, so a job that calls `docker` fails with

```text
failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon
is running: dial unix /var/run/docker.sock: connect: no such file or directory
```

The fix is the opt-in [Docker Engine module](containers.md#docker-engine-module), which runs the official Docker
Engine on the host's containerd:

```bash
ziroctl module enable docker
docker version                                            # a Server section means the engine is up
docker run --rm --privileged tonistiigi/binfmt --install all   # the step docker/setup-qemu-action runs
```

## Run the GitHub Actions runner

The runner is a .NET program built for glibc, and Ziro OS is musl. The simplest reliable setup is to run it in
GitHub's runner image as a container that talks to the host's Docker socket ("Docker outside of Docker"):

```yaml
# /srv/runner/compose.yaml
services:
  runner:
    image: ghcr.io/actions/actions-runner:latest
    restart: always
    user: "1001:1001"
    group_add: ["998"]              # the host's docker group
    environment:
      RUNNER_URL: https://github.com/OWNER/REPO       # or the organization URL
      RUNNER_TOKEN: ${RUNNER_TOKEN}                    # registration token, never committed
    command: >
      sh -c "./config.sh --unattended --replace --url $$RUNNER_URL --token $$RUNNER_TOKEN
      --name ziro-$$(hostname) --labels ziro,docker --work /srv/runner/_work --ephemeral && ./run.sh"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      # The docker CLI and its Compose/Buildx plugins from the host (static binaries).
      - /var/lib/ziro/plugins/docker/bin/docker:/usr/local/bin/docker:ro
      - /usr/libexec/docker/cli-plugins:/usr/libexec/docker/cli-plugins:ro
      # Containers a job starts mount paths from the host, so the work directory has the same path in both.
      - /srv/runner/_work:/srv/runner/_work
```

Notes:

- **Group id.** `998` is the `docker` group Ziro OS creates; check it with `getent group docker`.
- **Work directory.** Docker resolves bind mounts on the host, not in the runner container, so the work directory
  (`--work /srv/runner/_work`) has the same absolute path on both sides. Create it first and make it writable by uid
  1001: `mkdir -p /srv/runner/_work && chown 1001:1001 /srv/runner/_work`.
- **Ephemeral runners** (`--ephemeral`) take one job and exit; `restart: always` brings a clean one back. Prefer
  them over a long-lived runner that accumulates state.
- **Cleanup.** Add `docker system prune -af --volumes` to a [cron job](containers.md#scheduled-jobs) on busy
  hosts, and keep `/var/lib/docker` on a data disk.

## Security

The Docker socket is root on the host: anything that can use it can start a privileged container with `/` mounted.
Running a runner this way means every workflow it runs, including pull requests from forks, has root on the host.
Use self-hosted runners only for private repositories or trusted code, run them on a dedicated host or VM, and prefer
ephemeral runners. Never put the registration token in a repository or an image.

## Other CI systems

Any runner that talks to `/var/run/docker.sock` (GitLab Runner's Docker executor, Jenkins agents, Woodpecker, Drone)
works the same way once the module is enabled. Add its user to the `docker` group (`addgroup USER docker`), or mount
the socket into the runner container as above.

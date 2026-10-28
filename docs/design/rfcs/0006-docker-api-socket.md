# RFC 0006: An opt-in Docker Engine API socket

- **Status:** Draft
- **Author:** @sombochea
- **Pull request:** #

## Summary

Add `ziro-dockerd`, a service that serves a small subset of the Docker Engine API on `/run/docker.sock` and
translates it to containerd through `nerdctl`. It is off by default and enabled per host with
`ziroctl docker-api enable`. Its purpose is tools that manage a Docker host over SSH and the Docker socket, Coolify
first (issue #153).

## Motivation

Coolify's "Validate Server" step logs in over SSH and runs `docker version`, `docker info`, `docker network ls` and
`docker compose version`. Its proxy (Traefik) and helper containers then talk to `/var/run/docker.sock`. Ziro OS has
the `docker` command (a `nerdctl` link) but no Docker daemon, so the socket does not exist and Coolify cannot manage
the host. Prerequisites that need no design (`git`, `jq`, `bash`, `ID_LIKE`) are already in #158.

## Design

- **Service.** `ziro-dockerd` is a mode of `ziroctl` (`ziroctl docker-api serve`), run by init from
  `rootfs/etc/ziro/services/dockerd.conf` only when enabled. It listens on `/run/docker.sock`, mode 0660, owner
  `root:root`. `/var/run` must resolve to `/run` so the usual path works.
- **Endpoints (v1).** `/_ping`, `/version`, `/info`, the containers family (list, inspect, create, start, stop,
  restart, kill, remove, logs, exec create/start/inspect, copy a tar in), networks (list, create, inspect, remove),
  volumes (list, create, remove), images (list, pull, inspect, load) and `/events`. Anything else answers `501` with a
  message naming the route, so a missing call is visible rather than silently wrong.
- **Translation.** Each call runs the matching `nerdctl` command and maps its JSON to the Docker response shape.
  This is the smallest implementation and reuses CNI networking and containerd storage as they are. Speed is the
  cost: a call costs a process start. Move hot calls (list, inspect, events) to the containerd client once
  measured.
- **Commands.** `ziroctl docker-api enable|disable|status`. Enabling writes the service file, starts the service
  and records an audit entry. API route `/api/v1/docker-api` (role: admin) and an OpenAPI entry follow the
  [design standard](../README.md).
- **`docker` command.** `docker version` and `docker info` come from `nerdctl`. If Coolify's parsing needs
  Docker-shaped output, a thin wrapper fixes the differences and is tested against Coolify's own validation
  commands. Nothing is guessed before it is tried on a host.

## Security

The Docker socket is root on the host: whoever can call it can start a privileged container with the host
filesystem mounted. This RFC does not hide that.

- Off by default, and only an administrator can enable it. `disable` removes the socket.
- The socket is never mounted into catalog apps, stacks, sandboxes or cluster replicas. The compose preflight keeps
  refusing bind mounts of the Docker socket. Containers a tool creates through the socket are that tool's
  responsibility, because the caller is already root.
- Every mutating call (create, start, exec, remove, pull) is written to the hash-chained audit log
  (`/var/log/ziro/audit.log`) with the peer's uid. Reads are counted, not logged.
- Request bodies are size-limited and decoded strictly. Names, paths and arguments are passed to `nerdctl` as
  separate arguments, never through a shell.
- Cluster nodes: the API acts on the local host only. A cluster master does not enable it by default and the
  documentation says so.

An attacker who controls the SSH key or the socket already has root; the new exposure is the translator itself, so
it gets fuzz and table tests on every route it accepts.

## Compatibility

New and optional: existing hosts do not change until an administrator enables it. `docs/apps.md` and
`docs/containers.md` currently say there is no Docker socket and that Coolify is unsupported; they are updated when
the implementation lands, with the supported subset listed.

## Alternatives

- **Run a real Docker or Podman engine.** Full compatibility, but it adds a second runtime next to containerd, a
  larger base image (the 300 MB gate) and a second set of defaults to harden.
- **Podman's API socket.** Fewer routes to write, but it brings Podman as a second engine with its own storage.
- **Bind containerd's socket to the Docker path.** Not compatible: containerd speaks gRPC, not the Docker HTTP API.
- **Do nothing.** Coolify stays unsupported, as `docs/apps.md` says today.

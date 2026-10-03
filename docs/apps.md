# Apps

`ziroctl apps` deploys ready-made apps with one command. Each deploy generates credentials, runs hardened
containers with persistent data, and tells you how to connect. The definitions come from signed catalogs: the
official one is [ziro-os/apps](https://github.com/ziro-os/apps).

```sh
ziroctl apps search                         # postgres, mysql, mysql-cluster, valkey, ...
ziroctl apps info postgres                  # versions, pinned images, settings, what it keeps
ziroctl apps deploy postgres                # default version, on 127.0.0.1:5432
ziroctl apps credentials postgres           # URL, user, password
ziroctl apps list                           # what runs, where, and how many replicas are up
ziroctl apps rm postgres                    # keeps data and credentials
ziroctl apps rm postgres --purge            # deletes them too (on a cluster: on every node)
ziroctl apps purge postgres                 # same, or clean up what an earlier `rm` left behind
```

More examples:

```sh
ziroctl apps deploy postgres:16 --name billing --publish 5433 --set database=billing
ziroctl apps deploy mysql:8.4 --bind 0.0.0.0          # reachable from the network (the firewall still applies)
ziroctl apps deploy valkey
ziroctl apps deploy grafana --expose grafana.example.com   # also publish it through the gateway (HTTPS)
ziroctl apps deploy mysql-cluster                      # on a cluster master
ziroctl apps deploy mysql-cluster --replicas 5 --allow-from api
ziroctl apps deploy openclaw --secret ANTHROPIC_API_KEY=@anthropic.key   # an input secret (see apps info)
```

Coolify isn't in the catalog. It needs the host's Docker socket, which is root on the host and outside what an app
may do. Deploying your own code from git comes with `ziroctl deploy`.

## Where apps run

- **On a standalone host** (or with `--local`):
  - The app runs as containers on this host. They get the same hardening as cluster replicas: no-new-privileges,
    no `NET_RAW`, and `restart always`.
  - The app's port is published on `127.0.0.1` by default. `--publish` picks the host port, and `--bind 0.0.0.0`
    exposes it.
  - Data lives in `/var/lib/ziro/apps/<name>/0/`.
  - Credentials are in `/etc/ziro/apps/<name>.secrets` (0600).
- **On a cluster master:**
  - Each component becomes a cluster app. The image policy, scheduling, rolling updates and rollback all apply.
  - Credentials are a cluster secret named `app-<name>`: sealed, replicated, and passed to containers only through
    env files.
  - Other apps reach it at `<name>.cluster.ziro` on the pod network. Only the app itself and the apps named with
    `--allow-from` may connect. `--publish` also opens a host port.
  - Data is node-local: `/var/lib/ziro/apps/<name>/<replica>/` on the node running that replica. A replica that
    moves to another node starts empty and has to recover through the app's replication (for example
    mysql-cluster) or from a backup.

A redeploy with the same name updates the app in place and keeps its data, credentials and settings. Catalog
versions are major lines (`postgres:17`): patch releases arrive as catalog updates, so you pick them up with
`ziroctl plugin update` followed by a redeploy. Moving an instance to another version line is refused unless you
pass `--new-version`, because data written by one major version often can't be read by another (PostgreSQL
needs a dump and restore). To change major versions, deploy a new instance with `--name` and migrate.

## Official apps

| App | What you get |
|---|---|
| `postgres` (16, 17, 18) | PostgreSQL with SCRAM authentication and data checksums, plus a database and owner (`--set database=... user=...`). |
| `mysql` (8.4 LTS) | MySQL with generated root and app passwords, plus a database and user. |
| `mysql-cluster` (8.4) | Three-member InnoDB Group Replication in single-primary mode, with automatic failover and TLS between members. Needs a cluster with the pod network (a one-node cluster works). |
| `valkey` (8, 9) | Valkey, the Redis-compatible, BSD-licensed fork. Password auth and append-only persistence; it runs as the `valkey` user. |

### mysql-cluster

The replicas find each other by stable DNS names, `<replica>.<name>.cluster.ziro` (for example
`0.mysql-cluster.cluster.ziro`).

- **First start:** replica 0 bootstraps the group once every peer answers and none of them is in a group yet. The
  other replicas join.
- **Rejoining:** a restarted member rejoins by itself. A replica that starts empty receives the data from the
  group.
- **Writes:** writes go to the primary, and any member tells you which one it is:
  `SELECT MEMBER_HOST FROM performance_schema.replication_group_members WHERE MEMBER_ROLE='PRIMARY'`.
- **Failover:** when the primary fails, the others elect a new one within seconds. Use an odd number of replicas.
- **After a full outage** where a member is gone for good, replica 0 won't bootstrap on its own. This is on
  purpose: under a network partition, it would otherwise start a second group. Bootstrap it by hand on the member
  with the most data:

  ```sql
  SET GLOBAL group_replication_bootstrap_group=ON; START GROUP_REPLICATION USER='ziro_gr', PASSWORD='<replication_password>';
  SET GLOBAL group_replication_bootstrap_group=OFF;
  ```

  The password is the `replication_password` shown by `ziroctl apps credentials <name>`.

## API

```
GET    /api/v1/apps                      # deployed apps and running replicas (any token)
DELETE /api/v1/apps/{name}[?purge=true]  # admin; remove (and purge) in the background
POST /api/v1/apps/deploy     # admin; 202 Accepted, runs in the background (log: /var/log/ziro-apps.log)
     {"app": "postgres:18", "name": "db", "set": {"database": "shop"}, "publish": 5433, "allow_from": ["api"]}
```

Credentials are never served over the API. Read them on the host with `ziroctl apps credentials`.

## Writing an app definition

Open a pull request to [ziro-os/apps](https://github.com/ziro-os/apps) that adds `apps/<name>/app.json`, or run
your own catalog (`ziroctl catalog build . --kind app`, see [modules.md](modules.md#running-your-own-catalog))
and add it with `ziroctl plugin repo add <name> <url> --key <pem> --kind app`.

To deploy several apps together (in dependency order, as one unit), describe them in a
[stack](provisioning.md#stacks). Definitions can be YAML or JSON.

Start from `ziroctl dev new app <name>`. Test a definition with `ziroctl apps deploy -f app.json` on a host
(unsigned, development only), or in a throwaway VM with `ziroctl dev run app.json` ([SDK](sdk.md#the-dev-toolchain)).

```json
{
  "schema": 1,
  "name": "postgres",
  "description": "PostgreSQL database with a generated password and persistent data",
  "default": "18",
  "versions": {"18": {"images": {"db": "docker.io/library/postgres:18.6@sha256:<digest>"}}},
  "settings": [{"name": "database", "default": "app", "pattern": "^[a-z_][a-z0-9_]{0,62}$"}],
  "secrets": {"POSTGRES_PASSWORD": "alnum:32"},
  "components": [{
    "name": "db", "port": 5432, "replicas": 1,
    "env": {"POSTGRES_DB": "{{setting.database}}", "PGDATA": "/var/lib/postgresql/data/pgdata"},
    "secrets": ["POSTGRES_PASSWORD"],
    "data": ["/var/lib/postgresql/data"],
    "health": ["pg_isready", "-q", "-h", "127.0.0.1"],
    "resources": {"memory": "1Gi", "cpus": 2}
  }],
  "outputs": {"url": "postgres://app:{{secret.POSTGRES_PASSWORD}}@{{host}}:{{port}}/{{setting.database}}"}
}
```

Rules, enforced when a definition is loaded (catalog CI and every host):

- **Images:** every image is pinned by digest (`name:tag@sha256:...`). The tag only documents the version.
- **Secrets:** secrets are generated on the host and reach containers only as env files. Env values and args can't
  reference `{{secret.*}}`, because argv and plain env are visible in `inspect`. Only `outputs` can use them.
- **Input secrets:** a value only the operator has, such as an API key, is declared as `"input"` (required) or
  `"input?"` (optional) instead of a generator spec. It is given at deploy time and kept across redeploys. It is
  stored and delivered exactly like a generated secret, never as a setting.
  - CLI: `--secret KEY=@file`; or `--secret KEY`, which reads `$KEY`. `KEY=value` also works, but leaves the
    value in your shell history.
  - API: the `secrets` field. The deploy job gets the value through its environment, not its argv.
- **Placeholders:** `{{setting.x}}`, `{{app}}` (the component's name), `{{peers}}` (every replica's DNS name,
  comma-separated), `{{replicas}}`, and in outputs `{{host}}`, `{{port}}` and `{{secret.x}}`. They substitute values
  only.
- **Containers:** each container gets `ZIRO_APP`, `ZIRO_REPLICA` (0, 1, ...) and, for `"cluster": true` apps,
  `ZIRO_PEERS`.
- **Data owner:** `data` dirs are 0700 and owned by root; an image that starts as root chowns its own. For an
  image that runs as a fixed user (OpenClaw, Ghost, n8n: uid 1000), set `"data_uid": 1000` on the component.
- **Replicas:** several replicas need `"cluster": true`. `max_replicas` allows `--replicas`.
- **Privileges:** run the process as the image's own user, not root. If the command is wrapped in a shell, drop
  privileges yourself (the `valkey` definition uses `setpriv`). Never put a password in the command line; pass it
  on stdin or in a file.
- **Resources:** `resources` (`memory`, `cpus`, `pids`) limits each container. Set them: a container without a
  memory limit is the first the kernel kills when the host runs out of memory.
- **Unknown fields** are errors.

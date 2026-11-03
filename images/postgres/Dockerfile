# The Ziro Postgres member image: the official PostgreSQL image, pinned by digest, plus pgBackRest for
# backups, WAL archiving and point-in-time recovery (docs/postgres.md, "Backups and recovery").
#
# Built by .github/workflows/pg-images.yml for each supported major version; BASE is the official image
# ziroctl pins for that version (tools/ziroctl/cmd/pg_ops.go, pgImages). The official image already has
# the PostgreSQL (PGDG) apt repository, so pgbackrest comes from the same source as Postgres itself.
#
# The base image's gosu is replaced by gosu.sh (the same interface, on util-linux's setpriv): the gosu
# binary is built with an old Go release that scanners flag for standard library CVEs. The binary is
# deleted (a scanner still reports a file that a later layer only overwrites) and the script goes to
# /usr/local/sbin, which comes first on PATH, so `gosu` finds it.
#
# BASE defaults to the newest pinned official image (Debian: this file needs apt-get and util-linux's
# setpriv), so a plain `docker build` and image scanners see the base that ships. The workflow passes
# each version's pin explicitly.
ARG BASE=docker.io/library/postgres:18.6@sha256:3a4264520e121176619f54ff867d12774bc81e95e7b84db58d63bccdb6144b81
FROM ${BASE}
COPY --chmod=0755 gosu.sh /usr/local/sbin/gosu
RUN set -eux; \
	rm -f /usr/local/bin/gosu; \
	test "$(command -v gosu)" = /usr/local/sbin/gosu; \
	apt-get update; \
	apt-get install -y --no-install-recommends pgbackrest ca-certificates; \
	rm -rf /var/lib/apt/lists/*; \
	pgbackrest version; \
	install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest /var/spool/pgbackrest; \
	test "$(gosu postgres id -u)" = "$(id -u postgres)"; \
	gosu postgres pgbackrest version
LABEL org.opencontainers.image.title="ziro-postgres" \
	org.opencontainers.image.description="PostgreSQL with pgBackRest for Ziro OS Postgres clusters" \
	org.opencontainers.image.source="https://github.com/ziro-os/ziro-os"

# The Ziro Postgres member image: the official PostgreSQL image, pinned by digest, plus pgBackRest for
# backups, WAL archiving and point-in-time recovery (docs/postgres.md, "Backups and recovery").
#
# Built by .github/workflows/pg-images.yml for each supported major version; BASE is the official image
# ziroctl pins for that version (tools/ziroctl/cmd/pg_ops.go, pgImages). The official image already has
# the PostgreSQL (PGDG) apt repository, so pgbackrest comes from the same source as Postgres itself.
#
# The base image's gosu is replaced by gosu.sh (the same interface, on util-linux's setpriv): the gosu
# binary is built with an old Go release that scanners flag for standard library CVEs.
ARG BASE=postgres
FROM ${BASE}
COPY --chmod=0755 gosu.sh /usr/local/bin/gosu
RUN set -eux; \
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

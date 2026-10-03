# Python app: dependencies from requirements.txt or pyproject.toml, started by the Procfile's
# web command (or ziro.yaml start), as an unprivileged user.
FROM docker.io/library/python:3.13-slim@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PORT={{.Port}}
COPY . .
RUN {{.Install}} && useradd --system --uid 10001 --home-dir /app app && chown -R app /app
USER app
EXPOSE {{.Port}}
CMD {{.Start}}

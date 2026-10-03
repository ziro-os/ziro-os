# Static site (optionally built with Node: Vite, Astro, ...), served by unprivileged nginx on 8080.
{{- if .Install}}
FROM docker.io/library/node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
COPY . .
RUN {{.Setup}}{{.Install}}
RUN {{.Build}}
{{- end}}

FROM docker.io/nginxinc/nginx-unprivileged:1.31.6-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af
COPY <<'CONF' /etc/nginx/conf.d/default.conf
server {
    listen 8080;
    root /usr/share/nginx/html;
    server_tokens off;
    location / { try_files $uri $uri/ /index.html; }
}
CONF
{{- if .Install}}
COPY --from=build /app/{{.Output}} /usr/share/nginx/html
{{- else}}
COPY . /usr/share/nginx/html
{{- end}}
EXPOSE 8080

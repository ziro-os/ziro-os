# zirocd for containers, mainly to run a moon (a regional router relay) on any host:
#
#   docker run -d --name moon --read-only --restart unless-stopped \
#     -p 8443:8443/tcp -p 3478:3478/udp -v zirocd-moon:/var/lib/zirocd-moon \
#     -e ZIROCD_MOON_TOKEN=zm1_... ghcr.io/ziro-os/zirocd
#
# Built by .github/workflows/tools-release.yml from the signed release binaries (the build
# context holds zirocd-linux-<arch> and rootfs/). No shell, no package manager, not root.
FROM scratch
ARG TARGETARCH
COPY zirocd-linux-${TARGETARCH} /zirocd
COPY --chown=65532:65532 rootfs/ /
USER 65532:65532
EXPOSE 8443/tcp 3478/udp
ENTRYPOINT ["/zirocd"]
CMD ["moon", "--dir", "/var/lib/zirocd-moon"]

# Multi-arch minimal container base image for Ziro-OS
# Authentic Alpine-like container base built FROM scratch.
FROM scratch

ARG TARGETARCH

# Copy minimal rootfs contents for the targeted architecture
ADD build/ziro-rootfs-${TARGETARCH}.tar.gz /

ENV PATH=/usr/local/bin:/usr/bin:/bin:/sbin:/opt/cni/bin \
    TERM=xterm \
    HOME=/root

WORKDIR /root

# Default command is standard shell
CMD ["/bin/sh"]

# Standard OCI Metadata
LABEL org.opencontainers.image.title="Ziro-OS" \
      org.opencontainers.image.description="Ultra-lightweight, secure container-native base image" \
      org.opencontainers.image.authors="Ziro-OS Contributors" \
      org.opencontainers.image.url="https://github.com/ziro-os/ziro-os" \
      org.opencontainers.image.version="1.0.19"

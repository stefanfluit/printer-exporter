# Multi-stage build: compile a static binary on Alpine, ship it alone in an
# empty (scratch) image that runs as an unprivileged user.
#
#   podman build -t printer-exporter .
#   docker build -f Containerfile -t printer-exporter .

# ---- Build stage ----------------------------------------------------------
# Official Rust image, pinned by digest so the toolchain cannot change under
# us. Alpine's Rust targets musl and links statically by default, which is
# what lets the result run in an image with no libc at all.
FROM docker.io/library/rust:1.99.1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build

# Optional cap on parallel rustc jobs, e.g. --build-arg CARGO_BUILD_JOBS=4.
ARG CARGO_BUILD_JOBS

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# The crate has no dependencies, so the build needs no network at all:
# --network=none enforces that, --frozen makes cargo refuse to try.
RUN --network=none cargo build --frozen --release

# ---- Runtime stage --------------------------------------------------------
# scratch: no shell, no package manager, no libraries. The only file in the
# image is the exporter, owned by root and not writable by the user it runs as.
FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="printer-exporter" \
      org.opencontainers.image.description="Prometheus exporter for SNMP v2c network printers" \
      org.opencontainers.image.source="https://github.com/stefanfluit/printer-exporter" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=build --chown=0:0 --chmod=0555 /src/target/release/printer_exporter /printer_exporter

# Numeric, non-root UID:GID ("nobody"). Numeric so runtimes that enforce
# runAsNonRoot can verify it without an /etc/passwd, which scratch lacks.
USER 65534:65534

# Unprivileged port, so no capabilities are needed to bind it.
EXPOSE 9109

# Probes the exporter's own HTTP listener (not the printer). Exec form: there
# is no shell in this image. Podman only records this with --format docker.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/printer_exporter", "--healthcheck"]

ENTRYPOINT ["/printer_exporter"]

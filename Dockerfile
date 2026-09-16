# Builds every plugin as a wasm module. An initContainer copies them into a
# volume Traefik mounts as a localPlugin.
#
# -buildmode=c-shared is required: without it the module is a command exporting
# _start, so Traefik runs main and the module exits mid-request.
ARG TINYGO_VERSION=0.40.0
ARG BUSYBOX_VERSION=1.37.0-musl

FROM --platform=${BUILDPLATFORM} tinygo/tinygo:${TINYGO_VERSION} AS build
# The image runs as a non-root user that cannot write outside its home.
USER root
WORKDIR /src
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=local go mod download
COPY . .
RUN set -eu; \
    mkdir -p /out; \
    for name in request-id callsign-redirect legacy-mtls-headers; do \
      mkdir -p "/out/${name}"; \
      GOTOOLCHAIN=local tinygo build -target=wasip1 -buildmode=c-shared \
        -o "/out/${name}/plugin.wasm" "./plugins/${name}"; \
      cp "plugins/${name}/.traefik.yml" "/out/${name}/"; \
    done

FROM busybox:${BUSYBOX_VERSION} AS production
LABEL org.opencontainers.image.version="0.1.0+260911" \
      org.opencontainers.image.title="golang-traefik-plugins" \
      org.opencontainers.image.source="https://github.com/pvarki/golang-traefik-plugins"
COPY --from=build /out /plugins

# Builds every plugin as a wasm module and ships them in a minimal image.
# The image is consumed by an initContainer that copies the modules into a
# volume Traefik mounts as a localPlugin.
#
# TinyGo produces far smaller modules with no Go scheduler or GC, and Traefik
# holds one instance per concurrent request, so the difference is resident
# memory rather than disk. None of these plugins makes an outbound call, which
# is the one thing TinyGo cannot do on wasip1: revocation is answered by
# Traefik's forwardAuth middleware, not from inside a guest.
#
# -buildmode=c-shared is required: without it the module is a command exporting
# _start, Traefik runs main, main returns and the module exits mid-request.
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

# Builds every plugin as a wasm module and ships them in a minimal image.
# The image is consumed by an initContainer that copies the modules into a
# volume Traefik mounts as a localPlugin.
ARG GO_VERSION=1.25
ARG BUSYBOX_VERSION=1.37.0-musl

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN set -eu; \
    mkdir -p /out; \
    for dir in plugins/*/; do \
      name="$(basename "$dir")"; \
      mkdir -p "/out/${name}"; \
      GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build \
        -buildmode=c-shared -trimpath \
        -o "/out/${name}/plugin.wasm" "./plugins/${name}"; \
      cp "${dir}.traefik.yml" "/out/${name}/"; \
    done

FROM busybox:${BUSYBOX_VERSION} AS production
LABEL org.opencontainers.image.version="0.1.0+260911" \
      org.opencontainers.image.title="golang-traefik-plugins" \
      org.opencontainers.image.source="https://github.com/pvarki/golang-traefik-plugins"
COPY --from=build /out /plugins

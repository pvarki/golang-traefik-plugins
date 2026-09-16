# Ships the plugin sources. Traefik interprets them with Yaegi, so there is
# nothing to compile; an initContainer copies each plugin into a volume Traefik
# mounts as a localPlugin.
#
# Only the files Traefik reads are shipped. Tests and fixtures stay out.
#
# The go.mod files are written here rather than kept in the repository, because
# a go.mod in a subdirectory would split it off from the root module and break
# the shared CI's `./...` hooks. Yaegi resolves imports GOPATH-style and never
# reads them; they are shipped to match the layout Traefik documents.
FROM busybox:1.37.0-musl AS production
LABEL org.opencontainers.image.version="0.1.0+260911" \
      org.opencontainers.image.title="golang-traefik-plugins" \
      org.opencontainers.image.source="https://github.com/pvarki/golang-traefik-plugins"

COPY plugins/request-id/.traefik.yml plugins/request-id/plugin.go /plugins/request-id/
COPY plugins/callsign-redirect/.traefik.yml plugins/callsign-redirect/plugin.go /plugins/callsign-redirect/
COPY plugins/legacy-mtls-headers/.traefik.yml plugins/legacy-mtls-headers/plugin.go /plugins/legacy-mtls-headers/

RUN set -eu; \
    for entry in \
      "request-id:github.com/pvarki/golang-traefik-plugins/plugins/request-id" \
      "callsign-redirect:github.com/pvarki/golang-traefik-plugins/plugins/callsign-redirect" \
      "legacy-mtls-headers:github.com/pvarki/golang-traefik-plugins/plugins/legacy-mtls-headers"; do \
        dir="${entry%%:*}"; module="${entry#*:}"; \
        printf 'module %s\n\ngo 1.20\n' "$module" > "/plugins/${dir}/go.mod"; \
    done; \
    find /plugins -type f | sort

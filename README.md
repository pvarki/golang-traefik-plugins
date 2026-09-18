# golang-traefik-plugins

Traefik middleware plugins for the OpenDefence platform, interpreted by Yaegi.

## Plugins

| Plugin                | Purpose                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `callsign-redirect`   | Acts on the `Callsign-Valid` verdict: redirects to the error page, or denies with 403. The only place redirect policy lives. |
| `legacy-mtls-headers` | Re-publishes the verified client certificate as the `X-ClientCert-*` headers older product backends expect.                  |
| `request-id`          | Stamps every request with a fresh random `X-Request-ID`.                                                                     |

The `Callsign`, `Callsign-Valid` and `Callsign-Valid-Reason` headers that
`callsign-redirect` consumes come from the `callsign-validity` `forwardAuth`
middleware, not from a plugin here.

## Layout

Each plugin is a package whose `package` clause is the name Traefik derives from
the last element of its module path, with `-` replaced by `_` — `request_id` for
`github.com/pvarki/golang-traefik-plugins/plugins/request-id`, and so on. Traefik
evaluates `<basePkg>.CreateConfig` and `<basePkg>.New`, so the clause and the
module path have to agree.

The repository is a single Go module so `go test ./...` and the shared CI hooks
work at the root. The per-plugin `go.mod` files that Traefik's documented layout
expects are written by the Dockerfile instead of living here, because a `go.mod`
in a subdirectory would split it off from the root module. Yaegi resolves imports
GOPATH-style and never reads them.

Plugins must be **self-contained**: no imports outside the standard library and
no shared helper packages. Yaegi resolves from the plugin directory down, and
nothing above it is shipped.

## Test parity

`go test ./...` covers two things:

- each plugin's own unit tests, including a real TLS handshake for
  `legacy-mtls-headers`;
- `tools/yaegiverify`, which runs every case in `plugins/<name>/testdata/cases.json`
  against **both** the compiled package and `yaegi v0.16.1`, the interpreter
  Traefik v3.6.5 embeds.

The second is the important one. It stages each plugin under a temporary GOPATH,
evaluates it exactly as `pkg/plugins/middlewareyaegi.go` does, and drives real
requests through the resulting handler. Adding a case to `cases.json` covers both
engines, so the two cannot drift.

Certificate-dependent cases use the fixed `testdata/leaf.pem` so the expected DN,
serial and fingerprint can be written literally.

## Client certificates

`legacy-mtls-headers` reads `req.TLS.VerifiedChains` directly and rejects a peer
certificate that was not verified. It does not trust any header.

`callsign-validity` is a `forwardAuth` middleware rather than a plugin, so the
certificate reaches rasenmaeher-api as `X-Forwarded-Tls-Client-Cert`, set by
`passTLSClientCert`. **That header is authentication input**, trustworthy only
because `strip-identity-headers` blanks it on the entrypoint, which runs before
router middlewares. Both halves must stay in place.

## Deployment

The image carries `/plugins/<name>/{plugin.go,go.mod,.traefik.yml}`. An
initContainer copies each plugin into a volume Traefik mounts as a `localPlugin`.
Traefik interprets the source at startup, so a change needs a pod restart. Zarf
discovers the image from the rendered manifests.

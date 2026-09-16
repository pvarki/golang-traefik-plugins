# golang-traefik-plugins

Traefik middleware plugins for the OpenDefence platform, compiled to WebAssembly
with TinyGo.

## Plugins

| Plugin                | Purpose                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `callsign-redirect`   | Acts on the `Callsign-Valid` verdict: redirects to the error page, or denies with 403. The only place redirect policy lives. |
| `legacy-mtls-headers` | Re-publishes the client certificate as the `X-ClientCert-*` headers older product backends expect.                           |
| `request-id`          | Stamps every request with a fresh random `X-Request-ID`.                                                                     |

The `Callsign`, `Callsign-Valid` and `Callsign-Valid-Reason` headers that
`callsign-redirect` consumes come from the `callsign-validity` `forwardAuth`
middleware, not from a plugin here.

## Constraints

Traefik holds one guest instance per concurrent request, so module size is
resident memory rather than disk. TinyGo emits no Go scheduler, GC or netpoller
and keeps the modules small.

A TinyGo guest cannot open a socket: WASI preview 1 has no outbound networking
and TinyGo's `net` package has no driver for the WasmEdge socket extension.
Plugins here must not make outbound calls.

`-buildmode=c-shared` is required. Without it the module is a command exporting
`_start`, so Traefik runs `main` and the module exits mid-request. `task verify`
is the gate for this.

## Client certificates

The http-wasm ABI exposes no TLS state, so plugins that need the client
certificate read it from `X-Forwarded-Tls-Client-Cert`, set by Traefik's
`passTLSClientCert` middleware.

**That header is authentication input.** It is only trustworthy because
`strip-identity-headers` blanks it on the entrypoint, which runs before router
middlewares, and `mtls-pass-client-cert` then sets it from the verified
connection inside `mtls-chain`. Both halves must stay in place.

## Building

```sh
task test      # native go test
task build     # dist/<plugin>/plugin.wasm
task verify    # build, then check each module loads in wazero
task image     # local container image
```

`task build` runs TinyGo in a container, so no local TinyGo install is needed.

## Deployment

The image carries `/plugins/<name>/{plugin.wasm,.traefik.yml}`. An initContainer
copies each plugin into a volume that Traefik mounts as a `localPlugin`. Zarf
discovers the image from the rendered manifests, so offline packaging needs no
extra configuration.

## Testing

`go test ./...` covers the plugin logic natively, against the same source the
wasm build compiles. `internal/testpki` mints the certificates the tests need.

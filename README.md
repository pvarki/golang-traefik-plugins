# golang-traefik-plugins

Traefik middleware plugins for the OpenDefence platform, compiled to WebAssembly.

## Why wasm

These plugins previously ran as interpreted Go source under Yaegi, shipped in a
ConfigMap. Two problems ended that:

- Yaegi evaluated a `bool(x)` conversion in condition position as always-true,
  so a **revoked certificate was admitted**. Compiled tests could not see it,
  because production ran the interpreter and the tests ran the compiler.
- Yaegi needs every dependency shipped as source, which the 1 MiB ConfigMap
  limit ruled out, so anything non-trivial had to be hand-written.

Compiling to `wasip1` fixes both: `go test` exercises the same source that
produces the artifact, and dependencies resolve normally from `go.mod`.

## Why TinyGo

Traefik instantiates one guest per concurrent request and does not free them
(traefik#11119), so module size is resident memory, not disk. TinyGo emits no
Go scheduler, GC or netpoller and cuts each module by 4-5x.

The cost is that TinyGo cannot open a socket on `wasip1`: WASI preview 1 has no
outbound networking, and TinyGo's `net` package has no driver for the WasmEdge
socket extension that Traefik exposes. None of these plugins makes an outbound
call, so it does not bite. Revocation, which does need one, is answered by
Traefik's built-in `forwardAuth` middleware calling rasenmaeher-api directly —
see the `callsign-validity` Middleware in the platform repo.

## Plugins

| Plugin                | Purpose                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `callsign-redirect`   | Acts on the `Callsign-Valid` verdict: redirects to the error page, or denies with 403. The only place redirect policy lives. |
| `legacy-mtls-headers` | Re-publishes the client certificate as the `X-ClientCert-*` headers older product backends expect.                           |
| `request-id`          | Stamps every request with a fresh random `X-Request-ID`.                                                                     |

The `Callsign`, `Callsign-Valid` and `Callsign-Valid-Reason` headers that
`callsign-redirect` consumes are set by `forwardAuth`, not by a plugin here.

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
`task verify` is the gate that catches a missing `-buildmode=c-shared`, which
produces a module Traefik loads and then exits mid-request.

## Deployment

The image carries `/plugins/<name>/{plugin.wasm,.traefik.yml}`. An initContainer
copies each plugin into a volume that Traefik mounts as a `localPlugin`. Zarf
discovers the image from the rendered manifests, so offline packaging needs no
extra configuration.

## Testing

`go test ./...` covers the plugin logic natively, against the same source the
wasm build compiles. `internal/testpki` mints the certificates the tests need.

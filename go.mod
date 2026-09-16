module github.com/pvarki/golang-traefik-plugins

go 1.25.0

require (
	github.com/http-wasm/http-wasm-guest-tinygo v0.4.0
	github.com/tetratelabs/wazero v1.12.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/http-wasm/http-wasm-guest-tinygo => github.com/traefik/http-wasm-guest-tinygo v0.0.0-20240913140402-af96219ffea5

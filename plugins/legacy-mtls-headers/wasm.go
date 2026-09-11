//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/pvarki/golang-traefik-plugins/internal/version"
)

var hdrs headers

func init() {
	var cfg Config
	if raw := handler.Host.GetConfig(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			handler.Host.Log(api.LogLevelError, fmt.Sprintf("legacy-mtls-headers: bad config: %v", err))
			os.Exit(1)
		}
	}
	hdrs = cfg.headers()
	handler.HandleRequestFn = handleRequest
	handler.Host.Log(api.LogLevelInfo, "legacy-mtls-headers: loaded version "+version.Version)
}

func handleRequest(req api.Request, _ api.Response) (bool, uint32) {
	raw, _ := req.Headers().Get(hdrs.cert)

	values, ok := valuesFor(raw)
	if !ok {
		// No usable certificate: clear the headers so a client cannot assert
		// an identity by supplying them itself.
		req.Headers().Remove(hdrs.dn)
		req.Headers().Remove(hdrs.serial)
		req.Headers().Remove(hdrs.fingerprint)
		return true, 0
	}
	req.Headers().Set(hdrs.dn, values.dn)
	req.Headers().Set(hdrs.serial, values.serial)
	req.Headers().Set(hdrs.fingerprint, values.fingerprint)
	return true, 0
}

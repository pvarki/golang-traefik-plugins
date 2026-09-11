//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

const (
	forbidden = 403
	// forwardedProtoHeader replaces req.TLS, which a wasm guest cannot see.
	forwardedProtoHeader = "X-Forwarded-Proto"
)

var set settings

func init() {
	var cfg Config
	if raw := handler.Host.GetConfig(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			handler.Host.Log(api.LogLevelError, fmt.Sprintf("callsign-redirect: bad config: %v", err))
			os.Exit(1)
		}
	}
	set = cfg.settings()
	handler.HandleRequestFn = handleRequest
}

func handleRequest(req api.Request, resp api.Response) (bool, uint32) {
	valid, _ := req.Headers().Get(set.validityHeader)
	reason, _ := req.Headers().Get(reasonHeader)
	proto, _ := req.Headers().Get(forwardedProtoHeader)
	host, _ := req.Headers().Get("Host")

	decision := decide(set, valid, reason, host, proto)
	if decision.Forward {
		return true, 0
	}
	if decision.Location == "" {
		handler.Host.Log(api.LogLevelInfo, "callsign-redirect: invalid verdict and no redirect target; denying with 403")
		resp.SetStatusCode(forbidden)
		return false, 0
	}
	resp.SetStatusCode(set.redirectStatus)
	resp.Headers().Set("Location", decision.Location)
	return false, 0
}

//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

var headerName string

func init() {
	var cfg Config
	if raw := handler.Host.GetConfig(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			handler.Host.Log(api.LogLevelError, fmt.Sprintf("request-id: bad config: %v", err))
			os.Exit(1)
		}
	}
	headerName = cfg.headerName()
	handler.HandleRequestFn = handleRequest
}

func handleRequest(req api.Request, _ api.Response) (bool, uint32) {
	requestID, err := newRequestID()
	if err != nil {
		// Never forward a client-supplied id.
		req.Headers().Remove(headerName)
		handler.Host.Log(api.LogLevelWarn, fmt.Sprintf("request-id: could not generate an id: %v", err))
		return true, 0
	}
	req.Headers().Set(headerName, requestID)
	return true, 0
}

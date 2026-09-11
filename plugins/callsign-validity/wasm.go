//go:build wasip1

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/pvarki/golang-traefik-plugins/internal/ocspcheck"
	"github.com/pvarki/golang-traefik-plugins/internal/version"
	_ "github.com/stealthrocket/net/http"
	"github.com/stealthrocket/net/wasip1"
)

var (
	set     settings
	store   *issuerStore
	checker *ocspcheck.Checker
)

func init() {
	var cfg Config
	if err := json.Unmarshal(handler.Host.GetConfig(), &cfg); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("callsign-validity: bad config: %v", err))
		os.Exit(1)
	}
	if err := cfg.validate(); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("callsign-validity: %v", err))
		os.Exit(1)
	}
	set = cfg.settings()
	store = newIssuerStore(set.caBundlePath)

	// The guest has no native UDP dial, so the resolver always needs stealthrocket.
	// The address comes from the mounted /etc/resolv.conf unless dnsServer overrides it.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if set.dnsServer != "" {
				address = set.dnsServer
			}
			return (&wasip1.Dialer{Timeout: set.timeout}).DialContext(ctx, network, address)
		},
	}
	checker = &ocspcheck.Checker{URL: set.ocspURL, Client: &http.Client{Timeout: set.timeout}}

	if _, err := store.load(); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("callsign-validity: cannot read CA bundle: %v", err))
		os.Exit(1)
	}
	handler.HandleRequestFn = handleRequest
	handler.Host.Log(api.LogLevelInfo, "callsign-validity: loaded version "+version.Version)
}

func handleRequest(req api.Request, _ api.Response) (bool, uint32) {
	// Reset first so a client cannot spoof the verdict.
	req.Headers().Remove(set.callsignHeader)
	req.Headers().Set(set.validityHeader, Verdict{}.HeaderValue())
	req.Headers().Set(reasonHeader, reasonNoCert)

	raw, _ := req.Headers().Get(set.certHeader)
	verdict := Evaluate(checker, store, raw)

	if verdict.Callsign != "" {
		req.Headers().Set(set.callsignHeader, verdict.Callsign)
	}
	req.Headers().Set(set.validityHeader, verdict.HeaderValue())
	req.Headers().Set(reasonHeader, verdict.Reason)

	if !verdict.Valid && verdict.Reason != reasonNoCert {
		handler.Host.Log(api.LogLevelInfo,
			fmt.Sprintf("callsign-validity: callsign=%q verdict=false reason=%s", verdict.Callsign, verdict.Reason))
	}
	return true, 0
}

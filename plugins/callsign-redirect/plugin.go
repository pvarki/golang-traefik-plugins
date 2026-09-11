// Package main is the callsign-redirect Traefik middleware, compiled to Wasm.
//
// It is the single place that decides what to do with the validity verdict
// produced upstream by callsign-validity, so all redirect and deny policy
// lives in one file.
//
// "true" in the validity header forwards unchanged. Otherwise the reason
// header picks an /error code and, in order of precedence:
//  1. the configured redirectURL, if set, is used verbatim; otherwise
//  2. the base domain (the host with a leading "mtls." stripped) at /error
//     with the reason code, e.g. mtls.example.org/foo -> example.org/error?code=...
//
// If neither yields a target the request is denied with 403 rather than
// silently forwarded, so an invalid verdict never reaches a protected backend.
package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/pvarki/golang-traefik-plugins/internal/guest"
)

const (
	defaultValidityHeader = "Callsign-Valid"
	defaultRedirectStatus = 302
	validityTrue          = "true"

	reasonHeader = "Callsign-Valid-Reason"
	errorPath    = "/error"

	// Reason values set by callsign-validity, mapped to UI /error codes.
	reasonInvalid    = "invalid"
	reasonError      = "error"
	codeUnauthorized = "unauthorized"
	codeMTLSFail     = "mtls_fail"
)

// Config is the middleware configuration from the Traefik Middleware CR.
type Config struct {
	ValidityHeader string `json:"validityHeader,omitempty"`
	RedirectURL    string `json:"redirectURL,omitempty"`
	RedirectStatus int    `json:"redirectStatus,omitempty"`
	BaseDomain     string `json:"baseDomain,omitempty"`
}

type settings struct {
	validityHeader string
	redirectURL    string
	redirectStatus uint32
	baseDomain     string
}

func (c Config) settings() settings {
	status := c.RedirectStatus
	if status <= 0 {
		status = defaultRedirectStatus
	}
	return settings{
		validityHeader: guest.OrDefault(c.ValidityHeader, defaultValidityHeader),
		redirectURL:    strings.TrimSpace(c.RedirectURL),
		redirectStatus: uint32(status), //nolint:gosec // bounded by the check above
		baseDomain:     strings.TrimSpace(c.BaseDomain),
	}
}

type action struct {
	Forward  bool
	Location string // redirect target; empty means deny with 403
}

// decide maps the upstream verdict onto an action.
func decide(set settings, valid, reason, host, proto string) action {
	if strings.EqualFold(strings.TrimSpace(valid), validityTrue) {
		return action{Forward: true}
	}

	code := codeMTLSFail
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case reasonInvalid:
		code = codeUnauthorized
	case reasonError:
		code = "" // generic error page
	}

	dest := set.redirectURL
	if dest == "" {
		path := errorPath
		if code != "" {
			path += "?code=" + code
		}
		if computed, ok := redirectURLWithoutMTLSSubdomain(host, proto, path, set.baseDomain); ok {
			dest = computed
		}
	}
	return action{Location: dest}
}

// redirectURLWithoutMTLSSubdomain rewrites mtls.<domain> to <domain> at path.
// The scheme comes from X-Forwarded-Proto, since the ABI hides req.TLS.
func redirectURLWithoutMTLSSubdomain(host, proto, path, baseDomain string) (string, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}

	hostWithoutPort, port := host, ""
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		hostWithoutPort, port = parsedHost, parsedPort
	}

	if !strings.HasPrefix(strings.ToLower(hostWithoutPort), "mtls.") {
		return "", false
	}
	targetHost := hostWithoutPort[len("mtls."):]
	if targetHost == "" {
		return "", false
	}
	if baseDomain != "" && !strings.EqualFold(targetHost, baseDomain) {
		return "", false
	}
	if port != "" {
		targetHost = net.JoinHostPort(targetHost, port)
	}

	scheme := "https"
	if strings.EqualFold(strings.TrimSpace(proto), "http") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, targetHost, path), true
}

func main() {}

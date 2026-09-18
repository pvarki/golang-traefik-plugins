// Package callsign_redirect is the single place that decides what to
// do with the callsign validity verdict produced upstream by the
// callsign-validity middleware.
//
// It reads the validity header (default "Callsign-Valid"); "true" forwards
// unchanged. Otherwise it reads the reason header ("Callsign-Valid-Reason") to
// pick an /error code (invalid -> unauthorized, no_cert -> mtls_fail, error ->
// none) and acts in this order of precedence:
//  1. the configured redirectURL, if set → redirect there verbatim; otherwise
//  2. the base domain (the host with a leading "mtls." stripped) at /error with
//     the reason code, e.g. mtls.example.org/foo → example.org/error?code=…
//
// If neither yields a target (no redirectURL and the host has no "mtls."
// prefix or does not match baseDomain), the request is denied with 403 rather
// than silently forwarded, so an invalid verdict never reaches a protected
// backend.
package callsign_redirect

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
)

const (
	defaultValidityHeader = "Callsign-Valid"
	defaultRedirectStatus = http.StatusFound
	validityTrue          = "true"

	reasonHeader = "Callsign-Valid-Reason"
	errorPath    = "/error"

	// Reason values (set by callsign-validity) mapped to UI /error codes.
	reasonInvalid    = "invalid"
	reasonError      = "error"
	codeUnauthorized = "unauthorized"
	codeMTLSFail     = "mtls_fail"
)

type Config struct {
	ValidityHeader string `json:"validityHeader,omitempty"`
	RedirectURL    string `json:"redirectURL,omitempty"`
	RedirectStatus int    `json:"redirectStatus,omitempty"`
	BaseDomain     string `json:"baseDomain,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		ValidityHeader: defaultValidityHeader,
		RedirectStatus: defaultRedirectStatus,
	}
}

type Plugin struct {
	next           http.Handler
	logPrefix      string
	validityHeader string
	redirectURL    string
	redirectStatus int
	baseDomain     string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logPrefix := pluginLogPrefix(name)
	if next == nil {
		return nil, errors.New("next handler is nil")
	}
	if config == nil {
		config = CreateConfig()
	}

	validityHdr := strings.TrimSpace(config.ValidityHeader)
	if validityHdr == "" {
		validityHdr = defaultValidityHeader
	}
	status := config.RedirectStatus
	if status == 0 {
		status = defaultRedirectStatus
	}

	p := &Plugin{
		next:           next,
		logPrefix:      logPrefix,
		validityHeader: validityHdr,
		redirectURL:    strings.TrimSpace(config.RedirectURL),
		redirectStatus: status,
		baseDomain:     strings.ToLower(strings.TrimSpace(config.BaseDomain)),
	}

	log.Printf("INFO %s initialized; validityHeader=%s redirectURL=%q baseDomain=%q status=%d",
		logPrefix, p.validityHeader, p.redirectURL, p.baseDomain, p.redirectStatus)
	return p, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("ERROR %s panic: %v\n%s", p.logPrefix, recovered, string(debug.Stack()))
			if rw != nil {
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()

	if strings.EqualFold(strings.TrimSpace(req.Header.Get(p.validityHeader)), validityTrue) {
		p.next.ServeHTTP(rw, req)
		return
	}

	// Map the failure reason to a UI /error code.
	code := codeMTLSFail
	switch strings.ToLower(strings.TrimSpace(req.Header.Get(reasonHeader))) {
	case reasonInvalid:
		code = codeUnauthorized
	case reasonError:
		code = "" // generic error page
	}

	dest := p.redirectURL
	if dest == "" {
		path := errorPath
		if code != "" {
			path += "?code=" + code
		}
		if computed, ok := redirectURLWithoutMTLSSubdomain(req, path, p.baseDomain); ok {
			dest = computed
		}
	}
	if dest == "" {
		log.Printf("INFO %s invalid verdict and no redirect target for %s %s; denying with empty 403", p.logPrefix, req.Method, req.URL.Path)
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	log.Printf("INFO %s invalid verdict; redirecting %s %s -> %s", p.logPrefix, req.Method, req.URL.Path, dest)
	http.Redirect(rw, req, dest, p.redirectStatus)
}

func redirectURLWithoutMTLSSubdomain(req *http.Request, path, baseDomain string) (string, bool) {
	if req == nil {
		return "", false
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return "", false
	}

	hostWithoutPort := host
	port := ""
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		hostWithoutPort = parsedHost
		port = parsedPort
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
	if req.TLS == nil {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s%s", scheme, targetHost, path), true
}

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("callsign-redirect[%s]", name)
}

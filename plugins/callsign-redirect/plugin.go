// Package traefik_callsign_redirect is the single place that decides what to
// do with the callsign validity verdict produced upstream by the
// callsign-validity middleware.
//
// It reads the validity header (default "Callsign-Valid"):
//   - "true"  → forward to the next handler unchanged.
//   - anything else (invalid/revoked/unknown/no-cert/service-error) → redirect.
//
// The redirect target is, in order of precedence:
//  1. the configured redirectURL, if set; otherwise
//  2. the same request path on the base domain (the host with a leading
//     "mtls." stripped), e.g. mtls.example.org/foo → example.org/foo.
//
// If neither yields a target (no redirectURL and the host has no "mtls."
// prefix), the request is denied with 403 rather than silently forwarded, so
// an invalid verdict never reaches a protected backend.
package traefik_callsign_redirect

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
)

type Config struct {
	ValidityHeader string `json:"validityHeader,omitempty"`
	RedirectURL    string `json:"redirectURL,omitempty"`
	RedirectStatus int    `json:"redirectStatus,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		ValidityHeader: defaultValidityHeader,
		RedirectStatus: defaultRedirectStatus,
	}
}

type Plugin struct {
	next           http.Handler
	name           string
	logPrefix      string
	validityHeader string
	redirectURL    string
	redirectStatus int
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
		name:           name,
		logPrefix:      logPrefix,
		validityHeader: validityHdr,
		redirectURL:    strings.TrimSpace(config.RedirectURL),
		redirectStatus: status,
	}

	log.Printf("INFO %s initialized; validityHeader=%s redirectURL=%q status=%d",
		logPrefix, p.validityHeader, p.redirectURL, p.redirectStatus)
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

	dest := p.redirectURL
	if dest == "" {
		if computed, ok := redirectURLWithoutMTLSSubdomain(req); ok {
			dest = computed
		}
	}
	if dest == "" {
		log.Printf("INFO %s invalid verdict and no redirect target for %s %s; denying", p.logPrefix, req.Method, req.URL.Path)
		http.Error(rw, "forbidden: callsign not valid", http.StatusForbidden)
		return
	}

	log.Printf("INFO %s invalid verdict; redirecting %s %s -> %s", p.logPrefix, req.Method, req.URL.Path, dest)
	http.Redirect(rw, req, dest, p.redirectStatus)
}

func redirectURLWithoutMTLSSubdomain(req *http.Request) (string, bool) {
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
	if port != "" {
		targetHost = net.JoinHostPort(targetHost, port)
	}

	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}

	requestURI := "/"
	if req.URL != nil {
		requestURI = req.URL.RequestURI()
		if requestURI == "" {
			requestURI = "/"
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, targetHost, requestURI), true
}

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("callsign-redirect[%s]", name)
}

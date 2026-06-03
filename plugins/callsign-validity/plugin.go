// Package traefik_callsign_validity provides a Traefik middleware that
// annotates incoming mTLS requests with the result of a callsign validity
// check: it sends the client cert's CommonName (the "callsign") to a
// rasenmaeher-api HTTP endpoint and records the verdict in request headers.
//
// This middleware never blocks or redirects on its own — it ALWAYS forwards.
// It sets:
//   - the callsign header (default "Callsign") to the cert CN when a verified
//     client certificate is present, and
//   - the validity header (default "Callsign-Valid") to "true" only when the
//     callsign is confirmed valid, otherwise "false" (no/unverified cert,
//     empty CN, revoked/unknown callsign, or validity-service error).
//
// A downstream middleware (callsign-redirect) decides what to do with an
// invalid verdict, so all redirect/deny policy lives in a single place.
//
// Implementation note: this plugin uses stdlib net/http rather than a
// websocket library because Yaegi (Traefik's plugin interpreter) does not
// ship symbols for golang.org/x/net/websocket. The semantics are identical
// for the per-request check protocol we use.
package traefik_callsign_validity

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

const (
	defaultRequestTimeoutSeconds = 3
	defaultCallsignHeader        = "Callsign"
	defaultValidityHeader        = "Callsign-Valid"
	secretHeader                 = "Validity-Secret"

	validityTrue  = "true"
	validityFalse = "false"
)

// Config is the user-facing plugin configuration.
type Config struct {
	RmapiURL              string `json:"rmapiURL,omitempty"`
	SharedSecretEnv       string `json:"sharedSecretEnv,omitempty"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds,omitempty"`
	CallsignHeader        string `json:"callsignHeader,omitempty"`
	ValidityHeader        string `json:"validityHeader,omitempty"`
}

// CreateConfig returns a Config populated with safe defaults.
func CreateConfig() *Config {
	return &Config{
		RequestTimeoutSeconds: defaultRequestTimeoutSeconds,
		CallsignHeader:        defaultCallsignHeader,
		ValidityHeader:        defaultValidityHeader,
	}
}

type checkRequest struct {
	Callsign string `json:"callsign"`
}

type checkResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// Plugin is the Traefik middleware handler.
type Plugin struct {
	next           http.Handler
	name           string
	logPrefix      string
	url            string
	secret         string
	requestTimeout time.Duration
	callsignHeader string
	validityHeader string
	client         *http.Client
}

// New constructs the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logPrefix := pluginLogPrefix(name)
	if next == nil {
		return nil, errors.New("next handler is nil")
	}
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if strings.TrimSpace(config.RmapiURL) == "" {
		return nil, errors.New("rmapiURL is required")
	}

	requestTO := secondsOr(config.RequestTimeoutSeconds, defaultRequestTimeoutSeconds)
	callsignHdr := orDefault(config.CallsignHeader, defaultCallsignHeader)
	validityHdr := orDefault(config.ValidityHeader, defaultValidityHeader)

	secret := ""
	if envName := strings.TrimSpace(config.SharedSecretEnv); envName != "" {
		secret = os.Getenv(envName)
		if secret == "" {
			log.Printf("WARN %s shared-secret env %q is empty; calling without auth header", logPrefix, envName)
		}
	}

	p := &Plugin{
		next:           next,
		name:           name,
		logPrefix:      logPrefix,
		url:            config.RmapiURL,
		secret:         secret,
		requestTimeout: requestTO,
		callsignHeader: callsignHdr,
		validityHeader: validityHdr,
		client:         &http.Client{Timeout: requestTO},
	}

	log.Printf("INFO %s initialized; rmapi=%s timeout=%s callsignHeader=%s validityHeader=%s",
		logPrefix, p.url, p.requestTimeout, p.callsignHeader, p.validityHeader)
	return p, nil
}

// ServeHTTP records the validity verdict in request headers and always
// forwards. It never returns an error response (a panic is the only
// exception). Downstream middleware acts on the verdict.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("ERROR %s panic: %v\n%s", p.logPrefix, recovered, string(debug.Stack()))
			if rw != nil {
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()

	// Authoritatively reset both headers so a client cannot spoof them.
	req.Header.Del(p.callsignHeader)
	req.Header.Set(p.validityHeader, validityFalse)

	cert, reason := verifiedClientLeaf(req)
	if cert == nil {
		log.Printf("INFO %s no verified client certificate (%s) for %s %s; verdict=false", p.logPrefix, reason, req.Method, req.URL.Path)
		p.next.ServeHTTP(rw, req)
		return
	}
	callsign := strings.TrimSpace(cert.Subject.CommonName)
	if callsign == "" {
		log.Printf("INFO %s cert has empty CN for %s %s; verdict=false", p.logPrefix, req.Method, req.URL.Path)
		p.next.ServeHTTP(rw, req)
		return
	}

	// Expose the authenticated callsign regardless of validity.
	req.Header.Set(p.callsignHeader, callsign)

	valid, err := p.check(callsign)
	if err != nil {
		log.Printf("ERROR %s validity check failed for callsign=%q: %v; verdict=false", p.logPrefix, callsign, err)
		p.next.ServeHTTP(rw, req)
		return
	}
	if valid {
		req.Header.Set(p.validityHeader, validityTrue)
	} else {
		log.Printf("INFO %s callsign=%q is not valid; verdict=false", p.logPrefix, callsign)
	}

	p.next.ServeHTTP(rw, req)
}

func (p *Plugin) check(callsign string) (bool, error) {
	body, err := json.Marshal(checkRequest{Callsign: callsign})
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.secret != "" {
		req.Header.Set(secretHeader, p.secret)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("http call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var out checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != "" {
		return false, fmt.Errorf("server error: %s", out.Error)
	}
	return out.Valid, nil
}

func verifiedClientLeaf(req *http.Request) (*x509.Certificate, string) {
	if req == nil || req.TLS == nil {
		return nil, "request has no TLS state"
	}
	if len(req.TLS.VerifiedChains) == 0 {
		if len(req.TLS.PeerCertificates) > 0 {
			return nil, "peer certificate present but not verified"
		}
		return nil, "no peer certificate"
	}
	for _, chain := range req.TLS.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil {
			return chain[0], ""
		}
	}
	return nil, "verified chains present but leaf certificate missing"
}

func secondsOr(value int, fallback int) time.Duration {
	if value <= 0 {
		return time.Duration(fallback) * time.Second
	}
	return time.Duration(value) * time.Second
}

func orDefault(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("callsign-validity[%s]", name)
}

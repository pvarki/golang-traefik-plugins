// Package traefik_callsign_validity provides a Traefik middleware that
// authorizes incoming mTLS requests by sending the client cert's CommonName
// (the "callsign") to a rasenmaeher-api HTTP endpoint and forwarding only on
// a positive validity response. Negative response, timeout, or any transport
// error fails closed with HTTP 403.
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
	secretHeader                 = "Validity-Secret"
)

// Config is the user-facing plugin configuration.
type Config struct {
	RmapiURL              string `json:"rmapiURL,omitempty"`
	SharedSecretEnv       string `json:"sharedSecretEnv,omitempty"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds,omitempty"`
	CallsignHeader        string `json:"callsignHeader,omitempty"`
}

// CreateConfig returns a Config populated with safe defaults.
func CreateConfig() *Config {
	return &Config{
		RequestTimeoutSeconds: defaultRequestTimeoutSeconds,
		CallsignHeader:        defaultCallsignHeader,
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
	hdr := strings.TrimSpace(config.CallsignHeader)
	if hdr == "" {
		hdr = defaultCallsignHeader
	}

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
		callsignHeader: hdr,
		client:         &http.Client{Timeout: requestTO},
	}

	log.Printf("INFO %s initialized; rmapi=%s timeout=%s", logPrefix, p.url, p.requestTimeout)
	return p, nil
}

// ServeHTTP authorizes the request via the validity HTTP endpoint. Fail-closed.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("ERROR %s panic: %v\n%s", p.logPrefix, recovered, string(debug.Stack()))
			if rw != nil {
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()

	cert, reason := verifiedClientLeaf(req)
	if cert == nil {
		log.Printf("INFO %s denying %s %s: %s", p.logPrefix, req.Method, req.URL.Path, reason)
		http.Error(rw, "forbidden: no verified client certificate", http.StatusForbidden)
		return
	}
	callsign := strings.TrimSpace(cert.Subject.CommonName)
	if callsign == "" {
		log.Printf("INFO %s denying %s %s: cert has empty CN", p.logPrefix, req.Method, req.URL.Path)
		http.Error(rw, "forbidden: cert has no callsign", http.StatusForbidden)
		return
	}

	valid, err := p.check(callsign)
	if err != nil {
		log.Printf("ERROR %s validity check failed for callsign=%q: %v", p.logPrefix, callsign, err)
		http.Error(rw, "forbidden: validity service unavailable", http.StatusForbidden)
		return
	}
	if !valid {
		log.Printf("INFO %s denying request: callsign=%q is not valid", p.logPrefix, callsign)
		http.Error(rw, "forbidden: callsign revoked or unknown", http.StatusForbidden)
		return
	}

	req.Header.Set(p.callsignHeader, callsign)
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

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("callsign-validity[%s]", name)
}

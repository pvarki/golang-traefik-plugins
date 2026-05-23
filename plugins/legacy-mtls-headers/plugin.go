package traefik_legacy_mtls_headers

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
)

const (
	defaultClientCertDNHeader     = "X-ClientCert-DN"
	defaultClientCertSerialHeader = "X-ClientCert-Serial"
)

// Config controls output header names for legacy mTLS compatibility.
type Config struct {
	ClientCertDNHeader     string `json:"clientCertDNHeader,omitempty"`
	ClientCertSerialHeader string `json:"clientCertSerialHeader,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ClientCertDNHeader:     defaultClientCertDNHeader,
		ClientCertSerialHeader: defaultClientCertSerialHeader,
	}
}

// Plugin injects legacy client certificate headers for upstream services.
type Plugin struct {
	next                   http.Handler
	name                   string
	logPrefix              string
	clientCertDNHeader     string
	clientCertSerialHeader string
}

// New creates a new middleware instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logPrefix := pluginLogPrefix(name)
	if next == nil {
		err := errors.New("next handler is nil")
		log.Printf("ERROR %s initialization failed: %v", logPrefix, err)

		return nil, err
	}

	if config == nil {
		log.Printf("WARN %s received nil config, using defaults", logPrefix)
		config = CreateConfig()
	}

	clientCertDNHeader := normalizeHeaderName(config.ClientCertDNHeader, defaultClientCertDNHeader)
	clientCertSerialHeader := normalizeHeaderName(config.ClientCertSerialHeader, defaultClientCertSerialHeader)

	log.Printf(
		"INFO %s initialized with headers dn=%q serial=%q",
		logPrefix,
		clientCertDNHeader,
		clientCertSerialHeader,
	)

	return &Plugin{
		next:                   next,
		name:                   name,
		logPrefix:              logPrefix,
		clientCertDNHeader:     clientCertDNHeader,
		clientCertSerialHeader: clientCertSerialHeader,
	}, nil
}

// ServeHTTP sets legacy headers only when the client certificate is verified.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf(
				"ERROR %s panic while handling request: %v\n%s",
				p.logPrefix,
				recovered,
				string(debug.Stack()),
			)
			if rw != nil {
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()

	if req == nil {
		log.Printf("ERROR %s received nil request, aborting", p.logPrefix)
		if rw != nil {
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		return
	}

	cert, reason := verifiedClientLeaf(req)
	if cert != nil {
		serial := formatSerialHex(cert.SerialNumber)

		req.Header.Set(p.clientCertDNHeader, cert.Subject.String())
		req.Header.Set(p.clientCertSerialHeader, serial)
	} else {
		req.Header.Del(p.clientCertDNHeader)
		req.Header.Del(p.clientCertSerialHeader)
		if redirectURL, ok := redirectURLWithoutMTLSSubdomain(req); ok {
			log.Printf(
				"WARN %s no verified client certificate (%s), redirecting to %s for %s %s",
				p.logPrefix,
				reason,
				redirectURL,
				req.Method,
				req.URL.Path,
			)
			http.Redirect(rw, req, redirectURL, http.StatusFound)

			return
		}
		log.Printf(
			"ERROR %s no verified client certificate (%s), cleared legacy headers for %s %s",
			p.logPrefix,
			reason,
			req.Method,
			req.URL.Path,
		)
	}

	p.next.ServeHTTP(rw, req)
}

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}

	return fmt.Sprintf("legacy-mtls-headers[%s]", name)
}

func normalizeHeaderName(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	return value
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

func formatSerialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}

	value := strings.ToUpper(serial.Text(16))
	if len(value)%2 == 1 {
		return "0" + value
	}

	return value
}

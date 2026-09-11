// Package main annotates mTLS requests with the OCSP status of the client
// certificate. It never blocks; callsign-redirect acts on the verdict.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/pvarki/golang-traefik-plugins/internal/clientcert"
	"github.com/pvarki/golang-traefik-plugins/internal/guest"
	"github.com/pvarki/golang-traefik-plugins/internal/ocspcheck"
	"golang.org/x/crypto/ocsp"
)

const (
	defaultCallsignHeader = "Callsign"
	defaultValidityHeader = "Callsign-Valid"
	reasonHeader          = "Callsign-Valid-Reason"

	defaultRequestTimeoutSeconds = 3
	// caReloadInterval picks up CA rotation without restarting Traefik.
	caReloadInterval = 5 * time.Minute

	validityTrue  = "true"
	validityFalse = "false"

	// Reason values written to reasonHeader; consumed by callsign-redirect.
	reasonOK      = "ok"      // verified cert, OCSP says good
	reasonNoCert  = "no_cert" // no cert
	reasonInvalid = "invalid" // OCSP says revoked or unknown
	reasonError   = "error"   // responder errored, timed out, or failed validation
)

// Config is the middleware configuration from the Traefik Middleware CR.
type Config struct {
	OcspURL string `json:"ocspURL,omitempty"`
	// CABundlePath is the issuing CA, exposed to the guest via settings.mounts.
	// The ABI hides the TLS chain and the CA is created at runtime, so it can
	// be neither read from the connection nor inlined into a manifest.
	CABundlePath string `json:"caBundlePath,omitempty"`
	// DNSServer is the cluster resolver; the guest has no /etc/resolv.conf.
	DNSServer             string `json:"dnsServer,omitempty"`
	CertHeader            string `json:"certHeader,omitempty"`
	CallsignHeader        string `json:"callsignHeader,omitempty"`
	ValidityHeader        string `json:"validityHeader,omitempty"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds,omitempty"`
}

type settings struct {
	ocspURL        string
	caBundlePath   string
	dnsServer      string
	certHeader     string
	callsignHeader string
	validityHeader string
	timeout        time.Duration
}

func (c Config) settings() settings {
	return settings{
		ocspURL:        c.OcspURL,
		caBundlePath:   c.CABundlePath,
		dnsServer:      c.DNSServer,
		certHeader:     guest.OrDefault(c.CertHeader, clientcert.HeaderName),
		callsignHeader: guest.OrDefault(c.CallsignHeader, defaultCallsignHeader),
		validityHeader: guest.OrDefault(c.ValidityHeader, defaultValidityHeader),
		timeout: time.Duration(guest.SecondsOr(c.RequestTimeoutSeconds,
			defaultRequestTimeoutSeconds)) * time.Second,
	}
}

func (c Config) validate() error {
	if c.OcspURL == "" {
		return errors.New("ocspURL is required")
	}
	if c.CABundlePath == "" {
		return errors.New("caBundlePath is required")
	}
	return nil
}

// Verdict is what gets written to the request headers.
type Verdict struct {
	Callsign string
	Valid    bool
	Reason   string
}

// HeaderValue is the value for the validity header.
func (v Verdict) HeaderValue() string {
	if v.Valid {
		return validityTrue
	}
	return validityFalse
}

// issuerStore keeps the mounted CA bundle, re-reading it as it ages.
type issuerStore struct {
	path string

	mu      sync.Mutex
	certs   []*x509.Certificate
	fetched time.Time
}

func newIssuerStore(path string) *issuerStore { return &issuerStore{path: path} }

func (s *issuerStore) load() ([]*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.certs != nil && time.Since(s.fetched) < caReloadInterval {
		return s.certs, nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if s.certs != nil {
			return s.certs, nil // keep serving the last good bundle
		}
		return nil, err
	}
	certs, err := parseBundle(raw)
	if err != nil {
		if s.certs != nil {
			return s.certs, nil
		}
		return nil, err
	}
	s.certs, s.fetched = certs, time.Now()
	return certs, nil
}

func parseBundle(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("ca bundle contains no certificates")
	}
	return certs, nil
}

// issuerFor picks the bundle entry that actually signed leaf.
func issuerFor(leaf *x509.Certificate, bundle []*x509.Certificate) (*x509.Certificate, error) {
	for _, candidate := range bundle {
		if !bytes.Equal(candidate.RawSubject, leaf.RawIssuer) {
			continue
		}
		if err := leaf.CheckSignatureFrom(candidate); err == nil {
			return candidate, nil
		}
	}
	return nil, errors.New("no issuer in the CA bundle signed this certificate")
}

// Evaluate produces the verdict for one request.
func Evaluate(checker *ocspcheck.Checker, store *issuerStore, certHeader string) Verdict {
	leaf, err := clientcert.Parse(certHeader)
	if err != nil {
		return Verdict{Valid: false, Reason: reasonNoCert}
	}
	callsign := clientcert.CommonName(leaf)
	if callsign == "" {
		return Verdict{Valid: false, Reason: reasonNoCert}
	}

	bundle, err := store.load()
	if err != nil {
		return Verdict{Callsign: callsign, Valid: false, Reason: reasonError}
	}
	issuer, err := issuerFor(leaf, bundle)
	if err != nil {
		return Verdict{Callsign: callsign, Valid: false, Reason: reasonError}
	}

	resp, err := checker.Check(leaf, issuer)
	if err != nil {
		return Verdict{Callsign: callsign, Valid: false, Reason: reasonError}
	}
	if resp.Status == ocsp.Good {
		return Verdict{Callsign: callsign, Valid: true, Reason: reasonOK}
	}
	// Revoked and Unknown both deny.
	return Verdict{Callsign: callsign, Valid: false, Reason: reasonInvalid}
}

func main() {}

// Package clientcert recovers the mTLS client certificate from the
// passTLSClientCert header, since a wasm guest cannot see the TLS connection.
//
// SECURITY: this header is authentication input. It is only trustworthy
// because strip-identity-headers blanks it on the entrypoint (which runs
// before router middlewares) and mtls-pass-client-cert then sets it from the
// verified connection. Removing either half lets a client assert any identity.
package clientcert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
)

// HeaderName is the header passTLSClientCert populates.
const HeaderName = "X-Forwarded-Tls-Client-Cert"

const pemLineWidth = 64

var errNoCertificate = errors.New("no client certificate")

// ErrNoCertificate reports that the request carried no usable certificate.
func ErrNoCertificate() error { return errNoCertificate }

// Parse decodes the leaf from a passTLSClientCert header value. Traefik strips
// the PEM armour and comma-separates multiple certificates; only the first is
// the leaf. Accepts both the URL-encoded and literal forms.
func Parse(header string) (*x509.Certificate, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, errNoCertificate
	}

	// Do not unescape unconditionally: QueryUnescape turns "+" into a space,
	// and "+" is legal base64.
	var lastErr error
	for _, candidate := range candidates(header) {
		cert, err := parseOne(candidate)
		if err == nil {
			return cert, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func candidates(header string) []string {
	out := []string{header}
	if !strings.Contains(header, "%") {
		return out
	}
	if unescaped, err := url.QueryUnescape(header); err == nil && unescaped != header {
		out = append(out, unescaped)
	}
	return out
}

func parseOne(header string) (*x509.Certificate, error) {
	first := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
	if first == "" {
		return nil, errNoCertificate
	}
	block, _ := pem.Decode([]byte(rewrap(first)))
	if block == nil {
		return nil, errors.New("client certificate header is not PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("client certificate header is not a CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// rewrap restores the PEM armour and line breaks Traefik removed.
func rewrap(body string) string {
	if strings.Contains(body, "BEGIN CERTIFICATE") {
		return body
	}
	body = strings.Join(strings.Fields(body), "")

	var out strings.Builder
	out.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(body) > pemLineWidth {
		out.WriteString(body[:pemLineWidth])
		out.WriteByte('\n')
		body = body[pemLineWidth:]
	}
	out.WriteString(body)
	out.WriteString("\n-----END CERTIFICATE-----\n")
	return out.String()
}

// CommonName returns the trimmed CN, which is the callsign.
func CommonName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

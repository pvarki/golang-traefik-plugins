// Package main re-publishes the client certificate as the X-ClientCert-*
// headers older product backends expect. The certificate arrives via
// passTLSClientCert; see internal/clientcert for why that is trustworthy.
package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/pvarki/golang-traefik-plugins/internal/clientcert"
	"github.com/pvarki/golang-traefik-plugins/internal/guest"
)

const (
	defaultClientCertDNHeader          = "X-ClientCert-DN"
	defaultClientCertSerialHeader      = "X-ClientCert-Serial"
	defaultClientCertFingerprintHeader = "X-ClientCert-Fingerprint"
)

// Config is the middleware configuration from the Traefik Middleware CR.
type Config struct {
	ClientCertDNHeader          string `json:"clientCertDNHeader,omitempty"`
	ClientCertSerialHeader      string `json:"clientCertSerialHeader,omitempty"`
	ClientCertFingerprintHeader string `json:"clientCertFingerprintHeader,omitempty"`
	// CertHeader is where passTLSClientCert put the certificate.
	CertHeader string `json:"certHeader,omitempty"`
}

type headers struct {
	dn, serial, fingerprint, cert string
}

func (c Config) headers() headers {
	return headers{
		dn:          guest.OrDefault(c.ClientCertDNHeader, defaultClientCertDNHeader),
		serial:      guest.OrDefault(c.ClientCertSerialHeader, defaultClientCertSerialHeader),
		fingerprint: guest.OrDefault(c.ClientCertFingerprintHeader, defaultClientCertFingerprintHeader),
		cert:        guest.OrDefault(c.CertHeader, clientcert.HeaderName),
	}
}

type legacyValues struct {
	dn, serial, fingerprint string
}

// valuesFor returns false when there is no usable certificate.
func valuesFor(certHeader string) (legacyValues, bool) {
	cert, err := clientcert.Parse(certHeader)
	if err != nil || cert == nil {
		return legacyValues{}, false
	}
	return legacyValues{
		dn:          cert.Subject.String(),
		serial:      formatSerialHex(cert.SerialNumber),
		fingerprint: formatFingerprintHex(cert),
	}, true
}

// formatSerialHex renders the serial as uppercase hex, zero padded to an even
// number of digits. The backends match on this exact format.
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

// formatFingerprintHex is the SHA-1 of the DER. A wire format, not a security
// control.
func formatFingerprintHex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	digest := sha1.Sum(cert.Raw) //nolint:gosec // legacy wire format, not a security control
	return hex.EncodeToString(digest[:])
}

func main() {}

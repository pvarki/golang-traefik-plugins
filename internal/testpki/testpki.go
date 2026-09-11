// Package testpki builds throwaway certificates and the header encodings
// Traefik produces, so every plugin can be tested against realistic input.
//
// It is imported only from _test.go files, so it is never linked into a
// plugin's wasm module.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// CA is a throwaway issuing authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed EC certificate authority.
func NewCA(t *testing.T) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &CA{Cert: cert, Key: key}
}

// Issue signs a client certificate for the given callsign.
func (ca *CA) Issue(t *testing.T, commonName string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// ForwardedHeader renders certificates the way Traefik's passTLSClientCert
// middleware does: PEM delimiters and newlines stripped, multiple certificates
// comma separated, and the whole value URL encoded.
func ForwardedHeader(certs ...*x509.Certificate) string {
	parts := make([]string, 0, len(certs))
	for _, cert := range certs {
		body := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		body = strings.ReplaceAll(body, "-----BEGIN CERTIFICATE-----", "")
		body = strings.ReplaceAll(body, "-----END CERTIFICATE-----", "")
		body = strings.ReplaceAll(body, "\n", "")
		parts = append(parts, body)
	}
	return url.QueryEscape(strings.Join(parts, ","))
}

// PEM renders a certificate as ordinary PEM.
func PEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

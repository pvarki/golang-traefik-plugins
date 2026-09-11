package main

import (
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/pvarki/golang-traefik-plugins/internal/clientcert"
	"github.com/pvarki/golang-traefik-plugins/internal/testpki"
)

func TestValuesForRealCertificate(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	got, ok := valuesFor(testpki.ForwardedHeader(leaf))
	if !ok {
		t.Fatal("valuesFor returned false for a valid certificate")
	}
	if !strings.Contains(got.dn, "ALPHA01") {
		t.Errorf("dn = %q, want it to contain the CN", got.dn)
	}
	if got.serial != "4242" {
		t.Errorf("serial = %q, want 4242", got.serial)
	}
	digest := sha1.Sum(leaf.Raw)
	if got.fingerprint != hex.EncodeToString(digest[:]) {
		t.Errorf("fingerprint = %q, want the SHA-1 of the DER", got.fingerprint)
	}
}

func TestValuesForRejectsMissingCertificate(t *testing.T) {
	for _, header := range []string{"", "   ", "not-a-certificate"} {
		if _, ok := valuesFor(header); ok {
			t.Errorf("valuesFor(%q) returned true, want false so the headers get cleared", header)
		}
	}
}

func TestFormatSerialHex(t *testing.T) {
	testCases := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{name: "nil", serial: nil, want: ""},
		{name: "even digits", serial: big.NewInt(0x4242), want: "4242"},
		{name: "odd digits are zero padded", serial: big.NewInt(0xABC), want: "0ABC"},
		{name: "uppercase", serial: big.NewInt(0xdeadbeef), want: "DEADBEEF"},
		{name: "single digit", serial: big.NewInt(1), want: "01"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatSerialHex(tc.serial); got != tc.want {
				t.Errorf("formatSerialHex() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatFingerprintHexHandlesNil(t *testing.T) {
	if got := formatFingerprintHex(nil); got != "" {
		t.Errorf("formatFingerprintHex(nil) = %q, want empty", got)
	}
}

func TestConfigHeaderDefaults(t *testing.T) {
	hdrs := Config{}.headers()
	if hdrs.dn != defaultClientCertDNHeader {
		t.Errorf("dn = %q", hdrs.dn)
	}
	if hdrs.serial != defaultClientCertSerialHeader {
		t.Errorf("serial = %q", hdrs.serial)
	}
	if hdrs.fingerprint != defaultClientCertFingerprintHeader {
		t.Errorf("fingerprint = %q", hdrs.fingerprint)
	}
	if hdrs.cert != clientcert.HeaderName {
		t.Errorf("cert = %q, want %q", hdrs.cert, clientcert.HeaderName)
	}

	custom := Config{ClientCertDNHeader: " X-DN ", CertHeader: " X-Cert "}.headers()
	if custom.dn != "X-DN" {
		t.Errorf("custom dn = %q, want trimmed X-DN", custom.dn)
	}
	if custom.cert != "X-Cert" {
		t.Errorf("custom cert = %q, want trimmed X-Cert", custom.cert)
	}
}

package ocspcheck

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"
)

// These tests check this package against fixtures produced by
// python-cryptography, the library the rasenmaeher-api responder actually uses.
// Everything else in the suite builds its responses with the same helpers it is
// testing; only these can catch the two things that would break in production
// without breaking locally: a CertID that does not match what signer.py
// computes, and a nonce read from the wrong extension field.
//
// See testdata/generate.py to regenerate.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func fixtureCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(fixture(t, name))
	if block == nil {
		t.Fatalf("fixture %s is not PEM", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return cert
}

func fixtureNonce(t *testing.T) []byte {
	t.Helper()
	nonce, err := hex.DecodeString(strings.TrimSpace(string(fixture(t, "nonce.hex"))))
	if err != nil {
		t.Fatalf("decode fixture nonce: %v", err)
	}
	return nonce
}

// TestInteropCertIDMatchesCryptography checks that the request we build carries
// the CertID python-cryptography computes for the same pair. A drift here means
// responder.py answers UNAUTHORIZED in production, because it matches on these
// exact hashes.
func TestInteropCertIDMatchesCryptography(t *testing.T) {
	ca, leaf := fixtureCert(t, "ca.pem"), fixtureCert(t, "leaf.pem")

	want, err := ocsp.ParseRequest(fixture(t, "request.der"))
	if err != nil {
		t.Fatalf("parse the cryptography-generated request: %v", err)
	}

	base, err := ocsp.CreateRequest(leaf, ca, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	ours, err := withNonce(base, fixtureNonce(t))
	if err != nil {
		t.Fatalf("withNonce: %v", err)
	}
	got, err := ocsp.ParseRequest(ours)
	if err != nil {
		t.Fatalf("our nonce-carrying request does not re-parse: %v", err)
	}

	if got.HashAlgorithm != want.HashAlgorithm {
		t.Errorf("hash algorithm = %v, want %v", got.HashAlgorithm, want.HashAlgorithm)
	}
	if string(got.IssuerNameHash) != string(want.IssuerNameHash) {
		t.Error("issuerNameHash differs from cryptography's")
	}
	if string(got.IssuerKeyHash) != string(want.IssuerKeyHash) {
		t.Error("issuerKeyHash differs from cryptography's")
	}
	if got.SerialNumber.Cmp(want.SerialNumber) != 0 {
		t.Errorf("serial = %s, want %s", got.SerialNumber, want.SerialNumber)
	}
}

// TestInteropParsesCryptographyResponses is the load-bearing check: real signed
// responses from the responder's own library must verify, yield the right
// status, and echo the nonce where we look for it.
func TestInteropParsesCryptographyResponses(t *testing.T) {
	ca, leaf := fixtureCert(t, "ca.pem"), fixtureCert(t, "leaf.pem")
	nonce := fixtureNonce(t)

	testCases := []struct {
		file string
		want int
	}{
		{file: "response_good.der", want: ocsp.Good},
		{file: "response_revoked.der", want: ocsp.Revoked},
		{file: "response_unknown.der", want: ocsp.Unknown},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			der := fixture(t, tc.file)
			resp, err := ocsp.ParseResponseForCert(der, leaf, ca)
			if err != nil {
				t.Fatalf("ParseResponseForCert: %v", err)
			}
			if resp.Status != tc.want {
				t.Errorf("status = %d, want %d", resp.Status, tc.want)
			}
			if err := verifyNonce(der, nonce); err != nil {
				t.Errorf("verifyNonce on a real response: %v", err)
			}
			if tc.want == ocsp.Revoked && resp.RevocationReason != ocsp.PrivilegeWithdrawn {
				t.Errorf("revocation reason = %d, want privilegeWithdrawn", resp.RevocationReason)
			}
		})
	}
}

// TestInteropNonceCheckHasTeeth proves the fixture check above is not vacuous.
func TestInteropNonceCheckHasTeeth(t *testing.T) {
	der := fixture(t, "response_good.der")
	wrong := append([]byte(nil), fixtureNonce(t)...)
	wrong[0] ^= 0xFF

	if err := verifyNonce(der, wrong); err == nil {
		t.Error("verifyNonce accepted a mismatched nonce")
	}
}

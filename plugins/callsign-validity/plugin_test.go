package main

import (
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pvarki/golang-traefik-plugins/internal/ocspcheck"
	"github.com/pvarki/golang-traefik-plugins/internal/testpki"
	"golang.org/x/crypto/ocsp"
)

func bundleFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	body := ""
	for _, cert := range certs {
		body += testpki.PEM(cert)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// The responder here does not echo a nonce, so every Check fails. That is the
// correct behaviour, and it is asserted separately in internal/ocspcheck; these
// tests cover the header and issuer plumbing around it.
func TestEvaluateNoCertificate(t *testing.T) {
	ca := testpki.NewCA(t)
	store := newIssuerStore(bundleFile(t, ca.Cert))
	checker := &ocspcheck.Checker{URL: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}

	for _, header := range []string{"", "   ", "not-a-certificate"} {
		got := Evaluate(checker, store, header)
		if got.Valid || got.Reason != reasonNoCert {
			t.Errorf("Evaluate(%q) = %+v, want no_cert", header, got)
		}
		if got.Callsign != "" {
			t.Errorf("Evaluate(%q) leaked a callsign %q", header, got.Callsign)
		}
	}
}

func TestEvaluateUnknownIssuerIsAnError(t *testing.T) {
	ca := testpki.NewCA(t)
	other := testpki.NewCA(t)
	leaf := other.Issue(t, "ALPHA01", 0x4242)

	// Bundle holds a CA that did not sign the leaf.
	store := newIssuerStore(bundleFile(t, ca.Cert))
	checker := &ocspcheck.Checker{URL: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}

	got := Evaluate(checker, store, testpki.ForwardedHeader(leaf))
	if got.Valid || got.Reason != reasonError {
		t.Errorf("got %+v, want an error verdict", got)
	}
	if got.Callsign != "ALPHA01" {
		t.Errorf("Callsign = %q, want ALPHA01 even on failure", got.Callsign)
	}
}

func TestEvaluateResponderDown(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	store := newIssuerStore(bundleFile(t, ca.Cert))
	checker := &ocspcheck.Checker{URL: "http://127.0.0.1:1/api/v1/ocsp", Client: &http.Client{Timeout: time.Second}}

	got := Evaluate(checker, store, testpki.ForwardedHeader(leaf))
	if got.Valid || got.Reason != reasonError {
		t.Errorf("got %+v, want an error verdict", got)
	}
}

func TestEvaluateMissingBundleIsAnError(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	store := newIssuerStore(filepath.Join(t.TempDir(), "absent.pem"))
	checker := &ocspcheck.Checker{URL: "http://127.0.0.1:1", Client: &http.Client{Timeout: time.Second}}

	got := Evaluate(checker, store, testpki.ForwardedHeader(leaf))
	if got.Valid || got.Reason != reasonError {
		t.Errorf("got %+v, want an error verdict", got)
	}
}

func TestIssuerForPicksTheRealSigner(t *testing.T) {
	signer := testpki.NewCA(t)
	decoy := testpki.NewCA(t)
	leaf := signer.Issue(t, "ALPHA01", 0x4242)

	got, err := issuerFor(leaf, []*x509.Certificate{decoy.Cert, signer.Cert})
	if err != nil {
		t.Fatalf("issuerFor: %v", err)
	}
	if !got.Equal(signer.Cert) {
		t.Error("issuerFor chose a certificate that did not sign the leaf")
	}

	if _, err := issuerFor(leaf, []*x509.Certificate{decoy.Cert}); err == nil {
		t.Error("want an error when no bundle entry signed the leaf")
	}
}

func TestIssuerStoreServesLastGoodBundle(t *testing.T) {
	ca := testpki.NewCA(t)
	path := bundleFile(t, ca.Cert)
	store := newIssuerStore(path)

	if _, err := store.load(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove bundle: %v", err)
	}
	// A vanished or corrupt bundle must not take the middleware down.
	got, err := store.load()
	if err != nil {
		t.Fatalf("load after removal: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d certificates, want the cached 1", len(got))
	}
}

func TestParseBundleRejectsJunk(t *testing.T) {
	if _, err := parseBundle([]byte("not pem at all")); err == nil {
		t.Error("want an error for a bundle with no certificates")
	}
}

func TestConfigValidation(t *testing.T) {
	if err := (Config{OcspURL: "http://x", CABundlePath: "/ca"}).validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := (Config{CABundlePath: "/ca"}).validate(); err == nil {
		t.Error("want an error without ocspURL")
	}
	if err := (Config{OcspURL: "http://x"}).validate(); err == nil {
		t.Error("want an error without caBundlePath")
	}
}

func TestSettingsDefaults(t *testing.T) {
	set := Config{OcspURL: "http://x", CABundlePath: "/ca"}.settings()
	if set.callsignHeader != defaultCallsignHeader {
		t.Errorf("callsignHeader = %q", set.callsignHeader)
	}
	if set.validityHeader != defaultValidityHeader {
		t.Errorf("validityHeader = %q", set.validityHeader)
	}
	if set.timeout != defaultRequestTimeoutSeconds*time.Second {
		t.Errorf("timeout = %s", set.timeout)
	}
}

func TestEvaluateAgainstRealResponder(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	store := newIssuerStore(bundleFile(t, ca.Cert))
	header := testpki.ForwardedHeader(leaf)

	testCases := []struct {
		name       string
		opts       testpki.ResponderOpts
		wantValid  bool
		wantReason string
	}{
		{name: "good", opts: testpki.ResponderOpts{Status: ocsp.Good}, wantValid: true, wantReason: reasonOK},
		{name: "revoked", opts: testpki.ResponderOpts{Status: ocsp.Revoked}, wantReason: reasonInvalid},
		{name: "unknown", opts: testpki.ResponderOpts{Status: ocsp.Unknown}, wantReason: reasonInvalid},
		{name: "no nonce echo", opts: testpki.ResponderOpts{Status: ocsp.Good, OmitNonce: true}, wantReason: reasonError},
		{name: "expired response", opts: testpki.ResponderOpts{
			Status: ocsp.Good, NextUpdate: time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second),
		}, wantReason: reasonError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := ca.Serve(t, tc.opts)
			checker := &ocspcheck.Checker{URL: server.URL, Client: server.Client()}

			got := Evaluate(checker, store, header)
			if got.Valid != tc.wantValid {
				t.Errorf("Valid = %v, want %v", got.Valid, tc.wantValid)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Callsign != "ALPHA01" {
				t.Errorf("Callsign = %q, want ALPHA01", got.Callsign)
			}
		})
	}
}

// A responder signing with the wrong key must never be believed.
func TestEvaluateRejectsForeignSigner(t *testing.T) {
	ca := testpki.NewCA(t)
	other := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	store := newIssuerStore(bundleFile(t, ca.Cert))

	server := ca.Serve(t, testpki.ResponderOpts{Status: ocsp.Good, SignKey: other.Key})
	checker := &ocspcheck.Checker{URL: server.URL, Client: server.Client()}

	got := Evaluate(checker, store, testpki.ForwardedHeader(leaf))
	if got.Valid {
		t.Error("accepted a response signed by another key")
	}
	if got.Reason != reasonError {
		t.Errorf("Reason = %q, want %q", got.Reason, reasonError)
	}
}

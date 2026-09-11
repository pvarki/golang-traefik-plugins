package ocspcheck

import (
	"crypto"
	"encoding/asn1"
	"net/http"
	"testing"
	"time"

	"github.com/pvarki/golang-traefik-plugins/internal/testpki"
	"golang.org/x/crypto/ocsp"
)

func TestCheckStatuses(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	testCases := []struct {
		name string
		want int
	}{
		{name: "good", want: ocsp.Good},
		{name: "revoked", want: ocsp.Revoked},
		{name: "unknown", want: ocsp.Unknown},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := ca.Serve(t, testpki.ResponderOpts{Status: tc.want})
			checker := &Checker{URL: server.URL, Client: server.Client()}

			resp, err := checker.Check(leaf, ca.Cert)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if resp.Status != tc.want {
				t.Errorf("Status = %d, want %d", resp.Status, tc.want)
			}
			if tc.want == ocsp.Revoked && resp.RevocationReason != ocsp.PrivilegeWithdrawn {
				t.Errorf("RevocationReason = %d, want %d", resp.RevocationReason, ocsp.PrivilegeWithdrawn)
			}
		})
	}
}

// TestCheckRejectsNonceProblems is the point of hand-adding the nonce: a
// replayed or unauthenticated response must not be accepted.
func TestCheckRejectsNonceProblems(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	testCases := []struct {
		name string
		opts testpki.ResponderOpts
	}{
		{name: "nonce omitted", opts: testpki.ResponderOpts{Status: ocsp.Good, OmitNonce: true}},
		{name: "nonce mismatched", opts: testpki.ResponderOpts{Status: ocsp.Good, Nonce: []byte("not-the-nonce!!!")}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := ca.Serve(t, tc.opts)
			checker := &Checker{URL: server.URL, Client: server.Client()}

			if _, err := checker.Check(leaf, ca.Cert); err == nil {
				t.Fatal("accepted a response with a bad nonce, want an error")
			}
		})
	}
}

func TestCheckRejectsForeignSigner(t *testing.T) {
	ca := testpki.NewCA(t)
	other := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	// A responder that answers correctly but signs with the wrong key.
	server := ca.Serve(t, testpki.ResponderOpts{Status: ocsp.Good, SignKey: other.Key})
	checker := &Checker{URL: server.URL, Client: server.Client()}

	if _, err := checker.Check(leaf, ca.Cert); err == nil {
		t.Fatal("accepted a response signed by another key, want an error")
	}
}

func TestCheckRejectsResponseForAnotherCert(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	other := ca.Issue(t, "BRAVO02", 0x9999)

	server := ca.Serve(t, testpki.ResponderOpts{Status: ocsp.Good})
	checker := &Checker{URL: server.URL, Client: server.Client()}

	// The responder answers about whatever serial it is asked, so asking about
	// `leaf` while validating against `other` must be rejected.
	resp, err := checker.Check(leaf, ca.Cert)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("serial = %s, want %s", resp.SerialNumber, leaf.SerialNumber)
	}
	if resp.SerialNumber.Cmp(other.SerialNumber) == 0 {
		t.Fatal("response matched the wrong certificate")
	}
}

func TestCheckResponderUnreachable(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)
	checker := &Checker{URL: "http://127.0.0.1:1/api/v1/ocsp", Client: &http.Client{Timeout: time.Second}}

	if _, err := checker.Check(leaf, ca.Cert); err == nil {
		t.Fatal("want an error when the responder is unreachable")
	}
}

func TestCheckRequiresConfiguration(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	if _, err := (&Checker{}).Check(leaf, ca.Cert); err == nil {
		t.Error("want an error with no URL configured")
	}
	if _, err := (&Checker{URL: "http://example.invalid"}).Check(nil, ca.Cert); err == nil {
		t.Error("want an error with no leaf")
	}
	if _, err := (&Checker{URL: "http://example.invalid"}).Check(leaf, nil); err == nil {
		t.Error("want an error with no issuer")
	}
}

// TestWithNoncePreservesCertID guards the one risky thing the nonce helper
// does: re-marshalling the request produced by x/crypto. The CertID must come
// back byte-identical, because the responder matches on those hashes.
func TestWithNoncePreservesCertID(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	original, err := ocsp.CreateRequest(leaf, ca.Cert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	withExt, err := withNonce(original, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("withNonce: %v", err)
	}

	before, err := ocsp.ParseRequest(original)
	if err != nil {
		t.Fatalf("parse original: %v", err)
	}
	after, err := ocsp.ParseRequest(withExt)
	if err != nil {
		t.Fatalf("x/crypto cannot parse the nonce-carrying request: %v", err)
	}

	if after.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Error("serial changed")
	}
	if string(after.IssuerNameHash) != string(before.IssuerNameHash) {
		t.Error("issuerNameHash changed")
	}
	if string(after.IssuerKeyHash) != string(before.IssuerKeyHash) {
		t.Error("issuerKeyHash changed")
	}
	if after.HashAlgorithm != before.HashAlgorithm {
		t.Error("hash algorithm changed")
	}

	// And the extension really is present.
	var parsed ocspRequest
	if _, err := asn1.Unmarshal(withExt, &parsed); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	found := false
	for _, ext := range parsed.TBSRequest.RequestExtensions {
		if ext.Id.Equal(oidNonce) {
			found = true
		}
	}
	if !found {
		t.Error("nonce extension is missing")
	}
}

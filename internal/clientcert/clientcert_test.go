package clientcert_test

import (
	"strings"
	"testing"

	"github.com/pvarki/golang-traefik-plugins/internal/clientcert"
	"github.com/pvarki/golang-traefik-plugins/internal/testpki"
)

func TestParseAcceptsTraefikEncoding(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	got, err := clientcert.Parse(testpki.ForwardedHeader(leaf))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if clientcert.CommonName(got) != "ALPHA01" {
		t.Errorf("CommonName = %q, want ALPHA01", clientcert.CommonName(got))
	}
	if got.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("serial = %s, want %s", got.SerialNumber, leaf.SerialNumber)
	}
	if string(got.Raw) != string(leaf.Raw) {
		t.Error("DER does not round-trip; the fingerprint header would be wrong")
	}
}

// A chain is only present when the client chose to send one, and only the leaf
// is ours to use.
func TestParseTakesTheLeafFromAChain(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 0x4242)

	got, err := clientcert.Parse(testpki.ForwardedHeader(leaf, ca.Cert))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if clientcert.CommonName(got) != "ALPHA01" {
		t.Errorf("CommonName = %q, want the leaf ALPHA01", clientcert.CommonName(got))
	}
}

func TestParseAcceptsPlainPEM(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 1)

	if _, err := clientcert.Parse(testpki.PEM(leaf)); err != nil {
		t.Fatalf("Parse on unmodified PEM: %v", err)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 1)
	truncated := testpki.ForwardedHeader(leaf)[:40]

	testCases := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "whitespace", input: "   \t "},
		{name: "not base64", input: "not-a-certificate"},
		{name: "empty first element", input: ",abc"},
		{name: "truncated DER", input: truncated},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := clientcert.Parse(tc.input); err == nil {
				t.Errorf("Parse(%q) succeeded, want an error", tc.input)
			}
		})
	}
}

func TestCommonNameHandlesNil(t *testing.T) {
	if got := clientcert.CommonName(nil); got != "" {
		t.Errorf("CommonName(nil) = %q, want empty", got)
	}
}

func TestParseTrimsWhitespaceAroundValue(t *testing.T) {
	ca := testpki.NewCA(t)
	leaf := ca.Issue(t, "ALPHA01", 1)
	padded := "  " + testpki.ForwardedHeader(leaf) + "  "

	if _, err := clientcert.Parse(padded); err != nil {
		t.Fatalf("Parse on padded value: %v", err)
	}
	if !strings.Contains(padded, " ") {
		t.Fatal("test did not actually pad the value")
	}
}

// TestParseHandlesPlusInBase64 is a regression test. The header value was
// previously run through url.QueryUnescape unconditionally, which rewrites "+"
// as a space and corrupts any DER whose base64 contains one -- roughly three
// certificates in four.
func TestParseHandlesPlusInBase64(t *testing.T) {
	ca := testpki.NewCA(t)

	var unencoded string
	for i := 0; i < 200 && unencoded == ""; i++ {
		leaf := ca.Issue(t, "ALPHA01", int64(i+1))
		body := strings.ReplaceAll(testpki.PEM(leaf), "\n", "")
		body = strings.ReplaceAll(body, "-----BEGIN CERTIFICATE-----", "")
		body = strings.ReplaceAll(body, "-----END CERTIFICATE-----", "")
		if strings.Contains(body, "+") {
			unencoded = body
		}
	}
	if unencoded == "" {
		t.Skip("no certificate with a '+' in its base64 was generated")
	}

	got, err := clientcert.Parse(unencoded)
	if err != nil {
		t.Fatalf("Parse on an unencoded value containing '+': %v", err)
	}
	if clientcert.CommonName(got) != "ALPHA01" {
		t.Errorf("CommonName = %q, want ALPHA01", clientcert.CommonName(got))
	}
}

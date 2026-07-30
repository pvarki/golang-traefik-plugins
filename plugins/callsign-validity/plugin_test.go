package traefik_callsign_validity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	callsign             = "ALPHA01"
	customCallsignHeader = "X-Callsign"
	customValidityHeader = "X-Valid"
	secretEnv            = "TEST_CALLSIGN_VALIDITY_SECRET" // pragma: allowlist secret
	secretValue          = "s3cret"                        // pragma: allowlist secret

	unreachableURL = "http://127.0.0.1:1/api/v1/callsign/validity"
)

// Ensure normalization.
var (
	configDefault       = &Config{}
	configBlankHeaders  = &Config{CallsignHeader: "  ", ValidityHeader: "\t"}
	configCustomHeaders = &Config{CallsignHeader: " " + customCallsignHeader + " ", ValidityHeader: " " + customValidityHeader + " "}
)

// The plugin logs on every New and every request
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func certCN(commonName string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
}

func verifiedTLS(chains ...[]*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: chains}
}

var (
	tlsNoCert         = &tls.ConnectionState{}
	tlsPeerUnverified = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certCN(callsign)}}
	tlsNilLeaf        = verifiedTLS([]*x509.Certificate{nil})
	tlsEmptyChain     = verifiedTLS([]*x509.Certificate{})
	tlsVerified       = verifiedTLS([]*x509.Certificate{certCN(callsign)})
	tlsPaddedCN       = verifiedTLS([]*x509.Certificate{certCN("\t " + callsign + " \t")})
	tlsEmptyCN        = verifiedTLS([]*x509.Certificate{certCN("   ")})
	tlsSecondChain    = verifiedTLS([]*x509.Certificate{}, []*x509.Certificate{certCN(callsign)})
)

func respondWith(status int, body string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, body)
	}
}

var (
	respondValid       = respondWith(http.StatusOK, `{"valid": true}`)
	respondInvalid     = respondWith(http.StatusOK, `{"valid": false}`)
	respondErrorField  = respondWith(http.StatusOK, `{"valid": true, "error": "boom"}`)
	respondMalformed   = respondWith(http.StatusOK, `{`)
	respondEmpty       = respondWith(http.StatusOK, ``)
	respondServerError = respondWith(http.StatusInternalServerError, `{"valid": true}`)
	respondNotFound    = respondWith(http.StatusNotFound, ``)
)

func spoofed(callsignValue, validity, reason string) http.Header {
	headers := http.Header{}
	if callsignValue != "" {
		headers.Set(defaultCallsignHeader, callsignValue)
	}
	if validity != "" {
		headers[defaultValidityHeader] = []string{validity, validity}
	}
	if reason != "" {
		headers.Set(reasonHeader, reason)
	}
	return headers
}

type serveHTTPCase struct {
	name          string
	config        *Config
	tlsState      *tls.ConnectionState
	respond       http.HandlerFunc
	unreachable   bool
	headers       http.Header
	backendPanics bool
	wantChecked   bool
	wantCallsign  string
	wantValidity  string
	wantReason    string
	wantStatus    int
}

func (testCase serveHTTPCase) newRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = testCase.tlsState
	for name, values := range testCase.headers {
		request.Header[name] = values
	}
	return request
}

func assertHeader(t *testing.T, header http.Header, name string, want string) {
	t.Helper()
	values := header.Values(name)
	if want == "" {
		if len(values) != 0 {
			t.Errorf("%s = %v, want absent", name, values)
		}
		return
	}
	if len(values) != 1 || values[0] != want {
		t.Errorf("%s = %v, want [%q]", name, values, want)
	}
}

func TestServeHTTP(t *testing.T) {
	testCases := []serveHTTPCase{
		// A valid verdict is the only thing that yields true/ok.
		{name: "valid callsign", config: configDefault, tlsState: tlsVerified, respond: respondValid, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "cert CN is trimmed", config: configDefault, tlsState: tlsPaddedCN, respond: respondValid, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "leaf comes from the first non-empty chain", config: configDefault, tlsState: tlsSecondChain, respond: respondValid, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "custom header names", config: configCustomHeaders, tlsState: tlsVerified, respond: respondValid, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "blank header names fall back", config: configBlankHeaders, tlsState: tlsVerified, respond: respondValid, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "panic in the backend fails closed", config: configDefault, tlsState: tlsVerified, respond: respondValid, backendPanics: true, wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK, wantStatus: 500},

		// A verified cert whose callsign the service rejects.
		{name: "invalid callsign", config: configDefault, tlsState: tlsVerified, respond: respondInvalid, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonInvalid},

		// Without a verified client cert the service is never called.
		{name: "no TLS", config: configDefault, tlsState: nil, wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "TLS without a client cert", config: configDefault, tlsState: tlsNoCert, wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "peer cert present but unverified", config: configDefault, tlsState: tlsPeerUnverified, wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "verified chain with a nil leaf", config: configDefault, tlsState: tlsNilLeaf, wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "verified chain with no leaf", config: configDefault, tlsState: tlsEmptyChain, wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "cert with an empty CN", config: configDefault, tlsState: tlsEmptyCN, wantValidity: validityFalse, wantReason: reasonNoCert},

		// Do not trust client-supplied headers
		{name: "spoofed headers are reset without a cert", config: configDefault, tlsState: nil, headers: spoofed("admin", validityTrue, reasonOK), wantValidity: validityFalse, wantReason: reasonNoCert},
		{name: "spoofed callsign is replaced by the cert CN", config: configDefault, tlsState: tlsVerified, respond: respondValid, headers: spoofed("admin", validityTrue, reasonOK), wantChecked: true, wantCallsign: callsign, wantValidity: validityTrue, wantReason: reasonOK},
		{name: "spoofed valid does not survive an invalid callsign", config: configDefault, tlsState: tlsVerified, respond: respondInvalid, headers: spoofed("admin", validityTrue, reasonOK), wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonInvalid},

		// A failing check is an error verdict, not an invalid one.
		{name: "service returns 500", config: configDefault, tlsState: tlsVerified, respond: respondServerError, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
		{name: "service returns 404", config: configDefault, tlsState: tlsVerified, respond: respondNotFound, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
		{name: "response carries an error field", config: configDefault, tlsState: tlsVerified, respond: respondErrorField, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
		{name: "response is malformed JSON", config: configDefault, tlsState: tlsVerified, respond: respondMalformed, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
		{name: "response is empty", config: configDefault, tlsState: tlsVerified, respond: respondEmpty, wantChecked: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
		{name: "service is unreachable", config: configDefault, tlsState: tlsVerified, unreachable: true, wantCallsign: callsign, wantValidity: validityFalse, wantReason: reasonError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			checked := false
			service := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				checked = true
				if testCase.respond == nil {
					t.Errorf("validity service called unexpectedly")
					return
				}
				testCase.respond(rw, req)
			}))
			defer service.Close()

			var backendRequest *http.Request
			backend := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				backendRequest = request
				if testCase.backendPanics {
					panic("boom")
				}
			})

			config := *testCase.config
			config.RmapiURL = service.URL
			if testCase.unreachable {
				config.RmapiURL = unreachableURL
			}

			plugin, err := New(context.Background(), backend, &config, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			request, recorder := testCase.newRequest(), httptest.NewRecorder()
			plugin.ServeHTTP(recorder, request)

			if backendRequest == nil {
				t.Fatal("request was not forwarded to the backend")
			}
			if checked != testCase.wantChecked {
				t.Errorf("validity service called = %t, want %t", checked, testCase.wantChecked)
			}

			callsignHdr, validityHdr := defaultCallsignHeader, defaultValidityHeader
			if testCase.config == configCustomHeaders {
				callsignHdr, validityHdr = customCallsignHeader, customValidityHeader
			}
			assertHeader(t, backendRequest.Header, callsignHdr, testCase.wantCallsign)
			assertHeader(t, backendRequest.Header, validityHdr, testCase.wantValidity)
			assertHeader(t, backendRequest.Header, reasonHeader, testCase.wantReason)

			wantStatus := testCase.wantStatus
			if wantStatus == 0 {
				wantStatus = 200
			}
			if recorder.Code != wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, wantStatus)
			}
		})
	}
}

func TestCheckRequest(t *testing.T) {
	testCases := []struct {
		name       string
		secretEnv  string
		envValue   string
		wantSecret string
	}{
		{name: "deployed config sends no secret header", wantSecret: ""},
		{name: "empty secret env sends no header", secretEnv: secretEnv, wantSecret: ""},
		{name: "secret is sent when the env has a value", secretEnv: " " + secretEnv + " ", envValue: secretValue, wantSecret: secretValue},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(secretEnv, testCase.envValue)

			var got *http.Request
			var body []byte
			service := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				got, body = req, readAll(t, req.Body)
				respondValid(rw, req)
			}))
			defer service.Close()

			plugin, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				&Config{RmapiURL: service.URL, SharedSecretEnv: testCase.secretEnv}, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			request := serveHTTPCase{tlsState: tlsVerified}.newRequest()
			plugin.ServeHTTP(httptest.NewRecorder(), request)

			if got == nil {
				t.Fatal("validity service was not called")
			}
			if got.Method != http.MethodPost {
				t.Errorf("method = %s, want %s", got.Method, http.MethodPost)
			}
			if contentType := got.Header.Get("Content-Type"); contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", contentType)
			}
			assertHeader(t, got.Header, secretHeader, testCase.wantSecret)

			var sent checkRequest
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Fatalf("body %q is not the expected JSON: %v", body, err)
			}
			if sent.Callsign != callsign {
				t.Errorf("callsign = %q, want %q", sent.Callsign, callsign)
			}
		})
	}
}

func readAll(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

func TestNewRejectsBadInput(t *testing.T) {
	backend := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	testCases := []struct {
		name   string
		next   http.Handler
		config *Config
	}{
		{name: "nil next", next: nil, config: &Config{RmapiURL: unreachableURL}},
		{name: "nil config", next: backend, config: nil},
		{name: "missing rmapiURL", next: backend, config: CreateConfig()},
		{name: "whitespace rmapiURL", next: backend, config: &Config{RmapiURL: "   "}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plugin, err := New(context.Background(), testCase.next, testCase.config, "test")
			if err == nil || plugin != nil {
				t.Fatalf("got (%T, %v), want (nil, error)", plugin, err)
			}
		})
	}
}

func TestNewNormalizesTimeout(t *testing.T) {
	testCases := []struct {
		name   string
		config *Config
		want   time.Duration
	}{
		{name: "zero falls back", config: &Config{RequestTimeoutSeconds: 0}, want: 3 * time.Second},
		{name: "negative falls back", config: &Config{RequestTimeoutSeconds: -5}, want: 3 * time.Second},
		{name: "explicit", config: &Config{RequestTimeoutSeconds: 7}, want: 7 * time.Second},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := *testCase.config
			config.RmapiURL = unreachableURL

			handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &config, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			plugin, ok := handler.(*Plugin)
			if !ok {
				t.Fatalf("New returned %T, want *Plugin", handler)
			}
			if plugin.client.Timeout != testCase.want {
				t.Errorf("client timeout = %s, want %s", plugin.client.Timeout, testCase.want)
			}
		})
	}
}

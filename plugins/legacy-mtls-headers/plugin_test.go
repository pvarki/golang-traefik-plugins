package legacy_mtls_headers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const (
	callsign                = "ALPHA01"
	certDN                  = "CN=" + callsign + ",O=OpenDefence"
	certSerial              = "0ABC"
	spoofedDN               = "CN=admin"
	spoofedSerial           = "0123456789ABCDEF"
	spoofedFingerprint      = "0123456789abcdef0123456789abcdef01234567" // pragma: allowlist secret
	customDNHeader          = "X-DN"
	customSerialHeader      = "X-Serial"
	customFingerprintHeader = "X-Fingerprint"
)

var (
	certRaw         = []byte("test-certificate-der")
	certFingerprint = hexSHA1(certRaw)
)

func hexSHA1(raw []byte) string {
	digest := sha1.Sum(raw)
	return hex.EncodeToString(digest[:])
}

// Ensure normalization.
var (
	configDefault       = CreateConfig()
	configBlankHeaders  = &Config{ClientCertDNHeader: "  ", ClientCertSerialHeader: "\t", ClientCertFingerprintHeader: " "}
	configCustomHeaders = &Config{
		ClientCertDNHeader:          " " + customDNHeader + " ",
		ClientCertSerialHeader:      " " + customSerialHeader + " ",
		ClientCertFingerprintHeader: " " + customFingerprintHeader + " ",
	}
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func verifiedTLS(chains ...[]*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: chains}
}

var (
	leaf              = &x509.Certificate{Subject: pkix.Name{CommonName: callsign, Organization: []string{"OpenDefence"}}, SerialNumber: big.NewInt(0xabc), Raw: certRaw}
	tlsNoCert         = &tls.ConnectionState{}
	tlsPeerUnverified = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	tlsNilLeaf        = verifiedTLS([]*x509.Certificate{nil})
	tlsEmptyChain     = verifiedTLS([]*x509.Certificate{})
	tlsVerified       = verifiedTLS([]*x509.Certificate{leaf})
	tlsSecondChain    = verifiedTLS([]*x509.Certificate{}, []*x509.Certificate{leaf})
)

func spoofedHeaders() http.Header {
	headers := http.Header{}
	headers[defaultClientCertDNHeader] = []string{spoofedDN, spoofedDN}
	headers.Set(defaultClientCertSerialHeader, spoofedSerial)
	headers.Set(defaultClientCertFingerprintHeader, spoofedFingerprint)
	headers.Set(customDNHeader, spoofedDN)
	headers.Set(customSerialHeader, spoofedSerial)
	headers.Set(customFingerprintHeader, spoofedFingerprint)
	return headers
}

type serveHTTPCase struct {
	name            string
	config          *Config
	tlsState        *tls.ConnectionState
	backendPanics   bool
	wantDN          string
	wantSerial      string
	wantFingerprint string
	wantStatus      int
}

func (testCase serveHTTPCase) newRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = testCase.tlsState
	for name, values := range spoofedHeaders() {
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
		{name: "verified cert", config: configDefault, tlsState: tlsVerified, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint},
		{name: "leaf comes from the first non-empty chain", config: configDefault, tlsState: tlsSecondChain, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint},
		{name: "custom header names", config: configCustomHeaders, tlsState: tlsVerified, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint},
		{name: "blank header names fall back", config: configBlankHeaders, tlsState: tlsVerified, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint},
		{name: "nil config falls back", config: nil, tlsState: tlsVerified, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint},
		{name: "panic in the backend fails closed", config: configDefault, tlsState: tlsVerified, backendPanics: true, wantDN: certDN, wantSerial: certSerial, wantFingerprint: certFingerprint, wantStatus: 500},

		{name: "no TLS", config: configDefault, tlsState: nil},
		{name: "TLS without a client cert", config: configDefault, tlsState: tlsNoCert},
		{name: "peer cert present but unverified", config: configDefault, tlsState: tlsPeerUnverified},
		{name: "verified chain with a nil leaf", config: configDefault, tlsState: tlsNilLeaf},
		{name: "verified chain with no leaf", config: configDefault, tlsState: tlsEmptyChain},
		{name: "custom header names are cleared", config: configCustomHeaders, tlsState: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var backendRequest *http.Request
			backend := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				backendRequest = request
				if testCase.backendPanics {
					panic("boom")
				}
			})

			plugin, err := New(context.Background(), backend, testCase.config, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			request, recorder := testCase.newRequest(), httptest.NewRecorder()
			plugin.ServeHTTP(recorder, request)

			if backendRequest == nil {
				t.Fatal("request was not forwarded to the backend")
			}
			dnHeader, serialHeader, fingerprintHeader := defaultClientCertDNHeader, defaultClientCertSerialHeader, defaultClientCertFingerprintHeader
			if testCase.config == configCustomHeaders {
				dnHeader, serialHeader, fingerprintHeader = customDNHeader, customSerialHeader, customFingerprintHeader
			}
			assertHeader(t, backendRequest.Header, dnHeader, testCase.wantDN)
			assertHeader(t, backendRequest.Header, serialHeader, testCase.wantSerial)
			assertHeader(t, backendRequest.Header, fingerprintHeader, testCase.wantFingerprint)

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

func newCertPair(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: leaf.SerialNumber,
		Subject:      leaf.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCert, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: key}
}

func TestServeHTTPOverRealHandshake(t *testing.T) {
	caPool, clientCert := newCertPair(t)
	handshakeFingerprint := hexSHA1(clientCert.Certificate[0])

	testCases := []struct {
		name            string
		clientAuth      tls.ClientAuthType
		clientCAs       *x509.CertPool
		wantDN          string
		wantSerial      string
		wantFingerprint string
	}{
		{name: "cert verified", clientAuth: tls.RequireAndVerifyClientCert, clientCAs: caPool, wantDN: certDN, wantSerial: certSerial, wantFingerprint: handshakeFingerprint},
		{name: "cert accepted but never verified", clientAuth: tls.RequireAnyClientCert, clientCAs: x509.NewCertPool()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// The server goroutine outlives the handler, so keep a copy rather than the request.
			var backendHeaders http.Header
			backend := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				backendHeaders = request.Header.Clone()
			})

			plugin, err := New(context.Background(), backend, configDefault, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			server := httptest.NewUnstartedServer(plugin)
			server.TLS = &tls.Config{ClientAuth: testCase.clientAuth, ClientCAs: testCase.clientCAs}
			server.StartTLS()
			defer server.Close()

			client := server.Client()
			client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCert}
			request, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			for name, values := range spoofedHeaders() {
				request.Header[name] = values
			}

			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = response.Body.Close()

			if backendHeaders == nil {
				t.Fatal("request was not forwarded to the backend")
			}
			assertHeader(t, backendHeaders, defaultClientCertDNHeader, testCase.wantDN)
			assertHeader(t, backendHeaders, defaultClientCertSerialHeader, testCase.wantSerial)
			assertHeader(t, backendHeaders, defaultClientCertFingerprintHeader, testCase.wantFingerprint)
		})
	}
}

func TestFormatFingerprintHex(t *testing.T) {
	testCases := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{name: "nil", cert: nil, want: ""},
		{name: "sha1 of the raw der", cert: leaf, want: certFingerprint},
		{name: "empty der still hashes", cert: &x509.Certificate{}, want: hexSHA1(nil)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := formatFingerprintHex(testCase.cert); got != testCase.want {
				t.Errorf("got %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestFormatSerialHex(t *testing.T) {
	testCases := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{name: "nil", serial: nil, want: ""},
		{name: "zero is padded", serial: big.NewInt(0), want: "00"},
		{name: "odd nibble count is padded", serial: big.NewInt(0xabc), want: "0ABC"},
		{name: "even nibble count is not", serial: big.NewInt(0xabcd), want: "ABCD"},
		{name: "leading zero bytes are dropped, as DER parsing does", serial: new(big.Int).SetBytes([]byte{0x00, 0x9f, 0x1e}), want: "9F1E"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := formatSerialHex(testCase.serial); got != testCase.want {
				t.Errorf("got %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestServeHTTPRejectsNilRequest(t *testing.T) {
	forwarded := false
	plugin, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }), configDefault, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	recorder := httptest.NewRecorder()
	plugin.ServeHTTP(recorder, nil)
	plugin.ServeHTTP(nil, nil)

	if forwarded {
		t.Error("nil request was forwarded to the backend")
	}
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestNewRejectsNilNext(t *testing.T) {
	plugin, err := New(context.Background(), nil, CreateConfig(), "test")
	if err == nil || plugin != nil {
		t.Fatalf("got (%T, %v), want (nil, error)", plugin, err)
	}
}

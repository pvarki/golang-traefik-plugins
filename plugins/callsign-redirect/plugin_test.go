package callsign_redirect

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	mtlsHost   = "mtls.example.org"
	baseDomain = "example.org"
	portalURL  = "https://portal.example.org/denied"

	errorURLNoCode        = "http://" + baseDomain + errorPath
	mtlsFailURL           = errorURLNoCode + "?code=" + codeMTLSFail
	unauthorizedURL       = errorURLNoCode + "?code=" + codeUnauthorized
	httpsFailURL          = "https://" + baseDomain + errorPath + "?code=" + codeMTLSFail
	portPreservedFailURL  = "http://" + baseDomain + ":8443" + errorPath + "?code=" + codeMTLSFail
	permissiveHostFailURL = "http://whatever.test" + errorPath + "?code=" + codeMTLSFail
	mixedCaseHostFailURL  = "http://Example.ORG" + errorPath + "?code=" + codeMTLSFail
)

// Padded and mixed-case values to ensure normalization.
var (
	configDeployed         = &Config{BaseDomain: " EXAMPLE.ORG "}
	configNoBaseDomain     = &Config{}
	configRedirectURL      = &Config{RedirectURL: " " + portalURL + " ", BaseDomain: baseDomain}
	configBlankRedirectURL = &Config{RedirectURL: "   ", BaseDomain: baseDomain}
	configCustomHeader     = &Config{ValidityHeader: " X-Valid ", BaseDomain: baseDomain}
)

// The plugin logs on every New and every request
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// verdict builds the headers callsign-validity sets upstream; "" omits a header.
func verdict(validity, reason string) http.Header {
	headers := http.Header{}
	if validity != "" {
		headers.Set(defaultValidityHeader, validity)
	}
	if reason != "" {
		headers.Set(reasonHeader, reason)
	}
	return headers
}

type serveHTTPCase struct {
	name          string
	config        *Config
	method        string
	target        string
	host          string
	overTLS       bool
	backendPanics bool
	headers       http.Header
	wantForwarded bool
	wantStatus    int
	wantLocation  string
}

// newRequest builds the incoming request.
func (testCase serveHTTPCase) newRequest() *http.Request {
	method, target := testCase.method, testCase.target
	if method == "" {
		method = http.MethodGet
	}
	if target == "" {
		target = "/"
	}
	request := httptest.NewRequest(method, target, nil)
	request.Host = testCase.host
	request.TLS = nil
	if testCase.overTLS {
		request.TLS = &tls.ConnectionState{}
	}
	for name, values := range testCase.headers {
		request.Header[name] = values
	}
	return request
}

func TestServeHTTP(t *testing.T) {
	invalidVerdict := verdict("false", "no_cert")

	testCases := []serveHTTPCase{
		// A valid verdict is forwarded untouched.
		{name: "true", config: configDeployed, host: mtlsHost, headers: verdict("true", ""), wantForwarded: true, wantStatus: 200},
		{name: "TRUE", config: configDeployed, host: mtlsHost, headers: verdict("TRUE", ""), wantForwarded: true, wantStatus: 200},
		{name: "true with padding", config: configDeployed, host: mtlsHost, headers: verdict("\t true \t", ""), wantForwarded: true, wantStatus: 200},
		{name: "custom validity header", config: configCustomHeader, host: mtlsHost, headers: http.Header{"X-Valid": {"true"}}, wantForwarded: true, wantStatus: 200},
		{name: "panic in the backend fails closed", config: configDeployed, host: mtlsHost, headers: verdict("true", ""), backendPanics: true, wantForwarded: true, wantStatus: 500},

		// nothing else may be forwarded.
		{name: "false", config: configDeployed, host: mtlsHost, headers: verdict("false", ""), wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "no validity header", config: configDeployed, host: mtlsHost, headers: nil, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "truex", config: configDeployed, host: mtlsHost, headers: verdict("truex", ""), wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "yes", config: configDeployed, host: mtlsHost, headers: verdict("yes", ""), wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "multi-value keeps the first", config: configDeployed, host: mtlsHost, headers: http.Header{defaultValidityHeader: {"false", "true"}}, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "default header does not satisfy a custom one", config: configCustomHeader, host: mtlsHost, headers: verdict("true", ""), wantStatus: 302, wantLocation: mtlsFailURL},

		// The reason picks the /error code, case-insensitively and trimmed.
		{name: "reason invalid", config: configDeployed, host: mtlsHost, headers: verdict("false", reasonInvalid), wantStatus: 302, wantLocation: unauthorizedURL},
		{name: "reason invalid padded and uppercase", config: configDeployed, host: mtlsHost, headers: verdict("false", " INVALID "), wantStatus: 302, wantLocation: unauthorizedURL},
		{name: "reason error drops the code", config: configDeployed, host: mtlsHost, headers: verdict("false", reasonError), wantStatus: 302, wantLocation: errorURLNoCode},
		{name: "reason error padded and uppercase", config: configDeployed, host: mtlsHost, headers: verdict("false", " ERROR "), wantStatus: 302, wantLocation: errorURLNoCode},
		{name: "reason no_cert", config: configDeployed, host: mtlsHost, headers: invalidVerdict, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "client-supplied reason is not trusted", config: configDeployed, host: mtlsHost, headers: verdict("false", "ok"), wantStatus: 302, wantLocation: mtlsFailURL},

		// Target derivation from the request host.
		{name: "tls yields https", config: configDeployed, host: mtlsHost, overTLS: true, headers: invalidVerdict, wantStatus: 302, wantLocation: httpsFailURL},
		{name: "port is preserved", config: configDeployed, host: mtlsHost + ":8443", headers: invalidVerdict, wantStatus: 302, wantLocation: portPreservedFailURL},
		{name: "empty base domain is permissive", config: configNoBaseDomain, host: "mtls.whatever.test", headers: invalidVerdict, wantStatus: 302, wantLocation: permissiveHostFailURL},
		{name: "nil config is permissive", config: nil, host: mtlsHost, headers: invalidVerdict, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "host case is preserved in the target", config: configDeployed, host: "MTLS.Example.ORG", headers: invalidVerdict, wantStatus: 302, wantLocation: mixedCaseHostFailURL},
		{name: "original path and query are discarded", config: configDeployed, host: mtlsHost, target: "/foo/bar?x=1", headers: invalidVerdict, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "non-GET is redirected too", config: configDeployed, host: mtlsHost, method: http.MethodPost, headers: invalidVerdict, wantStatus: 302, wantLocation: mtlsFailURL},

		// no derivable target means deny, never pass through.
		{name: "non-mtls host", config: configDeployed, host: "app." + baseDomain, headers: invalidVerdict, wantStatus: 403},
		{name: "bare base domain", config: configDeployed, host: baseDomain, headers: invalidVerdict, wantStatus: 403},
		{name: "base domain mismatch", config: configDeployed, host: "mtls.other.test", headers: invalidVerdict, wantStatus: 403},
		{name: "empty host", config: configDeployed, host: "", headers: invalidVerdict, wantStatus: 403},
		{name: "whitespace host", config: configDeployed, host: "   ", headers: invalidVerdict, wantStatus: 403},
		{name: "mtls prefix only", config: configDeployed, host: "mtls.", headers: invalidVerdict, wantStatus: 403},
		{name: "mtls prefix only with port", config: configDeployed, host: "mtls.:8443", headers: invalidVerdict, wantStatus: 403},
		{name: "prefix must include the dot", config: configNoBaseDomain, host: "mtlsx." + baseDomain, headers: invalidVerdict, wantStatus: 403},
		{name: "prefix is not matched mid-host", config: configNoBaseDomain, host: "sub.mtls." + baseDomain, headers: invalidVerdict, wantStatus: 403},

		// redirectURL escape hatch.
		{name: "redirectURL rescues a denied host", config: configRedirectURL, host: "app.other.test", headers: invalidVerdict, wantStatus: 302, wantLocation: portalURL},
		{name: "redirectURL wins over the computed target", config: configRedirectURL, host: mtlsHost, headers: invalidVerdict, wantStatus: 302, wantLocation: portalURL},
		{name: "redirectURL takes no reason code", config: configRedirectURL, host: mtlsHost, headers: verdict("false", reasonInvalid), wantStatus: 302, wantLocation: portalURL},
		{name: "blank redirectURL falls through", config: configBlankRedirectURL, host: mtlsHost, headers: invalidVerdict, wantStatus: 302, wantLocation: mtlsFailURL},
		{name: "blank redirectURL still denies", config: configBlankRedirectURL, host: "app." + baseDomain, headers: invalidVerdict, wantStatus: 403},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// The protected backend: records the request it was handed, if it is reached at all.
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

			if forwarded := backendRequest != nil; forwarded != testCase.wantForwarded {
				t.Errorf("forwarded to backend = %t, want %t", forwarded, testCase.wantForwarded)
			}
			if recorder.Code != testCase.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, testCase.wantStatus)
			}
			if location := recorder.Header().Get("Location"); location != testCase.wantLocation {
				t.Errorf("Location = %q, want %q", location, testCase.wantLocation)
			}
			if recorder.Code == http.StatusForbidden && recorder.Body.Len() != 0 {
				t.Errorf("403 body = %q, want empty", recorder.Body.String())
			}
		})
	}
}

func TestNewRejectsNilNext(t *testing.T) {
	plugin, err := New(context.Background(), nil, CreateConfig(), "test")
	if err == nil || plugin != nil {
		t.Fatalf("got (%T, %v), want (nil, error)", plugin, err)
	}
}

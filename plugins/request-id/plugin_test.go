package traefik_request_id

import (
	"context"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	spoofedRequestID = "0123456789abcdef0123456789abcdef" // pragma: allowlist secret
	customHeader     = "X-Trace-Id"
)

// Ensure normalization.
var (
	configDefault      = CreateConfig()
	configBlankHeader  = &Config{HeaderName: "  "}
	configCustomHeader = &Config{HeaderName: " " + customHeader + " "}
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func spoofedHeaders() http.Header {
	headers := http.Header{}
	headers[defaultRequestIDHeader] = []string{spoofedRequestID, spoofedRequestID}
	headers.Set(customHeader, spoofedRequestID)
	return headers
}

func assertGeneratedID(t *testing.T, header http.Header, name string) {
	t.Helper()
	values := header.Values(name)
	if len(values) != 1 {
		t.Fatalf("%s = %v, want exactly one value", name, values)
	}
	if values[0] == spoofedRequestID {
		t.Errorf("%s = %q, want the client-supplied value to be overwritten", name, values[0])
	}
	raw, err := hex.DecodeString(values[0])
	if err != nil {
		t.Errorf("%s = %q, want lowercase hex: %v", name, values[0], err)
	}
	if len(raw) != requestIDBytes {
		t.Errorf("%s decoded to %d bytes, want %d", name, len(raw), requestIDBytes)
	}
}

func TestServeHTTP(t *testing.T) {
	testCases := []struct {
		name          string
		config        *Config
		wantHeader    string
		backendPanics bool
		wantStatus    int
	}{
		{name: "default header", config: configDefault, wantHeader: defaultRequestIDHeader},
		{name: "custom header name", config: configCustomHeader, wantHeader: customHeader},
		{name: "blank header name falls back", config: configBlankHeader, wantHeader: defaultRequestIDHeader},
		{name: "nil config falls back", config: nil, wantHeader: defaultRequestIDHeader},
		{name: "panic in the backend fails closed", config: configDefault, wantHeader: defaultRequestIDHeader, backendPanics: true, wantStatus: 500},
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

			request, recorder := httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder()
			for name, values := range spoofedHeaders() {
				request.Header[name] = values
			}
			plugin.ServeHTTP(recorder, request)

			if backendRequest == nil {
				t.Fatal("request was not forwarded to the backend")
			}
			assertGeneratedID(t, backendRequest.Header, testCase.wantHeader)

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

func TestServeHTTPGeneratesAFreshIDPerRequest(t *testing.T) {
	seen := map[string]bool{}
	backend := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		seen[request.Header.Get(defaultRequestIDHeader)] = true
	})

	plugin, err := New(context.Background(), backend, configDefault, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 5; i++ {
		plugin.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	if len(seen) != 5 {
		t.Errorf("got %d distinct ids over 5 requests, want 5", len(seen))
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

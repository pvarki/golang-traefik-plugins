// Package yaegiverify runs each plugin's behavioural cases against both the
// compiled package and the Yaegi interpreter that Traefik runs in production.
package yaegiverify

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
)

// Suite is the contents of a plugin's testdata/cases.json.
type Suite struct {
	Config map[string]any `json:"config"`
	Cases  []Case         `json:"cases"`
}

// Case is one request driven through the middleware.
type Case struct {
	Name string `json:"name"`
	// Config overrides the suite config for this case.
	Config         map[string]any    `json:"config"`
	Method         string            `json:"method"`
	Target         string            `json:"target"`
	Host           string            `json:"host"`
	RequestHeaders map[string]string `json:"requestHeaders"`
	// TLS selects how req.TLS is built: none, empty, peer or verified.
	TLS    string `json:"tls"`
	Expect Expect `json:"expect"`
}

// Expect is what the middleware should do with the request.
type Expect struct {
	Forwarded             bool              `json:"forwarded"`
	Status                int               `json:"status"`
	ResponseHeaders       map[string]string `json:"responseHeaders"`
	RequestHeaders        map[string]string `json:"requestHeaders"`
	RequestHeadersAbsent  []string          `json:"requestHeadersAbsent"`
	RequestHeaderPatterns map[string]string `json:"requestHeaderPatterns"`
}

// LoadSuite reads the cases for one plugin directory.
func LoadSuite(dir string) (Suite, error) {
	var suite Suite
	raw, err := os.ReadFile(filepath.Join(dir, "testdata", "cases.json"))
	if err != nil {
		return suite, err
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		return suite, fmt.Errorf("parse cases.json: %w", err)
	}
	return suite, nil
}

// LoadLeaf reads the optional fixture certificate a case attaches to req.TLS.
// It is a file rather than a generated cert so the expected DN, serial and
// fingerprint in cases.json can be written literally.
func LoadLeaf(dir string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "testdata", "leaf.pem"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("leaf.pem is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (c Case) request(leaf *x509.Certificate) (*http.Request, error) {
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	target := c.Target
	if target == "" {
		target = "https://example.org/"
	}
	req := httptest.NewRequest(method, target, nil)
	if c.Host != "" {
		req.Host = c.Host
	}
	for name, value := range c.RequestHeaders {
		req.Header.Set(name, value)
	}

	switch c.TLS {
	case "", "none":
		req.TLS = nil
	case "empty":
		req.TLS = &tls.ConnectionState{}
	case "peer":
		if leaf == nil {
			return nil, fmt.Errorf("case %q needs testdata/leaf.pem", c.Name)
		}
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	case "verified":
		if leaf == nil {
			return nil, fmt.Errorf("case %q needs testdata/leaf.pem", c.Name)
		}
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		}
	default:
		return nil, fmt.Errorf("case %q has unknown tls mode %q", c.Name, c.TLS)
	}
	return req, nil
}

// Builder constructs the middleware around next. Each engine supplies one.
type Builder func(next http.Handler) (http.Handler, error)

// Run drives one case through the middleware and reports every mismatch.
func (c Case) Run(build Builder, leaf *x509.Certificate) []string {
	req, err := c.request(leaf)
	if err != nil {
		return []string{err.Error()}
	}

	forwarded := false
	var seen http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		forwarded = true
		seen = r.Header.Clone()
	})

	handler, err := build(next)
	if err != nil {
		return []string{fmt.Sprintf("build middleware: %v", err)}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	var problems []string
	if forwarded != c.Expect.Forwarded {
		problems = append(problems, fmt.Sprintf("forwarded = %v, want %v", forwarded, c.Expect.Forwarded))
	}
	if c.Expect.Status != 0 && recorder.Code != c.Expect.Status {
		problems = append(problems, fmt.Sprintf("status = %d, want %d", recorder.Code, c.Expect.Status))
	}
	for name, want := range c.Expect.ResponseHeaders {
		if got := recorder.Header().Get(name); got != want {
			problems = append(problems, fmt.Sprintf("response header %s = %q, want %q", name, got, want))
		}
	}
	// Header assertions read from what the next handler saw, since the
	// middleware mutates the request in place before forwarding.
	if seen == nil {
		seen = req.Header
	}
	for name, want := range c.Expect.RequestHeaders {
		if got := seen.Get(name); got != want {
			problems = append(problems, fmt.Sprintf("request header %s = %q, want %q", name, got, want))
		}
	}
	for _, name := range c.Expect.RequestHeadersAbsent {
		if got := seen.Get(name); got != "" {
			problems = append(problems, fmt.Sprintf("request header %s = %q, want it absent", name, got))
		}
	}
	for name, pattern := range c.Expect.RequestHeaderPatterns {
		got := seen.Get(name)
		ok, err := regexp.MatchString(pattern, got)
		if err != nil {
			problems = append(problems, fmt.Sprintf("bad pattern for %s: %v", name, err))
			continue
		}
		if !ok {
			problems = append(problems, fmt.Sprintf("request header %s = %q, want match %s", name, got, pattern))
		}
	}
	return problems
}

// Factory produces a Builder for a given plugin configuration.
type Factory func(config map[string]any) Builder

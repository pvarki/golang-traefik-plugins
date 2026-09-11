package main

import "testing"

func TestDecide(t *testing.T) {
	base := Config{BaseDomain: "example.org"}.settings()
	pinned := Config{RedirectURL: "https://elsewhere.test/denied"}.settings()

	testCases := []struct {
		name     string
		set      settings
		valid    string
		reason   string
		host     string
		proto    string
		wantFwd  bool
		wantDest string
	}{
		{name: "valid forwards", set: base, valid: "true", host: "mtls.example.org", wantFwd: true},
		{name: "valid is case insensitive", set: base, valid: "TRUE", host: "mtls.example.org", wantFwd: true},
		{name: "valid is trimmed", set: base, valid: "  true  ", host: "mtls.example.org", wantFwd: true},

		{name: "invalid redirects to unauthorized", set: base, valid: "false", reason: "invalid",
			host: "mtls.example.org", wantDest: "https://example.org/error?code=unauthorized"},
		{name: "no_cert redirects to mtls_fail", set: base, valid: "false", reason: "no_cert",
			host: "mtls.example.org", wantDest: "https://example.org/error?code=mtls_fail"},
		{name: "error gets the generic page", set: base, valid: "false", reason: "error",
			host: "mtls.example.org", wantDest: "https://example.org/error"},
		{name: "missing reason defaults to mtls_fail", set: base, valid: "false",
			host: "mtls.example.org", wantDest: "https://example.org/error?code=mtls_fail"},

		{name: "port is preserved", set: base, valid: "false", reason: "invalid",
			host: "mtls.example.org:8443", wantDest: "https://example.org:8443/error?code=unauthorized"},
		{name: "forwarded proto http is honoured", set: base, valid: "false", reason: "invalid",
			host: "mtls.example.org", proto: "http", wantDest: "http://example.org/error?code=unauthorized"},

		{name: "redirectURL wins", set: pinned, valid: "false", reason: "invalid",
			host: "mtls.example.org", wantDest: "https://elsewhere.test/denied"},

		// No target: the caller must deny rather than forward.
		{name: "host without the mtls prefix denies", set: base, valid: "false", reason: "invalid",
			host: "example.org", wantDest: ""},
		{name: "host not matching baseDomain denies", set: base, valid: "false", reason: "invalid",
			host: "mtls.other.test", wantDest: ""},
		{name: "empty host denies", set: base, valid: "false", reason: "invalid", host: "", wantDest: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := decide(tc.set, tc.valid, tc.reason, tc.host, tc.proto)
			if got.Forward != tc.wantFwd {
				t.Fatalf("Forward = %v, want %v", got.Forward, tc.wantFwd)
			}
			if got.Location != tc.wantDest {
				t.Errorf("Location = %q, want %q", got.Location, tc.wantDest)
			}
		})
	}
}

// An unset baseDomain accepts any mtls.* host.
func TestDecideWithoutBaseDomain(t *testing.T) {
	set := Config{}.settings()
	got := decide(set, "false", "invalid", "mtls.anything.test", "")
	if got.Location != "https://anything.test/error?code=unauthorized" {
		t.Errorf("Location = %q", got.Location)
	}
}

func TestSettingsDefaults(t *testing.T) {
	set := Config{}.settings()
	if set.validityHeader != defaultValidityHeader {
		t.Errorf("validityHeader = %q", set.validityHeader)
	}
	if set.redirectStatus != defaultRedirectStatus {
		t.Errorf("redirectStatus = %d, want %d", set.redirectStatus, defaultRedirectStatus)
	}
	if got := (Config{RedirectStatus: 301}).settings().redirectStatus; got != 301 {
		t.Errorf("redirectStatus = %d, want 301", got)
	}
	if got := (Config{RedirectStatus: -5}).settings().redirectStatus; got != defaultRedirectStatus {
		t.Errorf("negative redirectStatus = %d, want the default", got)
	}
}

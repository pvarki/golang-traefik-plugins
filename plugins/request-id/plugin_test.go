package main

import "testing"

func TestConfigHeaderName(t *testing.T) {
	testCases := []struct {
		name   string
		config Config
		want   string
	}{
		{name: "unset falls back", config: Config{}, want: defaultRequestIDHeader},
		{name: "whitespace falls back", config: Config{HeaderName: "  \t "}, want: defaultRequestIDHeader},
		{name: "custom is trimmed", config: Config{HeaderName: "  X-Trace  "}, want: "X-Trace"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.headerName(); got != tc.want {
				t.Errorf("headerName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewRequestIDIsUniqueHex(t *testing.T) {
	seen := make(map[string]bool, 128)
	for i := 0; i < 128; i++ {
		id, err := newRequestID()
		if err != nil {
			t.Fatalf("newRequestID: %v", err)
		}
		if len(id) != requestIDBytes*2 {
			t.Fatalf("id %q has length %d, want %d", id, len(id), requestIDBytes*2)
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}

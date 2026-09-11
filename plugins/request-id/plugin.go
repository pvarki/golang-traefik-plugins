// Package main stamps every request with a fresh random id, replacing any
// client-supplied value.
package main

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/pvarki/golang-traefik-plugins/internal/guest"
)

const (
	defaultRequestIDHeader = "X-Request-ID"
	requestIDBytes         = 16
)

// Config is the middleware configuration from the Traefik Middleware CR.
type Config struct {
	HeaderName string `json:"headerName,omitempty"`
}

func (c Config) headerName() string {
	return guest.OrDefault(c.HeaderName, defaultRequestIDHeader)
}

func newRequestID() (string, error) {
	buf := make([]byte, requestIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func main() {}

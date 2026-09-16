package request_id

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
)

const (
	defaultRequestIDHeader = "X-Request-ID"
	requestIDBytes         = 16
)

type Config struct {
	HeaderName string `json:"headerName,omitempty"`
}

func CreateConfig() *Config {
	return &Config{HeaderName: defaultRequestIDHeader}
}

type Plugin struct {
	next       http.Handler
	name       string
	logPrefix  string
	headerName string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logPrefix := pluginLogPrefix(name)
	if next == nil {
		err := errors.New("next handler is nil")
		log.Printf("ERROR %s initialization failed: %v", logPrefix, err)

		return nil, err
	}

	if config == nil {
		log.Printf("WARN %s received nil config, using defaults", logPrefix)
		config = CreateConfig()
	}

	headerName := normalizeHeaderName(config.HeaderName, defaultRequestIDHeader)

	log.Printf("INFO %s initialized with header %q", logPrefix, headerName)

	return &Plugin{
		next:       next,
		name:       name,
		logPrefix:  logPrefix,
		headerName: headerName,
	}, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf(
				"ERROR %s panic while handling request: %v\n%s",
				p.logPrefix,
				recovered,
				string(debug.Stack()),
			)
			if rw != nil {
				http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()

	if req == nil {
		log.Printf("ERROR %s received nil request, aborting", p.logPrefix)
		if rw != nil {
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		return
	}

	if requestID, err := newRequestID(); err == nil {
		req.Header.Set(p.headerName, requestID)
	} else {
		req.Header.Del(p.headerName)
		log.Printf("WARN %s could not generate a request id: %v", p.logPrefix, err)
	}

	p.next.ServeHTTP(rw, req)
}

func pluginLogPrefix(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unnamed"
	}

	return fmt.Sprintf("request-id[%s]", name)
}

func normalizeHeaderName(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	return value
}

func newRequestID() (string, error) {
	buf := make([]byte, requestIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

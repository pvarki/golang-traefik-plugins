package yaegiverify

import (
	"context"
	"net/http"
	"reflect"

	redirect "github.com/pvarki/golang-traefik-plugins/plugins/callsign-redirect"
	legacy "github.com/pvarki/golang-traefik-plugins/plugins/legacy-mtls-headers"
	requestid "github.com/pvarki/golang-traefik-plugins/plugins/request-id"
)

// NativeFactories builds each plugin from its compiled package, so the same
// cases run against the compiler and the interpreter.
var NativeFactories = map[string]Factory{
	"request-id": func(config map[string]any) Builder {
		return func(next http.Handler) (http.Handler, error) {
			cfg := requestid.CreateConfig()
			if err := applyConfig(reflect.ValueOf(cfg), config); err != nil {
				return nil, err
			}
			return requestid.New(context.Background(), next, cfg, "yaegiverify")
		}
	},
	"callsign-redirect": func(config map[string]any) Builder {
		return func(next http.Handler) (http.Handler, error) {
			cfg := redirect.CreateConfig()
			if err := applyConfig(reflect.ValueOf(cfg), config); err != nil {
				return nil, err
			}
			return redirect.New(context.Background(), next, cfg, "yaegiverify")
		}
	},
	"legacy-mtls-headers": func(config map[string]any) Builder {
		return func(next http.Handler) (http.Handler, error) {
			cfg := legacy.CreateConfig()
			if err := applyConfig(reflect.ValueOf(cfg), config); err != nil {
				return nil, err
			}
			return legacy.New(context.Background(), next, cfg, "yaegiverify")
		}
	},
}

// Plugins is the set under verification.
var Plugins = []struct {
	Name       string
	Dir        string
	ModuleName string
}{
	{"request-id", "../../plugins/request-id", "github.com/pvarki/golang-traefik-plugins/plugins/request-id"},
	{"callsign-redirect", "../../plugins/callsign-redirect", "github.com/pvarki/golang-traefik-plugins/plugins/callsign-redirect"},
	{"legacy-mtls-headers", "../../plugins/legacy-mtls-headers", "github.com/pvarki/golang-traefik-plugins/plugins/legacy-mtls-headers"},
}

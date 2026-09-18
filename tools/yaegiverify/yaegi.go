package yaegiverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

// BasePkg derives the package name Traefik evaluates against, matching
// Manifest.BasePkg's default in pkg/plugins/types.go.
func BasePkg(importPath string) string {
	return strings.ReplaceAll(path.Base(importPath), "-", "_")
}

// InterpretedFactory loads a plugin the way Traefik does: stage the source
// under <goPath>/src/<moduleName>, evaluate an import of it, then resolve
// <basePkg>.CreateConfig and <basePkg>.New by reflection. The interpreter is
// set up once and reused for every case.
func InterpretedFactory(dir, moduleName string) (Factory, error) {
	goPath, err := stageSource(dir, moduleName)
	if err != nil {
		return nil, err
	}

	i := interp.New(interp.Options{GoPath: goPath})
	if err := i.Use(stdlib.Symbols); err != nil {
		return nil, fmt.Errorf("load stdlib symbols: %w", err)
	}
	if _, err := i.Eval(fmt.Sprintf("import %q", moduleName)); err != nil {
		return nil, fmt.Errorf("interpret %s: %w", moduleName, err)
	}

	basePkg := BasePkg(moduleName)
	fnCreate, err := i.Eval(basePkg + ".CreateConfig")
	if err != nil {
		return nil, fmt.Errorf("resolve %s.CreateConfig: %w", basePkg, err)
	}
	fnNew, err := i.Eval(basePkg + ".New")
	if err != nil {
		return nil, fmt.Errorf("resolve %s.New: %w", basePkg, err)
	}

	return func(config map[string]any) Builder {
		return func(next http.Handler) (http.Handler, error) {
			return buildInterpreted(fnCreate, fnNew, config, next)
		}
	}, nil
}

func buildInterpreted(fnCreate, fnNew reflect.Value, config map[string]any, next http.Handler) (http.Handler, error) {
	created := fnCreate.Call(nil)
	if len(created) != 1 {
		return nil, fmt.Errorf("plugin CreateConfig returned %d values", len(created))
	}
	cfg := created[0]
	if err := applyConfig(cfg, config); err != nil {
		return nil, err
	}

	results := fnNew.Call([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(next),
		cfg,
		reflect.ValueOf("yaegiverify"),
	})
	if len(results) != 2 {
		return nil, fmt.Errorf("plugin New returned %d values", len(results))
	}
	if err, ok := results[1].Interface().(error); ok && err != nil {
		return nil, err
	}
	handler, ok := results[0].Interface().(http.Handler)
	if !ok {
		return nil, errors.New("plugin New did not return an http.Handler")
	}
	return handler, nil
}

// stageSource copies the plugin's non-test sources into a throwaway GOPATH.
func stageSource(dir, moduleName string) (string, error) {
	goPath, err := os.MkdirTemp("", "yaegiverify")
	if err != nil {
		return "", err
	}
	target := filepath.Join(goPath, "src", filepath.FromSlash(moduleName))
	if err := os.MkdirAll(target, 0o750); err != nil {
		return "", err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		name := filepath.Base(entry.Name())
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// #nosec G304 -- developer tool reading its own repository
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		// #nosec G703 -- developer tool; target is a fresh temp dir and name is a base name
		if err := os.WriteFile(filepath.Join(target, name), raw, 0o600); err != nil {
			return "", err
		}
	}
	return goPath, nil
}

// applyConfig sets the fields Traefik would have decoded from the Middleware CR.
func applyConfig(cfg reflect.Value, config map[string]any) error {
	if cfg.Kind() != reflect.Pointer {
		return fmt.Errorf("CreateConfig returned %s, want a pointer", cfg.Kind())
	}
	target := cfg.Elem()
	for key, value := range config {
		field := target.FieldByNameFunc(func(name string) bool {
			return strings.EqualFold(name, key)
		})
		if !field.IsValid() || !field.CanSet() {
			return fmt.Errorf("config key %q has no settable field", key)
		}
		switch field.Kind() {
		case reflect.String:
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("config key %q wants a string", key)
			}
			field.SetString(text)
		case reflect.Int:
			number, ok := value.(float64)
			if !ok {
				return fmt.Errorf("config key %q wants a number", key)
			}
			field.SetInt(int64(number))
		default:
			return fmt.Errorf("config key %q has unsupported kind %s", key, field.Kind())
		}
	}
	return nil
}

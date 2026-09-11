// Command wasmverify checks that a built plugin is loadable by wazero, the
// runtime Traefik embeds, and exports the http-wasm entry points.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
)

var required = []string{"handle_request", "handle_response", "_initialize"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wasmverify <plugin.wasm>...")
		os.Exit(2)
	}
	failed := false
	for _, path := range os.Args[1:] {
		if err := verify(path); err != nil {
			fmt.Printf("FAIL %s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Printf("ok   %s\n", path)
	}
	if failed {
		os.Exit(1)
	}
}

func verify(path string) error {
	// #nosec G304,G703 -- developer tool; the path is a command line argument
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer func() { _ = runtime.Close(ctx) }()

	compiled, err := runtime.CompileModule(ctx, data)
	if err != nil {
		return fmt.Errorf("wazero cannot compile the module: %w", err)
	}
	exported := compiled.ExportedFunctions()
	for _, name := range required {
		if _, ok := exported[name]; !ok {
			return fmt.Errorf("missing export %q", name)
		}
	}
	return nil
}

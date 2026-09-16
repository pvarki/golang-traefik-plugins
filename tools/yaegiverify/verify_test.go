package yaegiverify_test

import (
	"testing"

	verify "github.com/pvarki/golang-traefik-plugins/tools/yaegiverify"
)

// TestEnginesAgree runs every case in every plugin's testdata/cases.json
// against both the compiled package and the Yaegi interpreter Traefik uses.
// Adding a case covers both engines; neither can drift from the other.
func TestEnginesAgree(t *testing.T) {
	for _, plugin := range verify.Plugins {
		t.Run(plugin.Name, func(t *testing.T) {
			suite, err := verify.LoadSuite(plugin.Dir)
			if err != nil {
				t.Fatalf("load cases: %v", err)
			}
			if len(suite.Cases) == 0 {
				t.Fatal("no cases; the suite would pass vacuously")
			}
			leaf, err := verify.LoadLeaf(plugin.Dir)
			if err != nil {
				t.Fatalf("load leaf: %v", err)
			}

			native, ok := verify.NativeFactories[plugin.Name]
			if !ok {
				t.Fatalf("no native factory for %s", plugin.Name)
			}
			interpreted, err := verify.InterpretedFactory(plugin.Dir, plugin.ModuleName)
			if err != nil {
				t.Fatalf("load under yaegi: %v", err)
			}

			engines := map[string]verify.Factory{"compiled": native, "yaegi": interpreted}
			for _, testCase := range suite.Cases {
				config := testCase.Config
				if config == nil {
					config = suite.Config
				}
				for engineName, factory := range engines {
					t.Run(testCase.Name+"/"+engineName, func(t *testing.T) {
						for _, problem := range testCase.Run(factory(config), leaf) {
							t.Error(problem)
						}
					})
				}
			}
		})
	}
}

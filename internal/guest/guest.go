// Package guest holds helpers shared by the wasm plugin entry points.
package guest

import "strings"

// OrDefault trims value and falls back when it is empty.
func OrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// SecondsOr converts a configured timeout, falling back when unset or absurd.
func SecondsOr(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

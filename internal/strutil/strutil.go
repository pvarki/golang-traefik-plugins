// Package strutil holds small string helpers shared by the plugins.
package strutil

import "strings"

// OrDefault trims value and falls back when it is empty.
func OrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// Package evidence provides helpers for building and redacting evidence records.
package evidence

import (
	"regexp"
	"strings"
)

// Secret-like JSON keys whose values are replaced with a redaction marker.
var secretKeyPattern = regexp.MustCompile(`(?i)"([^"]*(?:password|secret|token|privatekey|private_key|apikey|api_key|accesskey|access_key|credential|passwd|pwd|sessiontoken)[^"]*)"\s*:\s*"(?:[^"\\]|\\.)*"`)

// AWS secret access key heuristics (40-char base64-ish) and access key ids.
var akidPattern = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)

// Redacted is the marker inserted in place of a redacted value.
const Redacted = "[REDACTED]"

// Redact removes likely secret values from a raw document string. It preserves
// structure so evidence remains inspectable without leaking sensitive data.
func Redact(doc string) string {
	out := secretKeyPattern.ReplaceAllStringFunc(doc, func(m string) string {
		idx := strings.Index(m, ":")
		if idx < 0 {
			return m
		}
		return m[:idx+1] + `"` + Redacted + `"`
	})
	out = akidPattern.ReplaceAllString(out, Redacted)
	return out
}

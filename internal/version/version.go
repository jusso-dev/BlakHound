// Package version exposes build metadata for BlakHound.
package version

// These values are overridden at build time via -ldflags.
var (
	Version   = "0.1.0-dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// SchemaVersion is the SQLite schema version BlakHound expects.
const SchemaVersion = 1

// RuleSetVersion is the version of the embedded attack-rule set.
const RuleSetVersion = 1

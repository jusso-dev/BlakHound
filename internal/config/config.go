// Package config holds BlakHound runtime configuration derived from global CLI
// flags and the environment. AWS secret keys are never stored here.
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config carries options shared across commands.
type Config struct {
	Profile    string
	Region     string
	Regions    []string
	AllRegions bool
	AccountID  string
	RoleARN    string
	ExternalID string
	DBPath     string
	Output     string // table|json|yaml
	LogLevel   string
	NoColor    bool
	Quiet      bool
}

// DefaultDBPath returns ~/.blakhound/blakhound.db.
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".blakhound", "blakhound.db")
	}
	return filepath.Join(home, ".blakhound", "blakhound.db")
}

// Normalize fills defaults and splits comma lists.
func (c *Config) Normalize() {
	if c.DBPath == "" {
		c.DBPath = DefaultDBPath()
	}
	if c.Output == "" {
		c.Output = "table"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	c.DBPath = expandHome(c.DBPath)
}

// SplitList splits a comma-separated flag value, trimming blanks.
func SplitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

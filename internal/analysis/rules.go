// Package analysis contains the deterministic attack-path analysis engine:
// edge derivation, path finding and rule-based findings. Rules are declarative
// YAML metadata; detection logic lives in Go so YAML can never execute code.
package analysis

import (
	"embed"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

// Rule is declarative metadata describing a detection. It carries no executable
// logic; the matching function that consumes actions/edges is written in Go.
type Rule struct {
	ID               string   `yaml:"id"`
	Title            string   `yaml:"title"`
	Category         string   `yaml:"category"`
	Severity         string   `yaml:"severity"`
	Description      string   `yaml:"description"`
	Actions          []string `yaml:"actions"`
	CompanionActions []string `yaml:"companion_actions"`
	Edges            []string `yaml:"edges"`
	Remediation      string   `yaml:"remediation"`
}

// LoadRules parses all embedded rule files, sorted by ID for determinism.
func LoadRules() (map[string]Rule, error) {
	entries, err := rulesFS.ReadDir("rules")
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	out := map[string]Rule{}
	for _, e := range entries {
		b, err := rulesFS.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", e.Name(), err)
		}
		var rules []Rule
		if err := yaml.Unmarshal(b, &rules); err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", e.Name(), err)
		}
		for _, r := range rules {
			if r.ID == "" {
				return nil, fmt.Errorf("rule in %s missing id", e.Name())
			}
			out[r.ID] = r
		}
	}
	return out, nil
}

// SortedRuleIDs returns rule IDs in stable order.
func SortedRuleIDs(rules map[string]Rule) []string {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

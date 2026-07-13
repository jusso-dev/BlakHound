package cli

import (
	"encoding/json"
	"testing"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

func TestFilterFindingsEmptyJSON(t *testing.T) {
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	filtered := filterFindings(findings, models.SeverityLow, "")
	b, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Fatalf("expected empty JSON array, got %s", b)
	}
}

func TestCollectCommandIncludesAllRegionsFlag(t *testing.T) {
	cmd := newCollectCmd()
	if cmd.Flags().Lookup("all-regions") == nil {
		t.Fatal("collect command is missing --all-regions")
	}
	if cmd.Flags().Lookup("force") == nil {
		t.Fatal("collect command is missing --force")
	}
}

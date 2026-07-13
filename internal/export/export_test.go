package export

import (
	"strings"
	"testing"

	"github.com/blakhound/blakhound/pkg/models"
)

func TestMermaidEscapeNeutralisesInjection(t *testing.T) {
	g := Graph{Nodes: []models.Node{
		{ID: "a", Name: `evil"]--x-->y["`, Type: "iam-user"},
	}}
	out := Mermaid(g)
	if strings.Contains(out, `evil"]`) {
		t.Fatalf("unescaped quote/bracket leaked: %s", out)
	}
	if !strings.Contains(out, "#quot;") {
		t.Fatalf("expected escaped quote marker: %s", out)
	}
}

func TestMermaidTruncationWarning(t *testing.T) {
	g := Graph{Truncated: true}
	if !strings.Contains(Mermaid(g), "truncated") {
		t.Fatal("expected truncation notice")
	}
}

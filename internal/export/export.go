// Package export renders graphs and paths to JSON, Mermaid and Graphviz DOT.
// User-controlled names are escaped to keep output safe.
package export

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

// DefaultMaxNodes bounds graph exports to keep output readable.
const DefaultMaxNodes = 100

// Graph is a renderable node/edge set.
type Graph struct {
	Nodes     []models.Node
	Edges     []models.Edge
	Truncated bool
}

// Mermaid renders a flowchart. Node ids are sanitised; labels are escaped.
func Mermaid(g Graph) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	nodes := append([]models.Node{}, g.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	ids := map[string]string{}
	for i, n := range nodes {
		key := fmt.Sprintf("n%d", i)
		ids[n.ID] = key
		fmt.Fprintf(&b, "    %s[\"%s\"]\n", key, mermaidEscape(label(n)))
	}
	edges := append([]models.Edge{}, g.Edges...)
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	for _, e := range edges {
		from, ok1 := ids[e.FromNodeID]
		to, ok2 := ids[e.ToNodeID]
		if !ok1 || !ok2 {
			continue
		}
		fmt.Fprintf(&b, "    %s -->|\"%s\"| %s\n", from, mermaidEscape(e.Type), to)
	}
	if g.Truncated {
		b.WriteString("    %% output truncated: node limit reached\n")
	}
	return b.String()
}

// DOT renders Graphviz DOT.
func DOT(g Graph) string {
	var b strings.Builder
	b.WriteString("digraph blakhound {\n  rankdir=LR;\n  node [shape=box];\n")
	nodes := append([]models.Node{}, g.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	ids := map[string]string{}
	for i, n := range nodes {
		key := fmt.Sprintf("n%d", i)
		ids[n.ID] = key
		fmt.Fprintf(&b, "  %s [label=%q];\n", key, label(n))
	}
	edges := append([]models.Edge{}, g.Edges...)
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	for _, e := range edges {
		from, ok1 := ids[e.FromNodeID]
		to, ok2 := ids[e.ToNodeID]
		if !ok1 || !ok2 {
			continue
		}
		fmt.Fprintf(&b, "  %s -> %s [label=%q];\n", from, to, e.Type)
	}
	if g.Truncated {
		b.WriteString("  // output truncated: node limit reached\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// PathMermaid renders a single attack path.
func PathMermaid(p models.AttackPath) string {
	g := Graph{}
	seen := map[string]bool{}
	add := func(n models.Node) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}
	add(p.From)
	add(p.To)
	for _, s := range p.Steps {
		g.Edges = append(g.Edges, models.Edge{
			ID: s.EdgeID, FromNodeID: s.FromNodeID, ToNodeID: s.ToNodeID, Type: s.EdgeType,
		})
	}
	return Mermaid(g)
}

func label(n models.Node) string {
	name := n.Name
	if name == "" {
		name = n.ID
	}
	return fmt.Sprintf("%s\n(%s)", name, n.Type)
}

// mermaidEscape neutralises characters that break Mermaid or allow injection.
func mermaidEscape(s string) string {
	r := strings.NewReplacer(
		"\"", "#quot;",
		"\n", " ",
		"<", "#lt;",
		">", "#gt;",
		"|", "#124;",
		"[", "#91;",
		"]", "#93;",
		"{", "#123;",
		"}", "#125;",
		"`", "#96;",
	)
	return r.Replace(s)
}

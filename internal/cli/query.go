package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jusso-dev/BlakHound/internal/app"
	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/config"
	"github.com/jusso-dev/BlakHound/internal/export"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func traverseOpts(maxDepth, limit int, edges, minConf, toType string) graph.TraverseOptions {
	return graph.TraverseOptions{
		EdgeTypes: config.SplitList(edges), MaxDepth: maxDepth, Limit: limit,
		MinConf: minConf, ToType: toType,
	}
}

func newPathCmd() *cobra.Command {
	var from, to, toType, edges, minConf string
	var maxDepth, limit int
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Find attack paths between nodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return errf("--from is required")
			}
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				opt := traverseOpts(maxDepth, limit, edges, minConf, toType)
				paths, err := svc.FindPaths(ctx, from, to, opt)
				if err != nil {
					return err
				}
				emit(paths, func() { printPaths(paths) })
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "source node (arn, id or name)")
	f.StringVar(&to, "to", "", "target node")
	f.StringVar(&toType, "to-type", "", "target node type")
	f.StringVar(&edges, "edge", "", "restrict to edge types (comma-separated)")
	f.StringVar(&minConf, "min-confidence", "", "minimum confidence: definite|possible|unknown")
	f.IntVar(&maxDepth, "max-depth", 8, "maximum path depth")
	f.IntVar(&limit, "limit", 25, "maximum paths")
	return cmd
}

func newWhoCanAccessCmd() *cobra.Command {
	var minConf string
	var maxDepth int
	cmd := &cobra.Command{
		Use:   "who-can-access <resource>",
		Short: "List principals that can reach a resource",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				opt := traverseOpts(maxDepth, 0, "", minConf, "")
				paths, err := svc.WhoCanReach(ctx, args[0], opt)
				if err != nil {
					return err
				}
				emit(paths, func() { printReachSummary(paths, true) })
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&minConf, "min-confidence", "", "minimum confidence")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 8, "maximum depth")
	return cmd
}

func newWhatCanAccessCmd() *cobra.Command {
	var minConf string
	var maxDepth int
	cmd := &cobra.Command{
		Use:   "what-can-access <principal>",
		Short: "List resources a principal can reach",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				opt := traverseOpts(maxDepth, 0, "", minConf, "")
				paths, err := svc.WhatCanReach(ctx, args[0], opt)
				if err != nil {
					return err
				}
				emit(paths, func() { printReachSummary(paths, false) })
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&minConf, "min-confidence", "", "minimum confidence")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 8, "maximum depth")
	return cmd
}

func newExposureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exposure",
		Short: "List resources reachable from the internet",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				exposed, err := svc.InternetExposure(ctx)
				if err != nil {
					return err
				}
				emit(exposed, func() { printExposure(exposed) })
				return nil
			})
		},
	}
}

func printExposure(rs []app.ExposedResource) {
	if len(rs) == 0 {
		fmt.Println("No internet-exposed resources.")
		return
	}
	for _, r := range rs {
		ports := r.Ports
		if ports == "" {
			ports = "-"
		}
		fmt.Printf("%-16s %-40s ports=%s\n", r.Resource.Type, nodeLabel(r.Resource), ports)
		if r.Reason != "" {
			fmt.Printf("    %s\n", r.Reason)
		}
	}
}

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <edge-id>",
		Short: "Explain an edge and show its evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				exp, err := svc.ExplainEdge(ctx, args[0])
				if err != nil {
					return err
				}
				emit(exp, func() {
					e := exp.Edge
					fmt.Printf("Edge %s: %s --%s--> %s [%s]\n", e.ID, e.FromNodeID, e.Type, e.ToNodeID, e.Confidence)
					if x, ok := e.Properties["explanation"].(string); ok {
						fmt.Printf("  %s\n", x)
					}
					for _, ev := range exp.Evidence {
						fmt.Printf("  evidence %s [%s/%s] %s\n", ev.ID, ev.SourceService, ev.DocumentType, ev.Explanation)
					}
				})
				return nil
			})
		},
	}
}

func newGraphCmd() *cobra.Command {
	var format string
	var maxNodes int
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Export the graph (table|json|mermaid|dot)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				nodes, err := svc.Store.AllNodes(ctx)
				if err != nil {
					return err
				}
				edges, err := svc.Store.AllEdges(ctx)
				if err != nil {
					return err
				}
				g := export.Graph{Nodes: nodes, Edges: edges}
				if maxNodes > 0 && len(nodes) > maxNodes {
					g.Nodes = nodes[:maxNodes]
					g.Truncated = true
				}
				switch format {
				case "mermaid":
					fmt.Print(export.Mermaid(g))
				case "dot":
					fmt.Print(export.DOT(g))
				case "json":
					emit(map[string]any{"nodes": g.Nodes, "edges": g.Edges, "truncated": g.Truncated}, func() {})
				default:
					fmt.Printf("%d nodes, %d edges\n", len(nodes), len(edges))
					for _, n := range g.Nodes {
						fmt.Printf("  %-28s %s\n", n.Type, n.Name)
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "table|json|mermaid|dot")
	cmd.Flags().IntVar(&maxNodes, "max-nodes", export.DefaultMaxNodes, "maximum nodes to export")
	return cmd
}

func newSearchCmd() *cobra.Command {
	var types string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search nodes by name or ARN",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				nodes, err := svc.Store.Search(ctx, args[0], config.SplitList(types), limit)
				if err != nil {
					return err
				}
				emit(nodes, func() {
					for _, n := range nodes {
						fmt.Printf("%-28s %-40s %s\n", n.Type, n.Name, n.ARN)
					}
				})
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&types, "types", "", "restrict to node types")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum results")
	return cmd
}

func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Node inspection"}
	cmd.AddCommand(&cobra.Command{
		Use: "show <node-id>", Short: "Show a node", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				n, err := svc.Store.ResolveNode(ctx, args[0])
				if err != nil {
					return err
				}
				if n == nil {
					return errf("node not found: %s", args[0])
				}
				emit(n, func() {
					fmt.Printf("%s [%s]\nARN: %s\nAccount: %s  Region: %s\n", n.Name, n.Type, n.ARN, n.AccountID, n.Region)
				})
				return nil
			})
		},
	})
	return cmd
}

func newEdgeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "edge", Short: "Edge inspection"}
	cmd.AddCommand(&cobra.Command{
		Use: "show <edge-id>", Short: "Show an edge", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				exp, err := svc.ExplainEdge(ctx, args[0])
				if err != nil {
					return err
				}
				emit(exp, func() {
					e := exp.Edge
					fmt.Printf("%s: %s --%s--> %s [%s]\n", e.ID, e.FromNodeID, e.Type, e.ToNodeID, e.Confidence)
				})
				return nil
			})
		},
	})
	return cmd
}

// --- printers ---

func printWarnings(ws []collector.Warning) {
	if len(ws) == 0 {
		return
	}
	fmt.Println("\nCollection warnings:")
	for _, w := range ws {
		fmt.Printf("  %s %s: %s\n    Impact: %s\n", w.Service, w.API, w.Message, w.Impact)
	}
}

func printFindings(fs []models.Finding) {
	if len(fs) == 0 {
		fmt.Println("No findings.")
		return
	}
	for _, f := range fs {
		fmt.Printf("%-8s %-12s %s\n    %s\n", strings.ToUpper(f.Severity), f.ID, f.Title, f.Description)
	}
}

func printPaths(ps []models.AttackPath) {
	if len(ps) == 0 {
		fmt.Println("No paths found.")
		return
	}
	for i, p := range ps {
		fmt.Printf("\n[%d] %s → %s  score=%.0f severity=%s confidence=%s\n",
			i+1, nodeLabel(p.From), nodeLabel(p.To), p.Score, p.Severity, p.Confidence)
		for j, s := range p.Steps {
			fmt.Printf("  %d. %s\n", j+1, s.Explanation)
		}
	}
}

func printReachSummary(ps []models.AttackPath, who bool) {
	if len(ps) == 0 {
		fmt.Println("None found.")
		return
	}
	for _, p := range ps {
		if who {
			fmt.Printf("%-40s via %d step(s)  [%s, score %.0f]\n", nodeLabel(p.From), len(p.Steps), p.Confidence, p.Score)
		} else {
			fmt.Printf("%-40s via %d step(s)  [%s, score %.0f]\n", nodeLabel(p.To), len(p.Steps), p.Confidence, p.Score)
		}
	}
}

func nodeLabel(n models.Node) string {
	if n.Name != "" {
		return n.Name
	}
	if n.ARN != "" {
		return n.ARN
	}
	return n.ID
}

func sortedStrKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

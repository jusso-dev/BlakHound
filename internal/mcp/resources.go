package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blakhound/blakhound/internal/analysis"
	"github.com/blakhound/blakhound/internal/export"
	"github.com/blakhound/blakhound/internal/graph"
	"github.com/blakhound/blakhound/pkg/models"
)

type resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

func resourceList() []resource {
	return []resource{
		{"blakhound://inventory/summary", "Inventory summary", "Node and edge counts", "application/json"},
		{"blakhound://findings/open", "Open findings", "Currently open findings", "application/json"},
		{"blakhound://graph/schema", "Graph schema", "Node and edge types", "application/json"},
		{"blakhound://collection/latest", "Latest collection", "Most recent snapshot", "application/json"},
		{"blakhound://rules", "Attack rules", "Embedded detection rules", "application/json"},
	}
}

func (s *Server) onResourceRead(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var a struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &a); err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	payload, err := s.readResource(ctx, a.URI)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return map[string]any{
		"contents": []map[string]any{{"uri": a.URI, "mimeType": "application/json", "text": string(b)}},
	}, nil
}

func (s *Server) readResource(ctx context.Context, uri string) (any, error) {
	switch uri {
	case "blakhound://inventory/summary":
		nc, ec, err := s.svc.Store.Counts(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"node_counts": nc, "edge_counts": ec}, nil
	case "blakhound://findings/open":
		return s.svc.Store.ListFindings(ctx, graph.FindingFilter{Status: []string{models.StatusOpen}})
	case "blakhound://graph/schema":
		return map[string]any{"node_types": nodeTypes(), "edge_types": edgeTypes()}, nil
	case "blakhound://collection/latest":
		snaps, err := s.svc.Store.ListSnapshots(ctx)
		if err != nil || len(snaps) == 0 {
			return map[string]any{}, err
		}
		return snaps[0], nil
	case "blakhound://rules":
		return analysis.LoadRules()
	default:
		return nil, fmt.Errorf("unknown resource: %s", uri)
	}
}

func (s *Server) exportGraph(ctx context.Context, format string, maxNodes int) (any, error) {
	nodes, err := s.svc.Store.AllNodes(ctx)
	if err != nil {
		return nil, err
	}
	edges, err := s.svc.Store.AllEdges(ctx)
	if err != nil {
		return nil, err
	}
	if maxNodes <= 0 {
		maxNodes = export.DefaultMaxNodes
	}
	g := export.Graph{Nodes: nodes, Edges: edges}
	if len(nodes) > maxNodes {
		g.Nodes = nodes[:maxNodes]
		g.Truncated = true
	}
	switch format {
	case "dot":
		return map[string]any{"format": "dot", "graph": export.DOT(g), "truncated": g.Truncated}, nil
	case "json":
		return map[string]any{"format": "json", "nodes": g.Nodes, "edges": g.Edges, "truncated": g.Truncated}, nil
	default:
		return map[string]any{"format": "mermaid", "graph": export.Mermaid(g), "truncated": g.Truncated}, nil
	}
}

func nodeTypes() []string {
	return []string{
		models.NodeAWSAccount, models.NodeIAMUser, models.NodeIAMGroup, models.NodeIAMRole,
		models.NodeIAMPolicy, models.NodeInstanceProfile, models.NodeEC2Instance, models.NodeLambdaFunction,
		models.NodeS3Bucket, models.NodeSecret, models.NodeKMSKey, models.NodeExternalAccount,
		models.NodeServicePrincipal, models.NodeAnonymousPrincipal,
	}
}

func edgeTypes() []string {
	return []string{
		models.EdgeMemberOf, models.EdgeAttachedPolicy, models.EdgeInlinePolicy, models.EdgeAssumeRole,
		models.EdgePassRole, models.EdgeExternalTrust, models.EdgeCrossAccountAccess, models.EdgeRunsAs,
	}
}

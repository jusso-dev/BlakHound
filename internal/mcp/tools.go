package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jusso-dev/BlakHound/internal/graph"
)

// tool describes an MCP tool.
type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func toolList() []tool {
	return []tool{
		{"aws_identity", "Return the AWS identity and account represented by the current database.", obj(map[string]any{})},
		{"get_collection_status", "Return collection summary, snapshots and permission gaps.", obj(map[string]any{})},
		{"search_aws_resources", "Search inventory nodes by name or ARN.", obj(map[string]any{
			"query": str("search text"), "types": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "query")},
		{"get_aws_resource", "Fetch a node by ARN or id.", obj(map[string]any{"resource": str("arn or node id")}, "resource")},
		{"find_attack_paths", "Find explained attack paths between two nodes.", obj(map[string]any{
			"from": str("arn or node id"), "to": str("arn or node id"), "to_type": str("target node type"),
			"max_depth": integer("max path depth"), "limit": integer("max paths"), "minimum_confidence": str("definite|possible|unknown"),
		}, "from")},
		{"find_privilege_escalation_paths", "Find privilege-escalation paths from a principal.", obj(map[string]any{
			"principal": str("arn or node id"), "max_depth": integer("max depth"), "limit": integer("max paths"),
		}, "principal")},
		{"who_can_access_resource", "List principals that can reach a resource.", obj(map[string]any{
			"resource": str("arn or node id"),
		}, "resource")},
		{"what_can_principal_access", "List resources a principal can reach.", obj(map[string]any{
			"principal": str("arn or node id"),
		}, "principal")},
		{"explain_graph_edge", "Return an edge and all its evidence.", obj(map[string]any{"edge_id": str("edge id")}, "edge_id")},
		{"list_security_findings", "List findings filtered by severity/category/status.", obj(map[string]any{
			"severity": arrStr(), "category": arrStr(), "status": arrStr(),
		})},
		{"get_security_finding", "Get a finding by id.", obj(map[string]any{"finding_id": str("finding id")}, "finding_id")},
		{"export_attack_graph", "Export the graph as mermaid, dot or json.", obj(map[string]any{
			"format": str("mermaid|dot|json"), "max_nodes": integer("node cap"),
		})},
	}
}

func arrStr() map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
}

// onToolCall parses and dispatches a tool invocation.
func (s *Server) onToolCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	result, err := s.invokeTool(ctx, call.Name, call.Arguments)
	if err != nil {
		return toolText(fmt.Sprintf("error: %v", err), true), nil
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return toolText(string(b), false), nil
}

func toolText(text string, isErr bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func (s *Server) invokeTool(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	arg := func(v any) error {
		if len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, v)
	}
	switch name {
	case "aws_identity":
		acct, _ := s.svc.Store.GetMeta(ctx, "account_id")
		caller, _ := s.svc.Store.GetMeta(ctx, "caller_arn")
		snap, _ := s.svc.Store.GetMeta(ctx, "latest_snapshot")
		return map[string]any{"account_id": acct, "caller_arn": caller, "latest_snapshot": snap}, nil

	case "get_collection_status":
		nc, ec, err := s.svc.Store.Counts(ctx)
		if err != nil {
			return nil, err
		}
		snaps, _ := s.svc.Store.ListSnapshots(ctx)
		return map[string]any{"node_counts": nc, "edge_counts": ec, "snapshots": snaps}, nil

	case "search_aws_resources":
		var a struct {
			Query string   `json:"query"`
			Types []string `json:"types"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		if a.Query == "" {
			return nil, fmt.Errorf("query is required")
		}
		return s.svc.Store.Search(ctx, a.Query, a.Types, 50)

	case "get_aws_resource":
		var a struct {
			Resource string `json:"resource"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.Store.ResolveNode(ctx, a.Resource)

	case "find_attack_paths":
		var a struct {
			From     string `json:"from"`
			To       string `json:"to"`
			ToType   string `json:"to_type"`
			MinConf  string `json:"minimum_confidence"`
			MaxDepth int    `json:"max_depth"`
			Limit    int    `json:"limit"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		opt := graph.TraverseOptions{MaxDepth: a.MaxDepth, Limit: a.Limit, MinConf: a.MinConf, ToType: a.ToType}
		return s.svc.FindPaths(ctx, a.From, a.To, opt)

	case "find_privilege_escalation_paths":
		var a struct {
			Principal string `json:"principal"`
			MaxDepth  int    `json:"max_depth"`
			Limit     int    `json:"limit"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		opt := graph.TraverseOptions{MaxDepth: a.MaxDepth, Limit: a.Limit,
			EdgeTypes: privescEdges()}
		return s.svc.WhatCanReach(ctx, a.Principal, opt)

	case "who_can_access_resource":
		var a struct {
			Resource string `json:"resource"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.WhoCanReach(ctx, a.Resource, graph.TraverseOptions{})

	case "what_can_principal_access":
		var a struct {
			Principal string `json:"principal"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.WhatCanReach(ctx, a.Principal, graph.TraverseOptions{})

	case "explain_graph_edge":
		var a struct {
			EdgeID string `json:"edge_id"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.ExplainEdge(ctx, a.EdgeID)

	case "list_security_findings":
		var a graph.FindingFilter
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.Store.ListFindings(ctx, a)

	case "get_security_finding":
		var a struct {
			FindingID string `json:"finding_id"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.svc.Store.GetFinding(ctx, a.FindingID)

	case "export_attack_graph":
		var a struct {
			Format   string `json:"format"`
			MaxNodes int    `json:"max_nodes"`
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		return s.exportGraph(ctx, a.Format, a.MaxNodes)

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func privescEdges() []string {
	return []string{"assume-role", "pass-role", "can-update-policy", "can-attach-policy",
		"can-put-inline-policy", "can-modify-trust-policy", "can-create-access-key", "can-administer"}
}

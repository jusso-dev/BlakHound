package mcp

import (
	"encoding/json"
	"fmt"
)

type promptDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// guidance is prepended to every prompt so the client queries the graph, asks
// for evidence, and never invents resources or mutates AWS.
const guidance = `You are analysing an AWS account through BlakHound, a read-only attack-path tool.
Rules:
1. Query the graph before drawing conclusions; do not guess.
2. Ask for the evidence behind important edges (explain_graph_edge).
3. Distinguish definite, possible and unknown access explicitly.
4. Never invent resources, ARNs or permissions that the tools did not return.
5. Disclose incomplete collection coverage when findings may be affected.
6. Never suggest or make changes to the AWS account.`

var prompts = map[string]string{
	"review_aws_attack_surface":      "Review the overall AWS attack surface. Start with get_collection_status, then list_security_findings (severity critical,high), then find_internet_exposure and find_cross_account_access if available. Summarise the top risks with evidence.",
	"investigate_aws_principal":      "Investigate principal {{principal}}. Use what_can_principal_access and find_privilege_escalation_paths. Report definite vs possible access and cite evidence.",
	"review_sensitive_resource":      "Review who can access {{resource}} using who_can_access_resource. For each principal, show the path and evidence, and flag external or wildcard access.",
	"explain_privilege_escalation":   "Explain the privilege-escalation paths for {{principal}}. For each step call explain_graph_edge and state whether the step is definite or conditional.",
	"compare_aws_security_snapshots": "Compare two collection snapshots and describe added/removed nodes, edges and findings, and any changed attack paths.",
}

func promptList() []promptDef {
	return []promptDef{
		{"review_aws_attack_surface", "Review the overall AWS attack surface"},
		{"investigate_aws_principal", "Investigate a specific IAM principal"},
		{"review_sensitive_resource", "Review who can access a sensitive resource"},
		{"explain_privilege_escalation", "Explain privilege-escalation paths for a principal"},
		{"compare_aws_security_snapshots", "Compare two collection snapshots"},
	}
}

func (s *Server) onPromptGet(params json.RawMessage) (any, *rpcError) {
	var a struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &a); err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	body, ok := prompts[a.Name]
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "unknown prompt: " + a.Name}
	}
	for k, v := range a.Arguments {
		body = replaceAll(body, "{{"+k+"}}", v)
	}
	return map[string]any{
		"description": a.Name,
		"messages": []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": guidance + "\n\n" + body}},
		},
	}, nil
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = fmt.Sprint

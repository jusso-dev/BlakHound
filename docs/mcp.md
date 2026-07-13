# BlakHound MCP Server

`blakhound mcp` runs a **read-only** Model Context Protocol server exposing the
same deterministic analysis as the CLI.

- Default transport: `stdio` (protocol on stdout, logs on stderr).
- Optional: `--transport http --listen 127.0.0.1:8787`. Binds localhost only;
  non-localhost requires the explicit `--allow-remote` flag.

The MCP server queries an existing local BlakHound database. AWS collection is
performed explicitly with the CLI before starting the server.

## Safety guarantees

The MCP server is read-only. It never exposes AWS credentials or environment
variables, never runs shell or SQL supplied by the client, never offers tools
that modify AWS, redacts likely secret values from documents, and returns
references to secrets (never their contents). All arguments are validated and
traversal depth/result limits are enforced.

## Tools

`aws_identity`, `get_collection_status`, `search_aws_resources`,
`get_aws_resource`, `find_attack_paths`, `find_privilege_escalation_paths`,
`who_can_access_resource`, `what_can_principal_access`,
`find_internet_exposed_resources`, `explain_graph_edge`,
`list_security_findings`, `get_security_finding`, `export_attack_graph`.

Collection, mutation and arbitrary query tools are intentionally not exposed
over MCP. Snapshot comparison remains roadmap work.

## Resources

```
blakhound://inventory/summary
blakhound://findings/open
blakhound://graph/schema
blakhound://collection/latest
blakhound://rules
```

## Prompts

`review_aws_attack_surface`, `investigate_aws_principal`,
`review_sensitive_resource`, `explain_privilege_escalation`,
`compare_aws_security_snapshots`. Every prompt is prefixed with guidance telling
the client to query the graph, ask for evidence, distinguish
definite/possible/unknown, never invent resources, disclose coverage gaps and
never modify AWS.

## Client configuration

stdio:

```json
{
  "mcpServers": {
    "blakhound": {
      "command": "/usr/local/bin/blakhound",
      "args": ["mcp", "--db", "/Users/example/.blakhound/blakhound.db"]
    }
  }
}
```

development:

```json
{
  "mcpServers": {
    "blakhound-dev": {
      "command": "go",
      "args": ["run", "./cmd/blakhound", "mcp"],
      "cwd": "/path/to/blakhound"
    }
  }
}
```

# BlakHound Architecture

BlakHound is one Go binary with a layered design. AWS collection, graph
construction and attack-path analysis are strictly separated so backends and
collectors can be swapped or added without touching analysis code.

```
        AWS APIs (read-only)
              │
   ┌──────────▼───────────┐
   │  collector/*         │  normalise AWS objects -> Nodes/Edges/Evidence
   └──────────┬───────────┘
              │ CollectionResult
   ┌──────────▼───────────┐
   │  graph (SQLite)      │  Store: upsert + Go traversal (BFS/DFS)
   └──────────┬───────────┘
              │
   ┌──────────▼───────────┐
   │  analysis/*          │  derive edges, score paths, run rules
   │  iam (policy engine) │
   └──────────┬───────────┘
              │
   ┌──────────▼───────────┐
   │  app.Service         │  deterministic application layer
   └────┬────────────┬────┘
        │            │
   ┌────▼───┐   ┌────▼─────┐
   │  cli   │   │   mcp    │   thin adapters, identical behaviour
   └────────┘   └──────────┘
```

## Key rules

- **Deterministic core.** `app.Service` is the single source of truth. The CLI
  and MCP server are thin adapters over it. An LLM never decides graph edges.
- **Graph behind an interface.** Traversal is implemented in Go over a
  `graph.Store`, not in recursive SQL, so another backend can replace SQLite.
- **Evidence-first.** Collectors emit `Evidence` for every policy document;
  derived edges reference evidence ids.
- **Uncertainty is explicit.** The IAM engine returns
  `definite | possible | blocked | unknown`; unresolved conditions never
  silently grant access.

## Build order (implemented as a vertical slice first)

AWS profile → STS identity → IAM collection → trust-policy parsing →
AssumeRole/pass-role graph → path query → MCP `find_attack_paths`.

## Packages

| Package | Responsibility |
|---|---|
| `pkg/models` | Backend-agnostic domain types (no AWS SDK types) |
| `internal/iam` | Policy parse + wildcard/ARN/principal matching + evaluation |
| `internal/graph` | SQLite store, migrations, Go traversal, findings store |
| `internal/collector/*` | Read-only AWS collectors (`Collector` interface) |
| `internal/analysis` | Edge derivation, rules, scoring, scanning |
| `internal/evidence` | Evidence construction + secret redaction |
| `internal/export` | Mermaid / DOT / JSON rendering |
| `internal/app` | Deterministic application service layer |
| `internal/cli` | Cobra command tree (thin) |
| `internal/mcp` | Read-only MCP server (stdio + optional HTTP) |

## Roadmap phases

1. Foundations (CLI, config, migrations, auth, collector framework, snapshots) — **done**
2. IAM graph (users/groups/roles/policies, trust, AssumeRole, evidence) — **done**
3. Workloads & data (EC2, Lambda, ECS, S3, Secrets Manager, KMS)
4. Attack paths (privesc rules, traversal, findings, scoring, exports) — **core done**
5. Network paths (VPC, SGs, LBs, RDS, internet exposure)
6. MCP (tools, resources, prompts, tests) — **core done**

Future: interactive graph viewer, CloudTrail/Access Analyzer/Config/Security Hub
enrichment, VPC Reachability Analyzer, Terraform/CloudFormation comparison,
org-wide delegated collection, change alerts, plugin SDK.

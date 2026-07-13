<!-- Logo / banner placeholder -->
<p align="center"><img src="docs/banner-placeholder.png" alt="BlakHound" height="120"/></p>

# BlakHound

BlakHound maps AWS identities, policies, workloads, networks and resources into
a local attack graph so security engineers can discover and explain
privilege-escalation and access paths.

It runs as a standalone CLI **and** an MCP server. No SaaS account, external
database or LLM is required.

> ⚠️ **Security disclaimer.** BlakHound is a security analysis aid, not an
> authoritative AWS authorization simulator. AWS authorization can depend on
> runtime context, session policies, service-specific behaviour and condition
> keys that are not available during offline analysis. **Possible** and
> **unknown** paths must be manually validated. BlakHound is read-only and never
> modifies your AWS account.

<!-- CLI demo placeholder -->
<p align="center"><img src="docs/demo-placeholder.gif" alt="demo" width="640"/></p>

## Why BlakHound

- **Local-first.** Everything lives in a single SQLite file (`~/.blakhound/blakhound.db`, `0600`). No telemetry, no remote service.
- **Deterministic.** Graph edges and findings are computed in Go, never by an LLM. The MCP server exposes the *same* analysis to a model, but the model never decides whether an edge exists.
- **Evidence for everything.** Every derived edge and finding cites the exact policy, statement index and API source.
- **Honest about uncertainty.** Unresolved conditions produce `possible`/`unknown` results — never a silently-satisfied `definite`.

## Installation

```bash
# Go toolchain
go install github.com/jusso-dev/BlakHound/cmd/blakhound@latest

# Homebrew (once tapped)
brew install jusso-dev/tap/blakhound
```

Prebuilt binaries for macOS (arm64/amd64), Linux (arm64/amd64) and Windows
(amd64) are attached to each GitHub release with signed checksums.

## AWS authentication

BlakHound uses the standard AWS credential provider chain — environment
variables, shared credentials, config profiles, IAM Identity Center (SSO),
workload credentials and AssumeRole profiles.

```bash
export AWS_PROFILE=security-audit
blakhound auth check
blakhound collect --profile security-audit --role-arn arn:aws:iam::123456789012:role/BlakHoundReadOnly
```

BlakHound **never** stores AWS secret keys in its database or config.

## Five-minute quick start

```bash
blakhound auth check                       # confirm identity
blakhound collect                          # read-only inventory -> local graph
blakhound scan                             # run attack-rule detections
blakhound findings --status open           # review findings
blakhound path --from arn:aws:iam::123456789012:user/alice \
               --to   arn:aws:iam::123456789012:role/AdminLambdaRole
blakhound who-can-access arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:prod/db
blakhound graph --format mermaid > graph.mmd
blakhound mcp                              # serve the same analysis over MCP (stdio)
```

## Main commands

| Command | Purpose |
|---|---|
| `blakhound auth check` | Verify credentials and print caller identity |
| `blakhound collect` | Read-only AWS collection into the local graph |
| `blakhound scan` | Run versioned attack-rule detections |
| `blakhound findings` / `finding show` | List / inspect findings |
| `blakhound path --from --to` | Explained attack paths |
| `blakhound who-can-access <res>` | Principals that can reach a resource |
| `blakhound what-can-access <principal>` | Resources a principal can reach |
| `blakhound exposure` | Resources reachable from the internet |
| `blakhound explain <edge-id>` | Evidence behind an edge |
| `blakhound graph --format mermaid\|dot\|json` | Export the graph |
| `blakhound doctor` | Environment & database health checks |
| `blakhound mcp` | Run the MCP server (stdio default) |

## MCP configuration

Add to your MCP client (stdio transport):

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

See [docs/mcp.md](docs/mcp.md) for tools, resources, prompts and the optional
localhost HTTP transport.

## Supported AWS services

- **Identity:** IAM users/groups/roles/policies, inline + managed policies, role trust policies, instance profiles, STS.
- **Storage & data:** S3 (bucket policy, public-access block), Secrets Manager (metadata only — never values), KMS (key policies), SQS, SNS.
- **Compute:** EC2 (instance profiles), Lambda (execution role + resource policy), ECS (task/execution roles).
- **Derived access:** `can-read`/`can-decrypt`/`can-invoke`/`can-consume`/`can-publish` edges from principals to resources, plus workload-identity paths (EC2/Lambda/ECS → role → data).

Network (VPC, security groups, load balancers, RDS) collectors are next on the
roadmap and drop in behind the same `Collector` interface.

## Graph model

Nodes are AWS principals, resources and network objects; edges are relationships
(`assume-role`, `pass-role`, `attached-policy`, `cross-account-access`,
`external-trust`, …). See [docs/graph-model.md](docs/graph-model.md).

## Example attack paths

```text
CRITICAL  BH-AWS-IAM-004
alice can escalate to AdministratorAccess through AdminLambdaRole.
  1. alice can perform iam:PassRole on AdminLambdaRole
  2. alice can perform lambda:CreateFunction
  3. A new Lambda function executes as AdminLambdaRole
  4. AdminLambdaRole has AdministratorAccess
Confidence: definite
```

## Required AWS permissions

Use the least-privilege policy in
[examples/blakhound-readonly-policy.json](examples/blakhound-readonly-policy.json)
or an AWS managed read-only policy (broader than needed). See
[docs/permissions.md](docs/permissions.md).

## Known limitations

- Not a formal AWS IAM authorization simulator; condition evaluation is partial and surfaced as uncertainty.
- Network reachability is conservative and classified (`confirmed`/`likely`/`possible`/`unknown`).
- MVP covers IAM deeply; other collectors are on the roadmap.

## Roadmap

See [docs/architecture.md](docs/architecture.md) and the repository issues/milestones (Phases 1–6 plus future work: interactive graph viewer, CloudTrail enrichment, Access Analyzer, VPC Reachability Analyzer, IaC comparison, change alerts, plugin SDK).

## Contributing

Conventional Commits, `make lint test`, and no AWS write operations — ever.

## Security policy

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).

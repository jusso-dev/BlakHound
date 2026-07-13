# BlakHound Attack Rules & Scoring

Rules are declarative YAML embedded in the binary (`internal/analysis/rules/`).
YAML carries **metadata only** — id, title, severity, category, actions, edges,
remediation. Detection logic is written in Go, so a rule file can never execute
code.

## Rule shape

```yaml
- id: BH-AWS-IAM-004
  title: Principal can pass a role to a compute service it can launch
  category: privilege-escalation
  severity: critical
  actions: [iam:PassRole]
  companion_actions: [lambda:CreateFunction, ec2:RunInstances, ...]
  edges: [pass-role]
  remediation: Constrain iam:PassRole with iam:PassedToService and an approved role list.
```

## MVP detections

| Rule | Detects |
|---|---|
| BH-AWS-IAM-001 | `iam:CreatePolicyVersion` / `SetDefaultPolicyVersion` |
| BH-AWS-IAM-002 | `iam:Attach{User,Role,Group}Policy` |
| BH-AWS-IAM-003 | `iam:Put{User,Role,Group}Policy` |
| BH-AWS-IAM-004 | `iam:PassRole` + a service launch action |
| BH-AWS-IAM-005 | `iam:CreateAccessKey` / `Create/UpdateLoginProfile` |
| BH-AWS-IAM-006 | `iam:UpdateAssumeRolePolicy` |
| BH-AWS-IAM-007 | Effective administrator (`*` on `*`) |
| BH-AWS-XACCOUNT-001 | Role trusts an external or wildcard principal |
| BH-AWS-NET-001 | Security group ingress open to `0.0.0.0/0` / `::/0` |
| BH-AWS-NET-002 | EC2 instance reachable from the internet |
| BH-AWS-NET-003 | RDS instance publicly accessible |
| BH-AWS-NET-004 | Load balancer is internet-facing |

Multi-step escalation (e.g. pass-role → assume-role → admin) is found by the
path engine over derived edges.

## Path scoring

Transparent, no machine learning (`internal/analysis/score.go`):

```
score  = 20 (base)
       + destinationSensitivity * 10   (secret 3.0, kms 2.5, rds 2.5, s3 2.0, role/policy 1.5)
       + 15  if source is internet/anonymous/external/federated
       + 10  if any step crosses an account boundary
       - 2   per step beyond the first
score *= confidenceMultiplier          (definite 1.0, possible 0.6, unknown 0.3, blocked 0)
score  = clamp(score, 0, 100)
```

Severity: `>=70 critical, >=50 high, >=30 medium, >0 low, else info`.

## Findings

Findings have a stable `Fingerprint = sha1(ruleID, sourceNode, targetNode)` so
rescans do not duplicate issues. Statuses: `open, resolved, suppressed,
accepted`. Suppressions record reason, user, time, optional expiry and ticket.
Remediation is advisory only — BlakHound never applies changes.

# Required AWS Permissions

BlakHound is **read-only**. It never calls a mutating API and never retrieves
secret values (no `secretsmanager:GetSecretValue`, no `ssm:GetParameter` for
`SecureString`).

## Least-privilege policy

Use [`examples/blakhound-readonly-policy.json`](../examples/blakhound-readonly-policy.json).
The MVP IAM slice needs:

```
sts:GetCallerIdentity
iam:GetAccountAuthorizationDetails
iam:ListAccountAliases
iam:GetAccountPasswordPolicy
iam:GenerateCredentialReport
iam:GetCredentialReport
```

Storage, compute and network collectors add their `List*`/`Get*`/`Describe*`
actions (S3, Secrets Manager *metadata only*, KMS, EC2, Lambda, ECS, ELBv2,
RDS). The network slice (collectors `vpc`, `elbv2`, `rds`) needs:

```
ec2:DescribeVpcs
ec2:DescribeSubnets
ec2:DescribeRouteTables
ec2:DescribeInternetGateways
ec2:DescribeNatGateways
ec2:DescribeSecurityGroups
ec2:DescribeNetworkInterfaces
elasticloadbalancing:DescribeLoadBalancers
elasticloadbalancing:DescribeTargetGroups
rds:DescribeDBInstances
```

## Resource scoping

Many IAM/organisation read APIs only support `Resource: "*"`. Where that is the
case, the example policy uses `"*"` and this is an AWS limitation, not a
BlakHound choice. Service `Describe*`/`List*` calls that support resource-level
scoping should be scoped in production.

## Development shortcut

You may attach the AWS managed policies `ReadOnlyAccess` or
`SecurityAudit` for quick evaluation. ⚠️ These grant **broader** visibility than
BlakHound requires — prefer the least-privilege policy for ongoing use.

## Permission gaps

When an API is denied, BlakHound continues collecting other services and reports
the gap and its impact, e.g.:

```
Collection incomplete: iam:GetAccountAuthorizationDetails denied

Impact:
- IAM users, roles, groups and policies could not be collected.
- AssumeRole and privilege-escalation paths may be missing.
```

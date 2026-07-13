# BlakHound Graph Model

## Nodes

Every node carries `ID, Type, Provider, AccountID, Region, ARN, Name,
Properties, FirstSeenAt, LastSeenAt, SnapshotID`.

Node id convention: AWS resources use their ARN; synthetic nodes use prefixes
(`aws-account:<id>`, `external-account:<id>`, `service:<svc>`,
`inline:<ownerArn>#<name>`).

Types: `aws-account, organization, organizational-unit, iam-user, iam-group,
iam-role, iam-policy, instance-profile, ec2-instance, lambda-function,
ecs-cluster, ecs-service, ecs-task-definition, s3-bucket, secret, kms-key,
sqs-queue, sns-topic, vpc, subnet, route-table, security-group, network-acl,
internet-gateway, nat-gateway, eni, vpc-endpoint, load-balancer, target-group,
rds-instance, external-account, federated-principal, service-principal,
internet, authenticated-aws-principal, anonymous-principal`.

## Edges

Every edge carries `ID, FromNodeID, ToNodeID, Type, Effect, Conditions,
Properties, EvidenceIDs, Confidence, FirstSeenAt, LastSeenAt, SnapshotID`.

Structural edges (from collection) are `definite`. Derived edges carry the
confidence produced by the IAM engine (`definite`/`possible`/`unknown`) and an
`explanation` property.

Types include: `member-of, attached-policy, inline-policy, assume-role,
federates-as, pass-role, can-act-as, can-create-access-key, can-update-policy,
can-attach-policy, can-put-inline-policy, can-modify-trust-policy, can-invoke,
can-read, can-write, can-delete, can-decrypt, can-publish, can-consume,
can-administer, resource-policy-allows, identity-policy-allows, boundary-limits,
scp-limits, runs-as, has-instance-profile, attached-to, deployed-in, routes-to,
allows-ingress, allows-egress, reachable-from, targets, fronts, stores-secret,
encrypted-by, cross-account-access, public-access, external-trust`.

## Confidence

`definite` — access holds under offline analysis.
`possible` — allowed but gated by an unresolved condition, account-root trust,
or wildcard principal.
`blocked` — an explicit deny applies.
`unknown` — insufficient data.

## Evidence

`Evidence` preserves the source service/API/resource, document type, the
(redacted) document, an optional statement index, an explanation and the
collection timestamp. For IAM-derived edges you can recover the policy, version,
statement, effect, action, resource, principal and condition.

## Snapshots

Each collection creates a `snapshot` record and nodes/edges record `LastSeenAt`.
After a successful collection, the active graph is reconciled within the
selected service and region scopes so removed AWS resources do not remain in
queries. Snapshot and collection-run metadata are retained; historical graph
diff storage remains roadmap work.

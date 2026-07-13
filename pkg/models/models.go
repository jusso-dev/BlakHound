// Package models holds the core BlakHound domain types shared across the
// collector, graph, analysis and MCP layers. These types are backend-agnostic
// and must not embed AWS SDK objects.
package models

import (
	"encoding/json"
	"time"
)

// Node types.
const (
	NodeAWSAccount             = "aws-account"
	NodeOrganization           = "organization"
	NodeOU                     = "organizational-unit"
	NodeIAMUser                = "iam-user"
	NodeIAMGroup               = "iam-group"
	NodeIAMRole                = "iam-role"
	NodeIAMPolicy              = "iam-policy"
	NodeInstanceProfile        = "instance-profile"
	NodeEC2Instance            = "ec2-instance"
	NodeLambdaFunction         = "lambda-function"
	NodeECSCluster             = "ecs-cluster"
	NodeECSService             = "ecs-service"
	NodeECSTaskDefinition      = "ecs-task-definition"
	NodeS3Bucket               = "s3-bucket"
	NodeSecret                 = "secret"
	NodeKMSKey                 = "kms-key"
	NodeSQSQueue               = "sqs-queue"
	NodeSNSTopic               = "sns-topic"
	NodeVPC                    = "vpc"
	NodeSubnet                 = "subnet"
	NodeRouteTable             = "route-table"
	NodeSecurityGroup          = "security-group"
	NodeNetworkACL             = "network-acl"
	NodeInternetGateway        = "internet-gateway"
	NodeNATGateway             = "nat-gateway"
	NodeENI                    = "eni"
	NodeVPCEndpoint            = "vpc-endpoint"
	NodeLoadBalancer           = "load-balancer"
	NodeTargetGroup            = "target-group"
	NodeRDSInstance            = "rds-instance"
	NodeExternalAccount        = "external-account"
	NodeFederatedPrincipal     = "federated-principal"
	NodeServicePrincipal       = "service-principal"
	NodeInternet               = "internet"
	NodeAuthenticatedPrincipal = "authenticated-aws-principal"
	NodeAnonymousPrincipal     = "anonymous-principal"
)

// Edge types.
const (
	EdgeMemberOf            = "member-of"
	EdgeAttachedPolicy      = "attached-policy"
	EdgeInlinePolicy        = "inline-policy"
	EdgeAssumeRole          = "assume-role"
	EdgeFederatesAs         = "federates-as"
	EdgePassRole            = "pass-role"
	EdgeCanActAs            = "can-act-as"
	EdgeCanCreateAccessKey  = "can-create-access-key"
	EdgeCanUpdatePolicy     = "can-update-policy"
	EdgeCanAttachPolicy     = "can-attach-policy"
	EdgeCanPutInlinePolicy  = "can-put-inline-policy"
	EdgeCanModifyTrust      = "can-modify-trust-policy"
	EdgeCanInvoke           = "can-invoke"
	EdgeCanRead             = "can-read"
	EdgeCanWrite            = "can-write"
	EdgeCanDelete           = "can-delete"
	EdgeCanDecrypt          = "can-decrypt"
	EdgeCanPublish          = "can-publish"
	EdgeCanConsume          = "can-consume"
	EdgeCanAdminister       = "can-administer"
	EdgeResourcePolicyAllow = "resource-policy-allows"
	EdgeIdentityPolicyAllow = "identity-policy-allows"
	EdgeBoundaryLimits      = "boundary-limits"
	EdgeSCPLimits           = "scp-limits"
	EdgeRunsAs              = "runs-as"
	EdgeHasInstanceProfile  = "has-instance-profile"
	EdgeAttachedTo          = "attached-to"
	EdgeDeployedIn          = "deployed-in"
	EdgeRoutesTo            = "routes-to"
	EdgeAllowsIngress       = "allows-ingress"
	EdgeAllowsEgress        = "allows-egress"
	EdgeReachableFrom       = "reachable-from"
	EdgeTargets             = "targets"
	EdgeFronts              = "fronts"
	EdgeStoresSecret        = "stores-secret"
	EdgeEncryptedBy         = "encrypted-by"
	EdgeCrossAccountAccess  = "cross-account-access"
	EdgePublicAccess        = "public-access"
	EdgeExternalTrust       = "external-trust"
)

// Confidence levels used for edges, paths and access decisions.
const (
	ConfidenceDefinite = "definite"
	ConfidencePossible = "possible"
	ConfidenceBlocked  = "blocked"
	ConfidenceUnknown  = "unknown"
)

// Severity levels.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Node is a vertex in the security graph.
type Node struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Provider    string         `json:"provider"`
	AccountID   string         `json:"account_id"`
	Region      string         `json:"region"`
	ARN         string         `json:"arn"`
	Name        string         `json:"name"`
	Properties  map[string]any `json:"properties"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	SnapshotID  string         `json:"snapshot_id"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	ID          string         `json:"id"`
	FromNodeID  string         `json:"from_node_id"`
	ToNodeID    string         `json:"to_node_id"`
	Type        string         `json:"type"`
	Effect      string         `json:"effect"`
	Conditions  map[string]any `json:"conditions"`
	Properties  map[string]any `json:"properties"`
	EvidenceIDs []string       `json:"evidence_ids"`
	Confidence  string         `json:"confidence"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	SnapshotID  string         `json:"snapshot_id"`
}

// Evidence records exactly why a derived edge exists.
type Evidence struct {
	ID             string          `json:"id"`
	SourceService  string          `json:"source_service"`
	SourceAPI      string          `json:"source_api"`
	SourceResource string          `json:"source_resource"`
	DocumentType   string          `json:"document_type"`
	Document       json.RawMessage `json:"document"`
	StatementIndex *int            `json:"statement_index,omitempty"`
	Explanation    string          `json:"explanation"`
	CollectedAt    time.Time       `json:"collected_at"`
}

// Snapshot is one collection point in time.
type Snapshot struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

// PathStep is one hop in an attack path with a human explanation.
type PathStep struct {
	FromNodeID  string   `json:"from_node_id"`
	ToNodeID    string   `json:"to_node_id"`
	EdgeID      string   `json:"edge_id"`
	EdgeType    string   `json:"edge_type"`
	Confidence  string   `json:"confidence"`
	Explanation string   `json:"explanation"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// AttackPath is an explained chain from one node to another.
type AttackPath struct {
	ID          string       `json:"id"`
	From        Node         `json:"from"`
	To          Node         `json:"to"`
	Steps       []PathStep   `json:"steps"`
	Severity    string       `json:"severity"`
	Confidence  string       `json:"confidence"`
	Score       float64      `json:"score"`
	Explanation string       `json:"explanation"`
	Mitigations []Mitigation `json:"mitigations"`
}

// Mitigation is a recommended break point for a path or finding.
type Mitigation struct {
	Description string `json:"description"`
}

// Finding is a detected security issue.
type Finding struct {
	ID           string       `json:"id"`
	RuleID       string       `json:"rule_id"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     string       `json:"severity"`
	Confidence   string       `json:"confidence"`
	Category     string       `json:"category"`
	Status       string       `json:"status"`
	SourceNodeID string       `json:"source_node_id"`
	TargetNodeID string       `json:"target_node_id"`
	PathIDs      []string     `json:"path_ids"`
	EvidenceIDs  []string     `json:"evidence_ids"`
	Remediation  []Mitigation `json:"remediation"`
	FirstSeenAt  time.Time    `json:"first_seen_at"`
	LastSeenAt   time.Time    `json:"last_seen_at"`
	SnapshotID   string       `json:"snapshot_id"`
	Fingerprint  string       `json:"fingerprint"`
}

// Finding statuses.
const (
	StatusOpen       = "open"
	StatusResolved   = "resolved"
	StatusSuppressed = "suppressed"
	StatusAccepted   = "accepted"
)

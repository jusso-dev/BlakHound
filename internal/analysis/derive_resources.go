package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/blakhound/blakhound/internal/graph"
	"github.com/blakhound/blakhound/pkg/models"
)

// accessRule maps a sensitive resource type to the canonical action that grants
// access and the edge type to emit when a principal is allowed that action.
type accessRule struct {
	nodeType string
	action   string
	edge     string
	// resourceSuffix is appended to the node ARN for the access test (S3 objects
	// live under bucket/*).
	resourceSuffix string
}

var accessRules = []accessRule{
	{models.NodeSecret, "secretsmanager:GetSecretValue", models.EdgeCanRead, ""},
	{models.NodeKMSKey, "kms:Decrypt", models.EdgeCanDecrypt, ""},
	{models.NodeS3Bucket, "s3:GetObject", models.EdgeCanRead, "/*"},
	{models.NodeLambdaFunction, "lambda:InvokeFunction", models.EdgeCanInvoke, ""},
	{models.NodeSQSQueue, "sqs:ReceiveMessage", models.EdgeCanConsume, ""},
	{models.NodeSNSTopic, "sns:Publish", models.EdgeCanPublish, ""},
}

// DeriveResourceAccess emits identity-based access edges (can-read, can-decrypt,
// can-invoke, can-consume, can-publish) from principals to sensitive resources,
// using the IAM evaluation engine. Confidence reflects unresolved conditions.
func DeriveResourceAccess(ctx context.Context, store *graph.Store, snapshotID, accountID string) (int, error) {
	now := time.Now().UTC()
	users, err := store.NodesByType(ctx, models.NodeIAMUser)
	if err != nil {
		return 0, err
	}
	roles, err := store.NodesByType(ctx, models.NodeIAMRole)
	if err != nil {
		return 0, err
	}
	principals := append([]models.Node{}, users...)
	principals = append(principals, roles...)

	// Cache resource nodes per type.
	resourcesByType := map[string][]models.Node{}
	for _, r := range accessRules {
		if _, ok := resourcesByType[r.nodeType]; ok {
			continue
		}
		ns, err := store.NodesByType(ctx, r.nodeType)
		if err != nil {
			return 0, err
		}
		resourcesByType[r.nodeType] = ns
	}

	var edges []models.Edge
	for _, p := range principals {
		sources, err := PrincipalPolicies(ctx, store, p.ID)
		if err != nil {
			return 0, err
		}
		if len(sources) == 0 {
			continue
		}
		for _, rule := range accessRules {
			for _, resNode := range resourcesByType[rule.nodeType] {
				target := resNode.ARN
				if target == "" {
					target = resNode.ID
				}
				ok, matched, conf := AllowsAction(sources, rule.action, target+rule.resourceSuffix)
				if !ok {
					continue
				}
				expl := fmt.Sprintf("%s can perform %s on %s (via %s)", p.Name, rule.action, resNode.Name, policyNames(matched))
				e := derivedEdge(p.ID, rule.edge, resNode.ID, normConf(conf), expl, now)
				e.EvidenceIDs = policyEvidence(ctx, store, matched)
				edges = append(edges, e)
			}
		}
	}
	if len(edges) == 0 {
		return 0, nil
	}
	if err := store.Import(ctx, snapshotID, nil, edges, nil); err != nil {
		return 0, err
	}
	return len(edges), nil
}

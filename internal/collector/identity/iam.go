// Package identity collects AWS IAM and STS identity data.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// IAMCollector collects IAM users, groups, roles and policies plus the account
// node. It relies on GetAccountAuthorizationDetails, a single paginated API.
type IAMCollector struct{}

// NewIAM returns an IAM collector.
func NewIAM() *IAMCollector { return &IAMCollector{} }

func (c *IAMCollector) Name() string                   { return "iam" }
func (c *IAMCollector) Regions() collector.RegionScope { return collector.ScopeGlobal }

func (c *IAMCollector) RequiredPermissions() []string {
	return []string{
		"iam:GetAccountAuthorizationDetails",
		"iam:ListAccountAliases",
	}
}

// Collect gathers IAM data into a normalised result.
func (c *IAMCollector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	client := iam.NewFromConfig(t.AWSConfig)

	// Account node.
	acctID := t.AccountID
	res.Nodes = append(res.Nodes, models.Node{
		ID: collector.AccountNodeID(acctID), Type: models.NodeAWSAccount, Provider: "aws",
		AccountID: acctID, Name: acctID, ARN: "arn:aws:iam::" + acctID + ":root",
		FirstSeenAt: now, LastSeenAt: now,
	})

	// Account alias (best effort).
	if aliases, err := client.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{}); err == nil {
		res.APIRequests++
		if len(aliases.AccountAliases) > 0 {
			for i := range res.Nodes {
				if res.Nodes[i].Type == models.NodeAWSAccount {
					if res.Nodes[i].Properties == nil {
						res.Nodes[i].Properties = map[string]any{}
					}
					res.Nodes[i].Properties["alias"] = aliases.AccountAliases[0]
				}
			}
		}
	} else {
		res.Warnings = append(res.Warnings, warn("iam", "ListAccountAliases", err, "Account alias unavailable."))
	}

	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(client, &iam.GetAccountAuthorizationDetailsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			res.Warnings = append(res.Warnings, warn("iam", "GetAccountAuthorizationDetails", err,
				"IAM users, roles, groups and policies could not be collected. IAM-based paths will be missing."))
			return res, nil
		}
		res.APIRequests++
		c.processPage(page, acctID, now, res)
	}
	return res, nil
}

func (c *IAMCollector) processPage(page *iam.GetAccountAuthorizationDetailsOutput, acctID string, now time.Time, res *collector.CollectionResult) {
	for _, p := range page.Policies {
		c.addManagedPolicy(p, acctID, now, res)
	}
	for _, u := range page.UserDetailList {
		c.addUser(u, acctID, now, res)
	}
	for _, g := range page.GroupDetailList {
		c.addGroup(g, acctID, now, res)
	}
	for _, r := range page.RoleDetailList {
		c.addRole(r, acctID, now, res)
	}
}

func (c *IAMCollector) addManagedPolicy(p iamtypes.ManagedPolicyDetail, acctID string, now time.Time, res *collector.CollectionResult) {
	arn := aws.ToString(p.Arn)
	doc := defaultVersionDoc(p)
	node := models.Node{
		ID: arn, Type: models.NodeIAMPolicy, Provider: "aws", AccountID: acctID,
		ARN: arn, Name: aws.ToString(p.PolicyName), FirstSeenAt: now, LastSeenAt: now,
		Properties: map[string]any{
			"document":        doc,
			"default_version": aws.ToString(p.DefaultVersionId),
			"attachable":      p.IsAttachable,
			"managed":         true,
		},
	}
	res.Nodes = append(res.Nodes, node)
	if doc != "" {
		ev := collector.NewEvidence("iam", "GetAccountAuthorizationDetails", arn, "managed-policy", doc,
			"Managed policy "+aws.ToString(p.PolicyName)+" default version "+aws.ToString(p.DefaultVersionId), nil, now)
		res.Evidence = append(res.Evidence, ev)
	}
}

func defaultVersionDoc(p iamtypes.ManagedPolicyDetail) string {
	for _, v := range p.PolicyVersionList {
		if v.IsDefaultVersion {
			return aws.ToString(v.Document)
		}
	}
	if len(p.PolicyVersionList) > 0 {
		return aws.ToString(p.PolicyVersionList[len(p.PolicyVersionList)-1].Document)
	}
	return ""
}

func (c *IAMCollector) addUser(u iamtypes.UserDetail, acctID string, now time.Time, res *collector.CollectionResult) {
	arn := aws.ToString(u.Arn)
	node := models.Node{
		ID: arn, Type: models.NodeIAMUser, Provider: "aws", AccountID: acctID,
		ARN: arn, Name: aws.ToString(u.UserName), FirstSeenAt: now, LastSeenAt: now,
		Properties: map[string]any{"path": aws.ToString(u.Path)},
	}
	if u.PermissionsBoundary != nil {
		node.Properties["permissions_boundary"] = aws.ToString(u.PermissionsBoundary.PermissionsBoundaryArn)
	}
	res.Nodes = append(res.Nodes, node)

	for _, gname := range u.GroupList {
		gid := groupARN(acctID, gname)
		res.Edges = append(res.Edges, structEdge(arn, models.EdgeMemberOf, gid, now,
			aws.ToString(u.UserName)+" is a member of group "+gname))
	}
	c.attachPolicies(arn, u.AttachedManagedPolicies, now, res)
	c.inlinePolicies(arn, "GetAccountAuthorizationDetails", u.UserPolicyList, acctID, now, res)
}

func (c *IAMCollector) addGroup(g iamtypes.GroupDetail, acctID string, now time.Time, res *collector.CollectionResult) {
	arn := aws.ToString(g.Arn)
	res.Nodes = append(res.Nodes, models.Node{
		ID: arn, Type: models.NodeIAMGroup, Provider: "aws", AccountID: acctID,
		ARN: arn, Name: aws.ToString(g.GroupName), FirstSeenAt: now, LastSeenAt: now,
	})
	c.attachPolicies(arn, g.AttachedManagedPolicies, now, res)
	c.inlinePolicies(arn, "GetAccountAuthorizationDetails", g.GroupPolicyList, acctID, now, res)
}

func (c *IAMCollector) addRole(r iamtypes.RoleDetail, acctID string, now time.Time, res *collector.CollectionResult) {
	arn := aws.ToString(r.Arn)
	trust := aws.ToString(r.AssumeRolePolicyDocument)
	node := models.Node{
		ID: arn, Type: models.NodeIAMRole, Provider: "aws", AccountID: acctID,
		ARN: arn, Name: aws.ToString(r.RoleName), FirstSeenAt: now, LastSeenAt: now,
		Properties: map[string]any{
			"path":         aws.ToString(r.Path),
			"trust_policy": trust,
		},
	}
	if r.PermissionsBoundary != nil {
		node.Properties["permissions_boundary"] = aws.ToString(r.PermissionsBoundary.PermissionsBoundaryArn)
	}
	res.Nodes = append(res.Nodes, node)

	if trust != "" {
		ev := collector.NewEvidence("iam", "GetAccountAuthorizationDetails", arn, "role-trust-policy", trust,
			"Trust policy for role "+aws.ToString(r.RoleName), nil, now)
		res.Evidence = append(res.Evidence, ev)
	}
	// Instance profiles owned by the role.
	for _, ip := range r.InstanceProfileList {
		ipArn := aws.ToString(ip.Arn)
		res.Nodes = append(res.Nodes, models.Node{
			ID: ipArn, Type: models.NodeInstanceProfile, Provider: "aws", AccountID: acctID,
			ARN: ipArn, Name: aws.ToString(ip.InstanceProfileName), FirstSeenAt: now, LastSeenAt: now,
		})
		res.Edges = append(res.Edges, structEdge(ipArn, models.EdgeRunsAs, arn, now,
			"Instance profile "+aws.ToString(ip.InstanceProfileName)+" grants role "+aws.ToString(r.RoleName)))
	}
	c.attachPolicies(arn, r.AttachedManagedPolicies, now, res)
	c.inlinePolicies(arn, "GetAccountAuthorizationDetails", r.RolePolicyList, acctID, now, res)
}

func (c *IAMCollector) attachPolicies(ownerARN string, attached []iamtypes.AttachedPolicy, now time.Time, res *collector.CollectionResult) {
	for _, ap := range attached {
		pArn := aws.ToString(ap.PolicyArn)
		res.Edges = append(res.Edges, structEdge(ownerARN, models.EdgeAttachedPolicy, pArn, now,
			"Managed policy "+aws.ToString(ap.PolicyName)+" is attached"))
	}
}

func (c *IAMCollector) inlinePolicies(ownerARN, api string, policies []iamtypes.PolicyDetail, acctID string, now time.Time, res *collector.CollectionResult) {
	for _, pd := range policies {
		name := aws.ToString(pd.PolicyName)
		doc := aws.ToString(pd.PolicyDocument)
		pid := collector.InlinePolicyNodeID(ownerARN, name)
		res.Nodes = append(res.Nodes, models.Node{
			ID: pid, Type: models.NodeIAMPolicy, Provider: "aws", AccountID: acctID,
			Name: name, FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"document": doc, "inline": true, "owner": ownerARN},
		})
		ev := collector.NewEvidence("iam", api, ownerARN, "inline-policy", doc,
			"Inline policy "+name+" on "+ownerARN, nil, now)
		res.Evidence = append(res.Evidence, ev)
		edge := structEdge(ownerARN, models.EdgeInlinePolicy, pid, now, "Inline policy "+name)
		edge.EvidenceIDs = []string{ev.ID}
		res.Edges = append(res.Edges, edge)
	}
}

// structEdge builds a definite structural edge with an explanation property.
func structEdge(from, typ, to string, now time.Time, explanation string) models.Edge {
	return models.Edge{
		ID: collector.EdgeID(from, typ, to), FromNodeID: from, ToNodeID: to, Type: typ,
		Effect: "Allow", Confidence: models.ConfidenceDefinite,
		Properties:  map[string]any{"explanation": explanation},
		FirstSeenAt: now, LastSeenAt: now,
	}
}

func groupARN(acctID, name string) string {
	return "arn:aws:iam::" + acctID + ":group/" + name
}

func warn(service, api string, err error, impact string) collector.Warning {
	w := collector.Warning{Service: service, API: api, Message: err.Error(), Impact: impact}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		w.Code = ae.ErrorCode()
		w.Message = ae.ErrorMessage()
	}
	return w
}

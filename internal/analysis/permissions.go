package analysis

import (
	"context"

	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/internal/iam"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// PolicySource pairs a parsed identity policy document with the node it came
// from, so findings can cite the exact policy.
type PolicySource struct {
	PolicyNodeID string
	PolicyName   string
	PolicyARN    string
	Doc          *iam.Document
}

// PrincipalPolicies returns the effective identity policy documents for a
// principal, expanding one level of group membership for users.
func PrincipalPolicies(ctx context.Context, store *graph.Store, principalID string) ([]PolicySource, error) {
	seen := map[string]bool{}
	var out []PolicySource

	collect := func(ownerID string) error {
		edges, err := store.OutEdges(ctx, ownerID, []string{models.EdgeAttachedPolicy, models.EdgeInlinePolicy})
		if err != nil {
			return err
		}
		for _, e := range edges {
			if seen[e.ToNodeID] {
				continue
			}
			seen[e.ToNodeID] = true
			pnode, err := store.GetNode(ctx, e.ToNodeID)
			if err != nil || pnode == nil {
				continue
			}
			doc, _ := docFromNode(pnode)
			if doc == nil {
				continue
			}
			out = append(out, PolicySource{
				PolicyNodeID: pnode.ID, PolicyName: pnode.Name, PolicyARN: pnode.ARN, Doc: doc,
			})
		}
		return nil
	}

	if err := collect(principalID); err != nil {
		return nil, err
	}
	// Group expansion for users.
	groups, err := store.OutEdges(ctx, principalID, []string{models.EdgeMemberOf})
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if err := collect(g.ToNodeID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func docFromNode(n *models.Node) (*iam.Document, error) {
	if n.Properties == nil {
		return nil, nil
	}
	raw, ok := n.Properties["document"].(string)
	if !ok || raw == "" {
		return nil, nil
	}
	return iam.Parse(raw)
}

// AllowsAction reports whether any of the principal's policy sources allow the
// given action on the given resource, returning the matching sources and an
// overall confidence.
func AllowsAction(sources []PolicySource, action, resource string) (bool, []PolicySource, string) {
	var docs []*iam.Document
	for _, s := range sources {
		docs = append(docs, s.Doc)
	}
	dec := iam.EvaluateIdentity(docs, iam.Request{Action: action, Resource: resource})
	if dec.Decision != iam.DecisionAllow {
		return false, nil, iam.ConfBlocked
	}
	var matched []PolicySource
	for _, s := range sources {
		d := iam.EvaluateIdentity([]*iam.Document{s.Doc}, iam.Request{Action: action, Resource: resource})
		if d.Decision == iam.DecisionAllow {
			matched = append(matched, s)
		}
	}
	return true, matched, dec.Confidence
}

package collector

import (
	"time"

	"github.com/jusso-dev/BlakHound/internal/iam"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// ResourcePolicyEdges parses a resource-based policy and returns exposure nodes,
// edges (public-access / cross-account-access) and the policy evidence. It is
// shared by every storage/compute collector that has a resource policy.
func ResourcePolicyEdges(resourceNodeID, resourceARN, resourceAccount, service, api, docType, rawPolicy string, now time.Time) ([]models.Node, []models.Edge, []models.Evidence) {
	if rawPolicy == "" {
		return nil, nil, nil
	}
	doc, err := iam.Parse(rawPolicy)
	if err != nil {
		return nil, nil, nil
	}
	ev := NewEvidence(service, api, resourceARN, docType, rawPolicy, "Resource-based policy for "+resourceARN, nil, now)
	var nodes []models.Node
	var edges []models.Edge
	ex := iam.AnalyzeResourceExposure(doc, resourceAccount)

	if ex.Public {
		conf := models.ConfidenceDefinite
		expl := "Resource policy allows any principal (\"*\")"
		if ex.PublicConditional {
			conf = models.ConfidencePossible
			expl += " gated by an unresolved condition"
		}
		nodes = append(nodes, models.Node{ID: models.NodeAnonymousPrincipal, Type: models.NodeAnonymousPrincipal,
			Provider: "aws", Name: "Any principal (*)", FirstSeenAt: now, LastSeenAt: now})
		e := models.Edge{ID: EdgeID(models.NodeAnonymousPrincipal, models.EdgePublicAccess, resourceNodeID),
			FromNodeID: models.NodeAnonymousPrincipal, ToNodeID: resourceNodeID, Type: models.EdgePublicAccess,
			Effect: "Allow", Confidence: conf, Properties: map[string]any{"explanation": expl},
			EvidenceIDs: []string{ev.ID}, FirstSeenAt: now, LastSeenAt: now}
		edges = append(edges, e)
	}
	for _, acct := range ex.ExternalAccounts {
		id := ExternalAccountNodeID(acct)
		nodes = append(nodes, models.Node{ID: id, Type: models.NodeExternalAccount, Provider: "aws",
			AccountID: acct, Name: "External account " + acct, FirstSeenAt: now, LastSeenAt: now})
		e := models.Edge{ID: EdgeID(id, models.EdgeCrossAccountAccess, resourceNodeID),
			FromNodeID: id, ToNodeID: resourceNodeID, Type: models.EdgeCrossAccountAccess,
			Effect: "Allow", Confidence: models.ConfidencePossible,
			Properties:  map[string]any{"explanation": "Resource policy allows external account " + acct},
			EvidenceIDs: []string{ev.ID}, FirstSeenAt: now, LastSeenAt: now}
		edges = append(edges, e)
	}
	return nodes, edges, []models.Evidence{ev}
}

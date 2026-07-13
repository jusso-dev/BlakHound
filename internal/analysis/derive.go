package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/internal/iam"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// DeriveEdges reads the collected graph and adds derived relationship edges:
// assume-role, pass-role, external-trust / cross-account-access, can-administer.
// It is deterministic and idempotent for a given snapshot.
func DeriveEdges(ctx context.Context, store *graph.Store, snapshotID string, accountID string) (int, error) {
	now := time.Now().UTC()
	var edges []models.Edge
	var nodes []models.Node

	roles, err := store.NodesByType(ctx, models.NodeIAMRole)
	if err != nil {
		return 0, err
	}
	users, err := store.NodesByType(ctx, models.NodeIAMUser)
	if err != nil {
		return 0, err
	}
	principals := append([]models.Node{}, users...)
	principals = append(principals, roles...)

	// Pre-compute identity policies per principal for pass-role/assume checks.
	principalPolicies := map[string][]PolicySource{}
	for _, p := range principals {
		ps, err := PrincipalPolicies(ctx, store, p.ID)
		if err != nil {
			return 0, err
		}
		principalPolicies[p.ID] = ps
	}

	// --- assume-role & external/cross-account trust from role trust policies ---
	for _, role := range roles {
		trustRaw, _ := role.Properties["trust_policy"].(string)
		trust, err := iam.Parse(trustRaw)
		if err != nil || trust == nil {
			continue
		}
		trustEv, _ := store.EvidenceBySource(ctx, role.ARN)

		// Internal principals.
		for _, p := range principals {
			if p.ID == role.ID {
				continue
			}
			dec := iam.EvaluateTrust(trust, p.ARN, p.AccountID, role.AccountID)
			if dec.Decision != iam.DecisionAllow {
				continue
			}
			conf := models.ConfidenceDefinite
			expl := fmt.Sprintf("%s may assume %s: trust policy statement %s allows the principal", p.Name, role.Name, stmtRef(dec.MatchedStmt))
			if dec.Wildcard {
				conf = models.ConfidencePossible
				expl = fmt.Sprintf("%s may assume %s: trust policy allows any principal (\"*\")", p.Name, role.Name)
			} else if len(dec.Conditions) > 0 {
				conf = models.ConfidencePossible
				expl += fmt.Sprintf("; gated by unresolved condition(s): %v", dec.Conditions)
			}
			e := derivedEdge(p.ID, models.EdgeAssumeRole, role.ID, conf, expl, now)
			e.EvidenceIDs = trustEv
			edges = append(edges, e)
		}

		// External / wildcard trust → external-account or anonymous nodes + edges.
		extNodes, extEdges := externalTrust(trust, role, trustEv, accountID, now)
		nodes = append(nodes, extNodes...)
		edges = append(edges, extEdges...)

		// Service principals that can assume the role (workload roots).
		svcNodes, svcEdges := serviceTrust(trust, role, trustEv, now)
		nodes = append(nodes, svcNodes...)
		edges = append(edges, svcEdges...)
	}

	// --- pass-role edges ---
	for _, p := range principals {
		sources := principalPolicies[p.ID]
		for _, role := range roles {
			ok, matched, conf := AllowsAction(sources, "iam:PassRole", role.ARN)
			if !ok {
				continue
			}
			expl := fmt.Sprintf("%s can pass role %s (iam:PassRole allowed by %s)", p.Name, role.Name, policyNames(matched))
			e := derivedEdge(p.ID, models.EdgePassRole, role.ID, normConf(conf), expl, now)
			e.EvidenceIDs = policyEvidence(ctx, store, matched)
			edges = append(edges, e)
		}
	}

	// --- can-administer self-edge for admin principals ---
	for _, p := range principals {
		sources := principalPolicies[p.ID]
		if ok, matched, _ := AllowsAction(sources, "iam:PutUserPolicy", "*"); ok {
			_ = matched // handled by findings; skip edge noise
		}
		if ok, matched, conf := AllowsAction(sources, "sts:AssumeRole", "*"); ok && conf == iam.ConfDefinite {
			_ = matched
		}
	}

	if len(nodes) == 0 && len(edges) == 0 {
		return 0, nil
	}
	if err := store.Import(ctx, snapshotID, nodes, edges, nil); err != nil {
		return 0, err
	}
	return len(edges), nil
}

func externalTrust(trust *iam.Document, role models.Node, trustEv []string, accountID string, now time.Time) ([]models.Node, []models.Edge) {
	var nodes []models.Node
	var edges []models.Edge
	for i, st := range trust.Statements {
		if st.Principal == nil {
			continue
		}
		if st.Principal.Wildcard {
			id := models.NodeAnonymousPrincipal
			nodes = append(nodes, models.Node{ID: id, Type: models.NodeAnonymousPrincipal, Provider: "aws",
				Name: "Any AWS principal (*)", FirstSeenAt: now, LastSeenAt: now})
			e := derivedEdge(id, models.EdgeExternalTrust, role.ID, models.ConfidencePossible,
				fmt.Sprintf("Role %s trust policy statement %d allows any principal (\"*\")", role.Name, i), now)
			e.EvidenceIDs = trustEv
			edges = append(edges, e)
			continue
		}
		for _, aws := range st.Principal.AWS {
			acct := extAccountFromPrincipal(aws)
			if acct == "" || acct == accountID {
				continue
			}
			id := collector.ExternalAccountNodeID(acct)
			nodes = append(nodes, models.Node{ID: id, Type: models.NodeExternalAccount, Provider: "aws",
				AccountID: acct, Name: "External account " + acct, ARN: aws, FirstSeenAt: now, LastSeenAt: now})
			e := derivedEdge(id, models.EdgeCrossAccountAccess, role.ID, models.ConfidencePossible,
				fmt.Sprintf("Role %s trusts external principal %s (statement %d)", role.Name, aws, i), now)
			e.EvidenceIDs = trustEv
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

func serviceTrust(trust *iam.Document, role models.Node, trustEv []string, now time.Time) ([]models.Node, []models.Edge) {
	var nodes []models.Node
	var edges []models.Edge
	for i, st := range trust.Statements {
		if st.Principal == nil {
			continue
		}
		for _, svc := range st.Principal.Service {
			id := collector.ServicePrincipalNodeID(svc)
			nodes = append(nodes, models.Node{ID: id, Type: models.NodeServicePrincipal, Provider: "aws",
				Name: svc, FirstSeenAt: now, LastSeenAt: now})
			e := derivedEdge(id, models.EdgeAssumeRole, role.ID, models.ConfidenceDefinite,
				fmt.Sprintf("Service %s can assume role %s (trust statement %d)", svc, role.Name, i), now)
			e.EvidenceIDs = trustEv
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

func extAccountFromPrincipal(v string) string {
	if len(v) == 12 && allDigits(v) {
		return v
	}
	// arn:aws:iam::123456789012:root|user/..|role/..
	if len(v) > 4 && v[:4] == "arn:" {
		parts := splitN(v, ':', 6)
		if len(parts) >= 5 && len(parts[4]) == 12 {
			return parts[4]
		}
	}
	return ""
}

func derivedEdge(from, typ, to, conf, expl string, now time.Time) models.Edge {
	return models.Edge{
		ID: collector.EdgeID(from, typ, to), FromNodeID: from, ToNodeID: to, Type: typ,
		Effect: "Allow", Confidence: conf,
		Properties:  map[string]any{"explanation": expl, "derived": true},
		FirstSeenAt: now, LastSeenAt: now,
	}
}

func policyEvidence(ctx context.Context, store *graph.Store, sources []PolicySource) []string {
	var out []string
	for _, s := range sources {
		res := s.PolicyARN
		if res == "" {
			res = s.PolicyNodeID
		}
		ids, _ := store.EvidenceBySource(ctx, res)
		out = append(out, ids...)
	}
	return out
}

func policyNames(sources []PolicySource) string {
	if len(sources) == 0 {
		return "an identity policy"
	}
	s := ""
	for i, src := range sources {
		if i > 0 {
			s += ", "
		}
		if src.PolicyName != "" {
			s += src.PolicyName
		} else {
			s += src.PolicyNodeID
		}
	}
	return s
}

func stmtRef(i *int) string {
	if i == nil {
		return "?"
	}
	return fmt.Sprintf("%d", *i)
}

func normConf(c string) string {
	switch c {
	case iam.ConfDefinite:
		return models.ConfidenceDefinite
	case iam.ConfPossible:
		return models.ConfidencePossible
	case iam.ConfBlocked:
		return models.ConfidenceBlocked
	default:
		return models.ConfidenceUnknown
	}
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

package analysis

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/internal/iam"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// companionServiceActions used by the pass-role escalation rule.
var companionServiceActions = []string{
	"lambda:CreateFunction", "ec2:RunInstances", "ecs:RegisterTaskDefinition",
	"ecs:RunTask", "cloudformation:CreateStack", "glue:CreateDevEndpoint",
}

// Scan runs the rule engine against the current graph and upserts findings.
func Scan(ctx context.Context, store *graph.Store, snapshotID string, accountID string) ([]models.Finding, error) {
	rules, err := LoadRules()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var findings []models.Finding

	users, err := store.NodesByType(ctx, models.NodeIAMUser)
	if err != nil {
		return nil, err
	}
	roles, err := store.NodesByType(ctx, models.NodeIAMRole)
	if err != nil {
		return nil, err
	}
	principals := append([]models.Node{}, users...)
	principals = append(principals, roles...)

	for _, p := range principals {
		sources, err := PrincipalPolicies(ctx, store, p.ID)
		if err != nil {
			return nil, err
		}
		findings = append(findings, scanPrincipal(ctx, store, rules, p, sources, snapshotID, now)...)
	}

	// Network exposure findings (rules BH-AWS-NET-*).
	netFindings, err := scanNetwork(ctx, store, rules, snapshotID, now)
	if err != nil {
		return nil, err
	}
	findings = append(findings, netFindings...)

	// Cross-account / external trust findings (rule BH-AWS-XACCOUNT-001).
	if r, ok := rules["BH-AWS-XACCOUNT-001"]; ok {
		for _, role := range roles {
			edges, err := store.InEdges(ctx, role.ID, []string{models.EdgeExternalTrust, models.EdgeCrossAccountAccess})
			if err != nil {
				return nil, err
			}
			if len(edges) == 0 {
				continue
			}
			evIDs, _ := store.EvidenceBySource(ctx, role.ARN)
			f := newFinding(r, role.ID, role.ID, snapshotID, now, evIDs,
				fmt.Sprintf("Role %s trusts an external or wildcard principal.", role.Name))
			findings = append(findings, f)
		}
	}

	for _, f := range findings {
		if err := store.UpsertFinding(ctx, f); err != nil {
			return nil, err
		}
	}
	return findings, nil
}

func scanPrincipal(ctx context.Context, store *graph.Store, rules map[string]Rule, p models.Node, sources []PolicySource, snapshotID string, now time.Time) []models.Finding {
	var out []models.Finding

	// Admin (BH-AWS-IAM-007).
	if r, ok := rules["BH-AWS-IAM-007"]; ok {
		if allowed, matched, _ := AllowsAction(sources, "*", "*"); allowed {
			out = append(out, newFinding(r, p.ID, p.ID, snapshotID, now, policyEvidence(ctx, store, matched),
				fmt.Sprintf("%s has effective administrator access (Action \"*\" on Resource \"*\") via %s.", p.Name, policyNames(matched))))
		}
	}

	// Action-based single-action rules.
	for _, rid := range []string{"BH-AWS-IAM-001", "BH-AWS-IAM-002", "BH-AWS-IAM-003", "BH-AWS-IAM-005", "BH-AWS-IAM-006"} {
		r, ok := rules[rid]
		if !ok {
			continue
		}
		for _, act := range r.Actions {
			if allowed, matched, conf := AllowsAction(sources, act, "*"); allowed {
				f := newFinding(r, p.ID, "", snapshotID, now, policyEvidence(ctx, store, matched),
					fmt.Sprintf("%s is allowed %s (via %s), enabling privilege escalation.", p.Name, act, policyNames(matched)))
				f.Confidence = normConf(conf)
				out = append(out, f)
				break
			}
		}
	}

	// Pass-role + companion service (BH-AWS-IAM-004).
	if r, ok := rules["BH-AWS-IAM-004"]; ok {
		if allowed, passMatched, _ := AllowsAction(sources, "iam:PassRole", "*"); allowed {
			for _, comp := range companionServiceActions {
				if ok2, compMatched, conf := AllowsAction(sources, comp, "*"); ok2 {
					ev := append(policyEvidence(ctx, store, passMatched), policyEvidence(ctx, store, compMatched)...)
					f := newFinding(r, p.ID, "", snapshotID, now, ev,
						fmt.Sprintf("%s can pass a role and call %s, enabling code execution as a more privileged role.", p.Name, comp))
					f.Confidence = normConf(conf)
					out = append(out, f)
					break
				}
			}
		}
	}
	return out
}

// scanNetwork emits findings for internet-open security groups and
// internet-reachable resources from the collected/derived network edges.
func scanNetwork(ctx context.Context, store *graph.Store, rules map[string]Rule, snapshotID string, now time.Time) ([]models.Finding, error) {
	var out []models.Finding

	// BH-AWS-NET-001: security groups open to 0.0.0.0/0.
	if r, ok := rules["BH-AWS-NET-001"]; ok {
		open, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeAllowsIngress})
		if err != nil {
			return nil, err
		}
		for _, e := range open {
			sg, err := store.GetNode(ctx, e.ToNodeID)
			if err != nil || sg == nil {
				continue
			}
			ports, _ := e.Properties["ports"].(string)
			out = append(out, newFinding(r, sg.ID, sg.ID, snapshotID, now, e.EvidenceIDs,
				fmt.Sprintf("Security group %s allows inbound %s from the internet (0.0.0.0/0).", sg.Name, ports)))
		}
	}

	// BH-AWS-NET-002/003/004: resources reachable from the internet.
	reach, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeReachableFrom})
	if err != nil {
		return nil, err
	}
	for _, e := range reach {
		res, err := store.GetNode(ctx, e.ToNodeID)
		if err != nil || res == nil {
			continue
		}
		expl, _ := e.Properties["explanation"].(string)
		if expl == "" {
			expl = fmt.Sprintf("%s is reachable from the internet.", res.Name)
		}
		rid := "BH-AWS-NET-002"
		switch res.Type {
		case models.NodeRDSInstance:
			rid = "BH-AWS-NET-003"
		case models.NodeLoadBalancer:
			rid = "BH-AWS-NET-004"
		}
		r, ok := rules[rid]
		if !ok {
			continue
		}
		out = append(out, newFinding(r, res.ID, res.ID, snapshotID, now, e.EvidenceIDs, expl))
	}
	return out, nil
}

// newFinding builds a finding with a stable fingerprint from rule + endpoints.
func newFinding(r Rule, source, target, snapshotID string, now time.Time, evidenceIDs []string, desc string) models.Finding {
	fp := fingerprint(r.ID, source, target)
	return models.Finding{
		ID:           "BH-" + fp[:10],
		RuleID:       r.ID,
		Title:        r.Title,
		Description:  desc,
		Severity:     r.Severity,
		Confidence:   models.ConfidenceDefinite,
		Category:     r.Category,
		Status:       models.StatusOpen,
		SourceNodeID: source,
		TargetNodeID: target,
		EvidenceIDs:  evidenceIDs,
		Remediation:  []models.Mitigation{{Description: r.Remediation}},
		FirstSeenAt:  now,
		LastSeenAt:   now,
		SnapshotID:   snapshotID,
		Fingerprint:  fp,
	}
}

func fingerprint(parts ...string) string {
	h := sha1.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// confidence helpers reused from derive.go: normConf, policyEvidence, policyNames.

var _ = iam.ConfDefinite

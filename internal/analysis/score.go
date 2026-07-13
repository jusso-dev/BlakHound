package analysis

import "github.com/blakhound/blakhound/pkg/models"

// sensitiveTargetTypes raise a path's destination sensitivity.
var sensitiveTargetTypes = map[string]float64{
	models.NodeSecret:      3.0,
	models.NodeKMSKey:      2.5,
	models.NodeS3Bucket:    2.0,
	models.NodeRDSInstance: 2.5,
	models.NodeIAMRole:     1.5,
	models.NodeIAMPolicy:   1.5,
}

// ScorePath computes a transparent 0-100 severity score for a path.
//
// Formula (documented in docs/attack-rules.md):
//
//	base       = 20
//	+ destination sensitivity weight * 10
//	+ 15 if the source is an external/anonymous/internet principal (exposure)
//	+ 10 if any step crosses an account boundary
//	- 2 per step beyond the first (longer paths are harder to exploit)
//	* confidence multiplier (definite 1.0, possible 0.6, unknown 0.3)
func ScorePath(p models.AttackPath) float64 {
	score := 20.0
	score += sensitiveTargetTypes[p.To.Type] * 10

	switch p.From.Type {
	case models.NodeInternet, models.NodeAnonymousPrincipal, models.NodeExternalAccount, models.NodeFederatedPrincipal:
		score += 15
	}
	for _, s := range p.Steps {
		if s.EdgeType == models.EdgeCrossAccountAccess || s.EdgeType == models.EdgeExternalTrust {
			score += 10
			break
		}
	}
	if n := len(p.Steps); n > 1 {
		score -= float64(n-1) * 2
	}
	switch p.Confidence {
	case models.ConfidencePossible:
		score *= 0.6
	case models.ConfidenceUnknown, "":
		score *= 0.3
	case models.ConfidenceBlocked:
		score = 0
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// SeverityForScore maps a score to a severity label.
func SeverityForScore(score float64) string {
	switch {
	case score >= 70:
		return models.SeverityCritical
	case score >= 50:
		return models.SeverityHigh
	case score >= 30:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

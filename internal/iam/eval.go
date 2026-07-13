package iam

import (
	"fmt"
	"strings"
)

// Decision outcomes.
const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionNeutral = "neutral"
)

// Confidence values mirror models.Confidence* but are duplicated here to keep
// the iam package free of upward dependencies.
const (
	ConfDefinite = "definite"
	ConfPossible = "possible"
	ConfBlocked  = "blocked"
	ConfUnknown  = "unknown"
)

// AccessDecision is the explained result of an access evaluation.
type AccessDecision struct {
	Decision        string   `json:"decision"`
	Confidence      string   `json:"confidence"`
	AllowEvidence   []string `json:"allow_evidence"`
	DenyEvidence    []string `json:"deny_evidence"`
	BoundaryEffects []string `json:"boundary_effects"`
	SCPEffects      []string `json:"scp_effects"`
	Unknowns        []string `json:"unknowns"`
}

// Request describes a single access question.
type Request struct {
	Action   string
	Resource string
	// PrincipalARN is the principal making the request (for trust evaluation).
	PrincipalARN string
	// PrincipalAccount is the AWS account of the principal.
	PrincipalAccount string
}

// stmtMatchesAction accounts for Action / NotAction.
func stmtMatchesAction(st Statement, action string) bool {
	if len(st.Action) > 0 {
		return ActionMatches(st.Action, action)
	}
	if len(st.NotAction) > 0 {
		return !ActionMatches(st.NotAction, action)
	}
	return false
}

// stmtMatchesResource accounts for Resource / NotResource. A statement with
// neither element (as in a trust policy) matches any resource.
func stmtMatchesResource(st Statement, resource string) bool {
	if len(st.Resource) > 0 {
		return ResourceMatches(st.Resource, resource)
	}
	if len(st.NotResource) > 0 {
		return !ResourceMatches(st.NotResource, resource)
	}
	return true
}

// EvaluateIdentity evaluates identity-based policy documents (one or more) for
// a request. Explicit Deny always wins. Unsupported conditions downgrade an
// otherwise-allowing statement to possible rather than granting silently.
func EvaluateIdentity(docs []*Document, req Request) AccessDecision {
	d := AccessDecision{Decision: DecisionNeutral, Confidence: ConfDefinite}
	allowed := false
	conditional := false

	for di, doc := range docs {
		for si, st := range doc.Statements {
			if !stmtMatchesAction(st, req.Action) || !stmtMatchesResource(st, req.Resource) {
				continue
			}
			ref := fmt.Sprintf("policy[%d] statement %d", di, si)
			condRes := evalConditions(st.Condition)
			switch strings.ToLower(st.Effect) {
			case "deny":
				// A deny with an unresolved condition cannot be assumed away,
				// but we cannot confirm it fires either: record as unknown deny.
				if condRes == condUnknown {
					d.Unknowns = append(d.Unknowns, ref+": deny gated by unresolved condition")
					continue
				}
				if condRes == condTrue {
					d.Decision = DecisionDeny
					d.Confidence = ConfDefinite
					d.DenyEvidence = append(d.DenyEvidence, ref)
					return d
				}
			case "allow":
				switch condRes {
				case condTrue:
					allowed = true
					d.AllowEvidence = append(d.AllowEvidence, ref)
				case condUnknown:
					conditional = true
					d.AllowEvidence = append(d.AllowEvidence, ref+" (conditional)")
					d.Unknowns = append(d.Unknowns, ref+": allow gated by unresolved condition")
				}
			}
		}
	}

	switch {
	case allowed:
		d.Decision = DecisionAllow
		d.Confidence = ConfDefinite
	case conditional:
		d.Decision = DecisionAllow
		d.Confidence = ConfPossible
	}
	return d
}

// TrustDecision is the result of evaluating a role trust policy for a principal.
type TrustDecision struct {
	Decision       string   // allow | neutral
	Confidence     string   // definite | possible
	MatchedStmt    *int     // index of matching Allow statement
	External       bool     // principal is outside the role's account
	Wildcard       bool     // trust policy allows "*"
	Conditions     []string // unresolved conditions that gate the trust
	PrincipalKinds []string // aws | service | federated
}

// EvaluateTrust evaluates a role trust policy against a candidate principal.
// roleAccount is the account owning the role. It returns whether the principal
// may assume the role and whether conditions leave the result only possible.
func EvaluateTrust(trust *Document, principalARN, principalAccount, roleAccount string) TrustDecision {
	res := TrustDecision{Decision: DecisionNeutral, Confidence: ConfDefinite}
	if trust == nil {
		return res
	}
	for i, st := range trust.Statements {
		if strings.ToLower(st.Effect) != "allow" {
			continue
		}
		if !stmtMatchesAction(st, "sts:AssumeRole") &&
			!stmtMatchesAction(st, "sts:AssumeRoleWithSAML") &&
			!stmtMatchesAction(st, "sts:AssumeRoleWithWebIdentity") {
			continue
		}
		if st.Principal == nil {
			continue
		}
		match, kind, wildcard := principalMatches(st.Principal, principalARN, principalAccount)
		if !match {
			continue
		}
		res.Decision = DecisionAllow
		idx := i
		res.MatchedStmt = &idx
		res.Wildcard = wildcard
		res.PrincipalKinds = appendUnique(res.PrincipalKinds, kind)
		if roleAccount != "" && principalAccount != "" && principalAccount != roleAccount {
			res.External = true
		}
		if condRes := evalConditions(st.Condition); condRes == condUnknown {
			res.Confidence = ConfPossible
			for op := range st.Condition {
				res.Conditions = append(res.Conditions, op)
			}
		}
	}
	return res
}

// principalMatches reports whether the trust Principal element allows the given
// concrete IAM principal (a user or role ARN). Only the AWS block is considered
// here: Service and Federated trust are handled separately by the caller, since
// they name a service/IdP, not an IAM principal, and must not match arbitrary
// users or roles.
func principalMatches(p *Principal, principalARN, principalAccount string) (bool, string, bool) {
	if p.Wildcard {
		return true, "aws", true
	}
	for _, v := range p.AWS {
		if v == "*" {
			return true, "aws", true
		}
		if strings.EqualFold(v, principalARN) {
			return true, "aws", false
		}
		// Account-root form: arn:aws:iam::123456789012:root or bare account id.
		if acct := accountFromPrincipal(v); acct != "" && acct == principalAccount {
			return true, "aws", false
		}
		if MatchWildcard(v, principalARN) {
			return true, "aws", false
		}
	}
	return false, "", false
}

// accountFromPrincipal extracts an account id from a bare id or a :root ARN.
func accountFromPrincipal(v string) string {
	if len(v) == 12 && isDigits(v) {
		return v
	}
	if strings.HasPrefix(v, "arn:") && strings.HasSuffix(v, ":root") {
		parts := strings.Split(v, ":")
		if len(parts) >= 5 {
			return parts[4]
		}
	}
	return ""
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// condResult is the tri-state result of condition evaluation.
type condResult int

const (
	condTrue condResult = iota
	condUnknown
)

// evalConditions returns condTrue when a statement has no conditions, and
// condUnknown when any condition is present. The MVP does not resolve runtime
// context, so conditions are treated as unresolved (never silently satisfied).
func evalConditions(cond map[string]map[string]StringOrSlice) condResult {
	if len(cond) == 0 {
		return condTrue
	}
	return condUnknown
}

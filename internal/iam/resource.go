package iam

import "strings"

// ResourceExposure summarises what a resource-based policy exposes, independent
// of any specific requesting principal. Collectors use it to emit public-access
// and cross-account edges.
type ResourceExposure struct {
	Public            bool     // a statement allows Principal "*" (optionally gated by conditions)
	PublicConditional bool     // the public grant is gated by an unresolved condition
	ExternalAccounts  []string // external account ids named as principals
	AllowsActions     []string // sample of allowed actions (for evidence)
}

// AnalyzeResourceExposure inspects a resource-based policy. resourceAccount is
// the account owning the resource; principals from other accounts are external.
func AnalyzeResourceExposure(doc *Document, resourceAccount string) ResourceExposure {
	var ex ResourceExposure
	if doc == nil {
		return ex
	}
	seen := map[string]bool{}
	for _, st := range doc.Statements {
		if strings.ToLower(st.Effect) != "allow" || st.Principal == nil {
			continue
		}
		conditional := evalConditions(st.Condition) == condUnknown
		if st.Principal.Wildcard {
			ex.Public = true
			if conditional {
				ex.PublicConditional = true
			}
		}
		for _, v := range st.Principal.AWS {
			if v == "*" {
				ex.Public = true
				if conditional {
					ex.PublicConditional = true
				}
				continue
			}
			if acct := accountFromPrincipal(v); acct != "" && resourceAccount != "" && acct != resourceAccount && !seen[acct] {
				seen[acct] = true
				ex.ExternalAccounts = append(ex.ExternalAccounts, acct)
			}
		}
		for _, a := range st.Action {
			ex.AllowsActions = append(ex.AllowsActions, a)
		}
	}
	return ex
}

// EvaluateResourcePolicy decides whether a resource-based policy allows a
// specific principal to perform an action. Explicit Deny wins; unresolved
// conditions downgrade an allow to possible.
func EvaluateResourcePolicy(doc *Document, req Request) AccessDecision {
	d := AccessDecision{Decision: DecisionNeutral, Confidence: ConfDefinite}
	if doc == nil {
		return d
	}
	allowed, conditional := false, false
	for i, st := range doc.Statements {
		if !stmtMatchesAction(st, req.Action) || !stmtMatchesResource(st, req.Resource) {
			continue
		}
		if st.Principal == nil {
			continue
		}
		match, _, _ := principalMatches(st.Principal, req.PrincipalARN, req.PrincipalAccount)
		if !match && !st.Principal.Wildcard {
			continue
		}
		ref := stmtName(st, i)
		cond := evalConditions(st.Condition)
		switch strings.ToLower(st.Effect) {
		case "deny":
			if cond == condTrue {
				d.Decision = DecisionDeny
				d.Confidence = ConfDefinite
				d.DenyEvidence = append(d.DenyEvidence, ref)
				return d
			}
			d.Unknowns = append(d.Unknowns, ref+": deny gated by unresolved condition")
		case "allow":
			if cond == condTrue {
				allowed = true
				d.AllowEvidence = append(d.AllowEvidence, ref)
			} else {
				conditional = true
				d.Unknowns = append(d.Unknowns, ref+": allow gated by unresolved condition")
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

func stmtName(st Statement, i int) string {
	if st.Sid != "" {
		return "statement " + st.Sid
	}
	return "statement " + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

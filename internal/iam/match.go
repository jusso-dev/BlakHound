package iam

import "strings"

// MatchWildcard reports whether pattern (with AWS-style '*' and '?' wildcards)
// matches s. Matching is case-insensitive, as AWS action matching is.
func MatchWildcard(pattern, s string) bool {
	return wildcard(strings.ToLower(pattern), strings.ToLower(s))
}

// wildcard implements '*' (any run) and '?' (single char) globbing without
// regex, iteratively, to avoid pathological backtracking on adversarial input.
func wildcard(pattern, s string) bool {
	var si, pi int
	star := -1
	var ss int
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			ss = si
			pi++
			continue
		}
		if star != -1 {
			pi = star + 1
			ss++
			si = ss
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// ActionMatches reports whether any element of patterns matches action.
func ActionMatches(patterns []string, action string) bool {
	for _, p := range patterns {
		if MatchWildcard(p, action) {
			return true
		}
	}
	return false
}

// ResourceMatches reports whether any element of patterns matches resource.
// "*" matches everything.
func ResourceMatches(patterns []string, resource string) bool {
	for _, p := range patterns {
		if p == "*" || MatchWildcard(p, resource) {
			return true
		}
	}
	return false
}

// IsAdminAction reports whether the (effect Allow) action/resource pair grants
// effective administrator access ("*" on "*").
func IsAdminAction(action, resource string) bool {
	return (action == "*" || strings.EqualFold(action, "*:*")) && resource == "*"
}

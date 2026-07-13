// Package iam provides a focused AWS IAM policy parsing and reasoning engine.
// It is NOT a complete formal replacement for AWS authorization evaluation;
// unresolved conditions are surfaced as uncertainty rather than ignored.
package iam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Document is a parsed IAM policy document.
type Document struct {
	Version    string      `json:"Version"`
	ID         string      `json:"Id,omitempty"`
	Statements []Statement `json:"Statement"`
}

// Statement is a single IAM policy statement. AWS allows several fields to be
// either a string or an array of strings, so they are decoded via StringOrSlice.
type Statement struct {
	Sid          string                              `json:"Sid,omitempty"`
	Effect       string                              `json:"Effect"`
	Action       StringOrSlice                       `json:"Action,omitempty"`
	NotAction    StringOrSlice                       `json:"NotAction,omitempty"`
	Resource     StringOrSlice                       `json:"Resource,omitempty"`
	NotResource  StringOrSlice                       `json:"NotResource,omitempty"`
	Principal    *Principal                          `json:"Principal,omitempty"`
	NotPrincipal *Principal                          `json:"NotPrincipal,omitempty"`
	Condition    map[string]map[string]StringOrSlice `json:"Condition,omitempty"`
}

// StringOrSlice decodes a JSON value that may be a string or []string.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	*s = []string{single}
	return nil
}

// Principal is the Principal element of a statement. "*" is stored in AWS,
// AWS-account/role/user ARNs in AWS, Service in Service, Federated in Federated.
type Principal struct {
	AWS           StringOrSlice `json:"AWS,omitempty"`
	Service       StringOrSlice `json:"Service,omitempty"`
	Federated     StringOrSlice `json:"Federated,omitempty"`
	CanonicalUser StringOrSlice `json:"CanonicalUser,omitempty"`
	Wildcard      bool          `json:"-"`
}

// UnmarshalJSON handles the "*" shorthand and the object form.
func (p *Principal) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == `"*"` {
		p.Wildcard = true
		return nil
	}
	type alias Principal
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return fmt.Errorf("parse principal: %w", err)
	}
	*p = Principal(a)
	return nil
}

// Parse parses a policy document that may be URL-encoded (as returned by many
// IAM Get* APIs) or already-decoded JSON.
func Parse(raw string) (*Document, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return &Document{}, nil
	}
	if !strings.HasPrefix(s, "{") {
		if dec, err := url.QueryUnescape(s); err == nil {
			s = strings.TrimSpace(dec)
		}
	}
	var doc Document
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil, fmt.Errorf("parse policy document: %w", err)
	}
	return &doc, nil
}

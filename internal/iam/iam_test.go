package iam

import "testing"

func TestMatchWildcard(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "iam:CreateUser", true},
		{"iam:*", "iam:CreateUser", true},
		{"iam:*", "s3:GetObject", false},
		{"iam:Create*", "iam:CreateUser", true},
		{"iam:Create*", "iam:DeleteUser", false},
		{"s3:Get?bject", "s3:GetObject", true},
		{"S3:getobject", "s3:GetObject", true}, // case-insensitive
		{"iam:CreateUser", "iam:CreateUser", true},
		{"", "x", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range cases {
		if got := MatchWildcard(c.pattern, c.s); got != c.want {
			t.Errorf("MatchWildcard(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestResourceMatches(t *testing.T) {
	if !ResourceMatches([]string{"*"}, "arn:aws:s3:::x") {
		t.Fatal("star should match")
	}
	if !ResourceMatches([]string{"arn:aws:s3:::bucket/*"}, "arn:aws:s3:::bucket/key") {
		t.Fatal("prefix wildcard should match")
	}
	if ResourceMatches([]string{"arn:aws:s3:::other/*"}, "arn:aws:s3:::bucket/key") {
		t.Fatal("should not match different bucket")
	}
}

func TestEvaluateIdentityAllowAndDeny(t *testing.T) {
	allow, _ := Parse(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	dec := EvaluateIdentity([]*Document{allow}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k"})
	if dec.Decision != DecisionAllow || dec.Confidence != ConfDefinite {
		t.Fatalf("want definite allow, got %+v", dec)
	}
	// Explicit deny must win.
	deny, _ := Parse(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)
	dec = EvaluateIdentity([]*Document{deny}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k"})
	if dec.Decision != DecisionDeny {
		t.Fatalf("explicit deny must win, got %+v", dec)
	}
}

func TestEvaluateIdentityConditionIsPossibleNotDefinite(t *testing.T) {
	doc, _ := Parse(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:username":"bob"}}}]}`)
	dec := EvaluateIdentity([]*Document{doc}, Request{Action: "s3:GetObject", Resource: "x"})
	if dec.Decision != DecisionAllow || dec.Confidence != ConfPossible {
		t.Fatalf("conditional allow must be possible, got %+v", dec)
	}
	if len(dec.Unknowns) == 0 {
		t.Fatal("unresolved condition must be surfaced, not silently satisfied")
	}
}

func TestEvaluateTrustDirectAndWildcard(t *testing.T) {
	trust, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}`)
	d := EvaluateTrust(trust, "arn:aws:iam::111111111111:user/alice", "111111111111", "111111111111")
	if d.Decision != DecisionAllow || d.Confidence != ConfDefinite || d.Wildcard {
		t.Fatalf("direct trust should be definite, got %+v", d)
	}
	wc, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`)
	d = EvaluateTrust(wc, "arn:aws:iam::999999999999:root", "999999999999", "111111111111")
	if d.Decision != DecisionAllow || !d.Wildcard || !d.External {
		t.Fatalf("wildcard external trust expected, got %+v", d)
	}
}

func TestServiceTrustDoesNotMatchIAMUser(t *testing.T) {
	// A role that trusts only a service must not grant an assume edge to an
	// arbitrary IAM user.
	trust, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	d := EvaluateTrust(trust, "arn:aws:iam::111111111111:user/alice", "111111111111", "111111111111")
	if d.Decision == DecisionAllow {
		t.Fatalf("service trust must not match IAM user, got %+v", d)
	}
}

func TestParseURLEncoded(t *testing.T) {
	enc := "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%7D%5D%7D"
	doc, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Effect != "Allow" {
		t.Fatalf("url-encoded parse failed: %+v", doc)
	}
}

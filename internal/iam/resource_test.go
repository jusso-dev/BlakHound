package iam

import "testing"

func TestAnalyzeResourceExposurePublicAndExternal(t *testing.T) {
	doc, _ := Parse(`{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"s3:GetObject","Resource":"*"}
	]}`)
	ex := AnalyzeResourceExposure(doc, "111111111111")
	if !ex.Public {
		t.Fatal("expected public exposure")
	}
	if len(ex.ExternalAccounts) != 1 || ex.ExternalAccounts[0] != "999999999999" {
		t.Fatalf("expected external account 999999999999, got %v", ex.ExternalAccounts)
	}
}

func TestAnalyzeResourceExposurePublicConditional(t *testing.T) {
	doc, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}`)
	ex := AnalyzeResourceExposure(doc, "111111111111")
	if !ex.Public || !ex.PublicConditional {
		t.Fatalf("expected conditional public exposure, got %+v", ex)
	}
}

func TestEvaluateResourcePolicyPrincipalMatch(t *testing.T) {
	doc, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/App"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`)
	d := EvaluateResourcePolicy(doc, Request{Action: "secretsmanager:GetSecretValue", Resource: "arn:secret", PrincipalARN: "arn:aws:iam::111111111111:role/App", PrincipalAccount: "111111111111"})
	if d.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %+v", d)
	}
	// A different principal must not be allowed.
	d = EvaluateResourcePolicy(doc, Request{Action: "secretsmanager:GetSecretValue", Resource: "arn:secret", PrincipalARN: "arn:aws:iam::111111111111:role/Other", PrincipalAccount: "111111111111"})
	if d.Decision == DecisionAllow {
		t.Fatalf("unrelated principal must not match, got %+v", d)
	}
}

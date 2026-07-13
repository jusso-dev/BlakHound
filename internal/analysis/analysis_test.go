package analysis

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

const acct = "111111111111"

func seed(t *testing.T) (*graph.Store, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := graph.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()

	aliceARN := "arn:aws:iam::" + acct + ":user/alice"
	adminRoleARN := "arn:aws:iam::" + acct + ":role/AdminLambdaRole"
	adminPolicyARN := "arn:aws:iam::aws:policy/AdministratorAccess"
	extRoleARN := "arn:aws:iam::" + acct + ":role/BillingExportRole"
	inlineID := collector.InlinePolicyNodeID(aliceARN, "deploy")

	nodes := []models.Node{
		{ID: collector.AccountNodeID(acct), Type: models.NodeAWSAccount, AccountID: acct, Name: acct, FirstSeenAt: now, LastSeenAt: now},
		{ID: aliceARN, Type: models.NodeIAMUser, AccountID: acct, ARN: aliceARN, Name: "alice", FirstSeenAt: now, LastSeenAt: now},
		{ID: inlineID, Type: models.NodeIAMPolicy, AccountID: acct, Name: "deploy", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"inline": true, "owner": aliceARN,
				"document": `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]}`}},
		{ID: adminRoleARN, Type: models.NodeIAMRole, AccountID: acct, ARN: adminRoleARN, Name: "AdminLambdaRole", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"trust_policy": `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}},
		{ID: adminPolicyARN, Type: models.NodeIAMPolicy, Name: "AdministratorAccess", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"managed": true, "document": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}},
		{ID: extRoleARN, Type: models.NodeIAMRole, AccountID: acct, ARN: extRoleARN, Name: "BillingExportRole", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"trust_policy": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`}},
	}
	edges := []models.Edge{
		{ID: collector.EdgeID(aliceARN, models.EdgeInlinePolicy, inlineID), FromNodeID: aliceARN, ToNodeID: inlineID, Type: models.EdgeInlinePolicy, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(adminRoleARN, models.EdgeAttachedPolicy, adminPolicyARN), FromNodeID: adminRoleARN, ToNodeID: adminPolicyARN, Type: models.EdgeAttachedPolicy, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
	}
	snap, err := store.CreateSnapshot(ctx, acct, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, snap.ID, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	_ = store.SetMeta(ctx, "account_id", acct)
	return store, snap.ID
}

func TestDeriveEdgesAndPassRole(t *testing.T) {
	ctx := context.Background()
	store, snap := seed(t)
	n, err := DeriveEdges(ctx, store, snap, acct)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected derived edges")
	}
	aliceARN := "arn:aws:iam::" + acct + ":user/alice"
	adminRoleARN := "arn:aws:iam::" + acct + ":role/AdminLambdaRole"
	out, err := store.OutEdges(ctx, aliceARN, []string{models.EdgePassRole})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range out {
		if e.ToNodeID == adminRoleARN {
			found = true
			if e.Confidence != models.ConfidenceDefinite {
				t.Errorf("pass-role confidence = %s, want definite", e.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected pass-role edge alice -> AdminLambdaRole")
	}
	// External trust edge to BillingExportRole.
	extRoleARN := "arn:aws:iam::" + acct + ":role/BillingExportRole"
	in, err := store.InEdges(ctx, extRoleARN, []string{models.EdgeCrossAccountAccess})
	if err != nil {
		t.Fatal(err)
	}
	if len(in) == 0 {
		t.Fatal("expected cross-account edge into BillingExportRole")
	}
}

func TestScanFindsEscalationAndAdmin(t *testing.T) {
	ctx := context.Background()
	store, snap := seed(t)
	if _, err := DeriveEdges(ctx, store, snap, acct); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(ctx, store, snap, acct)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]bool{}
	for _, f := range findings {
		byRule[f.RuleID] = true
	}
	for _, want := range []string{"BH-AWS-IAM-004", "BH-AWS-IAM-007", "BH-AWS-XACCOUNT-001"} {
		if !byRule[want] {
			t.Errorf("expected finding for rule %s; got %v", want, byRule)
		}
	}
}

func TestDeriveResourceAccess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := graph.Open(ctx, dir+"/r.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()
	roleARN := "arn:aws:iam::" + acct + ":role/Reader"
	secretARN := "arn:aws:secretsmanager:ap-southeast-2:" + acct + ":secret:prod/db"
	polID := collector.InlinePolicyNodeID(roleARN, "read")
	nodes := []models.Node{
		{ID: roleARN, Type: models.NodeIAMRole, AccountID: acct, ARN: roleARN, Name: "Reader", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"trust_policy": ""}},
		{ID: polID, Type: models.NodeIAMPolicy, AccountID: acct, Name: "read", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"inline": true, "owner": roleARN,
				"document": `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"` + secretARN + `"}]}`}},
		{ID: secretARN, Type: models.NodeSecret, AccountID: acct, ARN: secretARN, Name: "prod/db", FirstSeenAt: now, LastSeenAt: now},
	}
	edges := []models.Edge{
		{ID: collector.EdgeID(roleARN, models.EdgeInlinePolicy, polID), FromNodeID: roleARN, ToNodeID: polID, Type: models.EdgeInlinePolicy, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
	}
	snap, _ := store.CreateSnapshot(ctx, acct, "", now)
	if err := store.Import(ctx, snap.ID, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	n, err := DeriveResourceAccess(ctx, store, snap.ID, acct)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected a can-read edge")
	}
	out, _ := store.OutEdges(ctx, roleARN, []string{models.EdgeCanRead})
	if len(out) != 1 || out[0].ToNodeID != secretARN {
		t.Fatalf("expected Reader can-read secret, got %+v", out)
	}
}

func TestFingerprintStable(t *testing.T) {
	a := fingerprint("R", "s", "t")
	b := fingerprint("R", "s", "t")
	if a != b {
		t.Fatal("fingerprint must be deterministic")
	}
	if a == fingerprint("R", "s", "u") {
		t.Fatal("different inputs must differ")
	}
}

func TestScorePathBounded(t *testing.T) {
	p := models.AttackPath{
		From:       models.Node{Type: models.NodeAnonymousPrincipal},
		To:         models.Node{Type: models.NodeSecret},
		Steps:      []models.PathStep{{EdgeType: models.EdgeCrossAccountAccess}},
		Confidence: models.ConfidenceDefinite,
	}
	s := ScorePath(p)
	if s < 0 || s > 100 {
		t.Fatalf("score out of range: %f", s)
	}
	if SeverityForScore(s) == "" {
		t.Fatal("severity must be set")
	}
}

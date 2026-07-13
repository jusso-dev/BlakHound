// Command seed populates a BlakHound database with a synthetic account so the
// CLI and MCP server can be explored without AWS credentials. Development aid
// only; it performs no AWS calls.
//
// Usage: go run ./examples/seed --db /tmp/blakhound-demo.db
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jusso-dev/BlakHound/internal/analysis"
	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

const acct = "123456789012"

func main() {
	db := flag.String("db", "/tmp/blakhound-demo.db", "database path")
	flag.Parse()
	if err := run(*db); err != nil {
		fmt.Fprintln(os.Stderr, "seed error:", err)
		os.Exit(1)
	}
	fmt.Printf("seeded demo account %s into %s\n", acct, *db)
	fmt.Println("try: blakhound --db", *db, "scan")
}

func run(dbPath string) error {
	ctx := context.Background()
	_ = os.Remove(dbPath)
	store, err := graph.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	now := time.Now().UTC()

	aliceARN := "arn:aws:iam::" + acct + ":user/alice"
	adminRoleARN := "arn:aws:iam::" + acct + ":role/AdminLambdaRole"
	adminPolicyARN := "arn:aws:iam::aws:policy/AdministratorAccess"
	extRoleARN := "arn:aws:iam::" + acct + ":role/BillingExportRole"
	inlineID := collector.InlinePolicyNodeID(aliceARN, "deploy")
	secretARN := "arn:aws:secretsmanager:ap-southeast-2:" + acct + ":secret:prod/db"
	kmsARN := "arn:aws:kms:ap-southeast-2:" + acct + ":key/1234abcd-12ab-34cd-56ef-1234567890ab"
	sgWebARN := "arn:aws:ec2:ap-southeast-2:" + acct + ":security-group/sg-web"
	webInstARN := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-web"
	rdsARN := "arn:aws:rds:ap-southeast-2:" + acct + ":db:prod"

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
		{ID: secretARN, Type: models.NodeSecret, AccountID: acct, Region: "ap-southeast-2", ARN: secretARN, Name: "prod/db", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"kms_key_id": kmsARN}},
		{ID: kmsARN, Type: models.NodeKMSKey, AccountID: acct, Region: "ap-southeast-2", ARN: kmsARN, Name: "prod-db-key", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"key_manager": "CUSTOMER"}},
		{ID: models.NodeInternet, Type: models.NodeInternet, Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgWebARN, Type: models.NodeSecurityGroup, AccountID: acct, Region: "ap-southeast-2", ARN: sgWebARN, Name: "web-sg", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"open_ingress_ports": "tcp/22, tcp/443"}},
		{ID: webInstARN, Type: models.NodeEC2Instance, AccountID: acct, Region: "ap-southeast-2", ARN: webInstARN, Name: "i-web", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"public_ip": "203.0.113.10"}},
		{ID: rdsARN, Type: models.NodeRDSInstance, AccountID: acct, Region: "ap-southeast-2", ARN: rdsARN, Name: "prod", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"publicly_accessible": true, "engine": "postgres"}},
	}
	ingress := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeAllowsIngress, sgWebARN),
		FromNodeID: models.NodeInternet, ToNodeID: sgWebARN, Type: models.EdgeAllowsIngress, Effect: "Allow",
		Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "web-sg allows inbound tcp/22, tcp/443 from 0.0.0.0/0", "ports": "tcp/22, tcp/443"}, FirstSeenAt: now, LastSeenAt: now}
	edges := []models.Edge{
		{ID: collector.EdgeID(aliceARN, models.EdgeInlinePolicy, inlineID), FromNodeID: aliceARN, ToNodeID: inlineID, Type: models.EdgeInlinePolicy, Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "Inline policy deploy on alice"}, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(adminRoleARN, models.EdgeAttachedPolicy, adminPolicyARN), FromNodeID: adminRoleARN, ToNodeID: adminPolicyARN, Type: models.EdgeAttachedPolicy, Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "AdministratorAccess attached to AdminLambdaRole"}, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(secretARN, models.EdgeEncryptedBy, kmsARN), FromNodeID: secretARN, ToNodeID: kmsARN, Type: models.EdgeEncryptedBy, Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "Secret prod/db encrypted by prod-db-key"}, FirstSeenAt: now, LastSeenAt: now},
		ingress,
		{ID: collector.EdgeID(webInstARN, models.EdgeAttachedTo, sgWebARN), FromNodeID: webInstARN, ToNodeID: sgWebARN, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "i-web attached to web-sg"}, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(rdsARN, models.EdgeAttachedTo, sgWebARN), FromNodeID: rdsARN, ToNodeID: sgWebARN, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, Properties: map[string]any{"explanation": "prod attached to web-sg"}, FirstSeenAt: now, LastSeenAt: now},
	}
	snap, err := store.CreateSnapshot(ctx, acct, "demo", now)
	if err != nil {
		return err
	}
	if err := store.Import(ctx, snap.ID, nodes, edges, nil); err != nil {
		return err
	}
	_ = store.SetMeta(ctx, "account_id", acct)
	_ = store.SetMeta(ctx, "caller_arn", "arn:aws:iam::"+acct+":user/demo")
	_ = store.SetMeta(ctx, "latest_snapshot", snap.ID)
	if _, err := analysis.DeriveEdges(ctx, store, snap.ID, acct); err != nil {
		return err
	}
	if _, err := analysis.DeriveResourceAccess(ctx, store, snap.ID, acct); err != nil {
		return err
	}
	if _, err := analysis.DeriveNetworkExposure(ctx, store, snap.ID, acct); err != nil {
		return err
	}
	_, err = analysis.Scan(ctx, store, snap.ID, acct)
	return err
}

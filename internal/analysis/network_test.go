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

// seedNetwork builds a small network graph: an open security group, a public
// EC2 instance attached to it, a private EC2 instance, an internet-facing LB,
// and a publicly-accessible RDS instance.
func seedNetwork(t *testing.T) (*graph.Store, string) {
	t.Helper()
	ctx := context.Background()
	store, err := graph.Open(ctx, filepath.Join(t.TempDir(), "net.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()

	sgOpen := "arn:aws:ec2:ap-southeast-2:" + acct + ":security-group/sg-open"
	sgClosed := "arn:aws:ec2:ap-southeast-2:" + acct + ":security-group/sg-closed"
	pubInst := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-public"
	privInst := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-private"
	lbARN := "arn:aws:elasticloadbalancing:ap-southeast-2:" + acct + ":loadbalancer/app/web/abc"
	rdsARN := "arn:aws:rds:ap-southeast-2:" + acct + ":db:prod"

	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgOpen, Type: models.NodeSecurityGroup, AccountID: acct, ARN: sgOpen, Name: "open", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgClosed, Type: models.NodeSecurityGroup, AccountID: acct, ARN: sgClosed, Name: "closed", FirstSeenAt: now, LastSeenAt: now},
		{ID: pubInst, Type: models.NodeEC2Instance, AccountID: acct, ARN: pubInst, Name: "i-public", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"public_ip": "1.2.3.4"}},
		{ID: privInst, Type: models.NodeEC2Instance, AccountID: acct, ARN: privInst, Name: "i-private", FirstSeenAt: now, LastSeenAt: now},
		{ID: lbARN, Type: models.NodeLoadBalancer, AccountID: acct, ARN: lbARN, Name: "web", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"internet_facing": true}},
		{ID: rdsARN, Type: models.NodeRDSInstance, AccountID: acct, ARN: rdsARN, Name: "prod", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"publicly_accessible": true}},
	}
	ingress := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeAllowsIngress, sgOpen),
		FromNodeID: models.NodeInternet, ToNodeID: sgOpen, Type: models.EdgeAllowsIngress, Effect: "Allow",
		Confidence: models.ConfidenceDefinite, Properties: map[string]any{"ports": "tcp/22"}, FirstSeenAt: now, LastSeenAt: now}
	edges := []models.Edge{
		ingress,
		{ID: collector.EdgeID(pubInst, models.EdgeAttachedTo, sgOpen), FromNodeID: pubInst, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(privInst, models.EdgeAttachedTo, sgClosed), FromNodeID: privInst, ToNodeID: sgClosed, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
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

func TestDeriveNetworkExposure(t *testing.T) {
	ctx := context.Background()
	store, snap := seedNetwork(t)
	n, err := DeriveNetworkExposure(ctx, store, snap, acct)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected reachable-from edges")
	}
	reach, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeReachableFrom})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range reach {
		got[e.ToNodeID] = true
	}
	pubInst := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-public"
	privInst := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-private"
	lbARN := "arn:aws:elasticloadbalancing:ap-southeast-2:" + acct + ":loadbalancer/app/web/abc"
	rdsARN := "arn:aws:rds:ap-southeast-2:" + acct + ":db:prod"
	for _, want := range []string{pubInst, lbARN, rdsARN} {
		if !got[want] {
			t.Errorf("expected %s reachable from internet; got %v", want, got)
		}
	}
	if got[privInst] {
		t.Error("private instance (closed SG, no public IP) must not be internet-reachable")
	}
}

func TestScanNetworkFindings(t *testing.T) {
	ctx := context.Background()
	store, snap := seedNetwork(t)
	if _, err := DeriveNetworkExposure(ctx, store, snap, acct); err != nil {
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
	for _, want := range []string{"BH-AWS-NET-001", "BH-AWS-NET-002", "BH-AWS-NET-003", "BH-AWS-NET-004"} {
		if !byRule[want] {
			t.Errorf("expected finding for rule %s; got %v", want, byRule)
		}
	}
}

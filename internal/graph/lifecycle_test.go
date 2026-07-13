package graph

import (
	"context"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

func TestPruneCollectionScopeRemovesOnlyStaleOwnedRecords(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	snap1, err := store.CreateSnapshot(ctx, "111111111111", "first", now)
	if err != nil {
		t.Fatal(err)
	}
	ec2ID := "arn:aws:ec2:ap-southeast-2:111111111111:instance/i-old"
	sgID := "arn:aws:ec2:ap-southeast-2:111111111111:security-group/sg-current"
	s3ID := "arn:aws:s3:::unrelated"
	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Provider: "aws", Name: "Internet", FirstSeenAt: now, LastSeenAt: now},
		{ID: ec2ID, Type: models.NodeEC2Instance, Provider: "aws", AccountID: "111111111111", Region: "ap-southeast-2", Name: "i-old", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgID, Type: models.NodeSecurityGroup, Provider: "aws", AccountID: "111111111111", Region: "ap-southeast-2", Name: "sg-current", FirstSeenAt: now, LastSeenAt: now},
		{ID: s3ID, Type: models.NodeS3Bucket, Provider: "aws", AccountID: "111111111111", Region: "us-east-1", Name: "unrelated", FirstSeenAt: now, LastSeenAt: now},
	}
	ingress := models.Edge{ID: "old-ingress", FromNodeID: models.NodeInternet, ToNodeID: sgID,
		Type: models.EdgeAllowsIngress, Properties: map[string]any{"ports": "tcp/22"}, FirstSeenAt: now, LastSeenAt: now}
	if err := store.Import(ctx, snap1.ID, nodes, []models.Edge{ingress}, nil); err != nil {
		t.Fatal(err)
	}

	snap2, err := store.CreateSnapshot(ctx, "111111111111", "second", now.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, snap2.ID, []models.Node{nodes[2]}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneCollectionScope(ctx, snap2.ID, "111111111111",
		[]string{models.NodeEC2Instance}, []string{models.EdgeDeployedIn}, []string{"ap-southeast-2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneCollectionScope(ctx, snap2.ID, "111111111111",
		[]string{models.NodeSecurityGroup}, []string{models.EdgeAllowsIngress}, []string{"ap-southeast-2"}); err != nil {
		t.Fatal(err)
	}
	if node, _ := store.GetNode(ctx, ec2ID); node != nil {
		t.Fatal("stale EC2 node was not pruned")
	}
	if node, _ := store.GetNode(ctx, s3ID); node == nil {
		t.Fatal("unrelated S3 node was incorrectly pruned")
	}
	if edge, _ := store.GetEdge(ctx, ingress.ID); edge != nil {
		t.Fatal("stale ingress edge was not pruned")
	}
}

func TestDeleteDerivedGraphAndResolveFindings(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	snap, err := store.CreateSnapshot(ctx, "111111111111", "", now)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []models.Node{node("A"), node("B")}
	edges := []models.Edge{{ID: "derived", FromNodeID: "A", ToNodeID: "B", Type: models.EdgeAssumeRole,
		Properties: map[string]any{"derived": true}, FirstSeenAt: now, LastSeenAt: now}}
	if err := store.Import(ctx, snap.ID, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteDerivedGraph(ctx); err != nil {
		t.Fatal(err)
	}
	if edge, _ := store.GetEdge(ctx, "derived"); edge != nil {
		t.Fatal("derived edge was not deleted")
	}

	finding := models.Finding{ID: "BH-test", RuleID: "rule", Title: "test", Severity: models.SeverityHigh,
		Confidence: models.ConfidenceDefinite, Category: "test", Status: models.StatusOpen,
		FirstSeenAt: now, LastSeenAt: now, SnapshotID: snap.ID, Fingerprint: "fingerprint"}
	if err := store.UpsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveOpenFindings(ctx); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.GetFinding(ctx, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Status != models.StatusResolved {
		t.Fatalf("expected resolved finding, got %+v", resolved)
	}
}

func TestPruneCollectionScopePreservesRelationshipsOwnedByOtherCollectors(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	snap1, err := store.CreateSnapshot(ctx, "111111111111", "first", now)
	if err != nil {
		t.Fatal(err)
	}
	ec2ID := "arn:aws:ec2:ap-southeast-2:111111111111:instance/i-current"
	subnetID := "arn:aws:ec2:ap-southeast-2:111111111111:subnet/subnet-current"
	ec2Node := models.Node{ID: ec2ID, Type: models.NodeEC2Instance, Provider: "aws", AccountID: "111111111111", Region: "ap-southeast-2", Name: "i-current", FirstSeenAt: now, LastSeenAt: now}
	subnetNode := models.Node{ID: subnetID, Type: models.NodeSubnet, Provider: "aws", AccountID: "111111111111", Region: "ap-southeast-2", Name: "subnet-current", FirstSeenAt: now, LastSeenAt: now}
	placement := models.Edge{ID: "ec2-subnet", FromNodeID: ec2ID, ToNodeID: subnetID, Type: models.EdgeDeployedIn, FirstSeenAt: now, LastSeenAt: now}
	if err := store.Import(ctx, snap1.ID, []models.Node{ec2Node, subnetNode}, []models.Edge{placement}, nil); err != nil {
		t.Fatal(err)
	}
	snap2, err := store.CreateSnapshot(ctx, "111111111111", "second", now.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, snap2.ID, []models.Node{subnetNode}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneCollectionScope(ctx, snap2.ID, "111111111111",
		[]string{models.NodeSubnet}, []string{models.EdgeDeployedIn}, []string{"ap-southeast-2"}); err != nil {
		t.Fatal(err)
	}
	if edge, _ := store.GetEdge(ctx, placement.ID); edge == nil {
		t.Fatal("VPC-only reconciliation deleted EC2-owned subnet placement")
	}
}

func TestResetInventoryPreservesSuppressions(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	finding := models.Finding{ID: "BH-suppressed", RuleID: "rule", Title: "test", Severity: models.SeverityHigh,
		Confidence: models.ConfidenceDefinite, Category: "test", Status: models.StatusOpen,
		FirstSeenAt: now, LastSeenAt: now, SnapshotID: "snap", Fingerprint: "suppressed-fingerprint"}
	if err := store.UpsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := store.Suppress(ctx, finding.Fingerprint, "accepted risk", "tester", "", now); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetFinding(ctx, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != models.StatusSuppressed {
		t.Fatalf("expected suppression to survive reset, got %+v", got)
	}
}

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
	subnetARN := "arn:aws:ec2:ap-southeast-2:" + acct + ":subnet/subnet-public"
	aclARN := "arn:aws:ec2:ap-southeast-2:" + acct + ":network-acl/acl-public"

	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgOpen, Type: models.NodeSecurityGroup, AccountID: acct, ARN: sgOpen, Name: "open", FirstSeenAt: now, LastSeenAt: now},
		{ID: sgClosed, Type: models.NodeSecurityGroup, AccountID: acct, ARN: sgClosed, Name: "closed", FirstSeenAt: now, LastSeenAt: now},
		{ID: subnetARN, Type: models.NodeSubnet, AccountID: acct, ARN: subnetARN, Name: "subnet-public", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"public": true}},
		{ID: aclARN, Type: models.NodeNetworkACL, AccountID: acct, ARN: aclARN, Name: "acl-public", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"open_ingress_ports": "all traffic", "open_egress_ports": "all traffic"}},
		{ID: pubInst, Type: models.NodeEC2Instance, AccountID: acct, ARN: pubInst, Name: "i-public", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"public_ip": "1.2.3.4"}},
		{ID: privInst, Type: models.NodeEC2Instance, AccountID: acct, ARN: privInst, Name: "i-private", FirstSeenAt: now, LastSeenAt: now},
		{ID: lbARN, Type: models.NodeLoadBalancer, AccountID: acct, ARN: lbARN, Name: "web", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"internet_facing": true, "type": "application", "listener_ports": "tcp/443"}},
		{ID: rdsARN, Type: models.NodeRDSInstance, AccountID: acct, ARN: rdsARN, Name: "prod", FirstSeenAt: now, LastSeenAt: now,
			Properties: map[string]any{"publicly_accessible": true, "port": 5432}},
	}
	ingress := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeAllowsIngress, sgOpen),
		FromNodeID: models.NodeInternet, ToNodeID: sgOpen, Type: models.EdgeAllowsIngress, Effect: "Allow",
		Confidence: models.ConfidenceDefinite, Properties: map[string]any{"ports": "tcp/22, tcp/443, tcp/5432"}, FirstSeenAt: now, LastSeenAt: now}
	edges := []models.Edge{
		ingress,
		{ID: collector.EdgeID(pubInst, models.EdgeAttachedTo, sgOpen), FromNodeID: pubInst, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(privInst, models.EdgeAttachedTo, sgClosed), FromNodeID: privInst, ToNodeID: sgClosed, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(lbARN, models.EdgeAttachedTo, sgOpen), FromNodeID: lbARN, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(rdsARN, models.EdgeAttachedTo, sgOpen), FromNodeID: rdsARN, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(pubInst, models.EdgeDeployedIn, subnetARN), FromNodeID: pubInst, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(privInst, models.EdgeDeployedIn, subnetARN), FromNodeID: privInst, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(lbARN, models.EdgeDeployedIn, subnetARN), FromNodeID: lbARN, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(rdsARN, models.EdgeDeployedIn, subnetARN), FromNodeID: rdsARN, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(subnetARN, models.EdgeAttachedTo, aclARN), FromNodeID: subnetARN, ToNodeID: aclARN, Type: models.EdgeAttachedTo, Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now},
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
	for _, edge := range reach {
		ports, _ := edge.Properties["ports"].(string)
		switch edge.ToNodeID {
		case lbARN:
			if ports != "tcp/443" {
				t.Errorf("expected LB listener intersection tcp/443, got %q", ports)
			}
		case rdsARN:
			if ports != "tcp/5432" {
				t.Errorf("expected RDS endpoint port tcp/5432, got %q", ports)
			}
		}
	}
}

func TestDeriveNetworkExposureRequiresSGExceptNLBWithoutOne(t *testing.T) {
	ctx := context.Background()
	store, snap := seedNetwork(t)
	now := time.Now().UTC()
	subnetARN := "arn:aws:ec2:ap-southeast-2:" + acct + ":subnet/subnet-public"
	closedLB := "arn:aws:elasticloadbalancing:ap-southeast-2:" + acct + ":loadbalancer/app/closed/abc"
	nlb := "arn:aws:elasticloadbalancing:ap-southeast-2:" + acct + ":loadbalancer/net/public/def"
	closedSG := "arn:aws:ec2:ap-southeast-2:" + acct + ":security-group/sg-closed"
	nodes := []models.Node{
		{ID: closedLB, Type: models.NodeLoadBalancer, Name: "closed", Properties: map[string]any{
			"internet_facing": true, "type": "application", "listener_ports": "tcp/443"}, FirstSeenAt: now, LastSeenAt: now},
		{ID: nlb, Type: models.NodeLoadBalancer, Name: "public-nlb", Properties: map[string]any{
			"internet_facing": true, "type": "network", "listener_ports": "tcp/8443"}, FirstSeenAt: now, LastSeenAt: now},
	}
	edges := []models.Edge{
		{ID: collector.EdgeID(closedLB, models.EdgeAttachedTo, closedSG), FromNodeID: closedLB, ToNodeID: closedSG, Type: models.EdgeAttachedTo, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(closedLB, models.EdgeDeployedIn, subnetARN), FromNodeID: closedLB, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(nlb, models.EdgeDeployedIn, subnetARN), FromNodeID: nlb, ToNodeID: subnetARN, Type: models.EdgeDeployedIn, FirstSeenAt: now, LastSeenAt: now},
	}
	if err := store.Import(ctx, snap, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveNetworkExposure(ctx, store, snap, acct); err != nil {
		t.Fatal(err)
	}
	reach, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeReachableFrom})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, edge := range reach {
		got[edge.ToNodeID], _ = edge.Properties["ports"].(string)
	}
	if _, ok := got[closedLB]; ok {
		t.Error("application load balancer with a closed security group must not be exposed")
	}
	if got[nlb] != "tcp/8443" {
		t.Errorf("expected NLB without a security group on tcp/8443, got %q", got[nlb])
	}
}

func TestDeriveNetworkExposureRouteAndACLConfidence(t *testing.T) {
	ctx := context.Background()
	store, snap := seedNetwork(t)
	now := time.Now().UTC()
	sgOpen := "arn:aws:ec2:ap-southeast-2:" + acct + ":security-group/sg-open"
	publicNoACL := "arn:aws:ec2:ap-southeast-2:" + acct + ":subnet/public-no-acl"
	privateSubnet := "arn:aws:ec2:ap-southeast-2:" + acct + ":subnet/private"
	possibleInstance := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-possible"
	blockedInstance := "arn:aws:ec2:ap-southeast-2:" + acct + ":instance/i-no-route"
	nodes := []models.Node{
		{ID: publicNoACL, Type: models.NodeSubnet, Name: "public-no-acl", Properties: map[string]any{"public": true}, FirstSeenAt: now, LastSeenAt: now},
		{ID: privateSubnet, Type: models.NodeSubnet, Name: "private", Properties: map[string]any{"public": false}, FirstSeenAt: now, LastSeenAt: now},
		{ID: possibleInstance, Type: models.NodeEC2Instance, Name: "i-possible", Properties: map[string]any{"public_ip": "198.51.100.10"}, FirstSeenAt: now, LastSeenAt: now},
		{ID: blockedInstance, Type: models.NodeEC2Instance, Name: "i-no-route", Properties: map[string]any{"public_ip": "198.51.100.11"}, FirstSeenAt: now, LastSeenAt: now},
	}
	edges := []models.Edge{
		{ID: collector.EdgeID(possibleInstance, models.EdgeAttachedTo, sgOpen), FromNodeID: possibleInstance, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(possibleInstance, models.EdgeDeployedIn, publicNoACL), FromNodeID: possibleInstance, ToNodeID: publicNoACL, Type: models.EdgeDeployedIn, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(blockedInstance, models.EdgeAttachedTo, sgOpen), FromNodeID: blockedInstance, ToNodeID: sgOpen, Type: models.EdgeAttachedTo, FirstSeenAt: now, LastSeenAt: now},
		{ID: collector.EdgeID(blockedInstance, models.EdgeDeployedIn, privateSubnet), FromNodeID: blockedInstance, ToNodeID: privateSubnet, Type: models.EdgeDeployedIn, FirstSeenAt: now, LastSeenAt: now},
	}
	if err := store.Import(ctx, snap, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveNetworkExposure(ctx, store, snap, acct); err != nil {
		t.Fatal(err)
	}
	reach, err := store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeReachableFrom})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, edge := range reach {
		got[edge.ToNodeID] = edge.Confidence
	}
	if got[possibleInstance] != models.ConfidencePossible {
		t.Errorf("expected missing ACL data to be possible, got %q", got[possibleInstance])
	}
	if _, ok := got[blockedInstance]; ok {
		t.Error("instance without a public subnet route must not be exposed")
	}
	findings, err := Scan(ctx, store, snap, acct)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.TargetNodeID == possibleInstance && finding.Confidence != models.ConfidencePossible {
			t.Errorf("expected possible exposure finding confidence, got %q", finding.Confidence)
		}
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

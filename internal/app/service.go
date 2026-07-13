// Package app is the deterministic application-service layer shared by the CLI
// and MCP adapters. All analysis flows through here so both surfaces behave
// identically. It never mutates AWS and never returns secret values.
package app

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jusso-dev/BlakHound/internal/analysis"
	"github.com/jusso-dev/BlakHound/internal/awsclient"
	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/collector/compute"
	"github.com/jusso-dev/BlakHound/internal/collector/identity"
	"github.com/jusso-dev/BlakHound/internal/collector/network"
	"github.com/jusso-dev/BlakHound/internal/collector/storage"
	"github.com/jusso-dev/BlakHound/internal/config"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// Service bundles the graph store and configuration.
type Service struct {
	Store *graph.Store
	Cfg   *config.Config
}

// New returns a Service.
func New(store *graph.Store, cfg *config.Config) *Service {
	return &Service{Store: store, Cfg: cfg}
}

// CollectOptions configures a collection run.
type CollectOptions struct {
	Services   []string
	Regions    []string
	AllRegions bool
	Force      bool
}

// CollectResult summarises a collection run.
type CollectResult struct {
	SnapshotID   string              `json:"snapshot_id"`
	AccountID    string              `json:"account_id"`
	CallerARN    string              `json:"caller_arn"`
	Nodes        int                 `json:"nodes"`
	Edges        int                 `json:"edges"`
	DerivedEdges int                 `json:"derived_edges"`
	APIRequests  int                 `json:"api_requests"`
	Warnings     []collector.Warning `json:"warnings"`
}

// Collect runs read-only collection, imports the graph, and derives edges.
func (s *Service) Collect(ctx context.Context, opts CollectOptions) (*CollectResult, error) {
	awsCfg, err := awsclient.Load(ctx, s.Cfg)
	if err != nil {
		return nil, err
	}
	ident, err := awsclient.WhoAmI(ctx, awsCfg)
	if err != nil {
		return nil, err
	}
	if s.Cfg.AccountID != "" && s.Cfg.AccountID != ident.Account {
		return nil, fmt.Errorf("authenticated account %s does not match --account-id %s", ident.Account, s.Cfg.AccountID)
	}
	if opts.AllRegions && (len(opts.Regions) > 0 || s.Cfg.Region != "") {
		return nil, fmt.Errorf("--all-regions cannot be combined with --region or --regions")
	}
	regions := append([]string(nil), opts.Regions...)
	if opts.AllRegions {
		regions, err = awsclient.EnabledRegions(ctx, awsCfg)
		if err != nil {
			return nil, err
		}
	}
	if len(regions) == 0 && awsCfg.Region != "" {
		regions = []string{awsCfg.Region}
	}
	collectors, err := selectCollectors(opts.Services)
	if err != nil {
		return nil, err
	}
	if opts.Force && len(opts.Services) > 0 {
		return nil, fmt.Errorf("--force rebuilds the complete inventory and cannot be combined with --services")
	}
	started := time.Now().UTC()

	target := collector.Target{AWSConfig: awsCfg, AccountID: ident.Account, CallerARN: ident.ARN, Regions: regions}

	agg := &collector.CollectionResult{Warnings: []collector.Warning{}}
	type completedCollection struct {
		collector collector.Collector
		result    *collector.CollectionResult
	}
	var completed []completedCollection
	for _, c := range collectors {
		r, err := c.Collect(ctx, target)
		if err != nil {
			// A single collector failing must not abort the run.
			agg.Warnings = append(agg.Warnings, collector.Warning{
				Service: c.Name(), API: "collect", Message: err.Error(),
				Impact: "This service was skipped; related paths may be missing.",
			})
			continue
		}
		agg.Merge(*r)
		completed = append(completed, completedCollection{collector: c, result: r})
	}
	if opts.Force && len(agg.Warnings) > 0 {
		return nil, fmt.Errorf("refusing --force rebuild with %d collection warning(s)", len(agg.Warnings))
	}
	snap, err := s.Store.CreateSnapshot(ctx, ident.Account, "", time.Now().UTC())
	if err != nil {
		return nil, err
	}
	snapshotComplete := false
	defer func() {
		if !snapshotComplete {
			_ = s.Store.DeleteSnapshot(context.Background(), snap.ID)
		}
	}()
	if opts.Force {
		if err := s.Store.ResetInventory(ctx); err != nil {
			return nil, fmt.Errorf("reset inventory: %w", err)
		}
	}
	if err := s.Store.Import(ctx, snap.ID, agg.Nodes, agg.Edges, agg.Evidence); err != nil {
		return nil, fmt.Errorf("import graph: %w", err)
	}
	for _, item := range completed {
		if len(item.result.Warnings) > 0 {
			continue
		}
		nodeTypes, edgeTypes := collectionOwnership(item.collector.Name())
		scopeRegions := regions
		if item.collector.Regions() == collector.ScopeGlobal {
			scopeRegions = nil
		}
		if err := s.Store.PruneCollectionScope(ctx, snap.ID, ident.Account, nodeTypes, edgeTypes, scopeRegions); err != nil {
			return nil, fmt.Errorf("reconcile %s collection: %w", item.collector.Name(), err)
		}
	}
	if err := s.Store.DeleteDerivedGraph(ctx); err != nil {
		return nil, fmt.Errorf("clear derived graph: %w", err)
	}
	derived, err := analysis.DeriveEdges(ctx, s.Store, snap.ID, ident.Account)
	if err != nil {
		return nil, fmt.Errorf("derive edges: %w", err)
	}
	resAccess, err := analysis.DeriveResourceAccess(ctx, s.Store, snap.ID, ident.Account)
	if err != nil {
		return nil, fmt.Errorf("derive resource access: %w", err)
	}
	derived += resAccess
	netExposure, err := analysis.DeriveNetworkExposure(ctx, s.Store, snap.ID, ident.Account)
	if err != nil {
		return nil, fmt.Errorf("derive network exposure: %w", err)
	}
	derived += netExposure

	runID := "run-" + started.Format("20060102T150405.000000000Z")
	_ = s.Store.RecordCollectionRun(ctx, runID, snap.ID, ident.Account, ident.ARN, "completed",
		join(regions), join(opts.Services), agg.APIRequests, started, time.Now().UTC())
	for _, w := range agg.Warnings {
		_ = s.Store.RecordCollectionError(ctx, runID, w.Service, w.API, w.Region, w.Code, w.Message, w.Impact, started)
	}
	_ = s.Store.SetMeta(ctx, "account_id", ident.Account)
	_ = s.Store.SetMeta(ctx, "caller_arn", ident.ARN)
	_ = s.Store.SetMeta(ctx, "latest_snapshot", snap.ID)
	snapshotComplete = true

	return &CollectResult{
		SnapshotID: snap.ID, AccountID: ident.Account, CallerARN: ident.ARN,
		Nodes: len(agg.Nodes), Edges: len(agg.Edges), DerivedEdges: derived,
		APIRequests: agg.APIRequests, Warnings: agg.Warnings,
	}, nil
}

func selectCollectors(services []string) ([]collector.Collector, error) {
	all := map[string]collector.Collector{
		"iam":            identity.NewIAM(),
		"s3":             storage.NewS3(),
		"secretsmanager": storage.NewSecrets(),
		"kms":            storage.NewKMS(),
		"sqs":            storage.NewSQS(),
		"sns":            storage.NewSNS(),
		"ec2":            compute.NewEC2(),
		"lambda":         compute.NewLambda(),
		"ecs":            compute.NewECS(),
		"vpc":            network.NewVPC(),
		"elbv2":          network.NewELB(),
		"rds":            network.NewRDS(),
	}
	if len(services) == 0 {
		out := make([]collector.Collector, 0, len(all))
		for _, name := range sortedKeys(all) {
			out = append(out, all[name])
		}
		return out, nil
	}
	var out []collector.Collector
	for _, s := range services {
		c, ok := all[s]
		if !ok {
			return nil, fmt.Errorf("unknown service %q (available: %s)", s, join(sortedKeys(all)))
		}
		out = append(out, c)
	}
	return out, nil
}

func collectionOwnership(service string) (nodeTypes, edgeTypes []string) {
	switch service {
	case "iam":
		return []string{models.NodeAWSAccount, models.NodeIAMUser, models.NodeIAMGroup, models.NodeIAMRole, models.NodeIAMPolicy, models.NodeInstanceProfile},
			[]string{models.EdgeMemberOf, models.EdgeAttachedPolicy, models.EdgeInlinePolicy, models.EdgeRunsAs}
	case "s3":
		return []string{models.NodeS3Bucket}, []string{models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "secretsmanager":
		return []string{models.NodeSecret}, []string{models.EdgeEncryptedBy, models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "kms":
		return []string{models.NodeKMSKey}, []string{models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "sqs":
		return []string{models.NodeSQSQueue}, []string{models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "sns":
		return []string{models.NodeSNSTopic}, []string{models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "ec2":
		return []string{models.NodeEC2Instance}, []string{models.EdgeHasInstanceProfile, models.EdgeDeployedIn}
	case "lambda":
		return []string{models.NodeLambdaFunction}, []string{models.EdgeRunsAs, models.EdgePublicAccess, models.EdgeCrossAccountAccess}
	case "ecs":
		return []string{models.NodeECSTaskDefinition, models.NodeECSCluster, models.NodeECSService}, []string{models.EdgeRunsAs}
	case "vpc":
		return []string{models.NodeVPC, models.NodeSubnet, models.NodeRouteTable, models.NodeSecurityGroup, models.NodeNetworkACL, models.NodeInternetGateway, models.NodeNATGateway},
			[]string{models.EdgeAttachedTo, models.EdgeDeployedIn, models.EdgeRoutesTo, models.EdgeAllowsIngress}
	case "elbv2":
		return []string{models.NodeLoadBalancer, models.NodeTargetGroup}, []string{models.EdgeAttachedTo, models.EdgeDeployedIn, models.EdgeFronts}
	case "rds":
		return []string{models.NodeRDSInstance}, []string{models.EdgeAttachedTo, models.EdgeDeployedIn}
	default:
		return nil, nil
	}
}

// Scan runs the rule engine and returns findings.
func (s *Service) Scan(ctx context.Context) ([]models.Finding, error) {
	snap, _ := s.Store.LatestSnapshot(ctx)
	acct, _ := s.Store.GetMeta(ctx, "account_id")
	if err := s.Store.ResolveOpenFindings(ctx); err != nil {
		return nil, err
	}
	return analysis.Scan(ctx, s.Store, snap, acct)
}

// FindPaths returns explained, scored attack paths from -> to.
func (s *Service) FindPaths(ctx context.Context, from, to string, opt graph.TraverseOptions) ([]models.AttackPath, error) {
	fromNode, err := s.Store.ResolveNode(ctx, from)
	if err != nil {
		return nil, err
	}
	if fromNode == nil {
		return nil, fmt.Errorf("source node not found: %s", from)
	}
	toID := ""
	if to != "" {
		toNode, err := s.Store.ResolveNode(ctx, to)
		if err != nil {
			return nil, err
		}
		if toNode == nil {
			return nil, fmt.Errorf("target node not found: %s", to)
		}
		toID = toNode.ID
	}
	raws, err := s.Store.AllPaths(ctx, fromNode.ID, toID, opt)
	if err != nil {
		return nil, err
	}
	var out []models.AttackPath
	for _, r := range raws {
		ap, err := s.Store.BuildAttackPath(ctx, r)
		if err != nil {
			return nil, err
		}
		ap.Score = analysis.ScorePath(ap)
		ap.Severity = analysis.SeverityForScore(ap.Score)
		out = append(out, ap)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return len(out[i].Steps) < len(out[j].Steps)
	})
	return out, nil
}

// WhoCanReach returns principals that have a path to the target node.
func (s *Service) WhoCanReach(ctx context.Context, target string, opt graph.TraverseOptions) ([]models.AttackPath, error) {
	tNode, err := s.Store.ResolveNode(ctx, target)
	if err != nil {
		return nil, err
	}
	if tNode == nil {
		return nil, fmt.Errorf("resource not found: %s", target)
	}
	principalTypes := map[string]bool{
		models.NodeIAMUser: true, models.NodeIAMRole: true, models.NodeExternalAccount: true,
		models.NodeAnonymousPrincipal: true, models.NodeServicePrincipal: true,
	}
	nodes, err := s.Store.AllNodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []models.AttackPath
	for _, n := range nodes {
		if !principalTypes[n.Type] || n.ID == tNode.ID {
			continue
		}
		raw, err := s.Store.ShortestPath(ctx, n.ID, tNode.ID, opt)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		ap, err := s.Store.BuildAttackPath(ctx, raw)
		if err != nil {
			return nil, err
		}
		ap.Score = analysis.ScorePath(ap)
		ap.Severity = analysis.SeverityForScore(ap.Score)
		out = append(out, ap)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// WhatCanReach returns nodes reachable from a principal with an explained path.
func (s *Service) WhatCanReach(ctx context.Context, principal string, opt graph.TraverseOptions) ([]models.AttackPath, error) {
	pNode, err := s.Store.ResolveNode(ctx, principal)
	if err != nil {
		return nil, err
	}
	if pNode == nil {
		return nil, fmt.Errorf("principal not found: %s", principal)
	}
	nodes, err := s.Store.AllNodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []models.AttackPath
	for _, n := range nodes {
		if n.ID == pNode.ID {
			continue
		}
		raw, err := s.Store.ShortestPath(ctx, pNode.ID, n.ID, opt)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		ap, err := s.Store.BuildAttackPath(ctx, raw)
		if err != nil {
			return nil, err
		}
		ap.Score = analysis.ScorePath(ap)
		ap.Severity = analysis.SeverityForScore(ap.Score)
		out = append(out, ap)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// ExposedResource is a resource reachable from the internet, with the open
// ports and the reason it is exposed.
type ExposedResource struct {
	Resource   models.Node `json:"resource"`
	Ports      string      `json:"ports"`
	Reason     string      `json:"reason"`
	EdgeID     string      `json:"edge_id"`
	Confidence string      `json:"confidence"`
}

// InternetExposure returns every resource the internet node can reach via a
// derived reachable-from edge, sorted by resource type then name. It reads the
// graph produced by analysis.DeriveNetworkExposure; run a collection first.
func (s *Service) InternetExposure(ctx context.Context) ([]ExposedResource, error) {
	edges, err := s.Store.OutEdges(ctx, models.NodeInternet, []string{models.EdgeReachableFrom})
	if err != nil {
		return nil, err
	}
	out := make([]ExposedResource, 0, len(edges))
	for _, e := range edges {
		n, err := s.Store.GetNode(ctx, e.ToNodeID)
		if err != nil || n == nil {
			continue
		}
		ports, _ := e.Properties["ports"].(string)
		reason, _ := e.Properties["explanation"].(string)
		out = append(out, ExposedResource{Resource: *n, Ports: ports, Reason: reason, EdgeID: e.ID, Confidence: e.Confidence})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Resource.Type != out[j].Resource.Type {
			return out[i].Resource.Type < out[j].Resource.Type
		}
		return out[i].Resource.Name < out[j].Resource.Name
	})
	return out, nil
}

// EdgeExplanation bundles an edge with its evidence records.
type EdgeExplanation struct {
	Edge     *models.Edge      `json:"edge"`
	Evidence []models.Evidence `json:"evidence"`
}

// ExplainEdge returns an edge and all its evidence.
func (s *Service) ExplainEdge(ctx context.Context, edgeID string) (*EdgeExplanation, error) {
	e, err := s.Store.GetEdge(ctx, edgeID)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("edge not found: %s", edgeID)
	}
	out := &EdgeExplanation{Edge: e}
	for _, id := range e.EvidenceIDs {
		ev, err := s.Store.GetEvidence(ctx, id)
		if err == nil && ev != nil {
			out.Evidence = append(out.Evidence, *ev)
		}
	}
	return out, nil
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

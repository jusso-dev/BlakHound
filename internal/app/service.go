// Package app is the deterministic application-service layer shared by the CLI
// and MCP adapters. All analysis flows through here so both surfaces behave
// identically. It never mutates AWS and never returns secret values.
package app

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/blakhound/blakhound/internal/analysis"
	"github.com/blakhound/blakhound/internal/awsclient"
	"github.com/blakhound/blakhound/internal/collector"
	"github.com/blakhound/blakhound/internal/collector/compute"
	"github.com/blakhound/blakhound/internal/collector/identity"
	"github.com/blakhound/blakhound/internal/collector/storage"
	"github.com/blakhound/blakhound/internal/config"
	"github.com/blakhound/blakhound/internal/graph"
	"github.com/blakhound/blakhound/pkg/models"
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
	Services []string
	Regions  []string
	Force    bool
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
	now := time.Now().UTC()
	snap, err := s.Store.CreateSnapshot(ctx, ident.Account, "", now)
	if err != nil {
		return nil, err
	}

	target := collector.Target{AWSConfig: awsCfg, AccountID: ident.Account, CallerARN: ident.ARN, Regions: opts.Regions}
	collectors := selectCollectors(opts.Services)

	agg := &collector.CollectionResult{}
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
	}

	if err := s.Store.Import(ctx, snap.ID, agg.Nodes, agg.Edges, agg.Evidence); err != nil {
		return nil, fmt.Errorf("import graph: %w", err)
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

	runID := "run-" + now.Format("20060102T150405Z")
	_ = s.Store.RecordCollectionRun(ctx, runID, snap.ID, ident.Account, ident.ARN, "completed",
		join(opts.Regions), join(opts.Services), agg.APIRequests, now, time.Now().UTC())
	for _, w := range agg.Warnings {
		_ = s.Store.RecordCollectionError(ctx, runID, w.Service, w.API, w.Region, w.Code, w.Message, w.Impact, now)
	}
	_ = s.Store.SetMeta(ctx, "account_id", ident.Account)
	_ = s.Store.SetMeta(ctx, "caller_arn", ident.ARN)
	_ = s.Store.SetMeta(ctx, "latest_snapshot", snap.ID)

	return &CollectResult{
		SnapshotID: snap.ID, AccountID: ident.Account, CallerARN: ident.ARN,
		Nodes: len(agg.Nodes), Edges: len(agg.Edges), DerivedEdges: derived,
		APIRequests: agg.APIRequests, Warnings: agg.Warnings,
	}, nil
}

func selectCollectors(services []string) []collector.Collector {
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
	}
	if len(services) == 0 {
		out := make([]collector.Collector, 0, len(all))
		for _, name := range sortedKeys(all) {
			out = append(out, all[name])
		}
		return out
	}
	var out []collector.Collector
	for _, s := range services {
		if c, ok := all[s]; ok {
			out = append(out, c)
		}
	}
	return out
}

// Scan runs the rule engine and returns findings.
func (s *Service) Scan(ctx context.Context) ([]models.Finding, error) {
	snap, _ := s.Store.LatestSnapshot(ctx)
	acct, _ := s.Store.GetMeta(ctx, "account_id")
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

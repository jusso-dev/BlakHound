// Package collector defines the read-only AWS collection framework. Individual
// service collectors normalise AWS objects into graph nodes, edges and
// evidence. No collector may mutate an AWS account or retrieve secret values.
package collector

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/blakhound/blakhound/pkg/models"
)

// RegionScope indicates whether a collector is global or regional.
type RegionScope int

const (
	// ScopeGlobal collectors run once (e.g. IAM).
	ScopeGlobal RegionScope = iota
	// ScopeRegional collectors run per requested region.
	ScopeRegional
)

// Target describes what to collect.
type Target struct {
	AWSConfig aws.Config
	AccountID string
	CallerARN string
	Regions   []string
}

// Warning records a non-fatal collection problem such as a permission gap.
type Warning struct {
	Service string `json:"service"`
	API     string `json:"api"`
	Region  string `json:"region"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Impact  string `json:"impact"`
}

// CollectionResult is the normalised output of a single collector.
type CollectionResult struct {
	Nodes       []models.Node
	Edges       []models.Edge
	Evidence    []models.Evidence
	Warnings    []Warning
	APIRequests int
}

// Merge appends another result into this one.
func (r *CollectionResult) Merge(other CollectionResult) {
	r.Nodes = append(r.Nodes, other.Nodes...)
	r.Edges = append(r.Edges, other.Edges...)
	r.Evidence = append(r.Evidence, other.Evidence...)
	r.Warnings = append(r.Warnings, other.Warnings...)
	r.APIRequests += other.APIRequests
}

// Collector is implemented by each service collector.
type Collector interface {
	Name() string
	Regions() RegionScope
	RequiredPermissions() []string
	Collect(ctx context.Context, target Target) (*CollectionResult, error)
}

package storage

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

// S3Collector collects S3 buckets, their policies and public-access settings.
// S3 is global for listing; each bucket is queried in its own region.
type S3Collector struct{}

func NewS3() *S3Collector                             { return &S3Collector{} }
func (c *S3Collector) Name() string                   { return "s3" }
func (c *S3Collector) Regions() collector.RegionScope { return collector.ScopeGlobal }
func (c *S3Collector) RequiredPermissions() []string {
	return []string{"s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketAcl"}
}

func (c *S3Collector) Collect(ctx context.Context, t collector.Target) (*collector.CollectionResult, error) {
	now := time.Now().UTC()
	res := &collector.CollectionResult{}
	client := s3.NewFromConfig(t.AWSConfig)
	list, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		res.Warnings = append(res.Warnings, warn("s3", "ListBuckets", "", err,
			"S3 buckets could not be listed; bucket-access paths may be missing."))
		return res, nil
	}
	res.APIRequests++
	for _, b := range list.Buckets {
		name := aws.ToString(b.Name)
		arn := "arn:aws:s3:::" + name
		region := bucketRegion(ctx, client, name, res)
		node := models.Node{ID: arn, Type: models.NodeS3Bucket, Provider: "aws", AccountID: t.AccountID,
			Region: region, ARN: arn, Name: name, FirstSeenAt: now, LastSeenAt: now, Properties: map[string]any{}}

		// Public Access Block.
		pab := publicAccessBlocked(ctx, client, name, res)
		node.Properties["public_access_block"] = pab

		res.Nodes = append(res.Nodes, node)

		// Bucket policy (resource-scoped to bucket + objects).
		pol, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
		if err == nil && pol.Policy != nil {
			res.APIRequests++
			doc := aws.ToString(pol.Policy)
			n, e, ev := collector.ResourcePolicyEdges(arn, arn, t.AccountID, "s3", "GetBucketPolicy", "s3-bucket-policy", doc, now)
			// Suppress public edges when a Public Access Block neutralises them.
			if pab {
				e = dropPublic(e)
			}
			res.Nodes = append(res.Nodes, n...)
			res.Edges = append(res.Edges, e...)
			res.Evidence = append(res.Evidence, ev...)
		}
	}
	return res, nil
}

func bucketRegion(ctx context.Context, client *s3.Client, name string, res *collector.CollectionResult) string {
	loc, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
	if err != nil {
		return ""
	}
	res.APIRequests++
	if loc.LocationConstraint == "" {
		return "us-east-1"
	}
	return string(loc.LocationConstraint)
}

func publicAccessBlocked(ctx context.Context, client *s3.Client, name string, res *collector.CollectionResult) bool {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
	if err != nil {
		return false
	}
	res.APIRequests++
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return false
	}
	return aws.ToBool(cfg.RestrictPublicBuckets) && aws.ToBool(cfg.IgnorePublicAcls)
}

func dropPublic(edges []models.Edge) []models.Edge {
	var out []models.Edge
	for _, e := range edges {
		if e.Type == models.EdgePublicAccess {
			continue
		}
		out = append(out, e)
	}
	return out
}

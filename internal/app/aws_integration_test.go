//go:build awsintegration

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jusso-dev/BlakHound/internal/config"
	"github.com/jusso-dev/BlakHound/internal/graph"
)

// TestReadOnlyAWSNetworkCollection exercises the real SDK credential chain and
// network collectors. It never creates, updates or deletes AWS resources.
func TestReadOnlyAWSNetworkCollection(t *testing.T) {
	if os.Getenv("BLAKHOUND_AWS_INTEGRATION") != "1" {
		t.Skip("set BLAKHOUND_AWS_INTEGRATION=1 to run read-only AWS integration tests")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "ap-southeast-2"
	}
	cfg := &config.Config{Profile: os.Getenv("AWS_PROFILE"), Region: region,
		DBPath: filepath.Join(t.TempDir(), "aws-integration.db")}
	cfg.Normalize()
	ctx := context.Background()
	store, err := graph.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	result, err := New(store, cfg).Collect(ctx, CollectOptions{
		Services: []string{"ec2", "vpc", "elbv2", "rds"}, Regions: []string{region},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountID == "" || result.SnapshotID == "" || result.APIRequests == 0 {
		t.Fatalf("incomplete integration result: %+v", result)
	}
	if _, err := New(store, cfg).InternetExposure(ctx); err != nil {
		t.Fatal(err)
	}
}

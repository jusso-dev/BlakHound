package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func TestInternetExposure(t *testing.T) {
	ctx := context.Background()
	store, err := graph.Open(ctx, filepath.Join(t.TempDir(), "exp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()

	rdsARN := "arn:aws:rds:ap-southeast-2:111111111111:db:prod"
	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now},
		{ID: rdsARN, Type: models.NodeRDSInstance, ARN: rdsARN, Name: "prod", FirstSeenAt: now, LastSeenAt: now},
	}
	edge := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeReachableFrom, rdsARN),
		FromNodeID: models.NodeInternet, ToNodeID: rdsARN, Type: models.EdgeReachableFrom, Effect: "Allow",
		Confidence:  models.ConfidenceDefinite,
		Properties:  map[string]any{"explanation": "prod is reachable from the internet", "ports": "tcp/5432"},
		FirstSeenAt: now, LastSeenAt: now}
	snap, err := store.CreateSnapshot(ctx, "111111111111", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, snap.ID, nodes, []models.Edge{edge}, nil); err != nil {
		t.Fatal(err)
	}

	svc := New(store, nil)
	exposed, err := svc.InternetExposure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exposed) != 1 {
		t.Fatalf("expected 1 exposed resource, got %d", len(exposed))
	}
	if exposed[0].Resource.ID != rdsARN {
		t.Errorf("expected %s, got %s", rdsARN, exposed[0].Resource.ID)
	}
	if exposed[0].Ports != "tcp/5432" {
		t.Errorf("expected ports tcp/5432, got %q", exposed[0].Ports)
	}
}

func TestInternetExposureEmptyJSON(t *testing.T) {
	ctx := context.Background()
	store, err := graph.Open(ctx, filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	exposed, err := New(store, nil).InternetExposure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(exposed)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Fatalf("expected empty JSON array, got %s", b)
	}
}

func TestSelectCollectorsRejectsUnknownService(t *testing.T) {
	if _, err := selectCollectors([]string{"not-a-service"}); err == nil {
		t.Fatal("expected unknown service error")
	}
	collectors, err := selectCollectors([]string{"vpc", "rds"})
	if err != nil {
		t.Fatal(err)
	}
	if len(collectors) != 2 || collectors[0].Name() != "vpc" || collectors[1].Name() != "rds" {
		t.Fatalf("unexpected collectors: %+v", collectors)
	}
}

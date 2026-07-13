package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/config"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func TestExposureCommandJSONPositiveAndEmpty(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cli-exposure.db")
	store, err := graph.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapshot, err := store.CreateSnapshot(ctx, "111111111111", "", now)
	if err != nil {
		t.Fatal(err)
	}
	resourceID := "arn:aws:rds:ap-southeast-2:111111111111:db:prod"
	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Provider: "aws", Name: "Internet", FirstSeenAt: now, LastSeenAt: now},
		{ID: resourceID, Type: models.NodeRDSInstance, Provider: "aws", Name: "prod", FirstSeenAt: now, LastSeenAt: now},
	}
	edge := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeReachableFrom, resourceID),
		FromNodeID: models.NodeInternet, ToNodeID: resourceID, Type: models.EdgeReachableFrom,
		Confidence: models.ConfidenceDefinite, Properties: map[string]any{"ports": "tcp/5432"},
		FirstSeenAt: now, LastSeenAt: now}
	if err := store.Import(ctx, snapshot.ID, nodes, []models.Edge{edge}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	oldCfg := cfg
	cfg = &config.Config{DBPath: dbPath, Output: "json"}
	t.Cleanup(func() { cfg = oldCfg })
	positive := captureStdout(t, func() {
		if err := newExposureCmd().ExecuteContext(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(positive, `"ports": "tcp/5432"`) {
		t.Fatalf("unexpected positive JSON output: %s", positive)
	}

	emptyPath := filepath.Join(t.TempDir(), "empty.db")
	cfg.DBPath = emptyPath
	empty := captureStdout(t, func() {
		if err := newExposureCmd().ExecuteContext(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if strings.TrimSpace(empty) != "[]" {
		t.Fatalf("expected empty JSON array, got %q", empty)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	fn()
	_ = writer.Close()
	os.Stdout = original
	b, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	return string(b)
}

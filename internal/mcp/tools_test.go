package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/internal/app"
	"github.com/jusso-dev/BlakHound/internal/collector"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	store, err := graph.Open(ctx, filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()

	lbARN := "arn:aws:elasticloadbalancing:ap-southeast-2:111111111111:loadbalancer/app/web/abc"
	nodes := []models.Node{
		{ID: models.NodeInternet, Type: models.NodeInternet, Name: "Internet (0.0.0.0/0)", FirstSeenAt: now, LastSeenAt: now},
		{ID: lbARN, Type: models.NodeLoadBalancer, ARN: lbARN, Name: "web", FirstSeenAt: now, LastSeenAt: now},
	}
	edge := models.Edge{ID: collector.EdgeID(models.NodeInternet, models.EdgeReachableFrom, lbARN),
		FromNodeID: models.NodeInternet, ToNodeID: lbARN, Type: models.EdgeReachableFrom,
		Confidence:  models.ConfidenceDefinite,
		Properties:  map[string]any{"explanation": "web is reachable from the internet", "ports": "tcp/443"},
		FirstSeenAt: now, LastSeenAt: now}
	snap, err := store.CreateSnapshot(ctx, "111111111111", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, snap.ID, nodes, []models.Edge{edge}, nil); err != nil {
		t.Fatal(err)
	}
	return NewServer(app.New(store, nil), nil)
}

func TestInvokeInternetExposedTool(t *testing.T) {
	s := testServer(t)
	res, err := s.invokeTool(context.Background(), "find_internet_exposed_resources", nil)
	if err != nil {
		t.Fatal(err)
	}
	exposed, ok := res.([]app.ExposedResource)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	if len(exposed) != 1 || exposed[0].Ports != "tcp/443" {
		t.Fatalf("expected one LB exposed on tcp/443, got %+v", exposed)
	}
}

func TestInvokeInternetExposedToolEmptyJSON(t *testing.T) {
	ctx := context.Background()
	store, err := graph.Open(ctx, filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	s := NewServer(app.New(store, nil), nil)
	result, rpcErr := s.onToolCall(ctx, json.RawMessage(`{
		"name":"find_internet_exposed_resources",
		"arguments":{}
	}`))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	content, ok := result.(map[string]any)["content"].([]map[string]any)
	if !ok || len(content) != 1 {
		t.Fatalf("unexpected tool result: %#v", result)
	}
	if text, _ := content[0]["text"].(string); text != "[]" {
		t.Fatalf("expected empty JSON array, got %q", text)
	}
}

func TestToolListIncludesExposure(t *testing.T) {
	found := false
	for _, tl := range toolList() {
		if tl.Name == "find_internet_exposed_resources" {
			found = true
		}
	}
	if !found {
		t.Fatal("find_internet_exposed_resources missing from tool list")
	}
}

func TestUnknownToolErrors(t *testing.T) {
	s := testServer(t)
	if _, err := s.invokeTool(context.Background(), "no_such_tool", json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

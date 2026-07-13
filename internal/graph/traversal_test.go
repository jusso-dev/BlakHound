package graph

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func node(id string) models.Node {
	now := time.Now().UTC()
	return models.Node{ID: id, Type: "iam-role", Name: id, FirstSeenAt: now, LastSeenAt: now}
}

func edge(from, to string) models.Edge {
	now := time.Now().UTC()
	return models.Edge{ID: from + "->" + to, FromNodeID: from, ToNodeID: to, Type: models.EdgeAssumeRole,
		Confidence: models.ConfidenceDefinite, FirstSeenAt: now, LastSeenAt: now}
}

func TestTraversalCyclePrevention(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	snap, _ := s.CreateSnapshot(ctx, "111111111111", "", time.Now().UTC())
	// A -> B -> C -> A (cycle) and C -> D (target).
	nodes := []models.Node{node("A"), node("B"), node("C"), node("D")}
	edges := []models.Edge{edge("A", "B"), edge("B", "C"), edge("C", "A"), edge("C", "D")}
	if err := s.Import(ctx, snap.ID, nodes, edges, nil); err != nil {
		t.Fatal(err)
	}
	paths, err := s.AllPaths(ctx, "A", "D", TraverseOptions{MaxDepth: 10, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected exactly one acyclic path, got %d", len(paths))
	}
	if len(paths[0]) != 3 {
		t.Fatalf("expected path A->B->C->D (3 edges), got %d", len(paths[0]))
	}
	sp, err := s.ShortestPath(ctx, "A", "D", TraverseOptions{MaxDepth: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sp) != 3 {
		t.Fatalf("shortest path length = %d, want 3", len(sp))
	}
}

func TestSearchIsParameterized(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	snap, _ := s.CreateSnapshot(ctx, "111111111111", "", time.Now().UTC())
	_ = s.Import(ctx, snap.ID, []models.Node{node("prod")}, nil, nil)
	// SQL-injection style input must be treated as a literal, not executed.
	res, err := s.Search(ctx, "'; DROP TABLE nodes;--", nil, 10)
	if err != nil {
		t.Fatalf("search should not error on injection input: %v", err)
	}
	if len(res) != 0 {
		t.Fatal("injection string should match nothing")
	}
	// Table must still exist.
	if _, err := s.NodesByType(ctx, "iam-role"); err != nil {
		t.Fatalf("nodes table missing after injection attempt: %v", err)
	}
}

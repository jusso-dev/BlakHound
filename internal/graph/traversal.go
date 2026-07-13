package graph

import (
	"context"
	"fmt"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

// TraverseOptions controls path finding.
type TraverseOptions struct {
	EdgeTypes []string // restrict to these edge types (empty = all)
	MaxDepth  int      // maximum number of edges in a path
	Limit     int      // maximum number of paths to return
	MinConf   string   // minimum confidence: definite|possible|unknown
	ToType    string   // if set, any node of this type is a valid target
}

const defaultMaxDepth = 8
const defaultLimit = 25

// rawPath is an ordered list of edges.
type rawPath []models.Edge

// ShortestPath returns the shortest path (by edge count) from -> to using BFS,
// or nil if none exists within MaxDepth.
func (s *Store) ShortestPath(ctx context.Context, from, to string, opt TraverseOptions) (rawPath, error) {
	maxDepth := opt.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	type qitem struct {
		node string
		path rawPath
	}
	visited := map[string]bool{from: true}
	queue := []qitem{{node: from}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cur := queue[0]
		queue = queue[1:]
		if len(cur.path) >= maxDepth {
			continue
		}
		edges, err := s.OutEdges(ctx, cur.node, opt.EdgeTypes)
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if !confidenceOK(e.Confidence, opt.MinConf) {
				continue
			}
			if visited[e.ToNodeID] {
				continue
			}
			np := append(append(rawPath{}, cur.path...), e)
			if e.ToNodeID == to {
				return np, nil
			}
			visited[e.ToNodeID] = true
			queue = append(queue, qitem{node: e.ToNodeID, path: np})
		}
	}
	return nil, nil
}

// AllPaths enumerates simple (acyclic) paths from -> to up to MaxDepth, capped
// at Limit. Uses DFS with an on-path visited set for cycle protection.
func (s *Store) AllPaths(ctx context.Context, from, to string, opt TraverseOptions) ([]rawPath, error) {
	maxDepth := opt.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	limit := opt.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	var out []rawPath
	onPath := map[string]bool{from: true}
	var dfs func(node string, path rawPath) error
	dfs = func(node string, path rawPath) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(out) >= limit || len(path) >= maxDepth {
			return nil
		}
		edges, err := s.OutEdges(ctx, node, opt.EdgeTypes)
		if err != nil {
			return err
		}
		for _, e := range edges {
			if len(out) >= limit {
				return nil
			}
			if !confidenceOK(e.Confidence, opt.MinConf) || onPath[e.ToNodeID] {
				continue
			}
			np := append(append(rawPath{}, path...), e)
			target := e.ToNodeID == to
			if opt.ToType != "" {
				if n, err := s.GetNode(ctx, e.ToNodeID); err == nil && n != nil && n.Type == opt.ToType {
					target = true
				}
			}
			if target {
				out = append(out, np)
				continue
			}
			onPath[e.ToNodeID] = true
			if err := dfs(e.ToNodeID, np); err != nil {
				return err
			}
			delete(onPath, e.ToNodeID)
		}
		return nil
	}
	if err := dfs(from, nil); err != nil {
		return nil, err
	}
	return out, nil
}

// confidenceOK reports whether edge confidence meets the minimum threshold.
// Ordering: definite > possible > unknown/blocked. Empty min = accept all
// except blocked.
func confidenceOK(edgeConf, min string) bool {
	if edgeConf == models.ConfidenceBlocked {
		return false
	}
	rank := func(c string) int {
		switch c {
		case models.ConfidenceDefinite:
			return 3
		case models.ConfidencePossible:
			return 2
		case models.ConfidenceUnknown, "":
			return 1
		default:
			return 0
		}
	}
	if min == "" {
		return true
	}
	return rank(edgeConf) >= rank(min)
}

// BuildAttackPath converts a rawPath (edge list) into an explained AttackPath.
func (s *Store) BuildAttackPath(ctx context.Context, p rawPath) (models.AttackPath, error) {
	if len(p) == 0 {
		return models.AttackPath{}, fmt.Errorf("empty path")
	}
	fromNode, err := s.GetNode(ctx, p[0].FromNodeID)
	if err != nil {
		return models.AttackPath{}, err
	}
	toNode, err := s.GetNode(ctx, p[len(p)-1].ToNodeID)
	if err != nil {
		return models.AttackPath{}, err
	}
	ap := models.AttackPath{Confidence: models.ConfidenceDefinite}
	if fromNode != nil {
		ap.From = *fromNode
	}
	if toNode != nil {
		ap.To = *toNode
	}
	worstConf := models.ConfidenceDefinite
	for _, e := range p {
		expl := explainEdge(ctx, s, e)
		ap.Steps = append(ap.Steps, models.PathStep{
			FromNodeID:  e.FromNodeID,
			ToNodeID:    e.ToNodeID,
			EdgeID:      e.ID,
			EdgeType:    e.Type,
			Confidence:  e.Confidence,
			Explanation: expl,
			EvidenceIDs: e.EvidenceIDs,
		})
		worstConf = weakerConfidence(worstConf, e.Confidence)
	}
	ap.Confidence = worstConf
	ap.ID = fmt.Sprintf("path-%s-to-%s-%d", ap.From.ID, ap.To.ID, len(p))
	return ap, nil
}

func weakerConfidence(a, b string) string {
	rank := map[string]int{
		models.ConfidenceDefinite: 3, models.ConfidencePossible: 2,
		models.ConfidenceUnknown: 1, "": 1, models.ConfidenceBlocked: 0,
	}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

// explainEdge produces a human-readable explanation for a path step, using the
// edge's own stored explanation property when present.
func explainEdge(ctx context.Context, s *Store, e models.Edge) string {
	if e.Properties != nil {
		if v, ok := e.Properties["explanation"].(string); ok && v != "" {
			return v
		}
	}
	from, _ := s.GetNode(ctx, e.FromNodeID)
	to, _ := s.GetNode(ctx, e.ToNodeID)
	fn, tn := e.FromNodeID, e.ToNodeID
	if from != nil && from.Name != "" {
		fn = from.Name
	}
	if to != nil && to.Name != "" {
		tn = to.Name
	}
	return fmt.Sprintf("%s --%s--> %s (%s)", fn, e.Type, tn, e.Confidence)
}

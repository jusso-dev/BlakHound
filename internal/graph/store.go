// Package graph implements a SQLite-backed security graph. Traversal is done in
// Go through a repository interface so the backend can later be swapped without
// touching analysis code.
package graph

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jusso-dev/BlakHound/internal/version"
	"github.com/jusso-dev/BlakHound/pkg/models"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is a SQLite-backed graph repository.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the SQLite database at path and applies
// migrations. The file is created with 0600 permissions.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("empty database path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // serialise writes; modernc sqlite is not concurrent-safe for writes
	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		// non-fatal: log-worthy but do not block usage
		_ = err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the on-disk database path.
func (s *Store) Path() string { return s.path }

// DB exposes the raw handle for admin commands (vacuum/info).
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.db.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO metadata(key,value) VALUES('schema_version',?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		fmt.Sprintf("%d", version.SchemaVersion))
	return err
}

// --- Snapshots ---

// CreateSnapshot inserts a new snapshot and returns it.
func (s *Store) CreateSnapshot(ctx context.Context, accountID, note string, now time.Time) (models.Snapshot, error) {
	snap := models.Snapshot{
		ID:        fmt.Sprintf("snap-%s", now.UTC().Format("20060102T150405Z")),
		AccountID: accountID,
		CreatedAt: now.UTC(),
		Note:      note,
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO snapshots(id,account_id,created_at,note) VALUES(?,?,?,?)`,
		snap.ID, snap.AccountID, snap.CreatedAt.Format(time.RFC3339Nano), snap.Note)
	if err != nil {
		return models.Snapshot{}, fmt.Errorf("insert snapshot: %w", err)
	}
	return snap, nil
}

// LatestSnapshot returns the most recent snapshot id, or "" if none.
func (s *Store) LatestSnapshot(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1`).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// ListSnapshots returns snapshots newest first.
func (s *Store) ListSnapshots(ctx context.Context) ([]models.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,account_id,created_at,COALESCE(note,'') FROM snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Snapshot
	for rows.Next() {
		var sn models.Snapshot
		var ts string
		if err := rows.Scan(&sn.ID, &sn.AccountID, &ts, &sn.Note); err != nil {
			return nil, err
		}
		sn.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// --- Node/Edge/Evidence upsert (transactional import) ---

// Import persists a collection result within a single transaction.
func (s *Store) Import(ctx context.Context, snapshotID string, nodes []models.Node, edges []models.Edge, ev []models.Evidence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range ev {
		if err := insertEvidence(ctx, tx, e); err != nil {
			return err
		}
	}
	for _, n := range nodes {
		n.SnapshotID = snapshotID
		if err := upsertNode(ctx, tx, n); err != nil {
			return err
		}
	}
	for _, e := range edges {
		e.SnapshotID = snapshotID
		if err := upsertEdge(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertEvidence(ctx context.Context, tx *sql.Tx, e models.Evidence) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO evidence(id,source_service,source_api,source_resource,document_type,document,statement_index,explanation,collected_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET explanation=excluded.explanation`,
		e.ID, e.SourceService, e.SourceAPI, e.SourceResource, e.DocumentType,
		string(e.Document), e.StatementIndex, e.Explanation, e.CollectedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert evidence %s: %w", e.ID, err)
	}
	return nil
}

func upsertNode(ctx context.Context, tx *sql.Tx, n models.Node) error {
	props, _ := json.Marshal(n.Properties)
	now := n.LastSeenAt.Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO nodes(id,type,provider,account_id,region,arn,name,properties,first_seen_at,last_seen_at,snapshot_id)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   last_seen_at=excluded.last_seen_at, snapshot_id=excluded.snapshot_id,
		   properties=excluded.properties, name=excluded.name, arn=excluded.arn`,
		n.ID, n.Type, n.Provider, n.AccountID, n.Region, n.ARN, n.Name,
		string(props), n.FirstSeenAt.Format(time.RFC3339Nano), now, n.SnapshotID)
	if err != nil {
		return fmt.Errorf("upsert node %s: %w", n.ID, err)
	}
	return nil
}

func upsertEdge(ctx context.Context, tx *sql.Tx, e models.Edge) error {
	cond, _ := json.Marshal(e.Conditions)
	props, _ := json.Marshal(e.Properties)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO edges(id,from_node_id,to_node_id,type,effect,conditions,properties,confidence,first_seen_at,last_seen_at,snapshot_id)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   last_seen_at=excluded.last_seen_at, snapshot_id=excluded.snapshot_id,
		   confidence=excluded.confidence, conditions=excluded.conditions, properties=excluded.properties`,
		e.ID, e.FromNodeID, e.ToNodeID, e.Type, e.Effect, string(cond), string(props),
		e.Confidence, e.FirstSeenAt.Format(time.RFC3339Nano), e.LastSeenAt.Format(time.RFC3339Nano), e.SnapshotID)
	if err != nil {
		return fmt.Errorf("upsert edge %s: %w", e.ID, err)
	}
	for _, evID := range e.EvidenceIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO edge_evidence(edge_id,evidence_id) VALUES(?,?)`, e.ID, evID); err != nil {
			return fmt.Errorf("link edge evidence: %w", err)
		}
	}
	return nil
}

// --- Reads ---

func scanNode(rs interface{ Scan(...any) error }) (models.Node, error) {
	var n models.Node
	var props, first, last string
	var acct, region, arn, name sql.NullString
	if err := rs.Scan(&n.ID, &n.Type, &n.Provider, &acct, &region, &arn, &name, &props, &first, &last, &n.SnapshotID); err != nil {
		return n, err
	}
	n.AccountID, n.Region, n.ARN, n.Name = acct.String, region.String, arn.String, name.String
	if props != "" {
		_ = json.Unmarshal([]byte(props), &n.Properties)
	}
	n.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
	n.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
	return n, nil
}

const nodeCols = `id,type,provider,account_id,region,arn,name,properties,first_seen_at,last_seen_at,snapshot_id`

// GetNode returns a node by id.
func (s *Store) GetNode(ctx context.Context, id string) (*models.Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id=?`, id)
	n, err := scanNode(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// GetNodeByARN returns a node by ARN.
func (s *Store) GetNodeByARN(ctx context.Context, arn string) (*models.Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE arn=? LIMIT 1`, arn)
	n, err := scanNode(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// ResolveNode looks up a node by id, then ARN, then name substring.
func (s *Store) ResolveNode(ctx context.Context, ref string) (*models.Node, error) {
	if n, err := s.GetNode(ctx, ref); err != nil || n != nil {
		return n, err
	}
	if n, err := s.GetNodeByARN(ctx, ref); err != nil || n != nil {
		return n, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE name=? LIMIT 1`, ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		return &n, nil
	}
	return nil, nil
}

// NodesByType returns all nodes of a given type, sorted by id for determinism.
func (s *Store) NodesByType(ctx context.Context, typ string) ([]models.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE type=? ORDER BY id`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AllNodes returns every node sorted by id.
func (s *Store) AllNodes(ctx context.Context) ([]models.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

const edgeCols = `id,from_node_id,to_node_id,type,effect,conditions,properties,confidence,first_seen_at,last_seen_at,snapshot_id`

func (s *Store) scanEdge(ctx context.Context, rs interface{ Scan(...any) error }) (models.Edge, error) {
	var e models.Edge
	var cond, props, first, last string
	var effect, conf sql.NullString
	if err := rs.Scan(&e.ID, &e.FromNodeID, &e.ToNodeID, &e.Type, &effect, &cond, &props, &conf, &first, &last, &e.SnapshotID); err != nil {
		return e, err
	}
	e.Effect, e.Confidence = effect.String, conf.String
	if cond != "" {
		_ = json.Unmarshal([]byte(cond), &e.Conditions)
	}
	if props != "" {
		_ = json.Unmarshal([]byte(props), &e.Properties)
	}
	e.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
	e.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
	return e, nil
}

// GetEdge returns an edge (with evidence ids) by id.
func (s *Store) GetEdge(ctx context.Context, id string) (*models.Edge, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+edgeCols+` FROM edges WHERE id=?`, id)
	e, err := s.scanEdge(ctx, row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.EvidenceIDs, _ = s.edgeEvidenceIDs(ctx, id)
	return &e, nil
}

func (s *Store) edgeEvidenceIDs(ctx context.Context, edgeID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT evidence_id FROM edge_evidence WHERE edge_id=? ORDER BY evidence_id`, edgeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// OutEdges returns outgoing edges from a node, optionally filtered by type.
func (s *Store) OutEdges(ctx context.Context, fromID string, edgeTypes []string) ([]models.Edge, error) {
	q := `SELECT ` + edgeCols + ` FROM edges WHERE from_node_id=?`
	args := []any{fromID}
	if len(edgeTypes) > 0 {
		q += ` AND type IN (` + placeholders(len(edgeTypes)) + `)`
		for _, t := range edgeTypes {
			args = append(args, t)
		}
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Edge
	for rows.Next() {
		e, err := s.scanEdge(ctx, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].EvidenceIDs, _ = s.edgeEvidenceIDs(ctx, out[i].ID)
	}
	return out, nil
}

// InEdges returns incoming edges to a node.
func (s *Store) InEdges(ctx context.Context, toID string, edgeTypes []string) ([]models.Edge, error) {
	q := `SELECT ` + edgeCols + ` FROM edges WHERE to_node_id=?`
	args := []any{toID}
	if len(edgeTypes) > 0 {
		q += ` AND type IN (` + placeholders(len(edgeTypes)) + `)`
		for _, t := range edgeTypes {
			args = append(args, t)
		}
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Edge
	for rows.Next() {
		e, err := s.scanEdge(ctx, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllEdges returns every edge sorted by id.
func (s *Store) AllEdges(ctx context.Context) ([]models.Edge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+edgeCols+` FROM edges ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Edge
	for rows.Next() {
		e, err := s.scanEdge(ctx, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEvidence returns an evidence record by id.
func (s *Store) GetEvidence(ctx context.Context, id string) (*models.Evidence, error) {
	var e models.Evidence
	var doc, collected string
	var svc, api, res, dt, expl sql.NullString
	var stmt sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT id,source_service,source_api,source_resource,document_type,document,statement_index,explanation,collected_at
		 FROM evidence WHERE id=?`, id).
		Scan(&e.ID, &svc, &api, &res, &dt, &doc, &stmt, &expl, &collected)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.SourceService, e.SourceAPI, e.SourceResource = svc.String, api.String, res.String
	e.DocumentType, e.Explanation = dt.String, expl.String
	e.Document = json.RawMessage(doc)
	if stmt.Valid {
		i := int(stmt.Int64)
		e.StatementIndex = &i
	}
	e.CollectedAt, _ = time.Parse(time.RFC3339Nano, collected)
	return &e, nil
}

// Search finds nodes whose name or arn contains q (case-insensitive).
func (s *Store) Search(ctx context.Context, q string, types []string, limit int) ([]models.Node, error) {
	like := "%" + strings.ToLower(q) + "%"
	query := `SELECT ` + nodeCols + ` FROM nodes WHERE (LOWER(name) LIKE ? OR LOWER(arn) LIKE ?)`
	args := []any{like, like}
	if len(types) > 0 {
		query += ` AND type IN (` + placeholders(len(types)) + `)`
		for _, t := range types {
			args = append(args, t)
		}
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Counts returns node and edge counts by type for summaries.
func (s *Store) Counts(ctx context.Context) (nodes map[string]int, edges map[string]int, err error) {
	nodes, err = countBy(ctx, s.db, `SELECT type,COUNT(*) FROM nodes GROUP BY type`)
	if err != nil {
		return nil, nil, err
	}
	edges, err = countBy(ctx, s.db, `SELECT type,COUNT(*) FROM edges GROUP BY type`)
	return nodes, edges, err
}

func countBy(ctx context.Context, db *sql.DB, q string) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// SetMeta stores a metadata key/value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// GetMeta returns a metadata value or "" if absent.
func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// RecordCollectionRun inserts a completed run row.
func (s *Store) RecordCollectionRun(ctx context.Context, id, snapshotID, accountID, caller, status, regions, services string, apiReqs int, started, finished time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO collection_runs(id,snapshot_id,account_id,caller_arn,started_at,finished_at,status,regions,services,api_requests)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, snapshotID, accountID, caller, started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano),
		status, regions, services, apiReqs)
	return err
}

// RecordCollectionError inserts a permission/collection gap row.
func (s *Store) RecordCollectionError(ctx context.Context, runID, service, api, region, code, message, impact string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO collection_errors(run_id,service,api,region,code,message,impact,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		runID, service, api, region, code, message, impact, now.Format(time.RFC3339Nano))
	return err
}

// EvidenceBySource returns evidence ids whose source_resource equals resource.
func (s *Store) EvidenceBySource(ctx context.Context, resource string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM evidence WHERE source_resource=? ORDER BY id`, resource)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

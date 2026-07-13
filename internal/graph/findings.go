package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jusso-dev/BlakHound/pkg/models"
)

// UpsertFinding inserts or refreshes a finding keyed by fingerprint. A
// suppressed fingerprint keeps its suppressed status.
func (s *Store) UpsertFinding(ctx context.Context, f models.Finding) error {
	rem, _ := json.Marshal(f.Remediation)
	// Preserve suppression.
	var suppressed bool
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM suppressions WHERE finding_fingerprint=?`, f.Fingerprint).Scan(new(int))
	if err == nil {
		suppressed = true
	} else if err != sql.ErrNoRows {
		return err
	}
	status := f.Status
	if suppressed {
		status = models.StatusSuppressed
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO findings(id,rule_id,title,description,severity,confidence,category,status,source_node_id,target_node_id,remediation,first_seen_at,last_seen_at,snapshot_id,fingerprint)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(fingerprint) DO UPDATE SET
		   last_seen_at=excluded.last_seen_at, snapshot_id=excluded.snapshot_id,
		   severity=excluded.severity, confidence=excluded.confidence, status=excluded.status,
		   title=excluded.title, description=excluded.description, remediation=excluded.remediation`,
		f.ID, f.RuleID, f.Title, f.Description, f.Severity, f.Confidence, f.Category, status,
		f.SourceNodeID, f.TargetNodeID, string(rem),
		f.FirstSeenAt.Format(time.RFC3339Nano), f.LastSeenAt.Format(time.RFC3339Nano), f.SnapshotID, f.Fingerprint)
	if err != nil {
		return err
	}
	for _, evID := range f.EvidenceIDs {
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO finding_evidence(finding_id,evidence_id) VALUES(?,?)`, f.ID, evID); err != nil {
			return err
		}
	}
	return nil
}

// FindingFilter narrows a finding query.
type FindingFilter struct {
	Severity []string
	Category []string
	Status   []string
}

// ResolveOpenFindings marks findings from the previous scan resolved. Findings
// rediscovered by the next scan are reopened by UpsertFinding; suppressions are
// preserved independently.
func (s *Store) ResolveOpenFindings(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE findings SET status=? WHERE status=?`, models.StatusResolved, models.StatusOpen)
	return err
}

func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]models.Finding, error) {
	q := `SELECT id,rule_id,title,description,severity,confidence,category,status,source_node_id,target_node_id,remediation,first_seen_at,last_seen_at,snapshot_id,fingerprint FROM findings WHERE 1=1`
	var args []any
	if len(f.Severity) > 0 {
		q += ` AND severity IN (` + placeholders(len(f.Severity)) + `)`
		for _, v := range f.Severity {
			args = append(args, v)
		}
	}
	if len(f.Category) > 0 {
		q += ` AND category IN (` + placeholders(len(f.Category)) + `)`
		for _, v := range f.Category {
			args = append(args, v)
		}
	}
	if len(f.Status) > 0 {
		q += ` AND status IN (` + placeholders(len(f.Status)) + `)`
		for _, v := range f.Status {
			args = append(args, v)
		}
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,rule_id,title,description,severity,confidence,category,status,source_node_id,target_node_id,remediation,first_seen_at,last_seen_at,snapshot_id,fingerprint FROM findings WHERE id=?`, id)
	f, err := scanFinding(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ids, _ := s.findingEvidence(ctx, id)
	f.EvidenceIDs = ids
	return &f, nil
}

func (s *Store) findingEvidence(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT evidence_id FROM finding_evidence WHERE finding_id=? ORDER BY evidence_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanFinding(rs interface{ Scan(...any) error }) (models.Finding, error) {
	var f models.Finding
	var desc, src, tgt, rem sql.NullString
	var first, last string
	if err := rs.Scan(&f.ID, &f.RuleID, &f.Title, &desc, &f.Severity, &f.Confidence, &f.Category, &f.Status,
		&src, &tgt, &rem, &first, &last, &f.SnapshotID, &f.Fingerprint); err != nil {
		return f, err
	}
	f.Description, f.SourceNodeID, f.TargetNodeID = desc.String, src.String, tgt.String
	if rem.String != "" {
		_ = json.Unmarshal([]byte(rem.String), &f.Remediation)
	}
	f.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
	f.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
	return f, nil
}

// Suppress adds a suppression and marks the finding suppressed.
func (s *Store) Suppress(ctx context.Context, fingerprint, reason, user, ticket string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO suppressions(finding_fingerprint,reason,created_by,created_at,ticket) VALUES(?,?,?,?,?)
		 ON CONFLICT(finding_fingerprint) DO UPDATE SET reason=excluded.reason`,
		fingerprint, reason, user, now.Format(time.RFC3339Nano), ticket)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE findings SET status=? WHERE fingerprint=?`, models.StatusSuppressed, fingerprint)
	return err
}

// Unsuppress removes a suppression and reopens the finding.
func (s *Store) Unsuppress(ctx context.Context, fingerprint string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE finding_fingerprint=?`, fingerprint); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE findings SET status=? WHERE fingerprint=? AND status=?`,
		models.StatusOpen, fingerprint, models.StatusSuppressed)
	return err
}

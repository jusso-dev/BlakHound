-- BlakHound schema v1. Rebuildable from scratch.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    alias      TEXT,
    is_org_management INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note       TEXT
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id            TEXT PRIMARY KEY,
    snapshot_id   TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    caller_arn    TEXT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL,
    regions       TEXT,
    services      TEXT,
    api_requests  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS collection_errors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    service      TEXT NOT NULL,
    api          TEXT NOT NULL,
    region       TEXT,
    code         TEXT,
    message      TEXT,
    impact       TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id            TEXT PRIMARY KEY,
    type          TEXT NOT NULL,
    provider      TEXT NOT NULL,
    account_id    TEXT,
    region        TEXT,
    arn           TEXT,
    name          TEXT,
    properties    TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    snapshot_id   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_arn ON nodes(arn);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_nodes_acct_region ON nodes(account_id, region);
CREATE INDEX IF NOT EXISTS idx_nodes_snapshot ON nodes(snapshot_id);

CREATE TABLE IF NOT EXISTS edges (
    id            TEXT PRIMARY KEY,
    from_node_id  TEXT NOT NULL,
    to_node_id    TEXT NOT NULL,
    type          TEXT NOT NULL,
    effect        TEXT,
    conditions    TEXT,
    properties    TEXT,
    confidence    TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    snapshot_id   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type);
CREATE INDEX IF NOT EXISTS idx_edges_snapshot ON edges(snapshot_id);

CREATE TABLE IF NOT EXISTS edge_evidence (
    edge_id     TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (edge_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,
    source_service  TEXT,
    source_api      TEXT,
    source_resource TEXT,
    document_type   TEXT,
    document        TEXT,
    statement_index INTEGER,
    explanation     TEXT,
    collected_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence(source_resource);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT,
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    category      TEXT NOT NULL,
    status        TEXT NOT NULL,
    source_node_id TEXT,
    target_node_id TEXT,
    remediation   TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    snapshot_id   TEXT NOT NULL,
    fingerprint   TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_findings_sev_status ON findings(severity, status);

CREATE TABLE IF NOT EXISTS finding_paths (
    finding_id TEXT NOT NULL,
    path_json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id  TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS suppressions (
    finding_fingerprint TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    created_by  TEXT,
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    ticket      TEXT
);
